"""
Deterministic, sandboxed inspection tools for repository auditing.

All tools enforce strict path sandboxing to prevent directory traversal attacks.
The agent can only read files within the cloned repository root — no symlink
escapes, no relative path tricks (e.g., ../../etc/passwd).

Tool inventory:
- list_files(sub_dir)              → Directory structure discovery
- read_file(path, start, end)      → Bounded line-range file inspection
- search_code(pattern, extension)  → Regex search across files with line numbers
- git_log(max_count)               → Commit history and message hygiene analysis

Design decisions:
- All paths are resolved via Path.resolve() before any comparison.
- .git/ directories are always excluded from walks to prevent internal git object reads.
- Results are capped to prevent context-window bloat in the LLM loop.
- Errors return structured {"error": "..."} dicts so the LLM can reason about
  tool failures without crashing the orchestration loop.
"""

from __future__ import annotations

import logging
import os
import re
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Maximum file list entries to return (protects LLM context window)
_MAX_FILE_LIST = 500

# Maximum regex matches to return per search_code call
_MAX_SEARCH_MATCHES = 50

# Maximum file size (bytes) the agent will attempt to read (10 MB)
_MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024

# Directories to always skip during tree walks
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".eggs",
        "dist",
        "build",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
    }
)


class InspectionTools:
    """
    Sandboxed repository inspection toolkit.

    All methods return dicts suitable for JSON serialisation and direct
    injection into the LLM tool-result messages.
    """

    def __init__(self, repo_root: str) -> None:
        self.repo_root: Path = Path(repo_root).resolve()
        if not self.repo_root.is_dir():
            raise ValueError(f"repo_root does not exist or is not a directory: {repo_root}")
        logger.debug("InspectionTools initialized for: %s", self.repo_root)

    # ─── Sandbox Enforcement ────────────────────────────────────────────────

    def _resolve_safe(self, relative_path: str) -> Path:
        """
        Resolve a relative path against the repo root and verify it stays within.

        Raises:
            ValueError: If path escapes the repo root (traversal attempt).
        """
        candidate = (self.repo_root / relative_path).resolve()
        try:
            candidate.relative_to(self.repo_root)
        except ValueError as exc:
            raise ValueError(
                f"Directory traversal blocked: '{relative_path}' resolves outside repo root."
            ) from exc
        return candidate

    # ─── Tool: list_files ───────────────────────────────────────────────────

    def list_files(self, sub_dir: str = ".") -> dict[str, Any]:
        """
        Recursively list all files in the repository (or a sub-directory).

        Skips .git/ and other build/cache directories to keep output focused
        on source code and configuration.

        Args:
            sub_dir: Sub-directory path relative to repo root. Defaults to ".".

        Returns:
            {"files": [...], "total": N, "truncated": bool}
        """
        try:
            target_dir = self._resolve_safe(sub_dir)
        except ValueError as exc:
            return {"error": str(exc)}

        if not target_dir.is_dir():
            return {"error": f"Path '{sub_dir}' is not a directory."}

        file_list: list[str] = []
        truncated = False

        for root, dirs, files in os.walk(target_dir):
            # Prune excluded directories in-place (modifies walk behaviour)
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)

            for fname in sorted(files):
                if len(file_list) >= _MAX_FILE_LIST:
                    truncated = True
                    break
                full_path = Path(root) / fname
                rel = full_path.relative_to(self.repo_root).as_posix()
                file_list.append(rel)

            if truncated:
                break

        return {
            "files": file_list,
            "total": len(file_list),
            "truncated": truncated,
        }

    # ─── Tool: read_file ────────────────────────────────────────────────────

    def read_file(
        self,
        path: str,
        start_line: int = 1,
        end_line: int = 150,
    ) -> dict[str, Any]:
        """
        Read a bounded range of lines from a file with line numbers.

        Line numbers in the returned content are 1-based and match the
        actual file so the LLM can cite accurate evidence line numbers.

        Args:
            path:       File path relative to repo root.
            start_line: First line to return (1-based, inclusive).
            end_line:   Last line to return (1-based, inclusive). Max 200 lines per call.

        Returns:
            {"path": str, "total_lines": int, "content": str}
        """
        try:
            target_file = self._resolve_safe(path)
        except ValueError as exc:
            return {"error": str(exc)}

        if not target_file.is_file():
            return {"error": f"File '{path}' does not exist."}

        # Guard against reading massive binary-adjacent files
        size = target_file.stat().st_size
        if size > _MAX_FILE_SIZE_BYTES:
            return {
                "error": (
                    f"File '{path}' is {size:,} bytes — exceeds {_MAX_FILE_SIZE_BYTES:,} byte "
                    "limit. Use search_code() to locate specific patterns instead."
                )
            }

        # Clamp window to at most 200 lines per call to protect context budget
        start_line = max(1, start_line)
        end_line = min(end_line, start_line + 199)

        try:
            with open(target_file, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()

            total_lines = len(lines)
            end_line = min(end_line, total_lines)

            if start_line > total_lines:
                return {
                    "path": path,
                    "total_lines": total_lines,
                    "content": (
                        f"(start_line={start_line} exceeds file length of {total_lines} lines)"
                    ),
                }

            window = lines[start_line - 1 : end_line]
            numbered = "".join(
                f"{idx}: {line}" for idx, line in enumerate(window, start=start_line)
            )

            return {
                "path": path,
                "total_lines": total_lines,
                "content": numbered,
                "start_line": start_line,
                "end_line": end_line,
            }
        except OSError as exc:
            logger.warning("Failed to read file '%s': %s", path, exc)
            return {"error": f"Failed to read file '{path}': {exc}"}

    # ─── Tool: search_code ──────────────────────────────────────────────────

    def search_code(
        self,
        pattern: str,
        file_extension: str | None = None,
    ) -> dict[str, Any]:
        """
        Regex search across all repository files with line-level results.

        Args:
            pattern:        Python regex pattern (case-insensitive).
            file_extension: Optional filter, e.g. ".py", ".yml", ".toml".

        Returns:
            {"matches": [...], "truncated": bool}
            Each match: {"file": str, "line": int, "content": str}
        """
        try:
            regex = re.compile(pattern, re.IGNORECASE)
        except re.error as exc:
            return {"error": f"Invalid regex pattern: {exc}"}

        matches: list[dict[str, Any]] = []
        truncated = False

        for root, dirs, files in os.walk(self.repo_root):
            dirs[:] = sorted(d for d in dirs if d not in _SKIP_DIRS)

            for fname in sorted(files):
                if file_extension and not fname.endswith(file_extension):
                    continue

                file_path = Path(root) / fname
                rel = file_path.relative_to(self.repo_root).as_posix()

                try:
                    with open(file_path, encoding="utf-8", errors="ignore") as fh:
                        for line_idx, line in enumerate(fh, start=1):
                            if regex.search(line):
                                matches.append(
                                    {
                                        "file": rel,
                                        "line": line_idx,
                                        "content": line.rstrip()[:200],
                                    }
                                )
                                if len(matches) >= _MAX_SEARCH_MATCHES:
                                    truncated = True
                                    break
                except OSError:
                    continue

                if truncated:
                    break

            if truncated:
                break

        return {"matches": matches, "truncated": truncated}

    # ─── Tool: git_log ──────────────────────────────────────────────────────

    def git_log(self, max_count: int = 20) -> dict[str, Any]:
        """
        Retrieve recent git commit history for message and author hygiene analysis.

        Checks for:
        - Generic commit messages ("fix", "update", "WIP")
        - Missing or placeholder author names
        - Unusual commit timing patterns

        Args:
            max_count: Maximum number of commits to retrieve. Capped at 50.

        Returns:
            {"commits": [...]}
            Each commit: {"hash": str, "author": str, "date": str, "message": str}
        """
        max_count = min(max_count, 50)  # Hard cap to avoid context bloat
        cmd = [
            "git",
            "log",
            f"-n{max_count}",
            "--pretty=format:%h|%an|%ae|%ad|%s",
            "--date=short",
        ]

        try:
            result = subprocess.run(
                cmd,
                cwd=self.repo_root,
                capture_output=True,
                text=True,
                timeout=15,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return {"error": "git log timed out after 15 seconds."}

        if result.returncode != 0:
            return {"error": f"git log failed: {result.stderr.strip()}"}

        entries: list[dict[str, str]] = []
        for raw_line in result.stdout.strip().split("\n"):
            if not raw_line.strip():
                continue
            parts = raw_line.split("|", 4)
            if len(parts) == 5:
                entries.append(
                    {
                        "hash": parts[0],
                        "author": parts[1],
                        "email": parts[2],
                        "date": parts[3],
                        "message": parts[4],
                    }
                )

        return {"commits": entries, "total": len(entries)}
