"""
Isolated repository cloning with automatic cleanup.

This module provides a context manager that:
1. Clones any public GitHub repository into an OS-managed temporary directory
   using --depth 1 (shallow clone) to minimize disk and network usage.
2. Yields the resolved local path for tool inspection.
3. Automatically cleans up the temp directory on exit — even on exceptions.

Security considerations:
- Uses subprocess list arguments (never shell=True) to prevent injection.
- Enforces a 60-second clone timeout to prevent hanging on slow/unreachable repos.
- The temp directory prefix ("auditor_") makes it identifiable for manual cleanup.
- Does NOT execute any code from the cloned repository.
"""

from __future__ import annotations

import logging
import shutil
import subprocess
import tempfile
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

logger = logging.getLogger(__name__)


@contextmanager
def clone_repository(repo_url: str, timeout: int = 60) -> Generator[str, None, None]:
    """
    Context manager that shallow-clones a repository and cleans up on exit.

    Args:
        repo_url: Public Git repository URL (https or ssh).
        timeout:  Maximum seconds to wait for the clone operation. Default: 60.

    Yields:
        Absolute path string of the cloned repository root directory.

    Raises:
        ValueError:   If repo_url is empty or obviously malformed.
        RuntimeError: If git clone fails (non-zero exit code).
        TimeoutError: If the clone exceeds the timeout threshold.

    Example:
        with clone_repository("https://github.com/pallets/flask") as repo_path:
            files = os.listdir(repo_path)
    """
    if not repo_url or not repo_url.strip():
        raise ValueError("repo_url must be a non-empty string.")

    repo_url = repo_url.strip()

    # Basic URL sanity check — must look like a git URL
    if not (repo_url.startswith("https://") or repo_url.startswith("git@")):
        raise ValueError(f"Invalid repo_url: '{repo_url}'. Must start with 'https://' or 'git@'.")

    temp_dir = tempfile.mkdtemp(prefix="auditor_")
    logger.info("Cloning repository: %s → %s", repo_url, temp_dir)

    try:
        cmd = [
            "git",
            "clone",
            "--depth",
            "1",  # Shallow — no full history needed
            "--single-branch",  # Only the default branch
            "--no-tags",  # Skip tag objects
            repo_url,
            temp_dir,
        ]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=timeout,
                check=False,  # We check manually for better error messages
            )
        except subprocess.TimeoutExpired as exc:
            raise TimeoutError(f"Git clone timed out after {timeout}s for: {repo_url}") from exc

        if result.returncode != 0:
            stderr_msg = result.stderr.strip()
            raise RuntimeError(
                f"Git clone failed (exit {result.returncode}) for {repo_url}.\n"
                f"Git stderr: {stderr_msg}"
            )

        resolved = Path(temp_dir).resolve()
        logger.info("Clone successful. Repo root: %s", resolved)
        yield str(resolved)

    finally:
        logger.debug("Cleaning up temporary clone directory: %s", temp_dir)
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.info("Temporary clone directory removed: %s", temp_dir)
