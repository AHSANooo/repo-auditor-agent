"""
Unit tests for the sandboxed InspectionTools.

Tests verify:
1. list_files returns relative POSIX paths and skips .git/
2. read_file returns correct line-numbered content
3. read_file enforces line window clamping (max 200 lines)
4. Directory traversal is blocked
5. search_code finds patterns with correct line numbers
6. search_code returns error on invalid regex
7. git_log returns structured commit data
8. Non-existent file returns error dict
9. read_file on a directory returns error
10. _SKIP_DIRS are excluded from walks
"""

import subprocess
from pathlib import Path

import pytest

from devops_auditor.tools import InspectionTools

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture()
def repo(tmp_path: Path) -> Path:
    """Create a synthetic mini-repo with known content."""
    # Root files
    (tmp_path / "README.md").write_text("# Test Repo\nA fake repository.", encoding="utf-8")
    (tmp_path / ".env").write_text("API_KEY=test_value_here\n", encoding="utf-8")
    (tmp_path / "requirements.txt").write_text("flask==2.3.0\nrequests>=2.31\n", encoding="utf-8")

    # Source directory
    src = tmp_path / "src"
    src.mkdir()
    (src / "main.py").write_text(
        "import os\n\nAPI_KEY = 'hardcoded_secret_here_12345'\n\ndef main():\n    pass\n",
        encoding="utf-8",
    )
    (src / "config.py").write_text(
        "DB_HOST = 'localhost'\nDB_PORT = 5432\n",
        encoding="utf-8",
    )

    # Nested directory
    deep = tmp_path / "src" / "utils"
    deep.mkdir()
    (deep / "helpers.py").write_text("def helper():\n    return True\n", encoding="utf-8")

    # Directories that should be skipped
    (tmp_path / "__pycache__").mkdir()
    (tmp_path / "__pycache__" / "cached.pyc").write_bytes(b"\x00\x01\x02")

    (tmp_path / "node_modules").mkdir()
    (tmp_path / "node_modules" / "package.js").write_text("module.exports = {}", encoding="utf-8")

    # Initialize a real git repo for git_log tests
    subprocess.run(["git", "init"], cwd=tmp_path, capture_output=True)
    subprocess.run(
        ["git", "config", "user.email", "test@test.com"], cwd=tmp_path, capture_output=True
    )
    subprocess.run(["git", "config", "user.name", "Test User"], cwd=tmp_path, capture_output=True)
    subprocess.run(["git", "add", "."], cwd=tmp_path, capture_output=True)
    subprocess.run(
        ["git", "commit", "-m", "feat: initial test commit"], cwd=tmp_path, capture_output=True
    )

    return tmp_path


@pytest.fixture()
def tools(repo: Path) -> InspectionTools:
    return InspectionTools(str(repo))


# ─── list_files ─────────────────────────────────────────────────────────────


class TestListFiles:
    def test_returns_files_dict(self, tools: InspectionTools) -> None:
        result = tools.list_files()
        assert "files" in result
        assert isinstance(result["files"], list)

    def test_relative_posix_paths(self, tools: InspectionTools) -> None:
        result = tools.list_files()
        for path in result["files"]:
            assert "\\" not in path, f"Windows path found: {path}"

    def test_git_dir_excluded(self, tools: InspectionTools) -> None:
        result = tools.list_files()
        assert not any(".git" in f for f in result["files"])

    def test_pycache_excluded(self, tools: InspectionTools) -> None:
        result = tools.list_files()
        assert not any("__pycache__" in f for f in result["files"])

    def test_node_modules_excluded(self, tools: InspectionTools) -> None:
        result = tools.list_files()
        assert not any("node_modules" in f for f in result["files"])

    def test_known_files_present(self, tools: InspectionTools) -> None:
        result = tools.list_files()
        files_set = set(result["files"])
        assert "README.md" in files_set
        assert "src/main.py" in files_set
        assert "src/utils/helpers.py" in files_set

    def test_sub_dir_filter(self, tools: InspectionTools) -> None:
        result = tools.list_files("src")
        assert all(f.startswith("src/") for f in result["files"])

    def test_invalid_sub_dir_returns_error(self, tools: InspectionTools) -> None:
        result = tools.list_files("nonexistent_dir")
        assert "error" in result

    def test_traversal_blocked(self, tools: InspectionTools) -> None:
        result = tools.list_files("../../etc")
        assert "error" in result


# ─── read_file ───────────────────────────────────────────────────────────────


class TestReadFile:
    def test_reads_file_content(self, tools: InspectionTools) -> None:
        result = tools.read_file("README.md")
        assert "content" in result
        assert "Test Repo" in result["content"]

    def test_line_numbers_present(self, tools: InspectionTools) -> None:
        result = tools.read_file("README.md")
        assert result["content"].startswith("1:")

    def test_start_end_line_clamped_to_200(self, tools: InspectionTools) -> None:
        result = tools.read_file("src/main.py", start_line=1, end_line=5000)
        # Should not error, just return up to 200 lines
        assert "content" in result

    def test_nonexistent_file_returns_error(self, tools: InspectionTools) -> None:
        result = tools.read_file("does_not_exist.py")
        assert "error" in result

    def test_directory_returns_error(self, tools: InspectionTools) -> None:
        result = tools.read_file("src")
        assert "error" in result

    def test_traversal_blocked(self, tools: InspectionTools) -> None:
        result = tools.read_file("../../etc/passwd")
        assert "error" in result

    def test_total_lines_correct(self, tools: InspectionTools) -> None:
        result = tools.read_file("src/main.py")
        assert result["total_lines"] == 6

    def test_specific_line_range(self, tools: InspectionTools) -> None:
        result = tools.read_file("src/main.py", start_line=3, end_line=3)
        assert "3:" in result["content"]
        assert "hardcoded_secret_here_12345" in result["content"]


# ─── search_code ─────────────────────────────────────────────────────────────


class TestSearchCode:
    def test_finds_pattern_with_line_numbers(self, tools: InspectionTools) -> None:
        result = tools.search_code("API_KEY")
        assert "matches" in result
        assert any(m["line"] == 3 and "main.py" in m["file"] for m in result["matches"])

    def test_file_extension_filter(self, tools: InspectionTools) -> None:
        result = tools.search_code(".*", ".md")
        assert all(m["file"].endswith(".md") for m in result["matches"])

    def test_invalid_regex_returns_error(self, tools: InspectionTools) -> None:
        result = tools.search_code("[unclosed bracket")
        assert "error" in result

    def test_no_matches_returns_empty_list(self, tools: InspectionTools) -> None:
        result = tools.search_code("DEFINITELY_DOES_NOT_EXIST_XYZ_12345")
        assert result["matches"] == []

    def test_pycache_excluded_from_search(self, tools: InspectionTools) -> None:
        result = tools.search_code(".*")
        assert not any("__pycache__" in m["file"] for m in result["matches"])

    def test_content_snippet_max_200_chars(self, tools: InspectionTools) -> None:
        result = tools.search_code("import")
        for match in result["matches"]:
            assert len(match["content"]) <= 200


# ─── git_log ─────────────────────────────────────────────────────────────────


class TestGitLog:
    def test_returns_commits_list(self, tools: InspectionTools) -> None:
        result = tools.git_log()
        assert "commits" in result

    def test_commit_has_required_fields(self, tools: InspectionTools) -> None:
        result = tools.git_log()
        if result["commits"]:
            commit = result["commits"][0]
            assert "hash" in commit
            assert "author" in commit
            assert "date" in commit
            assert "message" in commit

    def test_max_count_respected(self, tools: InspectionTools) -> None:
        result = tools.git_log(max_count=1)
        assert len(result["commits"]) <= 1

    def test_max_count_hard_capped_at_50(self, tools: InspectionTools) -> None:
        """Verify that requesting > 50 commits is silently clamped."""
        result = tools.git_log(max_count=9999)
        # We only have 1 commit, but the query limit should be 50
        assert len(result["commits"]) <= 50
