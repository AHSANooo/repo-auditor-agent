"""
Fixture-based integration tests for InspectionTools.

These tests use the three synthetic mini-repos (clean, vulnerable, invalid)
to verify that the tools correctly detect or miss violations on real file structures.

No LLM calls are made — only the tool layer is tested here.
"""

from __future__ import annotations

from devops_auditor.tools import InspectionTools

# ─── Clean Repo ───────────────────────────────────────────────────────────────


class TestCleanRepoTools:
    """Tools should find the right structure in the clean fixture."""

    def test_list_files_finds_readme(self, clean_repo_path: str) -> None:
        tools = InspectionTools(clean_repo_path)
        result = tools.list_files()
        assert not result.get("error")
        files = result["files"]
        assert any("README.md" in f for f in files)

    def test_list_files_finds_license(self, clean_repo_path: str) -> None:
        tools = InspectionTools(clean_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert any("LICENSE" in f for f in files)

    def test_list_files_finds_gitignore(self, clean_repo_path: str) -> None:
        tools = InspectionTools(clean_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert any(".gitignore" in f for f in files)

    def test_list_files_finds_ci_workflow(self, clean_repo_path: str) -> None:
        tools = InspectionTools(clean_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert any("ci.yml" in f for f in files)

    def test_search_no_hardcoded_secrets(self, clean_repo_path: str) -> None:
        """Clean repo should have zero AKIA-pattern matches."""
        tools = InspectionTools(clean_repo_path)
        result = tools.search_code(r"AKIA[0-9A-Z]{16}")
        assert result["matches"] == []

    def test_search_no_mutable_action_refs(self, clean_repo_path: str) -> None:
        """Clean repo CI uses SHA-pinned actions, not @main or @master."""
        tools = InspectionTools(clean_repo_path)
        result = tools.search_code(r"uses:.*@(main|master)", file_extension=".yml")
        assert result["matches"] == [], "SHA-pinned clean repo should have no mutable action refs"

    def test_read_requirements_pinned(self, clean_repo_path: str) -> None:
        """All dependencies in the clean repo must be pinned (contain ==)."""
        tools = InspectionTools(clean_repo_path)
        result = tools.read_file("requirements.txt")
        assert not result.get("error")
        content = result["content"]
        lines = [ln.split(": ", 1)[1].strip() for ln in content.splitlines() if ": " in ln]
        for line in lines:
            if line and not line.startswith("#"):
                assert "==" in line, f"Unpinned dependency found: {line}"


# ─── Vulnerable Repo ──────────────────────────────────────────────────────────


class TestVulnerableRepoTools:
    """Tools should surface all planted violations in the vulnerable fixture."""

    def test_search_finds_aws_access_key(self, vulnerable_repo_path: str) -> None:
        """search_code must detect the hardcoded AKIA pattern."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"AKIA[0-9A-Z]{16}")
        assert len(result["matches"]) >= 1
        match = result["matches"][0]
        assert "config.py" in match["file"] or ".env" in match["file"]

    def test_search_finds_debug_true(self, vulnerable_repo_path: str) -> None:
        """search_code should find DEBUG = True in production config."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"DEBUG\s*=\s*True", file_extension=".py")
        assert len(result["matches"]) >= 1

    def test_search_finds_hardcoded_path(self, vulnerable_repo_path: str) -> None:
        """search_code should detect hardcoded /Users/... absolute path."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"/Users/[a-zA-Z]")
        assert len(result["matches"]) >= 1

    def test_search_finds_shell_true(self, vulnerable_repo_path: str) -> None:
        """search_code should flag shell=True usage."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"shell\s*=\s*True", file_extension=".py")
        assert len(result["matches"]) >= 1

    def test_list_files_reveals_env_committed(self, vulnerable_repo_path: str) -> None:
        """.env file present in the file listing (not gitignored)."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert any(f == ".env" or f.endswith("/.env") for f in files)

    def test_search_finds_mutable_action_ref(self, vulnerable_repo_path: str) -> None:
        """Workflow uses @main — mutable, should be flagged."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"uses:.*@main", file_extension=".yml")
        assert len(result["matches"]) >= 1

    def test_search_finds_write_all_permissions(self, vulnerable_repo_path: str) -> None:
        """Workflow has permissions: write-all."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"permissions:\s*write-all", file_extension=".yml")
        assert len(result["matches"]) >= 1

    def test_search_finds_pytest_collect_only(self, vulnerable_repo_path: str) -> None:
        """CI skips tests via pytest --co."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.search_code(r"pytest\s+--co", file_extension=".yml")
        assert len(result["matches"]) >= 1

    def test_read_requirements_unpinned(self, vulnerable_repo_path: str) -> None:
        """requirements.txt should have unpinned deps (no == constraint)."""
        tools = InspectionTools(vulnerable_repo_path)
        result = tools.read_file("requirements.txt")
        assert not result.get("error")
        content = result["content"]
        lines = [ln.split(": ", 1)[1].strip() for ln in content.splitlines() if ": " in ln]
        unpinned = [ln for ln in lines if ln and not ln.startswith("#") and "==" not in ln]
        assert len(unpinned) >= 1, "Vulnerable repo should have unpinned dependencies"


# ─── Invalid Repo ─────────────────────────────────────────────────────────────


class TestInvalidRepoTools:
    """Tools should expose missing-structure violations in the invalid fixture."""

    def test_list_files_no_readme(self, invalid_repo_path: str) -> None:
        """Invalid repo has no README — tool should not list one."""
        tools = InspectionTools(invalid_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert not any(f.upper() == "README.MD" or f.upper().endswith("/README.MD") for f in files)

    def test_list_files_no_license(self, invalid_repo_path: str) -> None:
        """Invalid repo has no LICENSE file."""
        tools = InspectionTools(invalid_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert not any("LICENSE" in f.upper() for f in files)

    def test_list_files_no_ci_workflow(self, invalid_repo_path: str) -> None:
        """Invalid repo has no CI workflow."""
        tools = InspectionTools(invalid_repo_path)
        result = tools.list_files()
        files = result["files"]
        assert not any(".github" in f for f in files)

    def test_search_finds_github_pat(self, invalid_repo_path: str) -> None:
        """Invalid repo has a GitHub PAT (ghp_) hardcoded in main.py."""
        tools = InspectionTools(invalid_repo_path)
        result = tools.search_code(r"ghp_[A-Za-z0-9]{36}")
        assert len(result["matches"]) >= 1
        assert "main.py" in result["matches"][0]["file"]
