"""
Shared pytest fixtures and collection configuration for the DevOps Auditor test suite.

Collection rules:
  - tests/fixtures/** directories are test DATA (synthetic repos), not test files.
    They are excluded from pytest collection via pyproject.toml testpaths.

Fixtures provided:
  - clean_repo_path:      Synthetic well-structured repo (zero violations expected)
  - vulnerable_repo_path: Synthetic insecure repo (known violations planted)
  - invalid_repo_path:    Minimal/broken repo (missing README, LICENSE, CI, etc.)

Each fixture copies the corresponding static directory into a fresh tmp_path so
tests can modify files without affecting other tests.
"""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

# Absolute path to the fixtures directory
_FIXTURES_DIR = Path(__file__).parent / "fixtures"


def _copy_fixture(name: str, tmp_path: Path) -> str:
    """Copy a named fixture directory into a fresh temp directory.

    Returns the resolved absolute path string for InspectionTools.
    """
    src = _FIXTURES_DIR / name
    dest = tmp_path / name
    shutil.copytree(src, dest, dirs_exist_ok=True)
    return str(dest.resolve())


@pytest.fixture()
def clean_repo_path(tmp_path: Path) -> str:
    """
    Provide a path to a clean synthetic repository.

    Contains: README.md, LICENSE, .gitignore, pinned requirements.txt,
    safe source code, SHA-pinned GitHub Actions CI, and tests.

    Expected audit result: zero violations.
    """
    return _copy_fixture("clean-repo", tmp_path)


@pytest.fixture()
def vulnerable_repo_path(tmp_path: Path) -> str:
    """
    Provide a path to a deliberately vulnerable synthetic repository.

    Planted violations:
      SEC-001: Hardcoded AWS access key (AKIA pattern) in config.py
      SEC-002: Committed .env file with production secrets
      CFG-001: Hardcoded absolute path (/Users/john.doe/...) in config.py
      SEC-003: DEBUG=True in production config
      SEC-004: subprocess(shell=True) with user input
      DEP-001: Unpinned dependencies in requirements.txt
      CI-001:  GitHub Action pinned to @main (mutable ref)
      CI-002:  permissions: write-all in workflow
      TEST-001: CI uses pytest --co (collect-only, skips execution)
    """
    return _copy_fixture("vulnerable-repo", tmp_path)


@pytest.fixture()
def invalid_repo_path(tmp_path: Path) -> str:
    """
    Provide a path to a minimal/invalid synthetic repository.

    Planted violations:
      COLLAB-001: No README.md
      COLLAB-002: No LICENSE file
      HYGN-001:   No .gitignore
      SEC-001:    Hardcoded GitHub PAT (ghp_ pattern) in main.py
      DEP-001:    Unpinned dependencies in requirements.txt
    """
    return _copy_fixture("invalid-repo", tmp_path)
