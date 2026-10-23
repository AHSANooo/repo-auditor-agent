"""
Unit tests for repo_manager.py — clone_repository context manager.

Tests validation, success path, git failure, timeout handling, and automatic cleanup.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devops_auditor.repo_manager import clone_repository


class TestCloneRepositoryValidation:
    def test_empty_url_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"), clone_repository(""):
            pass

    def test_whitespace_url_raises_value_error(self) -> None:
        with pytest.raises(ValueError, match="non-empty string"), clone_repository("   "):
            pass

    def test_invalid_prefix_raises_value_error(self) -> None:
        with (
            pytest.raises(ValueError, match="Must start with 'https://' or 'git@'"),
            clone_repository("ftp://github.com/org/repo"),
        ):
            pass


class TestCloneRepositoryExecution:
    @patch("devops_auditor.repo_manager.subprocess.run")
    def test_successful_clone_yields_path_and_cleans_up(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        captured_path: str = ""
        with clone_repository("https://github.com/example/repo") as repo_path:
            captured_path = repo_path
            assert os.path.exists(repo_path)
            assert Path(repo_path).name.startswith("auditor_")

        # After exiting context manager, temp dir must be deleted
        assert not os.path.exists(captured_path)
        assert mock_run.called
        call_args = mock_run.call_args[0][0]
        assert call_args[0:4] == ["git", "clone", "--depth", "1"]

    @patch("devops_auditor.repo_manager.subprocess.run")
    def test_clone_failure_raises_runtime_error_and_cleans_up(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(
            returncode=128, stdout="", stderr="fatal: repository not found"
        )

        with (
            pytest.raises(RuntimeError, match="Git clone failed"),
            clone_repository("https://github.com/example/nonexistent"),
        ):
            pass

    @patch("devops_auditor.repo_manager.subprocess.run")
    def test_clone_timeout_raises_timeout_error_and_cleans_up(self, mock_run: MagicMock) -> None:
        mock_run.side_effect = subprocess.TimeoutExpired(cmd=["git"], timeout=5)

        with (
            pytest.raises(TimeoutError, match="Git clone timed out after 5s"),
            clone_repository("https://github.com/example/slow", timeout=5),
        ):
            pass

    @patch("devops_auditor.repo_manager.subprocess.run")
    def test_cleanup_occurs_when_caller_raises_exception(self, mock_run: MagicMock) -> None:
        mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")

        captured_path: str = ""
        with (
            pytest.raises(ZeroDivisionError),
            clone_repository("https://github.com/example/repo") as repo_path,
        ):
            captured_path = repo_path
            _ = 1 / 0

        assert not os.path.exists(captured_path)
