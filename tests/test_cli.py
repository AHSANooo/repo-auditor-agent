"""
Unit tests for cli.py — CLI entry point, argument parsing, validation, and error handling.
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from devops_auditor.cli import (
    EX_NETWORK,
    EX_OK,
    EX_SCHEMA,
    EX_USAGE,
    _parse_args,
    _validate_environment,
    _write_report,
    main,
)


class TestCLIArgumentParsing:
    def test_missing_required_args_exits(self) -> None:
        with pytest.raises(SystemExit):
            _parse_args([])

    def test_valid_args_parsed(self) -> None:
        args = _parse_args(["--repo", "https://github.com/org/repo", "--output", "out.json"])
        assert args.repo == "https://github.com/org/repo"
        assert args.output == "out.json"
        assert args.model is None
        assert args.max_iterations is None

    def test_optional_model_and_max_iterations(self) -> None:
        args = _parse_args(
            [
                "--repo",
                "https://github.com/org/repo",
                "--output",
                "out.json",
                "--model",
                "gpt-4o",
                "--max-iterations",
                "10",
            ]
        )
        assert args.model == "gpt-4o"
        assert args.max_iterations == 10


class TestCLIValidation:
    def test_missing_api_key_exits_1(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("OPENAI_API_KEY", raising=False)
        with pytest.raises(SystemExit) as exc_info:
            _validate_environment()
        assert exc_info.value.code == EX_USAGE

    def test_present_api_key_passes(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "test-key-123")
        # Should not raise
        _validate_environment()


class TestReportWriting:
    def test_atomic_write_creates_valid_json(self, tmp_path: Path) -> None:
        out_file = tmp_path / "subdir" / "report.json"
        data = {
            "repository": "https://github.com/org/repo",
            "violations": [{"rule_id": "SEC-001"}],
        }
        _write_report(data, str(out_file))

        assert out_file.exists()
        with open(out_file, encoding="utf-8") as f:
            loaded = json.load(f)
        assert loaded == data


class TestCLIMain:
    @patch("devops_auditor.cli.clone_repository")
    @patch("devops_auditor.cli.DevOpsAuditAgent")
    def test_main_success_flow(
        self,
        mock_agent_cls: MagicMock,
        mock_clone: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "dummy-key")
        out_file = tmp_path / "report.json"

        # Mock clone context manager
        mock_clone.return_value.__enter__.return_value = str(tmp_path)
        mock_clone.return_value.__exit__.return_value = None

        # Mock agent run
        mock_agent_instance = MagicMock()
        mock_agent_instance.run.return_value = {
            "repository": "https://github.com/org/repo",
            "violations": [],
        }
        mock_agent_cls.return_value = mock_agent_instance

        ret = main(["--repo", "https://github.com/org/repo", "--output", str(out_file)])
        assert ret == EX_OK
        assert out_file.exists()

    @patch("devops_auditor.cli.clone_repository")
    def test_main_timeout_returns_ex_network(
        self,
        mock_clone: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "dummy-key")
        mock_clone.side_effect = TimeoutError("Cloning timed out")

        out = str(tmp_path / "out.json")
        ret = main(["--repo", "https://github.com/org/repo", "--output", out])
        assert ret == EX_NETWORK

    @patch("devops_auditor.cli.clone_repository")
    def test_main_runtime_error_returns_ex_network(
        self,
        mock_clone: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "dummy-key")
        mock_clone.side_effect = RuntimeError("Git clone failed")

        out = str(tmp_path / "out.json")
        ret = main(["--repo", "https://github.com/org/repo", "--output", out])
        assert ret == EX_NETWORK

    @patch("devops_auditor.cli.clone_repository")
    def test_main_keyboard_interrupt_returns_ex_usage(
        self,
        mock_clone: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "dummy-key")
        mock_clone.side_effect = KeyboardInterrupt()

        out = str(tmp_path / "out.json")
        ret = main(["--repo", "https://github.com/org/repo", "--output", out])
        assert ret == EX_USAGE

    @patch("devops_auditor.cli.clone_repository")
    def test_main_unexpected_error_returns_ex_schema(
        self,
        mock_clone: MagicMock,
        tmp_path: Path,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        monkeypatch.setenv("OPENAI_API_KEY", "dummy-key")
        mock_clone.side_effect = ValueError("Unexpected problem")

        out = str(tmp_path / "out.json")
        ret = main(["--repo", "https://github.com/org/repo", "--output", out])
        assert ret == EX_SCHEMA
