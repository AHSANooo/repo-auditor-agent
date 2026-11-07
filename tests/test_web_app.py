"""
Unit tests for the Streamlit web dashboard components and caching mechanisms.
"""

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

pytest.importorskip("streamlit")

import web_app

from devops_auditor.agent import DevOpsAuditAgent
from devops_auditor.schemas import AuditReport


def test_get_remote_head_commit_success():
    """get_remote_head_commit parses the stdout of git ls-remote."""
    mock_res = MagicMock()
    mock_res.returncode = 0
    mock_res.stdout = "49943b5a94413a530761350f04e896f76e8d620e\tHEAD\n"

    with patch("subprocess.run", return_value=mock_res):
        sha = web_app.get_remote_head_commit("https://github.com/pallets/flask")
        assert sha == "49943b5a94413a530761350f04e896f76e8d620e"


def test_get_remote_head_commit_failure():
    """get_remote_head_commit returns empty string when command fails."""
    mock_res = MagicMock()
    mock_res.returncode = 128
    mock_res.stdout = ""

    with patch("subprocess.run", return_value=mock_res):
        sha = web_app.get_remote_head_commit("https://github.com/invalid/repo")
        assert sha == ""


def test_static_demo_reports_exist_and_validate():
    """Verify that flask_report.json and vulnerable_repo_report.json exist and validate."""
    root = Path(__file__).parent.parent
    flask_path = root / "flask_report.json"
    vuln_path = root / "vulnerable_repo_report.json"

    assert flask_path.exists(), "flask_report.json must exist in root"
    assert vuln_path.exists(), "vulnerable_repo_report.json must exist in root"

    with open(flask_path, encoding="utf-8") as f:
        flask_data = json.load(f)
    flask_report = AuditReport.model_validate(flask_data)
    assert flask_report.repository == "https://github.com/pallets/flask"
    assert len(flask_report.violations) == 2

    with open(vuln_path, encoding="utf-8") as f:
        vuln_data = json.load(f)
    vuln_report = AuditReport.model_validate(vuln_data)
    assert len(vuln_report.violations) == 10


def test_agent_invokes_step_callback():
    """Verify that DevOpsAuditAgent dispatches step_callback on tool calls."""
    mock_tools = MagicMock()
    mock_tools.list_files.return_value = {"files": ["README.md"]}

    # Create mock OpenAI client
    mock_client = MagicMock()
    # Turn 1: call list_files
    tc1 = MagicMock()
    tc1.id = "call_1"
    tc1.function.name = "list_files"
    tc1.function.arguments = json.dumps({})
    resp1 = MagicMock()
    resp1.choices = [MagicMock(message=MagicMock(tool_calls=[tc1], content=""))]

    # Turn 2: submit
    tc2 = MagicMock()
    tc2.id = "call_2"
    tc2.function.name = "submit_audit_report"
    tc2.function.arguments = json.dumps({"violations": []})
    resp2 = MagicMock()
    resp2.choices = [MagicMock(message=MagicMock(tool_calls=[tc2], content=""))]

    mock_client.chat.completions.create.side_effect = [resp1, resp2]

    steps = []

    def callback(fn_name, fn_args):
        steps.append((fn_name, fn_args))

    agent = DevOpsAuditAgent(
        tools=mock_tools,
        model="mock-model",
        max_iterations=5,
        client=mock_client,
        step_callback=callback,
    )

    report = agent.run("https://github.com/test/repo")
    assert report["violations"] == []
    assert len(steps) == 2
    assert steps[0][0] == "list_files"
    assert steps[1][0] == "submit_audit_report"


def test_agent_kwargs_backwards_compatible():
    """Verify that DevOpsAuditAgent handles extra or missing kwargs without raising TypeError."""
    mock_tools = MagicMock()
    mock_client = MagicMock()
    agent = DevOpsAuditAgent(
        tools=mock_tools,
        model="mock-model",
        client=mock_client,
        extra_unknown_param="safe",
    )
    assert agent.model == "mock-model"
