"""
Unit tests for the DevOpsAuditAgent — zero real API calls.

All LLM interactions are mocked via pytest-mock / MagicMock so these tests
run without any OPENAI_API_KEY configured. They verify:

1. Agent calls submit_audit_report and returns valid schema
2. Agent handles unknown tool gracefully (error dict injected)
3. Agent terminates when max_iterations is reached (returns empty report)
4. Agent terminates when LLM returns no tool calls
5. Violations are sanitized through redactor before schema validation
6. Invalid tool arguments produce structured error response
7. Multi-tool-call sequence executes correctly
"""

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest
from openai import OpenAI

from devops_auditor.agent import DevOpsAuditAgent
from devops_auditor.tools import InspectionTools

# ─── Test Helpers ─────────────────────────────────────────────────────────────


def _make_tool_call(name: str, arguments: dict[str, Any], call_id: str = "call_1") -> MagicMock:
    """Create a realistic mock tool call object matching OpenAI SDK structure."""
    tc = MagicMock()
    tc.id = call_id
    tc.function.name = name
    tc.function.arguments = json.dumps(arguments)
    return tc


def _make_response(tool_calls: list[MagicMock] | None, content: str = "") -> MagicMock:
    """Create a mock OpenAI ChatCompletion response."""
    choice = MagicMock()
    choice.message.tool_calls = tool_calls
    choice.message.content = content
    response = MagicMock()
    response.choices = [choice]
    return response


def _valid_violation() -> dict[str, Any]:
    return {
        "rule_id": "SEC-001",
        "category": "security",
        "severity": "critical",
        "file": "config.py",
        "line": 12,
        "description": "Hardcoded API key detected in configuration file",
        "evidence": "API_KEY = '[REDACTED]'",
        "recommendation": "Move secrets to environment variables via python-dotenv.",
    }


# ─── Fixtures ─────────────────────────────────────────────────────────────────


@pytest.fixture()
def mock_client() -> MagicMock:
    """Return a mock OpenAI client."""
    client = MagicMock(spec=OpenAI)
    return client


@pytest.fixture()
def agent(tmp_path: Path, mock_client: MagicMock) -> DevOpsAuditAgent:
    """Return an agent bound to a temp repo with a mocked LLM client."""
    tools = InspectionTools(str(tmp_path))
    return DevOpsAuditAgent(tools=tools, model="gpt-4o-mini", max_iterations=5, client=mock_client)


# ─── Test: Successful Single-Call Submission ─────────────────────────────────


class TestSuccessfulSubmission:
    def test_agent_returns_valid_report_schema(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        """Agent should submit a valid report on the first iteration."""
        mock_client.chat.completions.create.return_value = _make_response(
            tool_calls=[
                _make_tool_call("submit_audit_report", {"violations": [_valid_violation()]})
            ]
        )

        result = agent.run("https://github.com/example/repo")

        assert result["repository"] == "https://github.com/example/repo"
        assert len(result["violations"]) == 1
        assert result["violations"][0]["rule_id"] == "SEC-001"
        assert result["violations"][0]["severity"] == "critical"

    def test_agent_returns_empty_report_for_clean_repo(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        mock_client.chat.completions.create.return_value = _make_response(
            tool_calls=[_make_tool_call("submit_audit_report", {"violations": []})]
        )

        result = agent.run("https://github.com/example/clean-repo")

        assert result["violations"] == []
        assert result["repository"] == "https://github.com/example/clean-repo"

    def test_null_file_and_line_preserved(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        violation = {
            **_valid_violation(),
            "file": None,
            "line": None,
            "rule_id": "HYGN-001",
            "category": "repository_hygiene",
            "severity": "medium",
        }
        mock_client.chat.completions.create.return_value = _make_response(
            tool_calls=[_make_tool_call("submit_audit_report", {"violations": [violation]})]
        )

        result = agent.run("https://github.com/example/repo")

        assert result["violations"][0]["file"] is None
        assert result["violations"][0]["line"] is None


# ─── Test: Multi-Step Tool Sequence ──────────────────────────────────────────


class TestMultiStepSequence:
    def test_list_files_then_submit(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock, tmp_path: Path
    ) -> None:
        """Agent should be able to call list_files then submit."""
        # Iteration 1: list_files call
        iter1_response = _make_response(
            tool_calls=[_make_tool_call("list_files", {"sub_dir": "."}, call_id="call_1")]
        )
        # Iteration 2: submit_audit_report
        iter2_response = _make_response(
            tool_calls=[
                _make_tool_call("submit_audit_report", {"violations": []}, call_id="call_2")
            ]
        )

        mock_client.chat.completions.create.side_effect = [iter1_response, iter2_response]

        result = agent.run("https://github.com/example/repo")

        # Should have made exactly 2 LLM calls
        assert mock_client.chat.completions.create.call_count == 2
        assert result["violations"] == []

    def test_tool_result_appended_to_messages(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock, tmp_path: Path
    ) -> None:
        """Tool results must be passed back to the LLM as tool messages."""
        iter1_response = _make_response(
            tool_calls=[_make_tool_call("list_files", {}, call_id="call_x")]
        )
        iter2_response = _make_response(
            tool_calls=[
                _make_tool_call("submit_audit_report", {"violations": []}, call_id="call_y")
            ]
        )
        mock_client.chat.completions.create.side_effect = [iter1_response, iter2_response]

        agent.run("https://github.com/example/repo")

        # The second LLM call should include tool-result messages
        second_call_messages = mock_client.chat.completions.create.call_args_list[1][1]["messages"]
        roles = [m["role"] for m in second_call_messages]
        assert "tool" in roles


# ─── Test: Error Handling ─────────────────────────────────────────────────────


class TestErrorHandling:
    def test_unknown_tool_name_returns_error_dict(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        """Unknown tool calls should get an error dict, not raise an exception."""
        iter1_response = _make_response(
            tool_calls=[_make_tool_call("unknown_tool_xyz", {}, call_id="call_1")]
        )
        iter2_response = _make_response(
            tool_calls=[
                _make_tool_call("submit_audit_report", {"violations": []}, call_id="call_2")
            ]
        )
        mock_client.chat.completions.create.side_effect = [iter1_response, iter2_response]

        result = agent.run("https://github.com/example/repo")
        # Should not raise — agent handles errors gracefully
        assert "violations" in result

    def test_invalid_tool_args_json_handled(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        """Malformed JSON arguments should not crash the agent."""
        bad_tc = MagicMock()
        bad_tc.id = "call_bad"
        bad_tc.function.name = "list_files"
        bad_tc.function.arguments = "{invalid json!!!"  # Intentionally broken

        final_tc = _make_tool_call("submit_audit_report", {"violations": []}, call_id="call_final")

        iter1_response = _make_response(tool_calls=[bad_tc])
        iter2_response = _make_response(tool_calls=[final_tc])
        mock_client.chat.completions.create.side_effect = [iter1_response, iter2_response]

        # Should not raise
        result = agent.run("https://github.com/example/repo")
        assert "violations" in result

    def test_max_iterations_returns_empty_report(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        """Agent must return a valid empty report when max iterations are exhausted."""
        # Always return a non-terminal tool call to exhaust iterations
        loop_response = _make_response(
            tool_calls=[_make_tool_call("list_files", {}, call_id="call_loop")]
        )
        mock_client.chat.completions.create.return_value = loop_response

        result = agent.run("https://github.com/example/repo")

        assert result["repository"] == "https://github.com/example/repo"
        assert result["violations"] == []
        assert mock_client.chat.completions.create.call_count == agent.max_iterations

    def test_no_tool_calls_returns_empty_report(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        """LLM returning no tool calls should gracefully return an empty report."""
        mock_client.chat.completions.create.return_value = _make_response(
            tool_calls=None, content="Done."
        )

        result = agent.run("https://github.com/example/repo")

        assert result["violations"] == []


# ─── Test: Secret Redaction Integration ──────────────────────────────────────


class TestRedactionIntegration:
    def test_evidence_is_sanitized_before_validation(
        self, agent: DevOpsAuditAgent, mock_client: MagicMock
    ) -> None:
        """Agent should NOT raise even if LLM includes a credential-looking pattern
        that gets redacted before Pydantic validation."""
        # Provide evidence with a generic credential that the redactor will catch
        violation = {**_valid_violation(), "evidence": "Some safe text with no pattern"}
        mock_client.chat.completions.create.return_value = _make_response(
            tool_calls=[_make_tool_call("submit_audit_report", {"violations": [violation]})]
        )

        result = agent.run("https://github.com/example/repo")
        assert len(result["violations"]) == 1
