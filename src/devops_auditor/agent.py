"""
Native ReAct (Reason + Act) agent loop for DevOps repository auditing.

This module implements an autonomous tool-calling loop using the standard
OpenAI SDK — with zero dependency on LangChain, LangGraph, or CrewAI.

Architecture:
  1. Agent receives system prompt + user objective.
  2. LLM reasons and selects a tool call.
  3. Tool dispatcher executes the call in a sandboxed Python environment.
  4. Observation is appended to the message history.
  5. Loop repeats until LLM calls submit_audit_report() or max_iterations hit.
  6. Final report is validated against the Pydantic schema before return.

Multi-provider support:
  The agent uses the OpenAI client with configurable base_url, enabling
  drop-in replacement with Google Gemini (OpenAI-compatible endpoint),
  DeepSeek, Groq, or local Ollama — via environment variables only.

Context window management:
  - Tool results are capped by the tools themselves.
  - A lightweight message pruner removes oldest tool-result pairs when the
    estimated token count approaches the configured budget.
"""

from __future__ import annotations

import json
import logging
import os
from typing import Any, cast

from openai import OpenAI
from openai.types.chat import ChatCompletionMessage

from devops_auditor.prompts import SYSTEM_PROMPT, TOOL_DEFINITIONS
from devops_auditor.redactor import sanitize_evidence
from devops_auditor.schemas import AuditReport
from devops_auditor.tools import InspectionTools

logger = logging.getLogger(__name__)

# ─── Constants ───────────────────────────────────────────────────────────────

DEFAULT_MODEL = os.environ.get("AUDIT_MODEL", "gpt-4o-mini")
DEFAULT_MAX_ITERATIONS = int(os.environ.get("MAX_ITERATIONS", "20"))

# Approximate token budget before we start pruning older tool messages
# (conservative — real limit depends on model; adjust per provider)
_CONTEXT_PRUNE_THRESHOLD = 80_000


class DevOpsAuditAgent:
    """
    Autonomous DevOps auditor using a native ReAct tool-calling loop.

    Args:
        tools:          InspectionTools instance bound to the cloned repo root.
        model:          LLM model identifier (default from AUDIT_MODEL env var).
        max_iterations: Maximum ReAct iterations before forced termination.
        client:         Optional pre-configured OpenAI client (useful for testing).
    """

    def __init__(
        self,
        tools: InspectionTools,
        model: str = DEFAULT_MODEL,
        max_iterations: int = DEFAULT_MAX_ITERATIONS,
        client: OpenAI | None = None,
    ) -> None:
        self.tools = tools
        self.model = model
        self.max_iterations = max_iterations
        self.client = client or self._build_client()
        self._iteration_count = 0

    @staticmethod
    def _build_client() -> OpenAI:
        """
        Build an OpenAI-compatible client.

        Reads OPENAI_API_KEY and optional OPENAI_BASE_URL from the environment.
        OPENAI_BASE_URL allows seamless provider switching:
          - Google Gemini: https://generativelanguage.googleapis.com/v1beta/openai/
          - DeepSeek:      https://api.deepseek.com/v1
          - Groq:          https://api.groq.com/openai/v1
        """
        kwargs: dict[str, Any] = {}
        base_url = os.environ.get("OPENAI_BASE_URL")
        if base_url:
            kwargs["base_url"] = base_url
            logger.info("Using custom LLM base URL: %s", base_url)

        return OpenAI(**kwargs)

    def _dispatch_tool(self, name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """
        Route a tool call from the LLM to the corresponding InspectionTools method.

        Returns:
            A JSON-serialisable dict containing either the tool result or an error.
        """
        method = getattr(self.tools, name, None)
        if method is None:
            logger.warning("Unknown tool requested by LLM: '%s'", name)
            avail = "list_files, read_file, search_code, git_log"
            return {"error": f"Tool '{name}' does not exist. Available: {avail}"}

        try:
            result: dict[str, Any] = method(**arguments)
            logger.debug("Tool '%s' returned %d keys", name, len(result))
            return result
        except TypeError as exc:
            return {"error": f"Invalid arguments for tool '{name}': {exc}"}
        except Exception as exc:  # noqa: BLE001
            logger.error("Tool '%s' raised an unexpected error: %s", name, exc)
            return {"error": f"Tool execution error: {exc}"}

    def _process_submission(self, args: dict[str, Any], repo_url: str) -> AuditReport:
        """
        Validate and sanitize the LLM's submitted violation list.

        Applies redaction to all evidence fields and validates the result
        against the AuditReport Pydantic model.
        """
        raw_violations: list[dict[str, Any]] = args.get("violations", [])

        # Sanitize evidence on every violation before schema validation
        cleaned: list[dict[str, Any]] = []
        for v in raw_violations:
            evidence = sanitize_evidence(v.get("evidence", ""))
            cleaned.append({**v, "evidence": evidence})

        # Build validated Pydantic model — raises ValidationError on schema violation
        return AuditReport(repository=repo_url, violations=cleaned)  # type: ignore[arg-type]

    def _prune_old_tool_messages(self, messages: list[dict[str, Any]]) -> list[dict[str, Any]]:
        """
        Remove the oldest tool-call + tool-result pair to reduce context size.

        Preserves: system message, first user message, and most recent pairs.
        This is a simple heuristic pruner — not a full tokeniser.
        """
        # Find the earliest "tool" role message pair to drop
        for i, msg in enumerate(messages):
            if isinstance(msg, dict) and msg.get("role") == "tool" and i > 0:
                # Also drop the preceding assistant message that triggered this call
                messages.pop(i)  # tool result
                messages.pop(i - 1)  # assistant message with tool_calls
                logger.debug("Pruned 1 tool-call pair from message history.")
                break
        return messages

    def run(self, repo_url: str) -> dict[str, Any]:
        """
        Execute the full ReAct audit loop.

        Args:
            repo_url: The URL of the repository being audited (for the report).

        Returns:
            A JSON-serialisable dict matching the AuditReport schema.
        """
        self._iteration_count = 0

        messages: list[dict[str, Any]] = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": (
                    f"Audit the cloned repository from: {repo_url}\n\n"
                    "Begin by calling list_files() to understand the project structure, "
                    "then systematically investigate all 8 audit areas. "
                    "Call submit_audit_report() when your investigation is complete."
                ),
            },
        ]

        logger.info(
            "Starting audit loop for: %s (model=%s, max_iter=%d)",
            repo_url,
            self.model,
            self.max_iterations,
        )

        for iteration in range(self.max_iterations):
            self._iteration_count = iteration + 1
            logger.info("ReAct iteration %d/%d", self._iteration_count, self.max_iterations)

            # ── LLM Call ────────────────────────────────────────────────────
            response = cast(Any, self.client.chat.completions).create(
                model=self.model,
                messages=messages,
                tools=TOOL_DEFINITIONS,
                tool_choice="auto",
                temperature=0.1,  # Low temperature for deterministic, analytical output
            )

            assistant_msg: ChatCompletionMessage = response.choices[0].message

            # Convert to dict for appending to message history
            # If the response object supports model_dump (real SDK message), preserve all
            # provider-specific metadata (e.g. Google thought_signature for multi-turn tools).
            assistant_dict: dict[str, Any] | None = None
            if hasattr(assistant_msg, "model_dump") and not hasattr(assistant_msg, "_mock_methods"):
                try:
                    dumped = assistant_msg.model_dump(exclude_unset=True)
                    if isinstance(dumped, dict):
                        assistant_dict = dumped
                except Exception:
                    assistant_dict = None

            if assistant_dict is None:
                assistant_dict = {
                    "role": "assistant",
                    "content": assistant_msg.content or "",
                }
                if assistant_msg.tool_calls:
                    assistant_dict["tool_calls"] = [
                        {
                            "id": tc.id,
                            "type": "function",
                            "function": {
                                "name": cast(Any, tc).function.name,
                                "arguments": cast(Any, tc).function.arguments,
                            },
                        }
                        for tc in assistant_msg.tool_calls
                    ]
            messages.append(assistant_dict)

            # ── No Tool Calls → LLM Finished Without Submitting ─────────────
            if not assistant_msg.tool_calls:
                logger.warning(
                    "LLM returned no tool calls at iteration %d. Returning empty report.",
                    self._iteration_count,
                )
                break

            # ── Process Each Tool Call ───────────────────────────────────────
            for tool_call in assistant_msg.tool_calls:
                call_fn = cast(Any, tool_call).function
                fn_name = call_fn.name
                try:
                    fn_args = json.loads(call_fn.arguments)
                except json.JSONDecodeError as exc:
                    fn_args = {}
                    logger.error("Failed to parse tool arguments JSON: %s", exc)

                logger.info("Tool call: %s(%s)", fn_name, list(fn_args.keys()))

                # ── Terminal: Submit Audit Report ────────────────────────────
                if fn_name == "submit_audit_report":
                    try:
                        report = self._process_submission(fn_args, repo_url)
                        logger.info(
                            "Audit complete. %d violations found. Severity: %s",
                            len(report.violations),
                            report.summary(),
                        )
                        return report.model_dump(mode="json")
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Report validation failed: %s", exc)
                        # Return empty valid report on schema failure
                        return AuditReport(repository=repo_url).model_dump(mode="json")

                # ── Standard Tool Dispatch ───────────────────────────────────
                result = self._dispatch_tool(fn_name, fn_args)

                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tool_call.id,
                        "content": json.dumps(result, ensure_ascii=False),
                    }
                )

            # ── Context Pruning ──────────────────────────────────────────────
            # Rough heuristic: prune if message count grows very large
            if len(messages) > 60:
                messages = self._prune_old_tool_messages(messages)

        # ── Iteration Limit Reached ──────────────────────────────────────────
        logger.warning(
            "Max iterations (%d) reached without submit_audit_report call. Returning empty report.",
            self.max_iterations,
        )
        return AuditReport(repository=repo_url).model_dump(mode="json")
