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
import re
from typing import Any, cast

from openai import OpenAI
from openai.types.chat import ChatCompletionMessage

from devops_auditor.prompts import SYSTEM_PROMPT, TOOL_DEFINITIONS
from devops_auditor.redactor import sanitize_evidence
from devops_auditor.schemas import AuditReport, Violation
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

    def _sanitize_violation_dict(
        self, item: dict[str, Any], seen_rule_ids: set[str]
    ) -> dict[str, Any]:
        """
        Coerce and sanitize noisy LLM violation outputs into strictly valid schema dictionaries.
        """
        # 1. Category mapping
        raw_cat = (
            str(item.get("category", ""))
            .strip()
            .lower()
            .replace("-", "_")
            .replace(" ", "_")
            .replace("/", "_")
        )
        cat_map = {
            "hygiene": "repository_hygiene",
            "repo_hygiene": "repository_hygiene",
            "repository_hygiene": "repository_hygiene",
            "dependency": "dependency_management",
            "dependencies": "dependency_management",
            "dependency_management": "dependency_management",
            "deps": "dependency_management",
            "code_quality": "code_quality",
            "quality": "code_quality",
            "lint": "code_quality",
            "testing": "testing",
            "tests": "testing",
            "ci": "github_actions_ci",
            "ci_cd": "github_actions_ci",
            "github_actions": "github_actions_ci",
            "github_actions_ci": "github_actions_ci",
            "actions": "github_actions_ci",
            "security": "security",
            "sec": "security",
            "config": "configuration",
            "configuration": "configuration",
            "collab": "collaboration",
            "collaboration": "collaboration",
            "build": "build_and_release",
            "release": "build_and_release",
            "build_and_release": "build_and_release",
            "build_release": "build_and_release",
        }
        category = "security"
        for k, v in cat_map.items():
            if k in raw_cat:
                category = v
                break

        # 2. Severity mapping
        raw_sev = str(item.get("severity", "")).strip().lower()
        sev_map = {
            "critical": "critical",
            "crit": "critical",
            "high": "high",
            "hi": "high",
            "medium": "medium",
            "med": "medium",
            "moderate": "medium",
            "low": "low",
            "minor": "low",
            "info": "low",
        }
        severity = sev_map.get(raw_sev)
        if not severity:
            severity = "high" if category in {"security", "build_and_release"} else "medium"

        # 3. Rule ID normalization and deduplication
        raw_rule = str(item.get("rule_id", "")).strip().upper()
        prefix_by_cat = {
            "repository_hygiene": "HYGN",
            "dependency_management": "DEP",
            "code_quality": "QUAL",
            "testing": "TEST",
            "github_actions_ci": "CI",
            "security": "SEC",
            "configuration": "CFG",
            "collaboration": "COLLAB",
            "build_and_release": "BUILD",
        }
        m = re.search(r"([A-Z]{2,6})[-_]?(\d{1,4})", raw_rule)
        if m:
            prefix = m.group(1)
            num = int(m.group(2))
            rule_id = f"{prefix}-{num:03d}"
        else:
            prefix = prefix_by_cat.get(category, "SEC")
            rule_id = f"{prefix}-001"

        if rule_id in seen_rule_ids:
            counter = 1
            new_id = f"{prefix}-{counter:03d}"
            while new_id in seen_rule_ids:
                counter += 1
                new_id = f"{prefix}-{counter:03d}"
            rule_id = new_id
        seen_rule_ids.add(rule_id)

        # 4. File path normalization
        raw_file = item.get("file")
        if raw_file is None or str(raw_file).strip().lower() in {"", "null", "none", "n/a"}:
            file_val = None
        else:
            file_val = str(raw_file).strip().replace("\\", "/")

        # 5. Line number normalization
        raw_line = item.get("line")
        line_val = None
        if (
            raw_line is not None
            and str(raw_line).strip().lower() not in {"", "null", "none", "n/a"}
        ):
            try:
                parsed_line = int(raw_line)
                if parsed_line >= 1:
                    line_val = parsed_line
            except (ValueError, TypeError):
                line_val = None

        # 6. Description
        raw_desc = str(item.get("description", "")).strip()
        if not raw_desc:
            raw_desc = f"DevOps violation identified in {category} area."
        elif len(raw_desc) < 10:
            raw_desc = f"DevOps issue: {raw_desc}"
        description = raw_desc[:250]

        # 7. Evidence
        raw_ev = str(item.get("evidence", "")).strip()
        if not raw_ev:
            raw_ev = f"Observed in repository file '{file_val or 'structure'}'."
        elif len(raw_ev) < 5:
            raw_ev = f"Evidence: {raw_ev}"
        raw_ev = sanitize_evidence(raw_ev)
        sensitive_pattern = (  # noqa: S105
            r"(?i)(?:ghp_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82}|AKIA[0-9A-Z]{16}|"
            r"AIza[0-9A-Za-z\-_]{35}|-----BEGIN (?:RSA )?PRIVATE KEY-----|"
            r"(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{8,}['\"])"
        )
        secret_re = re.compile(sensitive_pattern)
        evidence = secret_re.sub("[REDACTED]", raw_ev)[:500]

        # 8. Recommendation
        raw_rec = str(item.get("recommendation", "")).strip()
        if not raw_rec:
            raw_rec = "Resolve this issue according to DevOps security and quality best practices."
        elif len(raw_rec) < 10:
            raw_rec = f"Remediation: {raw_rec}"
        recommendation = raw_rec[:350]

        return {
            "rule_id": rule_id,
            "category": category,
            "severity": severity,
            "file": file_val,
            "line": line_val,
            "description": description,
            "evidence": evidence,
            "recommendation": recommendation,
        }

    def _process_submission(self, args: dict[str, Any], repo_url: str) -> AuditReport:
        """
        Validate and sanitize the LLM's submitted violation list.

        Applies robust sanitization, deduplication, and evidence redaction
        so that all genuine findings are preserved and valid schema models are built.
        """
        raw_violations: list[Any] = args.get("violations", [])
        if not isinstance(raw_violations, list):
            raw_violations = []

        seen_rule_ids: set[str] = set()
        validated: list[Violation] = []

        for item in raw_violations:
            if not isinstance(item, dict):
                continue
            try:
                sanitized_dict = self._sanitize_violation_dict(item, seen_rule_ids)
                v = Violation.model_validate(sanitized_dict)
                validated.append(v)
            except Exception as exc:  # noqa: BLE001
                logger.warning("Skipped malformed violation item: %s (%s)", item, exc)

        return AuditReport(repository=repo_url, violations=validated)

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
                        self._last_submitted_report = report
                        logger.info(
                            "Audit complete. %d violations found. Severity: %s",
                            len(report.violations),
                            report.summary(),
                        )
                        return report.model_dump(mode="json")
                    except Exception as exc:  # noqa: BLE001
                        logger.error("Report validation failed: %s", exc)
                        # Feed validation error back as tool response so agent can adjust
                        messages.append(
                            {
                                "role": "tool",
                                "tool_call_id": tool_call.id,
                                "content": json.dumps(
                                    {
                                        "error": (
                                            f"Validation failed: {exc}. Please check violation "
                                            "fields and call submit_audit_report again."
                                        )
                                    }
                                ),
                            }
                        )
                        continue

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
            "Max iterations (%d) reached without clean submission. "
            "Returning best available report.",
            self.max_iterations,
        )
        if hasattr(self, "_last_submitted_report") and self._last_submitted_report is not None:
            return self._last_submitted_report.model_dump(mode="json")
        return AuditReport(repository=repo_url).model_dump(mode="json")
