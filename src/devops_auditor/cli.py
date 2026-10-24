"""
CLI entry point for the DevOps Auditor Agent.

Invocation (as required by the assignment spec):
    python agent.py --repo <github_url> --output <report.json>

Features:
- Structured JSON written atomically to the output path
- Exits with differentiated codes for precise error classification
- Configures logging from LOG_LEVEL environment variable

Exit Codes:
    0  (EX_OK)      Audit completed successfully
    1  (EX_USAGE)   Invalid arguments or missing environment variables
    2  (EX_NETWORK) Repository clone failed (network / git error, timeout)
    3  (EX_SCHEMA)  Unexpected internal error (schema validation, etc.)
"""

from __future__ import annotations

import argparse
import importlib.metadata
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any

from dotenv import load_dotenv

from devops_auditor.agent import DevOpsAuditAgent
from devops_auditor.repo_manager import clone_repository
from devops_auditor.tools import InspectionTools

# Load .env from the project root — must be called at module level so env vars are
# available before any function that reads them is invoked.
load_dotenv()

# ─── Exit Code Constants ─────────────────────────────────────────────────────

EX_OK = 0  # Audit completed successfully
EX_USAGE = 1  # Invalid arguments or missing environment variables
EX_NETWORK = 2  # Clone failed (git error, timeout, unreachable host)
EX_SCHEMA = 3  # Unexpected internal error (schema, unexpected exception)

# ─── Logging Configuration ───────────────────────────────────────────────────


def _configure_logging() -> None:
    """Configure structured logging from LOG_LEVEL environment variable."""
    log_level_name = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_name, logging.INFO)

    logging.basicConfig(
        level=log_level,
        format="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
        stream=sys.stderr,  # Keep stdout clean for piping report JSON
    )


# ─── Argument Parsing ────────────────────────────────────────────────────────


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate CLI arguments."""
    parser = argparse.ArgumentParser(
        prog="agent.py",
        description=(
            "DevOps Repository Auditor Agent — autonomously audits a GitHub "
            "repository for security and operational defects using a native "
            "ReAct tool-calling loop."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python agent.py --repo https://github.com/pallets/flask --output report.json
  python agent.py --repo https://github.com/org/repo --output /tmp/audit.json

Environment variables:
  OPENAI_API_KEY    Required. Your LLM provider API key.
  OPENAI_BASE_URL   Optional. Override to use Gemini, Groq, DeepSeek, etc.
  AUDIT_MODEL       Optional. Default: gpt-4o-mini
  MAX_ITERATIONS    Optional. Default: 20
  LOG_LEVEL         Optional. Default: INFO
        """,
    )

    parser.add_argument(
        "--repo",
        required=True,
        metavar="URL",
        help="Public GitHub repository URL to audit (e.g., https://github.com/org/repo)",
    )
    parser.add_argument(
        "--output",
        required=True,
        metavar="PATH",
        help="File path where the JSON audit report will be written",
    )
    parser.add_argument(
        "--model",
        default=None,
        metavar="MODEL",
        help="LLM model override (e.g., gpt-4o, gemini-1.5-pro). Overrides AUDIT_MODEL.",
    )
    parser.add_argument(
        "--max-iterations",
        type=int,
        default=None,
        metavar="N",
        help="Maximum ReAct iterations. Overrides MAX_ITERATIONS.",
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    return parser.parse_args(argv)


def _get_version() -> str:
    """Read package version from installed metadata (set in pyproject.toml)."""
    try:
        return importlib.metadata.version("devops-auditor")
    except importlib.metadata.PackageNotFoundError:
        return "0.0.0+unknown"


def _validate_environment() -> None:
    """Check that required environment variables are set."""
    if not os.environ.get("OPENAI_API_KEY"):
        sys.stderr.write(
            "ERROR: OPENAI_API_KEY environment variable is not set.\n"
            "Set it in your .env file or export it before running.\n"
        )
        sys.exit(EX_USAGE)


def _write_report(report_data: dict[str, Any], output_path: str) -> None:
    """Atomically write the JSON report to the output file."""
    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)

    # Write to a temp file first, then rename (atomic on POSIX, best-effort on Windows)
    tmp_path = output.with_suffix(".tmp")
    try:
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=2, ensure_ascii=False)
            f.write("\n")
        tmp_path.replace(output)
    except OSError:
        # On Windows, replace() may fail if target exists — fallback
        tmp_path.rename(output)


# ─── Main Entry Point ────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    """
    Main CLI entry point.

    Returns:
        0 on success, 1 on any fatal error.
    """
    _configure_logging()
    logger = logging.getLogger(__name__)

    args = _parse_args(argv)
    _validate_environment()

    # Build kwargs for agent — only override if explicitly provided
    agent_kwargs: dict[str, Any] = {}
    if args.model:
        agent_kwargs["model"] = args.model
    if args.max_iterations:
        agent_kwargs["max_iterations"] = args.max_iterations

    logger.info("DevOps Auditor Agent starting")
    logger.info("Target repository: %s", args.repo)
    logger.info("Output path: %s", args.output)

    try:
        with clone_repository(args.repo) as local_repo_path:
            logger.info("Repository cloned to: %s", local_repo_path)
            tools = InspectionTools(local_repo_path)
            agent = DevOpsAuditAgent(tools=tools, **agent_kwargs)
            report_data = agent.run(repo_url=args.repo)

        _write_report(report_data, args.output)

        violation_count = len(report_data.get("violations", []))
        logger.info("Audit complete. %d violations written to: %s", violation_count, args.output)
        print(f"[OK] Audit complete: {violation_count} violation(s) found -> {args.output}")

        return EX_OK

    except TimeoutError as exc:
        # EX_NETWORK — clone timed out (unreachable host or very slow repo)
        sys.stderr.write(f"TIMEOUT: {exc}\n")
        return EX_NETWORK
    except RuntimeError as exc:
        # EX_NETWORK — git clone failed (bad URL, auth error, etc.)
        sys.stderr.write(f"ERROR: {exc}\n")
        return EX_NETWORK
    except KeyboardInterrupt:
        sys.stderr.write("\nAborted by user.\n")
        return EX_USAGE
    except Exception as exc:  # noqa: BLE001
        logger.exception("Unexpected fatal error during audit")
        sys.stderr.write(f"FATAL: {exc}\n")
        return EX_SCHEMA


if __name__ == "__main__":
    sys.exit(main())
