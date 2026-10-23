"""
Secret sanitization and evidence redaction engine.

This module provides a multi-pattern regex scrubbing pipeline that removes
all recognizable credential patterns from log messages and evidence strings
before they enter the audit report or any logging handler.

Design principles:
- All patterns are applied in a fixed, deterministic order.
- Patterns are ordered from most specific (e.g., GitHub PAT format) to
  most general (generic key=value style) to prevent partial masking.
- The function is pure and idempotent: calling it multiple times on an
  already-sanitized string is safe and produces no changes.
- No external dependencies — stdlib `re` only.
"""

from __future__ import annotations

import logging
import re

# ─── Compiled Patterns ───────────────────────────────────────────────────────
# Each entry is (compiled_pattern, replacement_string).
# Ordering matters: more specific patterns must come before generic ones.

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    # ── GitHub Personal Access Tokens ────────────────────────────────────────
    (re.compile(r"ghp_[A-Za-z0-9]{36}"), "[REDACTED_GITHUB_PAT]"),
    (
        re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
        "[REDACTED_GITHUB_FINE_GRAINED_PAT]",
    ),
    # ── GitHub Actions Tokens ────────────────────────────────────────────────
    (re.compile(r"ghs_[A-Za-z0-9]{36}"), "[REDACTED_GITHUB_ACTIONS_TOKEN]"),
    # ── AWS Credentials ──────────────────────────────────────────────────────
    (re.compile(r"AKIA[0-9A-Z]{16}"), "[REDACTED_AWS_ACCESS_KEY]"),
    (re.compile(r"ABIA[0-9A-Z]{16}"), "[REDACTED_AWS_STS_KEY]"),
    (
        re.compile(
            r"(?i)aws[_\-]?secret[_\-]?access[_\-]?key\s*[:=]\s*['\"]?([A-Za-z0-9+/]{40})['\"]?"
        ),
        r"aws_secret_access_key=[REDACTED_AWS_SECRET]",
    ),
    # ── Private Keys (PEM blocks) ─────────────────────────────────────────────
    (
        re.compile(
            r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]+?"
            r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "[REDACTED_PRIVATE_KEY]",
    ),
    # ── JWT Tokens ────────────────────────────────────────────────────────────
    (
        re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
        "[REDACTED_JWT]",
    ),
    # ── Generic Bearer Tokens (Authorization headers) ─────────────────────────
    (
        re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_.~+/]+=*"),
        "Bearer [REDACTED_BEARER_TOKEN]",
    ),
    # ── Slack / Discord / Telegram Bot Tokens ────────────────────────────────
    (re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,48}"), "[REDACTED_SLACK_TOKEN]"),
    (
        re.compile(r"\d{8,10}:[A-Za-z0-9_\-]{35}"),
        "[REDACTED_TELEGRAM_BOT_TOKEN]",
    ),
    # ── Generic high-entropy key=value assignments ─────────────────────────────
    # Matches patterns like:  API_KEY = "sk-abc123..."  or  secret: 'xyz...'
    (
        re.compile(
            r"(?i)"
            r"(?:api[_\-]?key|api[_\-]?secret|client[_\-]?secret|auth[_\-]?token"
            r"|access[_\-]?token|private[_\-]?key|password|passwd|pwd|secret)"
            r"\s*[:=]\s*['\"]?([A-Za-z0-9+/=_\-]{8,})['\"]?"
        ),
        r"[REDACTED_CREDENTIAL]",
    ),
]


def sanitize_evidence(text: str) -> str:
    """
    Scrub all detectable credential patterns from an evidence string.

    Args:
        text: Raw evidence string that may contain sensitive data.

    Returns:
        Sanitized evidence with all credential patterns replaced by
        human-readable placeholders (e.g., [REDACTED_GITHUB_PAT]).

    Example:
        >>> sanitize_evidence("API_KEY = 'sk-abc123DEFabc123DEF'")
        '[REDACTED_CREDENTIAL]'
        >>> sanitize_evidence("No secrets here — safe.")
        'No secrets here — safe.'
    """
    if not text:
        return text

    result = text
    for pattern, replacement in _PATTERNS:
        result = pattern.sub(replacement, result)

    return result


def sanitize_log_record(message: str) -> str:
    """
    Convenience wrapper for use in logging filters.

    Identical behaviour to sanitize_evidence() but semantically named
    for use in logging.Filter.filter() implementations.
    """
    return sanitize_evidence(message)


class RedactionLoggingFilter:
    """
    Python logging filter that sanitizes all log messages and extra fields.

    Usage:
        import logging
        from devops_auditor.redactor import RedactionLoggingFilter

        handler = logging.StreamHandler()
        handler.addFilter(RedactionLoggingFilter())
        logger.addHandler(handler)
    """

    def filter(self, record: logging.LogRecord) -> bool:
        """Sanitize log record message in-place, always allow the record through."""
        record.msg = sanitize_evidence(str(record.msg))
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: sanitize_evidence(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, tuple):
                record.args = tuple(sanitize_evidence(str(a)) for a in record.args)
        return True
