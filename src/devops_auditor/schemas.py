"""
Pydantic V2 data contracts for the DevOps Auditor Agent.

This module defines the strict output schema required by the assignment rubric.
All output must conform exactly to these models — Pydantic validation is the
final gate before JSON serialization.

Schema contract:
- violations[].file   → relative path string, or JSON null  (never omitted)
- violations[].line   → 1-based integer, or JSON null        (never omitted)
- violations[].severity → one of: critical | high | medium | low
- No raw secrets may appear anywhere in the evidence field (enforced upstream
  by redactor.py, validated here by field validators).
"""

from __future__ import annotations

import re
from enum import Enum

from pydantic import BaseModel, Field, field_validator, model_validator


class SeverityLevel(str, Enum):
    """Allowed severity classification values — matches assignment rubric exactly."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class Category(str, Enum):
    """
    The 9 audit categories that map to the rubric's inspection areas.
    Rule IDs are prefixed by their category code (e.g., HYGN-001, SEC-003).
    """

    HYGIENE = "repository_hygiene"
    DEPENDENCY = "dependency_management"
    QUALITY = "code_quality"
    TESTING = "testing"
    CI_CD = "github_actions_ci"
    SECURITY = "security"
    CONFIG = "configuration"
    COLLABORATION = "collaboration"
    BUILD_RELEASE = "build_and_release"


# Regex patterns that must NOT appear in evidence (secret leakage guard).
# Note: (?i) must be at the START of the full pattern for Python re compatibility.
_SECRET_PATTERN = re.compile(
    r"(?i)"
    r"(?:"
    r"ghp_[A-Za-z0-9]{36}"  # GitHub PAT
    r"|github_pat_[A-Za-z0-9_]{82}"  # Fine-grained GitHub PAT
    r"|AKIA[0-9A-Z]{16}"  # AWS access key
    r"|-----BEGIN (?:RSA )?PRIVATE KEY-----"  # Private key header
    r"|(?:api[_-]?key|secret|token|password)\s*[:=]\s*['\"][A-Za-z0-9+/=_\-]{8,}['\"]"
    r")"
)


class Violation(BaseModel):
    """
    A single detected violation with all required fields.

    Design decisions:
    - rule_id follows  {CATEGORY_PREFIX}-{NNN}  format (e.g., SEC-001).
    - file and line use Optional types that serialize as JSON null when None.
    - evidence is validated to contain no raw secret patterns.
    - All string fields have length constraints to prevent context-bloating output.
    """

    rule_id: str = Field(
        ...,
        description="Unique rule code, e.g. SEC-001, CI-002, HYGN-003",
        min_length=3,
        max_length=20,
        pattern=r"^[A-Z]{2,6}-\d{3}$",
    )
    category: Category = Field(..., description="Audit category from the 9-category taxonomy")
    severity: SeverityLevel = Field(
        ..., description="Impact severity: critical | high | medium | low"
    )
    file: str | None = Field(
        default=None,
        description="File path relative to repo root, or null if repository-wide finding",
    )
    line: int | None = Field(
        default=None,
        ge=1,
        description="1-based line number, or null if not applicable to a specific line",
    )
    description: str = Field(
        ...,
        description="Concise human-readable description of the issue",
        min_length=10,
        max_length=250,
    )
    evidence: str = Field(
        ...,
        description="Sanitized, concrete code snippet or file reference — no raw secrets",
        min_length=5,
        max_length=500,
    )
    recommendation: str = Field(
        ...,
        description="Actionable, specific remediation advice",
        min_length=10,
        max_length=350,
    )

    @field_validator("rule_id")
    @classmethod
    def validate_rule_id_format(cls, v: str) -> str:
        """Enforce CATEGORY-NNN format strictly."""
        if not re.match(r"^[A-Z]{2,6}-\d{3}$", v):
            raise ValueError(
                f"rule_id '{v}' does not match required format CATEGORY-NNN "
                "(e.g., SEC-001, CI-002, HYGN-003)"
            )
        return v

    @field_validator("evidence")
    @classmethod
    def no_secrets_in_evidence(cls, v: str) -> str:
        """
        Final defence: raise a validation error if a raw secret pattern is detected.
        Evidence should have been sanitized upstream by redactor.sanitize_evidence().
        """
        if _SECRET_PATTERN.search(v):
            raise ValueError(
                "Evidence contains a potential raw secret. "
                "Ensure evidence is passed through redactor.sanitize_evidence() first."
            )
        return v

    @field_validator("file")
    @classmethod
    def normalize_file_path(cls, v: str | None) -> str | None:
        """Normalize Windows backslashes to POSIX-style forward slashes."""
        if v is not None:
            return v.replace("\\", "/")
        return v

    model_config = {
        "use_enum_values": True,
        "str_strip_whitespace": True,
    }


class AuditReport(BaseModel):
    """
    The top-level audit output contract.

    Serializes to JSON with:
    - repository: the original URL or identifier
    - violations: list of Violation objects (empty list is valid for clean repos)
    """

    repository: str = Field(..., description="GitHub repository URL that was audited", min_length=1)
    violations: list[Violation] = Field(
        default_factory=list,
        description="All detected violations. Empty list indicates a clean audit.",
    )

    @model_validator(mode="after")
    def validate_no_duplicate_rule_ids(self) -> AuditReport:
        """Ensure rule_id uniqueness — duplicates indicate a logic error in the agent."""
        seen: set[str] = set()
        for v in self.violations:
            if v.rule_id in seen:
                raise ValueError(
                    f"Duplicate rule_id detected: '{v.rule_id}'. "
                    "Each violation must have a unique rule identifier."
                )
            seen.add(v.rule_id)
        return self

    def summary(self) -> dict[str, int]:
        """Return a severity breakdown count for logging and CLI output."""
        counts: dict[str, int] = {level.value: 0 for level in SeverityLevel}
        for v in self.violations:
            counts[v.severity] += 1
        return counts

    model_config = {
        "use_enum_values": True,
    }
