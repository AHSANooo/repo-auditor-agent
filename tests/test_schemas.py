"""
Unit tests for src/devops_auditor/schemas.py

Tests validate:
1. Valid Violation and AuditReport construction
2. Severity enum enforcement
3. Category enum enforcement
4. rule_id format validation (CATEGORY-NNN)
5. Secret leakage guard on evidence field
6. null serialization for optional file and line fields
7. Duplicate rule_id detection on AuditReport
8. Windows path normalization for file field
9. AuditReport.summary() breakdown counts
"""

import json
from typing import Any

import pytest
from pydantic import ValidationError

from devops_auditor.schemas import AuditReport, Category, SeverityLevel, Violation

# ─── Helpers ────────────────────────────────────────────────────────────────


def make_violation(**overrides: object) -> dict[str, Any]:
    """Return a valid violation dict with optional field overrides."""
    base = {
        "rule_id": "SEC-001",
        "category": "security",
        "severity": "critical",
        "file": "config/settings.py",
        "line": 42,
        "description": "Hardcoded API key detected in source file",
        "evidence": "API_KEY = '[REDACTED]'",
        "recommendation": "Move secrets to environment variables and use python-dotenv.",
    }
    base.update(overrides)
    return base


# ─── SeverityLevel ──────────────────────────────────────────────────────────


class TestSeverityLevel:
    def test_all_values_present(self) -> None:
        levels = {s.value for s in SeverityLevel}
        assert levels == {"critical", "high", "medium", "low"}

    def test_str_enum_behaviour(self) -> None:
        assert SeverityLevel.CRITICAL.value == "critical"
        assert SeverityLevel("critical") == SeverityLevel.CRITICAL
        assert SeverityLevel.HIGH.value == "high"


# ─── Category ───────────────────────────────────────────────────────────────


class TestCategory:
    def test_nine_categories_present(self) -> None:
        assert len(Category) == 9

    def test_expected_values(self) -> None:
        expected = {
            "repository_hygiene",
            "dependency_management",
            "code_quality",
            "testing",
            "github_actions_ci",
            "security",
            "configuration",
            "collaboration",
            "build_and_release",
        }
        assert {c.value for c in Category} == expected


# ─── Violation ──────────────────────────────────────────────────────────────


class TestViolation:
    def test_valid_violation_creates_successfully(self) -> None:
        v = Violation(**make_violation())
        assert v.rule_id == "SEC-001"
        assert v.severity == "critical"
        assert v.category == "security"

    def test_null_file_and_line_allowed(self) -> None:
        v = Violation(**make_violation(file=None, line=None))
        assert v.file is None
        assert v.line is None

    def test_null_fields_serialize_to_json_null(self) -> None:
        v = Violation(**make_violation(file=None, line=None))
        data = json.loads(v.model_dump_json())
        assert data["file"] is None
        assert data["line"] is None

    def test_invalid_rule_id_format_raises(self) -> None:
        with pytest.raises(ValidationError, match="rule_id"):
            Violation(**make_violation(rule_id="INVALID"))

    def test_rule_id_too_short_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(rule_id="S-001"))

    def test_rule_id_lowercase_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(rule_id="sec-001"))

    def test_invalid_severity_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(severity="extreme"))

    def test_invalid_category_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(category="unknown_category"))

    def test_description_too_short_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(description="short"))

    def test_description_too_long_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(description="x" * 251))

    def test_evidence_secret_leakage_github_token(self) -> None:
        raw_token = "ghp_" + "A" * 36
        with pytest.raises(ValidationError, match="raw secret"):
            Violation(**make_violation(evidence=f"TOKEN = '{raw_token}'"))

    def test_evidence_secret_leakage_aws_key(self) -> None:
        aws_key = "AKIA" + "A" * 16
        with pytest.raises(ValidationError, match="raw secret"):
            Violation(**make_violation(evidence=f"aws_key = '{aws_key}'"))

    def test_evidence_redacted_token_passes(self) -> None:
        v = Violation(**make_violation(evidence="TOKEN = '[REDACTED_GITHUB_TOKEN]'"))
        assert "REDACTED" in v.evidence

    def test_windows_path_normalized_to_posix(self) -> None:
        v = Violation(**make_violation(file="src\\config\\settings.py"))
        assert v.file == "src/config/settings.py"

    def test_line_must_be_positive(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(line=0))

    def test_line_negative_raises(self) -> None:
        with pytest.raises(ValidationError):
            Violation(**make_violation(line=-1))


# ─── AuditReport ────────────────────────────────────────────────────────────


class TestAuditReport:
    def test_valid_empty_report(self) -> None:
        report = AuditReport(repository="https://github.com/example/repo")
        assert report.violations == []

    def test_valid_report_with_violations(self) -> None:
        v = Violation(**make_violation())
        report = AuditReport(
            repository="https://github.com/example/repo",
            violations=[v],
        )
        assert len(report.violations) == 1

    def test_duplicate_rule_id_raises(self) -> None:
        v1 = Violation(**make_violation(rule_id="SEC-001"))
        v2 = Violation(**make_violation(rule_id="SEC-001", severity="high"))
        with pytest.raises(ValidationError, match="Duplicate rule_id"):
            AuditReport(
                repository="https://github.com/example/repo",
                violations=[v1, v2],
            )

    def test_summary_empty_report(self) -> None:
        report = AuditReport(repository="https://github.com/example/repo")
        summary = report.summary()
        assert summary == {"critical": 0, "high": 0, "medium": 0, "low": 0}

    def test_summary_counts_correctly(self) -> None:
        violations = [
            Violation(**make_violation(rule_id="SEC-001", severity="critical")),
            Violation(**make_violation(rule_id="SEC-002", severity="critical")),
            Violation(
                **make_violation(rule_id="CI-001", severity="high", category="github_actions_ci")
            ),
            Violation(
                **make_violation(
                    rule_id="DEP-001", severity="low", category="dependency_management"
                )
            ),
        ]
        report = AuditReport(
            repository="https://github.com/example/repo",
            violations=violations,
        )
        summary = report.summary()
        assert summary["critical"] == 2
        assert summary["high"] == 1
        assert summary["low"] == 1
        assert summary["medium"] == 0

    def test_json_serialization_round_trip(self) -> None:
        v = Violation(**make_violation(file=None, line=None))
        report = AuditReport(
            repository="https://github.com/example/repo",
            violations=[v],
        )
        json_str = report.model_dump_json(indent=2)
        loaded = json.loads(json_str)
        assert loaded["repository"] == "https://github.com/example/repo"
        assert loaded["violations"][0]["file"] is None
        assert loaded["violations"][0]["line"] is None
        assert loaded["violations"][0]["severity"] == "critical"

    def test_multiple_categories_in_single_report(self) -> None:
        violations = [
            Violation(
                **make_violation(rule_id="SEC-001", category="security", severity="critical")
            ),
            Violation(
                **make_violation(rule_id="CI-001", category="github_actions_ci", severity="high")
            ),
            Violation(
                **make_violation(
                    rule_id="DEP-001", category="dependency_management", severity="medium"
                )
            ),
            Violation(
                **make_violation(rule_id="HYGN-001", category="repository_hygiene", severity="low")
            ),
        ]
        report = AuditReport(
            repository="https://github.com/example/repo",
            violations=violations,
        )
        assert len(report.violations) == 4
