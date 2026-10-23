"""
Unit tests for the secret sanitization / redaction engine.

Tests verify:
1. GitHub Personal Access Token redaction
2. Fine-grained GitHub PAT redaction
3. AWS Access Key redaction
4. PEM private key block redaction
5. JWT token redaction
6. Bearer token redaction
7. Generic key=value credential redaction
8. Safe text passes through unchanged
9. Idempotency — running sanitize twice yields same result
10. Empty / None-like string handling
11. RedactionLoggingFilter integration
"""

import logging

from devops_auditor.redactor import RedactionLoggingFilter, sanitize_evidence

# ─── Individual Pattern Tests ────────────────────────────────────────────────


class TestGitHubTokens:
    def test_github_pat_redacted(self) -> None:
        raw = "ghp_" + "A" * 36
        result = sanitize_evidence(f"TOKEN={raw}")
        assert "ghp_" not in result
        assert "REDACTED_GITHUB_PAT" in result

    def test_github_actions_token_redacted(self) -> None:
        raw = "ghs_" + "B" * 36
        result = sanitize_evidence(f"GITHUB_TOKEN={raw}")
        assert "ghs_" not in result
        assert "REDACTED" in result


class TestAWSCredentials:
    def test_aws_access_key_id_redacted(self) -> None:
        raw = "AKIA" + "A" * 16
        result = sanitize_evidence(f"aws_access_key_id = '{raw}'")
        assert raw not in result
        assert "REDACTED_AWS_ACCESS_KEY" in result

    def test_aws_secret_not_in_result(self) -> None:
        raw = "AKIA" + "Z" * 16
        result = sanitize_evidence(raw)
        assert raw not in result


class TestPrivateKeys:
    def test_rsa_private_key_block_redacted(self) -> None:
        raw = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
        result = sanitize_evidence(raw)
        assert "BEGIN RSA PRIVATE KEY" not in result
        assert "REDACTED_PRIVATE_KEY" in result

    def test_openssh_private_key_block_redacted(self) -> None:
        raw = (
            "-----BEGIN OPENSSH PRIVATE KEY-----\n"
            "b3BlbnNzaC1rZXktdjEAAAAA...\n"
            "-----END OPENSSH PRIVATE KEY-----"
        )
        result = sanitize_evidence(raw)
        assert "OPENSSH PRIVATE KEY" not in result
        assert "REDACTED" in result


class TestJWTTokens:
    def test_jwt_redacted(self) -> None:
        # Realistic but fake JWT (3-part base64url format)
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        result = sanitize_evidence(f"Authorization: Bearer {jwt}")
        assert jwt not in result
        assert "REDACTED" in result


class TestBearerTokens:
    def test_bearer_token_redacted(self) -> None:
        result = sanitize_evidence("Authorization: Bearer abc123XYZsecrettoken456")
        assert "abc123XYZsecrettoken456" not in result
        assert "REDACTED_BEARER_TOKEN" in result


class TestGenericCredentials:
    def test_api_key_assignment_redacted(self) -> None:
        result = sanitize_evidence("API_KEY = 'sk-abcDEF123abcDEF123'")
        assert "sk-abcDEF123abcDEF123" not in result
        assert "REDACTED" in result

    def test_password_field_redacted(self) -> None:
        result = sanitize_evidence('password = "my_super_secret_pw"')
        assert "my_super_secret_pw" not in result

    def test_secret_field_redacted(self) -> None:
        result = sanitize_evidence("secret: 'longSecretValue1234567890'")
        assert "longSecretValue1234567890" not in result


# ─── Safe Text Passthrough ───────────────────────────────────────────────────


class TestSafeText:
    def test_normal_text_unchanged(self) -> None:
        text = "No secrets here — just a plain configuration comment."
        assert sanitize_evidence(text) == text

    def test_code_comment_unchanged(self) -> None:
        code = "# This sets the default timeout for requests"
        assert sanitize_evidence(code) == code

    def test_empty_string_unchanged(self) -> None:
        assert sanitize_evidence("") == ""

    def test_whitespace_only_unchanged(self) -> None:
        assert sanitize_evidence("   ") == "   "

    def test_dummy_token_in_test_fixture_context(self) -> None:
        """
        Demo/test credentials with obvious placeholder names should not be
        misclassified, but our scrubber may sanitize them anyway since it uses
        structural patterns not semantic context.  This test documents the
        expected (conservative) behaviour.
        """
        # Pattern doesn't match because 'dummy_token' is fewer than 8 chars
        # after the assignment operator — it depends on exact pattern length.
        text = 'TEST_TOKEN = "dummy"'
        # "dummy" is only 5 chars — below the 8-char minimum of our generic pattern
        result = sanitize_evidence(text)
        # Should pass through since it's too short to be a real secret
        assert "dummy" in result


# ─── Idempotency ─────────────────────────────────────────────────────────────


class TestIdempotency:
    def test_double_sanitization_is_idempotent(self) -> None:
        text = "API_KEY = 'sk-realkey1234567890ABCDEF'"
        once = sanitize_evidence(text)
        twice = sanitize_evidence(once)
        assert once == twice

    def test_safe_text_idempotent(self) -> None:
        text = "This is a plain English sentence."
        assert sanitize_evidence(sanitize_evidence(text)) == text


# ─── Logging Filter ──────────────────────────────────────────────────────────


class TestRedactionLoggingFilter:
    def test_filter_sanitizes_log_message(self) -> None:
        raw_key = "AKIA" + "B" * 16
        record = logging.LogRecord(
            name="test",
            level=logging.WARNING,
            pathname="",
            lineno=0,
            msg=f"Found key: {raw_key}",
            args=(),
            exc_info=None,
        )
        f = RedactionLoggingFilter()
        assert f.filter(record) is True
        assert raw_key not in record.msg
        assert "REDACTED" in record.msg

    def test_filter_always_returns_true(self) -> None:
        """Filter must not suppress any log records."""
        record = logging.LogRecord(
            name="test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="Safe message without secrets",
            args=(),
            exc_info=None,
        )
        f = RedactionLoggingFilter()
        assert f.filter(record) is True
