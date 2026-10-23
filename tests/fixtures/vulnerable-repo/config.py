"""
Application configuration — deliberately insecure for audit testing.

AUDIT TRIGGERS IN THIS FILE:
  SEC-001: AWS access key hardcoded (AKIA pattern)
  SEC-002: Hardcoded database password
  CFG-001: Hardcoded absolute path (Linux-style)
  SEC-003: DEBUG = True in production config
"""

import subprocess

# ── Hardcoded AWS credentials (SEC-001) ──────────────────────────────────────
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

# ── Hardcoded database password (SEC-002) ────────────────────────────────────
DATABASE_URL = "postgresql://admin:SuperSecretPassword123@prod-db.internal:5432/myapp"

# ── DEBUG=True in production config (SEC-003) ────────────────────────────────
DEBUG = True

# ── Hardcoded absolute path (CFG-001) ────────────────────────────────────────
LOG_FILE = "/Users/john.doe/projects/myapp/logs/app.log"

# ── Unsafe subprocess with shell=True (SEC-004) ──────────────────────────────
def run_command(user_input: str) -> str:
    result = subprocess.run(user_input, shell=True, capture_output=True, text=True)
    return result.stdout
