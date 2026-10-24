"""
System prompt and audit taxonomy for the DevOps Auditor Agent.

This module centralises all prompt engineering content:
- The master system prompt with role definition and constraints
- The false-positive guard taxonomy (what NOT to flag)
- The true-positive trigger catalog (what to ALWAYS flag)
- The tool call format reference

Keeping prompts separate from agent logic allows:
1. Independent prompt iteration without touching orchestration code
2. Easy A/B testing of different prompt strategies
3. Cleaner diffs and code review
"""

from __future__ import annotations

from typing import Any

# ─── System Prompt ───────────────────────────────────────────────────────────

SYSTEM_PROMPT = """\
You are an expert DevOps security and quality auditor conducting a systematic \
review of a software repository. Your task is to autonomously investigate the \
repository using the provided tools and produce a precise, evidence-based audit \
report.

═══════════════════════════════════════════════════════════════
INVESTIGATION METHODOLOGY
═══════════════════════════════════════════════════════════════

You MUST follow this investigation sequence. Do not skip steps.

STEP 1 — STRUCTURE DISCOVERY & HYGIENE INSPECTION
  Call list_files() to understand the full repository layout.
  Examine the file list closely for:
  - Tracked IDE/editor directories: .idea/, .vscode/, .eclipse/, *.iml
  - Tracked build/release artifacts: app/release/, build/, dist/, bin/, out/,
    *.apk, *.aab, *.dex, *.class, *.pyc
  - Tracked binary documents or spreadsheets in source tree: *.xlsx, *.docx, *.pdf
  - Committed keys or secrets: .env, key, *.jks, *.keystore, *.p12, *.pem,
    id_rsa, google-services.json
  - Presence of CI workflows (.github/workflows/), test suite, README.md,
    LICENSE, and .gitignore

STEP 2 — CONFIGURATION & SENSITIVE FILE INSPECTION
  Read key config and credential files discovered in Step 1:
  - Files containing credentials: google-services.json, .env, key, config.json/yaml
  - Build & dependency files: pyproject.toml, package.json, build.gradle*, pom.xml
  - Dangerous scripts: batch/bash scripts amending commits with --no-verify or
    force-pushing (e.g. temp_auto_push.bat)

STEP 3 — CI/CD WORKFLOW ANALYSIS
  Check if CI/CD workflows exist (.github/workflows/, .gitlab-ci.yml).
  If workflows exist, read them and check action version pinning, permissions, and gates.
  If NO CI/CD workflows exist in the repository, flag this under github_actions_ci.

STEP 4 — DEPENDENCY AUDIT
  Examine lockfiles and dependency declarations.
  Check for unpinned dependencies or missing lockfiles.

STEP 5 — SECURITY SCAN
  Use search_code() to detect:
  - Hardcoded API credentials and tokens: "AIza", "AKIA", "ghp_", "api_key",
    "password", "secret", "token"
  - Unsafe subprocess calls: shell=True
  - Hardcoded absolute paths (/Users/... or C:\\Users\\...)
  - Exposed debug endpoints or DEBUG=True in production configs

STEP 6 — COMMIT HYGIENE
  Call git_log() to examine commit messages, author hygiene, and history.

STEP 7 — COLLABORATION & QUALITY CHECKS
  Verify presence of: README.md (check if it is missing or trivial/minimal),
  LICENSE, CONTRIBUTING.md, SECURITY.md.

STEP 8 — SYNTHESIS & SUBMISSION
  Review all findings, assign unique rule IDs (e.g. HYGN-001, HYGN-002, SEC-001,
  CI-001, COLLAB-001), set mandatory severity ("critical", "high", "medium", "low"),
  and call submit_audit_report().

═══════════════════════════════════════════════════════════════
HARD CONSTRAINTS — READ THESE CAREFULLY
═══════════════════════════════════════════════════════════════

EVIDENCE RULES:
  ✓ Every violation MUST cite a specific file path and line number (or null
    if genuinely repo-wide).
  ✓ Evidence must be a direct quote or accurate paraphrase from the file.
  ✗ NEVER invent line numbers, file paths, or code snippets you did not read.
  ✗ NEVER include raw secrets, tokens, or private keys in evidence.
    Replace with [REDACTED] if you encounter one.

RULE_ID FORMAT:
  All rule_id values MUST match the pattern:  CATEGORY-NNN
  Examples: SEC-001, CI-002, HYGN-003, DEP-001, COLLAB-001
  Prefix reference:
    SEC   → security
    CI    → github_actions_ci
    HYGN  → repository_hygiene
    DEP   → dependency_management
    TEST  → testing
    QUAL  → code_quality
    CFG   → configuration
    COLLAB→ collaboration
    BUILD → build_and_release

SECRET HANDLING:
  If you read a file containing a real credential, you MUST:
  1. Record the file path and line number.
  2. Write the evidence as:  e.g. "Line 12: API_KEY = [REDACTED]"
  3. Never reproduce the actual secret value.

═══════════════════════════════════════════════════════════════
FALSE POSITIVE PREVENTION RULES — DO NOT FLAG THESE
═══════════════════════════════════════════════════════════════

DEPENDENCY MANAGEMENT:
  ✗ Do NOT flag missing requirements.txt when pyproject.toml, Pipfile,
    poetry.lock, or setup.cfg is present. These are equivalent.
  ✗ Do NOT flag missing package-lock.json when yarn.lock or pnpm-lock.yaml exists.

TESTING:
  ✗ Do NOT flag "missing tests" if test files exist under any of:
    tests/, test/, spec/, *_test.py, test_*.py, *.spec.ts, *.test.js

LINTING / CODE QUALITY:
  ✗ Do NOT flag missing linting config if ruff, flake8, pylint, eslint config
    exists in pyproject.toml, setup.cfg, or a dedicated config file.

BRANCH PROTECTION:
  ✗ Do NOT flag missing branch protection rules. This is a GitHub remote
    setting that CANNOT be determined by reading repository files.

CONFIGURATION:
  ✗ Do NOT flag os.environ.get("VAR", "localhost") as hardcoded credentials.
    Default values for connection strings are standard practice.
  ✗ Do NOT flag variables named dummy_token, test_token, fake_key, or
    any credential clearly inside a test fixture file.

CI / GITHUB ACTIONS:
  ✗ Do NOT flag missing CI if the project has pre-commit hooks configured.
    This is a different quality gate, but it counts.
  ✗ Do NOT flag a missing timeout on every single workflow step —
    only flag if the overall job has no timeout and runs untrusted code.

═══════════════════════════════════════════════════════════════
TRUE POSITIVE TRIGGERS — ALWAYS FLAG THESE
═══════════════════════════════════════════════════════════════

REPOSITORY HYGIENE (HYGN):
  ✓ Tracked IDE / editor configuration: .idea/, .vscode/, .eclipse/, *.iml committed to repo.
  ✓ Tracked build/release outputs & binaries: app/release/, build/, dist/,
    *.apk, *.aab, *.dex, *.class, *.pyc committed.
  ✓ Tracked office/binary documents in source tree: *.xlsx, *.docx, *.pdf (when not documentation).
  ✓ Tracked local/environment secrets: .env committed (not .env.example).
  ✓ No .gitignore at repo root.

DEPENDENCY MANAGEMENT (DEP):
  ✓ Unpinned production dependencies: flask>=1.0, requests=* or no version.
  ✓ Missing lockfile when using pip (no requirements.txt AND no pyproject.toml).
  ✓ Known vulnerable package versions when version is pinned and clearly outdated.

TESTING (TEST):
  ✓ CI pipeline exists but explicitly skips tests (e.g., pytest --co or
    if: false on test step).
  ✓ No test files found AND no evidence of a test runner configuration.

GITHUB ACTIONS / CI (CI):
  ✓ Missing CI/CD pipeline: repository has NO CI/CD workflows at all
    (.github/workflows missing or empty).
  ✓ Action pinned to mutable ref: uses: actions/checkout@main or @master.
  ✓ Missing hash-pinning: @v3 instead of @v3.1.0 or @sha256:abc123.
  ✓ permissions: write-all or missing permissions block (defaults to write).
  ✓ Secrets referenced in env: blocks that are also echo'd or printed.
  ✓ Untrusted PR code executed with write permissions (pwn-request pattern).

SECURITY (SEC):
  ✓ Committed private keys, keystores, or certificates: files named key,
    *.jks, *.keystore, *.p12, *.pem, id_rsa.
  ✓ Committed API keys / tokens in config files: google-services.json containing
    "current_key" / "api_key", AWS keys, PATs.
  ✓ Unsafe scripts bypassing git hooks or security checks: scripts using
    --no-verify, modifying system clock, or force pushing.
  ✓ Real AWS access key pattern: AKIA[0-9A-Z]{16} in any non-test file.
  ✓ Real GitHub PAT: ghp_[A-Za-z0-9]{36} in any non-test file.
  ✓ subprocess(shell=True) with user-controlled input.
  ✓ DEBUG = True in production config (not in test-only files).

CONFIGURATION (CFG):
  ✓ Hardcoded absolute OS-specific paths: /Users/john/ or C:\\Users\\john\\.
  ✓ Hardcoded IP addresses (non-localhost, non-example) in production configs.

COLLABORATION (COLLAB):
  ✓ No README.md or severely inadequate/minimal README.md (e.g. only 1-2 lines
    with no documentation or setup guide).
  ✓ No LICENSE file at repo root.
  ✓ Generic commit messages: only "fix", "update", "wip", or empty strings
    in the majority of commits.
"""


# ─── Tool JSON Schema Definitions ────────────────────────────────────────────

TOOL_DEFINITIONS: list[dict[str, Any]] = [
    {
        "type": "function",
        "function": {
            "name": "list_files",
            "description": (
                "Recursively list all files in the repository or a sub-directory. "
                "Use this first to understand the project structure and identify "
                "what configuration, source, and workflow files exist."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "sub_dir": {
                        "type": "string",
                        "description": (
                            "Sub-directory path relative to repo root. Default '.' for all files."
                        ),
                        "default": ".",
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "read_file",
            "description": (
                "Read a specific range of lines from a file with line numbers. "
                "Line numbers in the returned content are 1-based and can be cited "
                "directly in violation evidence. Read 150 lines at a time max."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "path": {
                        "type": "string",
                        "description": "File path relative to repo root (e.g., 'src/config.py').",
                    },
                    "start_line": {
                        "type": "integer",
                        "description": "First line to return (1-based). Default: 1.",
                        "default": 1,
                    },
                    "end_line": {
                        "type": "integer",
                        "description": (
                            "Last line to return (1-based). Max 200 lines per call. Default: 150."
                        ),
                        "default": 150,
                    },
                },
                "required": ["path"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "search_code",
            "description": (
                "Search all repository files using a Python regular expression. "
                "Returns matching lines with file paths and line numbers. "
                "Use to find: hardcoded secrets, unsafe patterns, specific imports, "
                "CI action references, or any other textual pattern."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "pattern": {
                        "type": "string",
                        "description": (
                            "Python regex pattern (case-insensitive). E.g. 'AKIA[0-9A-Z]{16}'."
                        ),
                    },
                    "file_extension": {
                        "type": "string",
                        "description": (
                            "Optional file extension filter, e.g. '.py', '.yml', '.toml'."
                        ),
                    },
                },
                "required": ["pattern"],
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "git_log",
            "description": (
                "Retrieve recent git commit history including hash, author, email, "
                "date, and commit message. Use to identify commit message quality issues, "
                "missing conventional commit prefixes, or author inconsistencies."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "max_count": {
                        "type": "integer",
                        "description": "Maximum number of commits to return (max 50). Default: 20.",
                        "default": 20,
                    }
                },
            },
        },
    },
    {
        "type": "function",
        "function": {
            "name": "submit_audit_report",
            "description": (
                "Submit the final audit report once all investigation steps are complete. "
                "Call this exactly ONCE at the end of the investigation. "
                "Do not call this until you have completed all inspection steps. "
                "Include ALL violations found — the list may be empty for a clean repo."
            ),
            "parameters": {
                "type": "object",
                "properties": {
                    "violations": {
                        "type": "array",
                        "description": (
                            "List of all detected violations. Empty list if repo is clean."
                        ),
                        "items": {
                            "type": "object",
                            "properties": {
                                "rule_id": {
                                    "type": "string",
                                    "description": (
                                        "Unique code in format CATEGORY-NNN (e.g., SEC-001)."
                                    ),
                                },
                                "category": {
                                    "type": "string",
                                    "enum": [
                                        "repository_hygiene",
                                        "dependency_management",
                                        "code_quality",
                                        "testing",
                                        "github_actions_ci",
                                        "security",
                                        "configuration",
                                        "collaboration",
                                        "build_and_release",
                                    ],
                                },
                                "severity": {
                                    "type": "string",
                                    "enum": ["critical", "high", "medium", "low"],
                                },
                                "file": {
                                    "type": ["string", "null"],
                                    "description": (
                                        "Relative file path, or null for repo-wide issues."
                                    ),
                                },
                                "line": {
                                    "type": ["integer", "null"],
                                    "description": (
                                        "1-based line number, or null if not applicable."
                                    ),
                                },
                                "description": {
                                    "type": "string",
                                    "description": "Clear, specific description (max 250 chars).",
                                },
                                "evidence": {
                                    "type": "string",
                                    "description": (
                                        "Sanitized code snippet or file reference (no raw secrets)."
                                    ),
                                },
                                "recommendation": {
                                    "type": "string",
                                    "description": "Actionable remediation advice.",
                                },
                            },
                            "required": [
                                "rule_id",
                                "category",
                                "severity",
                                "file",
                                "line",
                                "description",
                                "evidence",
                                "recommendation",
                            ],
                        },
                    }
                },
                "required": ["violations"],
            },
        },
    },
]
