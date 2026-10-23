# 🔍 DevOps Auditor Agent

<div align="center">

[![CI Pipeline](https://github.com/AHSANooo/repo-auditor-agent/actions/workflows/ci.yml/badge.svg)](https://github.com/AHSANooo/repo-auditor-agent/actions/workflows/ci.yml)
[![Security Audit](https://github.com/AHSANooo/repo-auditor-agent/actions/workflows/security.yml/badge.svg)](https://github.com/AHSANooo/repo-auditor-agent/actions/workflows/security.yml)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Code Style: Ruff](https://img.shields.io/badge/code%20style-ruff-000000.svg)](https://github.com/astral-sh/ruff)
[![Type Checked: Mypy](https://img.shields.io/badge/type%20checked-mypy%20strict-blue.svg)](https://mypy-lang.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](./LICENSE)
[![Zero Frameworks](https://img.shields.io/badge/agent%20framework-none%20%E2%80%94%20native%20ReAct-green.svg)](#architecture)
[![Changelog](https://img.shields.io/badge/changelog-keep%20a%20changelog-orange.svg)](./CHANGELOG.md)

**An autonomous AI agent that audits GitHub repositories for DevOps and security defects.**

Built with a **zero-framework native ReAct tool-calling loop** — no LangChain, no LangGraph, no CrewAI.
Just clean Python, the OpenAI SDK, and defense-in-depth security engineering.
Default provider: **Google Gemini** (`gemini-3.5-flash-lite`) via the OpenAI-compatible endpoint.

[Quickstart](#-quickstart) · [Architecture](#-architecture) · [Features](#-features) · [Sample Output](#-sample-output) · [Docker](#-docker) · [Contributing](#-contributing)

</div>

---

## 🎯 What It Does

The agent autonomously inspects any public GitHub repository across **9 audit categories**:

| # | Category | What's Checked |
|---|----------|----------------|
| 1 | 🧹 Repository Hygiene | Tracked `.env`, `node_modules/`, `.DS_Store`, missing `.gitignore` |
| 2 | 📦 Dependency Management | Unpinned versions, missing lockfiles, vulnerable packages |
| 3 | 🧪 Testing | CI that skips tests, missing test configuration |
| 4 | ⚙️ GitHub Actions / CI | Mutable action refs (`@main`), `permissions: write-all`, pwn-request patterns |
| 5 | 🔒 Security | Hardcoded secrets, AWS keys, GitHub PATs, private keys in source |
| 6 | 🔧 Configuration | Hardcoded absolute paths, `DEBUG=True` in production configs |
| 7 | 🤝 Collaboration | Missing LICENSE, README, CONTRIBUTING, generic commit messages |
| 8 | 🏗️ Build & Release | Missing Dockerfile, unversioned releases |
| 9 | 📝 Code Quality | Unconfigured linting, style issues |

Produces a **schema-validated JSON report** with per-violation severity, evidence, and actionable recommendations.

---

## 🏗️ Architecture

The agent implements a native **ReAct (Reason + Act)** loop — the same fundamental pattern as GPT-4 Plugins and Claude's tool use, implemented without abstraction layers:

```
┌─────────────────────────────────────────────────────────────────┐
│                      CLI Entry Point                            │
│              python agent.py --repo <url> --output report.json  │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                   Repository Manager                             │
│   git clone --depth 1 → isolated /tmp/auditor_XXXXX/ directory  │
│   Context manager guarantees cleanup on exit                    │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│              Native ReAct Agent Loop  (agent.py)                │
│                                                                 │
│  ┌──────────┐    tool_calls    ┌────────────────────────────┐  │
│  │          │ ───────────────► │    Tool Dispatcher          │  │
│  │   LLM    │                  │                            │  │
│  │ Reasoner │ ◄─────────────── │  list_files()              │  │
│  │          │   observations   │  read_file()               │  │
│  └──────────┘                  │  search_code()             │  │
│       │                        │  git_log()                 │  │
│       │ submit_audit_report()  │  submit_audit_report() ──┐ │  │
│       └────────────────────────┘                         │ │  │
│                                                          │ │  │
└──────────────────────────────────────────────────────────┼─┘  │
                                                           │
                               ┌───────────────────────────┘
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│                 Security Pipeline                                │
│                                                                 │
│  1. redactor.sanitize_evidence()  → strips all credential      │
│     patterns (AWS keys, GitHub PATs, private keys, JWTs)       │
│                                                                 │
│  2. Pydantic V2 AuditReport validation  → enforces exact       │
│     schema contract, rejects duplicate rule_ids, blocks        │
│     raw secrets from passing through evidence validators        │
└──────────────────────────────┬──────────────────────────────────┘
                               │
                               ▼
                    ✅  report.json  (schema-validated JSON)
```

### Key Engineering Decisions

| Decision | Rationale |
|----------|-----------|
| **Zero agent framework** | Demonstrates deep understanding of tool-calling primitives; avoids black-box dependencies that hide failure modes |
| **Shallow clone (`--depth 1`)** | Minimizes disk and network usage; the agent doesn't need git history for static analysis |
| **Context manager cleanup** | Guarantees zero temp-disk leakage even on agent crash or `KeyboardInterrupt` |
| **Path traversal sandbox** | All file reads go through `Path.resolve().relative_to(repo_root)` — untrusted repo symlinks cannot escape |
| **Pydantic V2 schemas** | Single source of truth for the output contract; catches schema drift before it reaches the caller |
| **Regex secret redaction before Pydantic** | Defense-in-depth: even if the LLM hallucinates a credential, the validator blocks its serialization |

---

## ✨ Features

- **🧠 Native ReAct Loop** — autonomous multi-step investigation, up to 20 configurable iterations
- **🌐 Multi-Provider LLM** — works with Google Gemini (default), OpenAI, DeepSeek, Groq, or local Ollama via a single env var
- **🔐 Defense-in-Depth Security**:
  - Path traversal prevention on all file reads
  - Multi-pattern regex credential scrubbing (AWS, GitHub, JWT, RSA keys)
  - Secret-safe logging via `RedactionLoggingFilter`
  - Pydantic evidence field validator as final backstop
- **📋 Strict Output Contract** — Pydantic V2 models enforce every field type, `null` serialization, and rule_id format
- **🧪 122+ Unit Tests** — zero API calls, mocked LLM responses, >80% coverage, 3 synthetic fixture repos
- **🐳 Production Docker** — multi-stage build, non-root user, OCI labels
- **🔄 Full CI/CD** — lint, format, mypy strict, pytest matrix (3.10, 3.11, 3.12), Bandit, pip-audit, TruffleHog
- **🔒 Supply-Chain Hardened** — all GitHub Actions pinned to immutable commit SHAs

---

## 🚀 Quickstart

### Prerequisites

- Python 3.10+
- Git
- An API key for any OpenAI-compatible LLM provider

### 1. Clone & Install

```bash
git clone https://github.com/AHSANooo/repo-auditor-agent.git
cd repo-auditor-agent

python -m venv .venv
# Linux/macOS:
source .venv/bin/activate
# Windows:
.\.venv\Scripts\activate

# Either install the package in editable mode:
pip install -e .
# Or install via requirements.txt:
pip install -r requirements.txt
```

### 2. Configure API Key

```bash
cp .env.example .env
# Edit .env and set your OPENAI_API_KEY
```

**Default provider: Google Gemini** (recommended for best tool-calling and context window)

| Provider | `OPENAI_BASE_URL` | Recommended `AUDIT_MODEL` |
|----------|-------------------|---------------------------|
| **Google Gemini (default)** | `https://generativelanguage.googleapis.com/v1beta/openai/` | `gemini-3.5-flash-lite` |
| OpenAI | *(not set)* | `gpt-4o-mini` |
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` |
| Groq | `https://api.groq.com/openai/v1` | `qwen/qwen3.8-27b` |
| Ollama (local) | `http://localhost:11434/v1` | `llama3.1` |

### 3. Run the Audit

```bash
# Audit any public GitHub repository
python agent.py --repo https://github.com/pallets/flask --output report.json

# Alternative: use the installed CLI entrypoint (after pip install -e .)
devops-auditor --repo https://github.com/pallets/flask --output report.json

# View the structured report
cat report.json
```

### 4. Advanced Options

```bash
# Use a specific model
python agent.py --repo <url> --output report.json --model gemini-3.5-flash-lite

# Increase iterations for thorough analysis of large repos
python agent.py --repo <url> --output report.json --max-iterations 30

# Check installed version
python agent.py --version

# Debug logging
LOG_LEVEL=DEBUG python agent.py --repo <url> --output report.json
```

> **Exit Codes**: `0` = success · `1` = usage/env error · `2` = network/clone error · `3` = internal error

---

## 📊 Sample Output

See [`sample_report.json`](./sample_report.json) for a full example. Excerpt:

```json
{
  "repository": "https://github.com/example/deliberately-vulnerable-demo",
  "violations": [
    {
      "rule_id": "SEC-001",
      "category": "security",
      "severity": "critical",
      "file": "config/settings.py",
      "line": 14,
      "description": "AWS Access Key ID hardcoded directly in source file",
      "evidence": "AWS_ACCESS_KEY_ID = '[REDACTED_AWS_ACCESS_KEY]'",
      "recommendation": "Remove the key immediately, rotate it in AWS IAM, and use environment variables or AWS Secrets Manager instead."
    },
    {
      "rule_id": "CI-001",
      "category": "github_actions_ci",
      "severity": "high",
      "file": ".github/workflows/deploy.yml",
      "line": 8,
      "description": "GitHub Action pinned to mutable 'main' branch ref instead of a commit SHA",
      "evidence": "uses: org/some-action@main",
      "recommendation": "Pin actions to an immutable commit SHA to prevent supply-chain attacks."
    }
  ]
}
```

**Severity breakdown from the sample**: 2 critical · 2 high · 3 medium · 3 low

---

## 🐳 Docker

### Build

```bash
docker build -t devops-auditor:latest .
```

### Run

```bash
# Mount a local reports directory
docker run --rm \
  -e OPENAI_API_KEY=your_key_here \
  -v $(pwd)/reports:/reports \
  devops-auditor:latest \
  --repo https://github.com/pallets/flask \
  --output /reports/flask-audit.json
```

The container runs as a non-root `auditor` user with minimal permissions.

---

## 🧪 Development

### Install Dev Dependencies

```bash
pip install -e ".[dev]"
```

### Run Tests

```bash
# Full test suite
pytest tests/ -v

# With coverage report
pytest tests/ --cov=src/devops_auditor --cov-report=term-missing

# Run a specific test class
pytest tests/test_tools.py::TestListFiles -v
```

### Linting & Type Checking

```bash
# Lint
ruff check .

# Format
ruff format .

# Static types
mypy src/

# Security scan
bandit -r src/ -c pyproject.toml
```

### Pre-commit Hooks

```bash
pre-commit install
# Now hooks run automatically on every commit
```

---

## 📁 Project Structure

```text
repo-auditor-agent/
├── .github/
│   ├── ISSUE_TEMPLATE/
│   │   ├── bug_report.md       # Bug report template
│   │   └── feature_request.md  # Feature request template
│   ├── pull_request_template.md # PR checklist with security section
│   └── workflows/
│       ├── ci.yml              # Lint, type-check, pytest matrix (3.10–3.12) — SHA-pinned
│       └── security.yml        # Bandit, pip-audit, TruffleHog — SHA-pinned
├── src/
│   └── devops_auditor/
│       ├── __init__.py
│       ├── agent.py            # Native ReAct loop & tool dispatcher
│       ├── cli.py              # CLI argument parsing & orchestration
│       ├── prompts.py          # System prompt, tool schemas, audit taxonomy
│       ├── redactor.py         # Multi-pattern credential scrubbing engine
│       ├── repo_manager.py     # Isolated shallow clone & automatic cleanup
│       ├── schemas.py          # Pydantic V2 output contract models
│       └── tools.py            # Sandboxed inspection tools
├── tests/
│   ├── fixtures/
│   │   ├── clean-repo/         # Synthetic clean repo (zero violations expected)
│   │   ├── vulnerable-repo/    # Synthetic repo with 9 planted violations
│   │   └── invalid-repo/       # Minimal broken repo (missing README, LICENSE, CI)
│   ├── conftest.py             # Shared fixture helpers (clean/vulnerable/invalid paths)
│   ├── test_agent.py           # LLM mock tests — zero API calls
│   ├── test_cli.py             # CLI runner, argument parsing, & error handling
│   ├── test_fixtures.py        # Fixture-based integration tests (20 tests)
│   ├── test_redactor.py        # Credential masking verification
│   ├── test_repo_manager.py    # Isolated shallow clone & cleanup lifecycle
│   ├── test_schemas.py         # JSON schema contract validation
│   └── test_tools.py           # Sandboxing & tool unit tests
├── .env.example                # Environment template (Gemini configured as default)
├── .pre-commit-config.yaml     # Ruff, Mypy, Bandit, secret detection
├── agent.py                    # Root CLI shim (assignment contract)
├── CHANGELOG.md                # Keep a Changelog format
├── CODE_OF_CONDUCT.md          # Contributor Covenant v2.1
├── Dockerfile                  # Multi-stage non-root container
├── LICENSE                     # MIT
├── pyproject.toml              # PEP 621 packaging + tool configuration
├── README.md                   # This file
├── sample_report.json          # Verified example audit output
├── SECURITY.md                 # Responsible disclosure policy
└── tools.py                    # Root tools shim
```

---

## 🔒 Security Design

This project implements multiple layers of defence:

1. **Isolated Execution** — target repositories are cloned to OS-managed temp directories and deleted on exit, preventing persistent state or host contamination.
2. **Path Traversal Prevention** — all `read_file` and `list_files` calls validate that the resolved path is within the cloned root before any file I/O.
3. **Secret Scrubbing** — a 9-pattern regex pipeline strips AWS keys, GitHub PATs, JWT tokens, PEM key blocks, and generic `key=value` credentials from all evidence before serialization.
4. **No Untrusted Code Execution** — the agent reads and searches files; it never executes scripts or test suites from the target repository.
5. **Schema Validation as Final Guard** — Pydantic field validators independently detect raw credential patterns in evidence fields even if redaction was somehow bypassed.
6. **Secure Subprocess** — all `git` commands use list arguments (never `shell=True`), with a 60-second timeout.

---

## 🤝 Contributing

Contributions welcome! Please:

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes, add tests
4. Ensure `pytest` and `ruff` pass
5. Submit a pull request to `main`

See [CONTRIBUTING.md](./CONTRIBUTING.md) for detailed guidelines.

---

## 📄 License

[MIT](./LICENSE) © 2026 AHSANooo
