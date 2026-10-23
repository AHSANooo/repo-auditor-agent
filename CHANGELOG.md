# Changelog

All notable changes to **DevOps Auditor Agent** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [0.1.0] — 2026-10-24

### Added

#### Core Agent
- Native ReAct (Reason + Act) tool-calling loop — zero dependency on LangChain, LangGraph, or CrewAI
- Multi-provider LLM support via `OPENAI_BASE_URL` environment variable (OpenAI, Google Gemini, DeepSeek, Groq, Ollama)
- Context-window management: lightweight message pruner removes oldest tool-result pairs when history grows large
- Configurable `MAX_ITERATIONS` (default: 20) with graceful fallback to empty report on exhaustion

#### Audit Tools (sandboxed)
- `list_files(sub_dir)` — recursive file discovery with `_SKIP_DIRS` exclusion and 500-file cap
- `read_file(path, start_line, end_line)` — bounded line-range reader with path traversal sandbox and 10 MB size guard
- `search_code(pattern, file_extension)` — case-insensitive regex search with 50-match cap and line numbers
- `git_log(max_count)` — commit history inspection with author, email, date, and message fields (capped at 50)

#### Security Pipeline
- `redactor.py` — 9-pattern regex credential scrubbing (GitHub PAT, fine-grained PAT, Actions token, AWS access key, AWS STS key, AWS secret key, PEM private keys, JWT tokens, Bearer tokens, Slack tokens, Telegram tokens, generic key=value)
- `RedactionLoggingFilter` — sanitizes all log record messages and args before emission
- `repo_manager.py` — `--depth 1 --single-branch --no-tags` shallow clone with automatic cleanup in `finally` block

#### Data Contracts
- Pydantic V2 `AuditReport`, `Violation`, `SeverityLevel`, `Category` models
- `rule_id` format validator: `CATEGORY-NNN` pattern enforced via regex
- Evidence field validator: blocks raw credential patterns from passing schema validation
- `validate_no_duplicate_rule_ids` model validator on `AuditReport`
- `summary()` method returning severity breakdown counts

#### CLI
- `python agent.py --repo <url> --output <path>` — assignment-specified invocation
- `devops-auditor` installed entrypoint via `pyproject.toml` scripts
- `--model` and `--max-iterations` flags for runtime overrides
- Atomic JSON write (temp file → rename) to prevent partial output files
- Structured logging to `stderr` (stdout stays clean for piping)

#### DevOps & CI/CD
- GitHub Actions CI matrix: Ruff lint + format, Mypy strict, Pytest on Python 3.10/3.11/3.12
- GitHub Actions Security: Bandit, pip-audit, TruffleHog (scheduled weekly + on PRs)
- Multi-stage Dockerfile with non-root `auditor` user, OCI labels, and health check
- Pre-commit hooks: Ruff, Mypy, trailing whitespace, check-yaml/json/toml, detect-private-key, no-commit-to-main

#### Testing
- 122 unit tests across 7 test files — zero real API calls (all LLM interactions mocked)
- `tests/fixtures/` — 3 synthetic mini-repos:
  - `clean-repo/` — well-structured, zero violations expected
  - `vulnerable-repo/` — 9 planted violations across SEC, CI, DEP, CFG, TEST categories
  - `invalid-repo/` — minimal broken repo with COLLAB and HYGN violations
- `tests/conftest.py` — shared `clean_repo_path`, `vulnerable_repo_path`, `invalid_repo_path` fixtures
- `tests/test_fixtures.py` — 20 fixture-based integration tests verifying tool detection accuracy

#### Documentation
- `README.md` — 7 badges, ASCII ReAct architecture diagram, quickstart, Docker usage, multi-provider table, sample output
- `CONTRIBUTING.md` — branch strategy, Conventional Commits convention, PR checklist
- `SECURITY.md` — responsible disclosure policy with response timelines
- `CODE_OF_CONDUCT.md` — Contributor Covenant v2.1
- `.github/ISSUE_TEMPLATE/` — bug report and feature request templates
- `.github/pull_request_template.md` — PR checklist with security section
- `sample_report.json` — 10-violation verified example output
- `CHANGELOG.md` — this file

[0.1.0]: https://github.com/AHSANooo/repo-auditor-agent/releases/tag/v0.1.0
