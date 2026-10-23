# Contributing to DevOps Auditor Agent

Thank you for your interest in contributing! This document outlines the guidelines for contributing to this project.

## Branch Strategy

- `main` — stable, protected branch. **No direct commits.**
- `feature/<feature-name>` — all new features
- `fix/<issue-description>` — bug fixes
- `docs/<description>` — documentation updates
- `chore/<description>` — maintenance tasks

## Commit Convention

We follow [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(scope): <description>

Types:
  feat     — new feature
  fix      — bug fix
  docs     — documentation only
  style    — formatting, no code change
  refactor — code restructuring
  test     — adding/fixing tests
  chore    — maintenance, dependency updates
  ci       — CI/CD configuration
  perf     — performance improvement
  security — security improvement
```

Examples:
```
feat(tools): add search_code file extension filter
fix(redactor): handle multiline private key blocks correctly
test(agent): add max-iterations termination test
chore(deps): update openai to 1.45.0
ci(security): add TruffleHog secret scanner workflow
```

## Development Setup

```bash
git clone https://github.com/AHSANooo/repo-auditor-agent.git
cd repo-auditor-agent
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
pre-commit install
```

## Pull Request Process

1. Branch from `main` with a descriptive name
2. Write tests for your changes
3. Ensure `pytest tests/ -v` passes
4. Ensure `ruff check .` and `ruff format --check .` pass
5. Ensure `mypy src/` passes with zero errors
6. Submit a PR with a clear description of the changes

## Code Standards

- All code must pass **Ruff** linting and formatting
- All public functions must have **docstrings**
- All new features must have **unit tests**
- Maintain **>80% test coverage**
- **No raw secrets** anywhere — use `[REDACTED]` in tests

## Security Disclosures

Please do NOT open a public GitHub issue for security vulnerabilities.
Contact the maintainer directly via GitHub private security advisories.
