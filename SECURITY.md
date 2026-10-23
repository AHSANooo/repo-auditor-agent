# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | ✅ Active support  |

## Reporting a Vulnerability

**Please do NOT open a public GitHub issue for security vulnerabilities.**

We take security seriously. If you discover a vulnerability in **DevOps Auditor Agent**, please report it responsibly:

### Option 1 — GitHub Private Security Advisory (Preferred)

Use [GitHub's private security advisory feature](https://github.com/AHSANooo/repo-auditor-agent/security/advisories/new) to report confidentially.

### Option 2 — Direct Contact

Contact the maintainer directly via GitHub. Navigate to the [profile page](https://github.com/AHSANooo) and use the contact options available there.

## What to Include

To help us triage and fix the issue quickly, please include:

- **Description** of the vulnerability and its potential impact
- **Steps to reproduce** (minimal reproduction case if possible)
- **Affected version(s)**
- **Suggested fix** (optional but appreciated)

## Response Timeline

| Stage | Target Time |
|-------|-------------|
| Acknowledgement | Within **48 hours** |
| Initial assessment | Within **5 business days** |
| Fix or mitigation | Within **30 days** for critical issues |
| Public disclosure | Coordinated with reporter |

## Scope

In scope for this project:

- **Secret leakage** — credentials appearing in agent output or logs
- **Path traversal** — agent reading files outside the cloned repository root
- **Command injection** — untrusted repository content influencing subprocess calls
- **Dependency vulnerabilities** — CVEs in `openai`, `pydantic`, or other runtime deps

Out of scope:

- Issues in LLM provider APIs (OpenAI, Google, Groq, etc.)
- Social engineering attacks on repository maintainers
- Theoretical vulnerabilities without practical exploit paths

## Security Design

This project implements multiple defence layers described in the [Security Design section of the README](./README.md#-security-design). If you discover a bypass of any of these layers, that is definitely in scope.

## Disclosure Policy

We follow [Coordinated Vulnerability Disclosure (CVD)](https://cheatsheetseries.owasp.org/cheatsheets/Vulnerability_Disclosure_Cheat_Sheet.html). We will:

1. Work with you to understand and fix the issue
2. Credit you in the release notes (unless you prefer anonymity)
3. Publish a security advisory once a fix is available

Thank you for helping keep DevOps Auditor Agent and its users safe. 🔒
