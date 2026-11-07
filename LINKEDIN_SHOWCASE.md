# 💼 LinkedIn Profile & Post Assets

---

## 📌 Projects Section Entry (LinkedIn Profile)

Add this entry under your **Projects** section on LinkedIn:

**Autonomous DevOps Repository Auditing Agent**  
*Associated with FAST-NUCES / Personal Projects*  
*Link:* [https://repo-auditor-agent.streamlit.app/](https://repo-auditor-agent.streamlit.app/)

* Engineered an autonomous ReAct auditing agent in pure Python to inspect public GitHub repositories for CI/CD misconfigurations, exposed secrets, and dependency hygiene flaws.
* Implemented deterministic local tool dispatch (`list_files`, `read_file`, `search_code`, `git_log`) inside a sandboxed shallow-clone lifecycle with path-traversal prevention.
* Designed an evidence sanitizer using multi-pattern regex redaction to prevent secret leakage in agent observation loops and final JSON reports.
* Enforced schema validation using Pydantic V2 to output deterministic severity ratings, line numbers, and actionable remediation advice.
* Deployed a live dashboard on Streamlit Cloud with BYOK fallbacks, token-conserving result caching, and real-time execution tracing.

**Tech stack:** Python, Gemini API, Pydantic V2, Git, Streamlit, Ruff, Pytest, Docker.

---

## 🚀 LinkedIn Post Draft

Most LLM wrappers fail silently when auditing infrastructure files because static prompts can't handle non-linear investigations.

I built an autonomous DevOps auditing agent from scratch in Python—no LangChain, no orchestration frameworks.

It accepts a public GitHub repo URL, uses a native ReAct loop to inspect files, searches for misconfigurations, and returns a structured JSON audit report.

Key technical implementation details:

1. **Native ReAct Loop**  
   The agent selects and executes tools sequentially (`list_files`, `read_file`, `search_code`, `git_log`). It investigates CI/CD workflows, lockfiles, and configs based on what it discovers rather than a fixed checklist.

2. **Sandboxed Inspection**  
   Clones targets using `git clone --depth 1` into temporary workspaces. All file read operations enforce strict path traversal checks to prevent directory escaping.

3. **Zero Secret Leakage**  
   Evidence strings are sanitized with regex scrapers before tool outputs return to context or the final payload. Real keys and tokens are never reproduced.

4. **Strict Data Contract**  
   Findings are validated through Pydantic V2 to enforce rule IDs, severity levels (critical, high, medium, low), exact line numbers, and actionable remediation steps.

Built with Python, Gemini 1.5/2.0 Flash, Pydantic, and deployed on Streamlit.

🔗 **Live tool:** [https://repo-auditor-agent.streamlit.app/](https://repo-auditor-agent.streamlit.app/)  
📂 **Codebase:** https://github.com/AHSANooo/repo-auditor-agent

