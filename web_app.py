"""
Streamlit Web Dashboard for DevOps Repository Auditor Agent.

Run locally:
    streamlit run web_app.py

Deploy for free:
    Streamlit Community Cloud (https://share.streamlit.io)
"""

from __future__ import annotations

import importlib
import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import streamlit as st

# Ensure src is on sys.path
src_path = str(Path(__file__).parent / "src")
if src_path not in sys.path:
    sys.path.insert(0, src_path)

if "devops_auditor.agent" in sys.modules:
    try:
        import devops_auditor.agent

        importlib.reload(devops_auditor.agent)
    except Exception:  # noqa: S110, BLE001
        pass

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
    pass

try:
    from google.api_core.exceptions import ResourceExhausted
except ImportError:

    class ResourceExhausted(Exception):  # type: ignore[no-redef] # noqa: N818
        pass


try:
    from openai import RateLimitError
except ImportError:

    class RateLimitError(Exception):  # type: ignore[no-redef] # noqa: N818
        pass


try:
    from devops_auditor.agent import DevOpsAuditAgent
    from devops_auditor.repo_manager import clone_repository
    from devops_auditor.tools import InspectionTools
except ImportError as err:
    st.error(
        f"⚠️ Missing required dependencies: `{err}`\n\n"
        "Please install the dependencies in your active environment:\n"
        "```bash\n"
        "pip install -r requirements.txt\n"
        "```"
    )
    st.stop()

st.set_page_config(
    page_title="DevOps Auditor Agent",
    page_icon="🔍",
    layout="wide",
)

st.title("🔍 Autonomous DevOps Repository Auditor")
st.markdown(
    "Audits any public GitHub repository for **security leaks, CI/CD flaws, dependency "
    "vulnerabilities, and infrastructure hygiene** using an autonomous ReAct agent loop."
)

# ── Load default configuration from Streamlit Secrets or Environment ───────────
default_api_key = ""
default_base_url = "https://generativelanguage.googleapis.com/v1beta/openai/"
default_model = "gemini-3.5-flash-lite"

try:
    if hasattr(st, "secrets"):
        if "OPENAI_API_KEY" in st.secrets:
            default_api_key = str(st.secrets["OPENAI_API_KEY"]).strip()
        if "OPENAI_BASE_URL" in st.secrets:
            default_base_url = str(st.secrets["OPENAI_BASE_URL"]).strip()
        if "AUDIT_MODEL" in st.secrets:
            default_model = str(st.secrets["AUDIT_MODEL"]).strip()
except Exception:  # noqa: S110, BLE001
    pass

if not default_api_key and os.environ.get("OPENAI_API_KEY"):
    default_api_key = os.environ.get("OPENAI_API_KEY", "").strip()
if os.environ.get("OPENAI_BASE_URL"):
    default_base_url = os.environ.get("OPENAI_BASE_URL", "").strip()
if os.environ.get("AUDIT_MODEL"):
    default_model = os.environ.get("AUDIT_MODEL", "").strip()


def get_remote_head_commit(repo_url: str, timeout: int = 6) -> str:
    """Fetch the latest commit SHA from the remote git repository without a full clone."""
    try:
        res = subprocess.run(
            ["git", "ls-remote", repo_url.strip(), "HEAD"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        if res.returncode == 0 and res.stdout.strip():
            parts = res.stdout.strip().split()
            if parts:
                return parts[0]
    except Exception:  # noqa: S110, BLE001
        pass
    return ""


@st.cache_data(ttl=86400, show_spinner=False)
def run_cached_audit(
    repo_url: str,
    model_name: str,
    max_iter: int,
    api_key: str,
    commit_hash: str = "",
    _step_cb: Any = None,
) -> dict[str, Any]:
    """
    Execute repository audit with Streamlit native caching by repo URL and commit hash.

    Identical targets hit cache and avoid LLM invocation within 24h.
    """
    os.environ["OPENAI_API_KEY"] = api_key
    os.environ["OPENAI_BASE_URL"] = default_base_url
    os.environ["AUDIT_MODEL"] = model_name

    with clone_repository(repo_url.strip()) as repo_path:
        tools = InspectionTools(repo_path)
        try:
            agent = DevOpsAuditAgent(
                tools=tools,
                model=model_name,
                max_iterations=max_iter,
                step_callback=_step_cb,
            )
        except TypeError:
            agent = DevOpsAuditAgent(
                tools=tools,
                model=model_name,
                max_iterations=max_iter,
            )
            agent.step_callback = _step_cb

        try:
            return agent.run(repo_url=repo_url.strip(), step_callback=_step_cb)
        except TypeError:
            return agent.run(repo_url=repo_url.strip())


# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")

    override_key = ""
    if default_api_key:
        st.success("🔒 Default Gemini API Key configured in Secrets")
        override_key = st.text_input(
            "Session Gemini API Key (Override)",
            value="",
            type="password",
            placeholder="Enter key to override if default hits limit",
            help=(
                "If the shared default API key hits rate limits, "
                "provide your own Gemini API key for this session."
            ),
        )
        active_api_key = override_key.strip() if override_key.strip() else default_api_key
    else:
        active_api_key = st.text_input(
            "Gemini API Key",
            value="",
            type="password",
            placeholder="Enter your Gemini API key...",
            help="Provide your Google Gemini API key.",
        ).strip()

    # Lock model to Gemini 3.5 Flash Lite
    st.text_input(
        "Audit Model",
        value=default_model,
        disabled=True,
        help=(
            "Locked to Gemini 3.5 Flash Lite for optimal speed, "
            "token efficiency, and quota management."
        ),
    )
    model = default_model

    # Clamp default iterations for public runs:
    # Default is 8 on community quota. Unlock up to 15 only if user supplies their own key.
    user_supplied_key = bool(override_key.strip()) if default_api_key else bool(active_api_key)
    if user_supplied_key:
        max_iters = st.slider(
            "Max ReAct Iterations",
            min_value=3,
            max_value=15,
            value=10,
            help="Custom Gemini API Key detected: Unlocked up to 15 iterations.",
        )
    else:
        max_iters = st.slider(
            "Max ReAct Iterations",
            min_value=3,
            max_value=8,
            value=8,
            help=(
                "Clamped to 8 iterations on community quota. "
                "Supply your own API key to unlock up to 15."
            ),
        )

    st.divider()
    st.markdown("### 🛡️ Safe Sandbox Notice")
    notice = (
        "`Clones with --depth 1, path traversal validation enabled, zero code execution on server`"
    )
    st.caption(notice)


# ── Main UI ───────────────────────────────────────────────────────────────────
repo_url = st.text_input(
    "Public GitHub Repository URL",
    placeholder="https://github.com/pallets/flask",
)

st.markdown("##### ⚡ Instant Sample Audits (Zero API tokens consumed):")
col_demo1, col_demo2, col_clear = st.columns([1.2, 1.2, 0.8])

with col_demo1:
    if st.button("🧪 Vulnerable Repo Demo (10 Flaws)", use_container_width=True):
        sample_path = Path(__file__).parent / "vulnerable_repo_report.json"
        if not sample_path.exists():
            sample_path = Path(__file__).parent / "sample_report.json"
        with open(sample_path, encoding="utf-8") as f:
            st.session_state["active_report"] = json.load(f)
            st.session_state["report_source"] = (
                "Pre-loaded Demo: Deliberately Vulnerable Repository (10 Flaws)"
            )
        st.rerun()

with col_demo2:
    if st.button("🌶️ Pallets / Flask Demo (Clean)", use_container_width=True):
        sample_path = Path(__file__).parent / "flask_report.json"
        with open(sample_path, encoding="utf-8") as f:
            st.session_state["active_report"] = json.load(f)
            st.session_state["report_source"] = "Pre-loaded Demo: pallets/flask"
        st.rerun()

with col_clear:
    has_report = bool(st.session_state.get("active_report"))
    if has_report and st.button("🔄 Reset View", use_container_width=True):
        st.session_state.pop("active_report", None)
        st.session_state.pop("report_source", None)
        st.rerun()

st.write("")

if st.button("🚀 Start Audit", type="primary", use_container_width=True):
    if not repo_url.strip():
        st.error("Please provide a valid GitHub repository URL.")
    elif not active_api_key:
        st.error(
            "⚠️ No API Key found! Please configure `OPENAI_API_KEY` in Streamlit Secrets "
            "or enter an override key in the sidebar."
        )
    else:
        status_box = st.status("Auditing repository...", expanded=True)
        try:
            status_box.write("📥 Checking repository commit SHA...")
            commit_sha = get_remote_head_commit(repo_url.strip())
            if commit_sha:
                status_box.write(f"📌 Target Commit SHA: `{commit_sha[:8]}`")
            status_box.write("🧠 Initializing ReAct loop and inspection sandbox...")

            def trace_step(fn_name: str, fn_args: dict[str, Any]) -> None:
                if fn_name == "list_files":
                    sub = fn_args.get("sub_dir")
                    if sub:
                        status_box.write(f"Executing: list_files(sub_dir='{sub}')")
                    else:
                        status_box.write("Executing: list_files()")
                elif fn_name == "read_file":
                    p = fn_args.get("file_path") or fn_args.get("path") or ""
                    status_box.write(f"Inspecting: {p}")
                elif fn_name == "search_code":
                    pat = str(fn_args.get("pattern", ""))
                    cred_words = ["secret", "key", "token", "password", "aws", "cred"]
                    if any(w in pat.lower() for w in cred_words):
                        status_box.write("Running regex pattern search for credentials...")
                    else:
                        snippet = (pat[:35] + "...") if len(pat) > 35 else pat
                        status_box.write(f"Running regex pattern search: `{snippet}`")
                elif fn_name == "git_log":
                    status_box.write("Inspecting git commit history: git_log()")
                elif fn_name == "submit_audit_report":
                    status_box.write("Validating findings against Pydantic V2 contract...")
                else:
                    status_box.write(f"Executing: {fn_name}()")

            report = run_cached_audit(
                repo_url=repo_url.strip(),
                model_name=model,
                max_iter=max_iters,
                api_key=active_api_key,
                commit_hash=commit_sha,
                _step_cb=trace_step,
            )

            status_box.update(label="Audit Complete! ✅", state="complete", expanded=False)
            st.session_state["active_report"] = report
            target_info = f"{repo_url.strip()}" + (f" ({commit_sha[:8]})" if commit_sha else "")
            st.session_state["report_source"] = f"Live Audit: {target_info}"

        except ResourceExhausted:
            status_box.update(label="API Quota Exhausted ⚠️", state="error", expanded=True)
            st.error(
                "Default community API quota exhausted for today. "
                "Get a free Gemini API key in 10 seconds at aistudio.google.com/apikey "
                "and paste it into the sidebar."
            )
            st.stop()
        except RateLimitError:
            status_box.update(label="API Quota Exhausted ⚠️", state="error", expanded=True)
            st.error(
                "Default community API quota exhausted for today. "
                "Get a free Gemini API key in 10 seconds at aistudio.google.com/apikey "
                "and paste it into the sidebar."
            )
            st.stop()
        except Exception as exc:
            err_msg = str(exc)
            if any(
                k in err_msg.lower()
                for k in ["rate limit", "429", "resource_exhausted", "quota", "too many requests"]
            ):
                status_box.update(label="API Quota Exhausted ⚠️", state="error", expanded=True)
                st.error(
                    "Default community API quota exhausted for today. "
                    "Get a free Gemini API key in 10 seconds at aistudio.google.com/apikey "
                    "and paste it into the sidebar."
                )
                st.stop()
            else:
                status_box.update(label="Audit Failed ❌", state="error")
                st.error(f"Error during audit: {exc}")


# ── Render Dual-View Output ───────────────────────────────────────────────────
if "active_report" in st.session_state and st.session_state["active_report"]:
    report = st.session_state["active_report"]
    violations = report.get("violations", [])
    report_source = st.session_state.get("report_source", report.get("repository", "Audit"))

    st.markdown("---")
    st.subheader(f"📊 Audit Results: {report_source}")

    tab_visual, tab_raw = st.tabs(["📊 Visual Report", "📄 Raw Contract"])

    with tab_visual:
        col1, col2, col3, col4 = st.columns(4)
        criticals = sum(1 for v in violations if v.get("severity") == "critical")
        highs = sum(1 for v in violations if v.get("severity") == "high")
        mediums = sum(1 for v in violations if v.get("severity") == "medium")
        lows = sum(1 for v in violations if v.get("severity") == "low")

        col1.metric("Critical 🔴", criticals)
        col2.metric("High 🟠", highs)
        col3.metric("Medium 🟡", mediums)
        col4.metric("Low 🔵", lows)

        total_findings = len(violations)
        st.markdown(
            f"**Total Findings:** `{total_findings}` violation(s) detected "
            "across 9 DevOps audit categories."
        )

        if not violations:
            st.success("🎉 No DevOps violations detected! The repository appears clean.")
        else:
            for v in violations:
                sev = str(v.get("severity", "low")).upper()
                if sev == "CRITICAL":
                    badge = "🔴"
                elif sev == "HIGH":
                    badge = "🟠"
                elif sev == "MEDIUM":
                    badge = "🟡"
                else:
                    badge = "🔵"

                exp_title = f"{badge} [{v.get('rule_id')}] {v.get('description')} ({sev})"
                with st.expander(exp_title, expanded=(sev in ["CRITICAL", "HIGH"])):
                    st.markdown(
                        f"**Rule ID:** `{v.get('rule_id')}` | "
                        f"**Category:** `{v.get('category')}` | "
                        f"**Severity:** `{sev}`"
                    )
                    loc_file = v.get("file") or "Repository root / structure"
                    loc_line = f"Line {v.get('line')}" if v.get("line") is not None else "N/A"
                    st.markdown(f"**Location:** `{loc_file}` ({loc_line})")
                    st.markdown("**Evidence:**")
                    st.code(v.get("evidence", "No evidence recorded"), language="text")
                    st.markdown(f"**Actionable Recommendation:**\n{v.get('recommendation')}")

    with tab_raw:
        st.markdown("Validated Pydantic V2 Schema Output:")
        report_json_str = json.dumps(report, indent=2)
        st.code(report_json_str, language="json")

        st.download_button(
            label="Download report.json",
            data=report_json_str,
            file_name="report.json",
            mime="application/json",
        )
