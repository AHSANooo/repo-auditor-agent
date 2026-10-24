"""
Streamlit Web Dashboard for DevOps Repository Auditor Agent.

Run locally:
    streamlit run web_app.py

Deploy for free:
    Streamlit Community Cloud (https://share.streamlit.io)
"""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path

import streamlit as st

# Ensure src is on sys.path
sys.path.insert(0, str(Path(__file__).parent / "src"))

try:
    from dotenv import load_dotenv

    load_dotenv()
except ImportError:
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
except Exception:
    pass

if not default_api_key and os.environ.get("OPENAI_API_KEY"):
    default_api_key = os.environ.get("OPENAI_API_KEY", "").strip()
if os.environ.get("OPENAI_BASE_URL"):
    default_base_url = os.environ.get("OPENAI_BASE_URL", "").strip()
if os.environ.get("AUDIT_MODEL"):
    default_model = os.environ.get("AUDIT_MODEL", "").strip()

# ── Sidebar ───────────────────────────────────────────────────────────────────
with st.sidebar:
    st.header("⚙️ Configuration")

    if default_api_key:
        st.success("🔒 Default Gemini API Key configured in Secrets")
        override_key = st.text_input(
            "Session Gemini API Key (Override)",
            value="",
            type="password",
            placeholder="Enter key to override if default hits limit",
            help="If the shared default API key hits rate limits, provide your own Gemini API key for this session.",
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
        help="Locked to Gemini 3.5 Flash Lite for optimal speed, token efficiency, and quota management.",
    )
    model = default_model

    max_iters = st.slider("Max ReAct Iterations", min_value=5, max_value=30, value=15)

repo_url = st.text_input(
    "Public GitHub Repository URL",
    placeholder="https://github.com/pallets/flask",
)

if st.button("🚀 Start Audit", type="primary", use_container_width=True):
    if not repo_url.strip():
        st.error("Please provide a valid GitHub repository URL.")
    elif not active_api_key:
        st.error(
            "⚠️ No API Key found! Please configure `OPENAI_API_KEY` in Streamlit Secrets "
            "or enter an override key in the sidebar."
        )
    else:
        os.environ["OPENAI_API_KEY"] = active_api_key
        os.environ["OPENAI_BASE_URL"] = default_base_url
        os.environ["AUDIT_MODEL"] = model

        status_box = st.status("Auditing repository...", expanded=True)
        try:
            status_box.write("📥 Cloning repository (shallow clone)...")
            with clone_repository(repo_url.strip()) as repo_path:
                status_box.write("🧠 Initializing ReAct loop and inspection sandbox...")
                tools = InspectionTools(repo_path)
                agent = DevOpsAuditAgent(tools=tools, model=model, max_iterations=max_iters)
                status_box.write("🔍 Autonomous investigation in progress across 8 audit areas...")
                report = agent.run(repo_url=repo_url.strip())

            status_box.update(label="Audit Complete! ✅", state="complete", expanded=False)

            violations = report.get("violations", [])
            st.subheader(f"📊 Audit Results ({len(violations)} Violations Found)")

            col1, col2, col3, col4 = st.columns(4)
            criticals = sum(1 for v in violations if v.get("severity") == "critical")
            highs = sum(1 for v in violations if v.get("severity") == "high")
            mediums = sum(1 for v in violations if v.get("severity") == "medium")
            lows = sum(1 for v in violations if v.get("severity") == "low")

            col1.metric("Critical", criticals)
            col2.metric("High", highs)
            col3.metric("Medium", mediums)
            col4.metric("Low", lows)

            if not violations:
                st.success("🎉 No DevOps violations detected! The repository appears clean.")
            else:
                for v in violations:
                    sev = v.get("severity", "low").upper()
                    badge_color = "🔴" if sev == "CRITICAL" else "🟠" if sev == "HIGH" else "🟡"
                    with st.expander(
                        f"{badge_color} [{v.get('rule_id')}] {v.get('description')} ({sev})"
                    ):
                        st.markdown(f"**Category:** `{v.get('category')}`")
                        loc_file = v.get("file") or "N/A"
                        loc_line = v.get("line") or "N/A"
                        st.markdown(f"**Location:** `{loc_file}` (Line {loc_line})")
                        st.markdown(f"**Evidence:**\n```\n{v.get('evidence')}\n```")
                        st.markdown(f"**Actionable Recommendation:**\n{v.get('recommendation')}")

            # Download report JSON
            report_json = json.dumps(report, indent=2)
            st.download_button(
                label="💾 Download Audit Report (JSON)",
                data=report_json,
                file_name="audit_report.json",
                mime="application/json",
            )

        except Exception as exc:
            status_box.update(label="Audit Failed ❌", state="error")
            err_msg = str(exc)
            if any(
                k in err_msg.lower()
                for k in ["rate limit", "429", "resource_exhausted", "quota", "too many requests"]
            ):
                st.error(
                    "⚠️ **Gemini API Quota / Rate Limit Exceeded**\n\n"
                    "The shared default API key has reached its request quota. "
                    "Please provide an alternative Gemini API Key in the sidebar under "
                    "**'Session Gemini API Key (Override)'** to resume auditing."
                )
            else:
                st.error(f"Error during audit: {exc}")
