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
from dotenv import load_dotenv

# Ensure src is on sys.path
sys.path.insert(0, str(Path(__file__).parent / "src"))

from devops_auditor.agent import DevOpsAuditAgent
from devops_auditor.repo_manager import clone_repository
from devops_auditor.tools import InspectionTools

load_dotenv()

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

with st.sidebar:
    st.header("⚙️ Configuration")
    api_key = st.text_input(
        "Gemini / OpenAI API Key",
        value=os.environ.get("OPENAI_API_KEY", ""),
        type="password",
        help="Leave blank if OPENAI_API_KEY is already set in deployment secrets.",
    )
    model = st.selectbox(
        "Audit Model",
        options=["gemini-3.5-flash-lite", "gpt-4o-mini", "qwen/qwen3.8-27b"],
        index=0,
    )
    max_iters = st.slider("Max ReAct Iterations", min_value=5, max_value=30, value=15)

repo_url = st.text_input(
    "Public GitHub Repository URL",
    placeholder="https://github.com/pallets/flask",
)

if st.button("🚀 Start Audit", type="primary", use_container_width=True):
    if not repo_url.strip():
        st.error("Please provide a valid GitHub repository URL.")
    else:
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
            if "gemini" in model:
                os.environ["OPENAI_BASE_URL"] = (
                    "https://generativelanguage.googleapis.com/v1beta/openai/"
                )

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
            st.error(f"Error during audit: {exc}")
