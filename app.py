"""Business Intelligence Agent - Human-Centered Streamlit Interface.

Orchestrates deterministic analytics, local Ollama reasoning, audit persistence,
verified-result caching, secure chart plotting, and PDF executive reports.
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

import streamlit as st

from ui.components import (
    render_chart_artifact,
    render_clarification_card,
    render_context_strip,
    render_direct_answer,
    render_error_card,
    render_evidence_section,
    render_header,
    render_kpi_cards,
    render_provenance_section,
    render_report_artifact,
    render_security_blocked_card,
)
from ui.onboarding import render_sidebar
from ui.state import init_session_state
from ui.theme import apply_custom_theme

logger = logging.getLogger(__name__)

# Configure Streamlit page options
st.set_page_config(
    page_title="Business Intelligence Agent",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Apply global styling
apply_custom_theme()

# Initialize session state variables safely
init_session_state()

# Render sidebar control and inspection rail
render_sidebar(agent=st.session_state.agent)

# Render main workspace top components
render_header()
render_context_strip(active_context=st.session_state.active_context)

# Check active database context
active_context = st.session_state.active_context

if active_context is None:
    st.markdown(
        """
        <div class="bi-card" style="text-align: center; padding: 48px 24px; margin-top: 24px;">
            <div style="font-size: 40px; margin-bottom: 12px;">🗄️</div>
            <h2 style="font-size: 20px; font-weight: 600; color: #0F172A; margin-bottom: 8px;">
                No Database Selected
            </h2>
            <p style="font-size: 15px; color: #475569; max-width: 540px; margin: 0 auto 16px auto;">
                Select an existing MySQL database schema or upload a dataset in the sidebar to begin deterministic business intelligence analysis.
            </p>
            <div class="bi-metadata">
                Enterprise security policy: Analysis is strictly read-only and backed by tamper-evident audit logs.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
else:
    # Render existing conversation messages
    selected_clarification_option = None

    for msg_idx, msg in enumerate(st.session_state.messages):
        role = msg.get("role")
        if role == "user":
            with st.chat_message("user"):
                st.markdown(msg.get("content", ""))
        elif role == "assistant":
            with st.chat_message("assistant"):
                result = msg.get("result")
                if result is None:
                    st.markdown(msg.get("content", ""))
                else:
                    status = getattr(result, "status", "UNKNOWN")
                    if status == "SUCCESS":
                        # 1. Grounded direct business answer
                        if msg.get("content"):
                            render_direct_answer(msg["content"])

                        # 2. Strict KPI authority (0-4 verified scalar metrics)
                        render_kpi_cards(result, msg.get("evidence_items"))

                        # 3. Verified Charts
                        for chart in getattr(result, "chart_artifacts", []):
                            render_chart_artifact(chart)

                        # 4. Verified PDF Reports
                        for report in getattr(result, "report_artifacts", []):
                            render_report_artifact(report)

                        # 5. Verified Evidence (interactive dataframe)
                        render_evidence_section(
                            evidence_items=msg.get("evidence_items"),
                            evidence_refs=getattr(result, "evidence_refs", []),
                        )

                        # 6. Technical Provenance & Execution Audit
                        render_provenance_section(result)

                    elif status == "NEEDS_CLARIFICATION":
                        opt = render_clarification_card(result)
                        if opt is not None and msg_idx == len(st.session_state.messages) - 1:
                            selected_clarification_option = opt
                        render_provenance_section(result)

                    elif status == "SECURITY_BLOCKED":
                        render_security_blocked_card(result)
                        render_provenance_section(result)

                    else:
                        # Error / Failure
                        render_error_card(result)
                        render_provenance_section(result)

    # Empty-state analytical suggestions when conversation is empty
    if not st.session_state.messages and active_context.approved_objects:
        st.markdown("### Suggested Inquiries for Active Schema")
        sample_tables = list(active_context.approved_objects)[:3]
        cols = st.columns(len(sample_tables))
        sample_prompt = None
        for i, tbl in enumerate(sample_tables):
            with cols[i]:
                prompt_text = f"What are the total records in {tbl}?"
                if st.button(prompt_text, key=f"btn_sample_{tbl}"):
                    sample_prompt = prompt_text

    else:
        sample_prompt = None

    # Chat input control
    user_input = st.chat_input("Ask a business question about the active schema...")

    # Determine query to execute
    prompt_to_run = selected_clarification_option or sample_prompt or user_input

    # Exactly-once submission execution
    if prompt_to_run and not st.session_state.is_running:
        submission_nonce = str(uuid.uuid4())

        # Append user message
        st.session_state.messages.append({
            "role": "user",
            "content": prompt_to_run,
            "nonce": submission_nonce,
        })
        st.session_state.is_running = True

        # Render user question immediately
        with st.chat_message("user"):
            st.markdown(prompt_to_run)

        # Execute agent D.A.T.A. loop
        with st.chat_message("assistant"):
            with st.spinner("Executing D.A.T.A. analytical loop with local model reasoning..."):
                agent = st.session_state.agent
                result = agent.run(
                    question=prompt_to_run,
                    database_context=active_context,
                    session_id=st.session_state.session_id,
                    force_refresh=st.session_state.force_refresh,
                )

                evidence_items = []
                if hasattr(agent, "last_ledger") and agent.last_ledger is not None:
                    allowed_refs = set(result.evidence_refs or [])
                    evidence_items = [
                        item for item in agent.last_ledger.all_items()
                        if getattr(item, "evidence_id", None) in allowed_refs
                    ]

                st.session_state.messages.append({
                    "role": "assistant",
                    "content": result.answer or "",
                    "result": result,
                    "evidence_items": evidence_items,
                    "nonce": submission_nonce,
                })

                # Adopt authoritative session_id returned by Agent
                if result and getattr(result, "session_id", None):
                    st.session_state.session_id = result.session_id

                st.session_state.last_executed_nonce = submission_nonce
                st.session_state.is_running = False

        st.rerun()
