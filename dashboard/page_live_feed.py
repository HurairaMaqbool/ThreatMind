import streamlit as st
import pandas as pd
import sqlite3
import os
import re
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "autothreat.db")
MOCK_THREAT_RE = re.compile(r"^threat_\d{1,2}$")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from utils.system_status import read_status
from dashboard.ui import page_header, metric_row, severity_badge


def load_real_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM generated_queries ORDER BY created_at DESC", conn
        )
        conn.close()
        df = df[~df["threat_id"].apply(lambda x: bool(MOCK_THREAT_RE.match(str(x))))]
        return df
    except Exception:
        return pd.DataFrame()


def render():
    page_header(
        "Live Threat Feed",
        "Real-time detections from autonomous RSS intelligence pipeline",
        "📡",
    )

    df = load_real_data()
    pipeline_status = read_status().get("pipeline_status", "unknown")
    status_sub = {
        "idle": "Pipeline online",
        "running": "Processing articles",
        "degraded": "Partial errors",
        "error": "Pipeline error",
    }.get(pipeline_status, "Status unknown")

    metric_row(
        [
            ("Threats", str(df["threat_id"].nunique() if not df.empty else 0), "Unique campaigns"),
            ("Queries", str(len(df) if not df.empty else 0), "Across all platforms"),
            ("Platforms", str(df["platform"].nunique() if not df.empty else 0), "SIEM coverage"),
            ("Pipeline", pipeline_status.upper(), status_sub),
        ]
    )

    if df.empty:
        st.markdown(
            """
            <div class="at-panel" style="text-align:center;padding:2.5rem;">
                <div style="font-size:2rem;margin-bottom:0.5rem;">⏳</div>
                <div style="color:#e2e8f0;font-weight:600;font-size:1.1rem;">Pipeline Initializing</div>
                <div style="color:#64748b;font-size:0.9rem;margin-top:0.5rem;max-width:480px;margin-left:auto;margin-right:auto;">
                    Crawling Microsoft Security Blog, Unit42, CrowdStrike, CISA and more.
                    First results typically appear within 5–15 minutes.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        st.progress(0.15, text="Awaiting first pipeline result...")
        return

    col_main, col_preview = st.columns([2, 1])

    with col_main:
        st.markdown(
            f'<div class="at-panel-title">DETECTED THREATS · {df["threat_id"].nunique()} campaigns</div>',
            unsafe_allow_html=True,
        )

        threats = (
            df.groupby("threat_id")
            .agg(
                threat_name=("threat_name", "first"),
                severity=("severity", "first"),
                platform=("platform", "nunique"),
                query_count=("id", "count"),
                created_at=("created_at", "first"),
            )
            .reset_index()
        )

        for _, row in threats.iterrows():
            c1, c2 = st.columns([5, 1])
            with c1:
                st.markdown(
                    f"""
                    <div class="at-threat-card">
                        {severity_badge(row["severity"])}
                        <span style="color:#f1f5f9;font-weight:600;margin-left:0.4rem;">
                            {row["threat_name"][:72]}
                        </span>
                        <div style="color:#64748b;font-size:0.78rem;margin-top:0.4rem;">
                            {row["platform"]} platforms · {row["query_count"]} queries · {str(row["created_at"])[:16]}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
            with c2:
                if st.button("View →", key=f"btn_{row['threat_id']}", use_container_width=True):
                    st.session_state["selected_threat_id"] = row["threat_id"]
                    st.session_state["current_page"] = "Threat Detail"
                    st.rerun()

    with col_preview:
        st.markdown('<div class="at-panel">', unsafe_allow_html=True)
        st.markdown('<div class="at-panel-title">SEVERITY BREAKDOWN</div>', unsafe_allow_html=True)
        for sev, count in df["severity"].value_counts().items():
            st.markdown(
                f"{severity_badge(sev)} <span style='color:#94a3b8;margin-left:0.5rem;'>{count} queries</span>",
                unsafe_allow_html=True,
            )

        st.markdown('<div class="at-panel-title" style="margin-top:1rem;">TOP TECHNIQUES</div>', unsafe_allow_html=True)
        if "technique" in df.columns:
            top_tech = df[df["technique"] != ""]["technique"].value_counts().head(5)
            for tech, count in top_tech.items():
                st.markdown(
                    f'<code style="color:#00d4aa;background:rgba(0,212,170,0.1);padding:0.15rem 0.4rem;border-radius:4px;">{tech}</code>'
                    f' <span style="color:#64748b;">× {count}</span>',
                    unsafe_allow_html=True,
                )
        st.markdown("</div>", unsafe_allow_html=True)
