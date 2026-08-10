import streamlit as st
import pandas as pd
import sqlite3
import os
import re
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "autothreat.db")
MOCK_RE = re.compile(r"^threat_\d{1,2}$")

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
from dashboard.ui import page_header, metric_row, severity_badge

TIER_COLORS = {
    "behavioral": "#00d4aa",
    "tool_artifact": "#fbbf24",
    "network_artifact": "#6366f1",
    "indicator": "#ef4444",
}


def load_threat_queries(threat_id: str) -> pd.DataFrame:
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT * FROM generated_queries WHERE threat_id = ? ORDER BY created_at ASC",
            conn,
            params=(threat_id,),
        )
        conn.close()
        return df
    except Exception:
        return pd.DataFrame()


def load_all_threats() -> pd.DataFrame:
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM generated_queries ORDER BY created_at DESC", conn)
        conn.close()
        df = df[~df["threat_id"].apply(lambda x: bool(MOCK_RE.match(str(x))))]
        return df
    except Exception:
        return pd.DataFrame()


def render():
    page_header("Threat Detail", "Deep-dive analysis with MITRE mapping and detection queries", "🎯")

    df_all = load_all_threats()
    if df_all.empty:
        st.markdown(
            '<div class="at-panel" style="text-align:center;padding:2rem;color:#64748b;">'
            "No threats processed yet. Pipeline is running — check back shortly.</div>",
            unsafe_allow_html=True,
        )
        return

    threats = (
        df_all.groupby("threat_id")
        .agg(
            threat_name=("threat_name", "first"),
            severity=("severity", "first"),
            created_at=("created_at", "first"),
        )
        .reset_index()
    )

    selected_id = st.session_state.get("selected_threat_id", threats.iloc[0]["threat_id"])
    options = {
        row["threat_id"]: f"{row['threat_name'][:55]} · {row['severity']}"
        for _, row in threats.iterrows()
    }

    chosen_id = st.selectbox(
        "Select threat campaign",
        options=list(options.keys()),
        format_func=lambda x: options[x],
        index=list(options.keys()).index(selected_id) if selected_id in options else 0,
    )

    df = load_threat_queries(chosen_id)
    if df.empty:
        st.warning("No queries found for this threat.")
        return

    threat_name = df.iloc[0]["threat_name"]
    severity = df.iloc[0]["severity"]
    created_at = str(df.iloc[0]["created_at"])[:19]
    platforms = df["platform"].nunique()

    st.markdown(
        f"""
        <div class="at-panel" style="margin-bottom:1.25rem;">
            {severity_badge(severity)}
            <span style="color:#f1f5f9;font-size:1.2rem;font-weight:700;margin-left:0.5rem;">{threat_name}</span>
            <div style="color:#64748b;font-size:0.8rem;margin-top:0.5rem;">
                ID: <code style="color:#00d4aa;">{chosen_id}</code> ·
                {platforms} platforms · Processed {created_at}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    metric_row(
        [
            ("Queries", str(len(df)), "Detection rules"),
            ("Techniques", str(df["technique"].nunique()), "MITRE ATT&CK"),
            ("Tiers", str(df["tier"].nunique()), "Pyramid of Pain"),
            ("Severity", severity, "Threat rating"),
        ]
    )

    st.markdown('<div class="at-panel-title">MITRE ATT&CK COVERAGE</div>', unsafe_allow_html=True)
    tech_df = df[df["technique"].str.strip() != ""][["technique", "tier", "angle_id", "platform"]].drop_duplicates()
    if not tech_df.empty:
        st.dataframe(
            tech_df.rename(
                columns={
                    "technique": "Technique",
                    "tier": "Tier",
                    "angle_id": "Angle",
                    "platform": "Platform",
                }
            ),
            use_container_width=True,
            hide_index=True,
        )

    st.markdown(
        f'<div class="at-panel-title" style="margin-top:1rem;">DETECTION QUERIES · {len(df)}</div>',
        unsafe_allow_html=True,
    )

    for _, row in df.iterrows():
        tier_color = TIER_COLORS.get(row["tier"], "#94a3b8")
        label = f"`{row['platform']}` · {row['angle_id']} · {row['technique']}"
        with st.expander(label):
            st.markdown(
                f"**Tier:** <span style='color:{tier_color};font-weight:600'>{row['tier']}</span>",
                unsafe_allow_html=True,
            )
            lang = "kusto" if row["platform"] == "sentinel" else "sql"
            st.code(row["query_text"], language=lang)
            ext = ".kql" if row["platform"] == "sentinel" else ".txt"
            st.download_button(
                "Download",
                data=row["query_text"],
                file_name=f"{row['angle_id']}_{row['platform']}{ext}",
                key=f"dl_detail_{row['id']}",
            )

    report_md = f"# Threat Report: {threat_name}\n\n**Severity:** {severity}\n**ID:** {chosen_id}\n**Processed:** {created_at}\n\n"
    for _, row in df.iterrows():
        report_md += f"## {row['angle_id']} ({row['platform']})\n\n```{row['query_text']}\n```\n\n"

    st.download_button(
        "Download Full Report (.md)",
        data=report_md,
        file_name=f"{chosen_id}_report.md",
        mime="text/markdown",
        use_container_width=True,
    )
