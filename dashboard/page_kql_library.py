import streamlit as st
import pandas as pd
import sqlite3
import os
import re
import plotly.express as px

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "autothreat.db")
from dashboard.ui import page_header, metric_row

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#94a3b8"),
    margin=dict(l=20, r=20, t=40, b=20),
)


@st.cache_data(ttl=30)
def get_kql_library_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query(
            "SELECT id, threat_id, threat_name, angle_id, platform, technique, tier, "
            "severity, query_text, validation_score, created_at FROM generated_queries "
            "ORDER BY created_at DESC",
            conn,
        )
        conn.close()
        df = df[~df["threat_id"].apply(lambda x: bool(re.match(r"^threat_\d{1,2}$", str(x))))]
        return df
    except Exception:
        return pd.DataFrame()


def render():
    page_header(
        "Detection Library",
        "Validated multi-platform queries organized by Pyramid of Pain tier",
        "📚",
    )

    df = get_kql_library_data()
    if df.empty:
        st.markdown(
            '<div class="at-panel" style="text-align:center;padding:2rem;color:#64748b;">'
            "Library empty — run the pipeline to generate detections.</div>",
            unsafe_allow_html=True,
        )
        return

    avg_score = int(df["validation_score"].dropna().mean()) if df["validation_score"].notna().any() else 0
    metric_row(
        [
            ("Total Queries", str(len(df)), "All platforms"),
            ("Platforms", str(df["platform"].nunique()), "SIEM targets"),
            ("Threats", str(df["threat_name"].nunique()), "Campaigns covered"),
            ("Avg Score", f"{avg_score}/100", "Validation quality"),
        ]
    )

    side_col, main_col = st.columns([1, 3])

    with side_col:
        st.markdown('<div class="at-panel">', unsafe_allow_html=True)
        st.markdown('<div class="at-panel-title">FILTERS</div>', unsafe_allow_html=True)
        tier_opts = sorted(df["tier"].dropna().unique().tolist())
        sev_opts = sorted(df["severity"].dropna().unique().tolist())
        plat_opts = sorted(df["platform"].dropna().unique().tolist())

        selected_tier = st.multiselect("Pyramid Tier", tier_opts, default=tier_opts)
        selected_sev = st.multiselect("Severity", sev_opts, default=sev_opts)
        selected_plat = st.multiselect("Platform", plat_opts, default=plat_opts)
        search_tech = st.text_input("Technique")
        search_threat = st.text_input("Threat name")
        st.markdown("</div>", unsafe_allow_html=True)

    with main_col:
        filtered = df.copy()
        if selected_tier:
            filtered = filtered[filtered["tier"].isin(selected_tier)]
        if selected_sev:
            filtered = filtered[filtered["severity"].isin(selected_sev)]
        if selected_plat:
            filtered = filtered[filtered["platform"].isin(selected_plat)]
        if search_tech:
            filtered = filtered[filtered["technique"].str.contains(search_tech, case=False, na=False)]
        if search_threat:
            filtered = filtered[filtered["threat_name"].str.contains(search_threat, case=False, na=False)]

        if filtered.empty:
            st.info("No queries match the selected filters.")
            return

        c1, c2 = st.columns(2)
        color_map = {
            "behavioral": "#00d4aa",
            "tool_artifact": "#fbbf24",
            "network_artifact": "#6366f1",
            "indicator": "#ef4444",
        }

        tier_counts = filtered["tier"].value_counts().reset_index()
        tier_counts.columns = ["Tier", "Count"]
        fig_tier = px.bar(
            tier_counts,
            x="Tier",
            y="Count",
            color="Tier",
            color_discrete_map=color_map,
        )
        fig_tier.update_layout(**PLOTLY_LAYOUT, title="Queries by Pyramid Tier", showlegend=False)
        c1.plotly_chart(fig_tier, use_container_width=True)

        sev_color = {"CRITICAL": "#ef4444", "HIGH": "#fb923c", "MEDIUM": "#fbbf24", "LOW": "#00d4aa"}
        sev_counts = filtered["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        fig_sev = px.pie(
            sev_counts,
            names="Severity",
            values="Count",
            color="Severity",
            color_discrete_map=sev_color,
            hole=0.45,
        )
        fig_sev.update_layout(**PLOTLY_LAYOUT, title="Severity Distribution")
        c2.plotly_chart(fig_sev, use_container_width=True)

        st.dataframe(
            filtered[["threat_name", "platform", "technique", "tier", "severity", "validation_score", "created_at"]],
            use_container_width=True,
            hide_index=True,
        )

        for _, row in filtered.head(25).iterrows():
            tier_color = color_map.get(row["tier"], "#94a3b8")
            with st.expander(f"{row['threat_name'][:50]} · {row['platform']} · {row['technique']}"):
                st.markdown(
                    f"**Tier:** <span style='color:{tier_color}'>{row['tier']}</span> · "
                    f"**Score:** {row.get('validation_score', '—')}/100 · "
                    f"**Angle:** `{row['angle_id']}`",
                    unsafe_allow_html=True,
                )
                lang = "kusto" if row["platform"] == "sentinel" else "sql"
                st.code(row["query_text"], language=lang)
                st.download_button(
                    "Download",
                    data=row["query_text"],
                    file_name=f"{row['angle_id']}.kql",
                    key=f"dl_kql_{row['id']}",
                )
