import streamlit as st
import pandas as pd
import sqlite3
import os
import re
import plotly.express as px
from dashboard.ui import page_header, metric_row

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "autothreat.db")
PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#94a3b8"),
)


@st.cache_data(ttl=60)
def load_queries():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    conn = sqlite3.connect(DB_PATH)
    try:
        df = pd.read_sql_query("SELECT * FROM generated_queries ORDER BY created_at DESC", conn)
        df = df[~df["threat_id"].apply(lambda x: bool(re.match(r"^threat_\d{1,2}$", str(x))))]
        return df
    except Exception:
        return pd.DataFrame()
    finally:
        conn.close()


def render():
    page_header(
        "Query Explorer",
        "Browse, filter, and export multi-platform detection queries",
        "🔍",
    )

    df = load_queries()
    if df.empty:
        st.markdown(
            '<div class="at-panel" style="text-align:center;padding:2rem;color:#64748b;">'
            "No queries yet. Pipeline will populate this view automatically.</div>",
            unsafe_allow_html=True,
        )
        return

    def derive_tier(row):
        if pd.notna(row["tier"]) and str(row["tier"]).lower() != "unknown":
            return row["tier"]
        text = str(row["query_text"]).lower()
        if any(x in text for x in ["hash", "ip", "domain"]):
            return "indicator"
        if any(x in text for x in ["registry", "file", "path", "pipe", "service"]):
            return "tool_artifact"
        return "behavioral"

    df["tier"] = df.apply(derive_tier, axis=1)

    threat_tiers = df.groupby("threat_name")["tier"].apply(list)
    behavioral_threats = sum("behavioral" in tiers for tiers in threat_tiers)
    gap_threats = len(threat_tiers) - behavioral_threats

    metric_row(
        [
            ("Total Queries", str(len(df)), "All platforms"),
            ("Platforms", str(df["platform"].nunique()), "SIEM coverage"),
            ("Behavioral", str(behavioral_threats), "High-durability detections"),
            ("Gaps", str(gap_threats), "Missing behavioral tier"),
        ]
    )

    c1, c2 = st.columns(2)
    plat_counts = df["platform"].value_counts().reset_index()
    plat_counts.columns = ["platform", "count"]
    fig1 = px.bar(plat_counts, x="platform", y="count", color="platform")
    fig1.update_layout(**PLOTLY_LAYOUT, title="Queries by Platform", showlegend=False)
    c1.plotly_chart(fig1, use_container_width=True)

    tier_counts = df["tier"].value_counts().reset_index()
    tier_counts.columns = ["tier", "count"]
    fig2 = px.bar(
        tier_counts,
        x="tier",
        y="count",
        color="tier",
        color_discrete_map={
            "indicator": "#ef4444",
            "tool_artifact": "#fbbf24",
            "behavioral": "#00d4aa",
        },
    )
    fig2.update_layout(**PLOTLY_LAYOUT, title="Queries by Pyramid Tier", showlegend=False)
    c2.plotly_chart(fig2, use_container_width=True)

    st.markdown('<div class="at-panel-title">FILTER & SEARCH</div>', unsafe_allow_html=True)
    f1, f2, f3, f4, f5 = st.columns(5)
    plats = f1.multiselect("Platform", df["platform"].unique())
    sevs = f2.multiselect("Severity", df["severity"].unique())
    tiers = f3.multiselect("Tier", df["tier"].unique())
    tech_search = f4.text_input("Technique")
    threat_search = f5.text_input("Threat")

    filtered_df = df.copy()
    if plats:
        filtered_df = filtered_df[filtered_df["platform"].isin(plats)]
    if sevs:
        filtered_df = filtered_df[filtered_df["severity"].isin(sevs)]
    if tiers:
        filtered_df = filtered_df[filtered_df["tier"].isin(tiers)]
    if tech_search:
        filtered_df = filtered_df[filtered_df["technique"].str.contains(tech_search, case=False, na=False)]
    if threat_search:
        filtered_df = filtered_df[filtered_df["threat_name"].str.contains(threat_search, case=False, na=False)]

    st.caption(f"Showing {len(filtered_df)} of {len(df)} queries")

    PAGE_SIZE = 25
    if "query_page" not in st.session_state:
        st.session_state.query_page = 0
    total_pages = max(1, (len(filtered_df) - 1) // PAGE_SIZE + 1)

    if total_pages > 1:
        p1, p2, p3 = st.columns([1, 8, 1])
        if p1.button("← Prev", use_container_width=True) and st.session_state.query_page > 0:
            st.session_state.query_page -= 1
            st.rerun()
        p2.markdown(
            f"<div style='text-align:center;color:#64748b;padding-top:0.4rem;'>"
            f"Page {st.session_state.query_page + 1} / {total_pages}</div>",
            unsafe_allow_html=True,
        )
        if p3.button("Next →", use_container_width=True) and st.session_state.query_page < total_pages - 1:
            st.session_state.query_page += 1
            st.rerun()

    page_df = filtered_df.iloc[
        st.session_state.query_page * PAGE_SIZE : st.session_state.query_page * PAGE_SIZE + PAGE_SIZE
    ]

    tier_colors = {"indicator": "#ef4444", "tool_artifact": "#fbbf24", "behavioral": "#00d4aa"}
    for _, row in page_df.iterrows():
        tc = tier_colors.get(row["tier"], "#94a3b8")
        with st.expander(f"{row['threat_name'][:45]} · {row['platform']} · {row['technique']}"):
            st.markdown(
                f"**Tier:** <span style='color:{tc}'>{row['tier']}</span> · **Severity:** {row['severity']}",
                unsafe_allow_html=True,
            )
            lang_map = {
                "sentinel": "kusto",
                "splunk": "sql",
                "qradar": "sql",
                "elastic": "sql",
                "wazuh": "xml",
            }
            st.code(row["query_text"], language=lang_map.get(row["platform"], "text"))
            ext = ".kql" if row["platform"] == "sentinel" else ".spl" if row["platform"] == "splunk" else ".txt"
            st.download_button(
                "Download",
                data=row["query_text"],
                file_name=f"{row['angle_id']}_{row['platform']}{ext}",
                key=f"dl_{row['id']}",
            )
