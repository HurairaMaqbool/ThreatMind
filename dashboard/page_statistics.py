import streamlit as st
import plotly.express as px
import pandas as pd
import sqlite3
import os
import re
import datetime
import sys

DB_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "autothreat.db")
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.system_status import read_status
from dashboard.ui import page_header, metric_row

PLOTLY_LAYOUT = dict(
    paper_bgcolor="rgba(0,0,0,0)",
    plot_bgcolor="rgba(0,0,0,0)",
    font=dict(color="#94a3b8"),
)


@st.cache_data(ttl=30)
def load_real_data():
    if not os.path.exists(DB_PATH):
        return pd.DataFrame()
    try:
        conn = sqlite3.connect(DB_PATH)
        df = pd.read_sql_query("SELECT * FROM generated_queries ORDER BY created_at DESC", conn)
        conn.close()
        df = df[~df["threat_id"].apply(lambda x: bool(re.match(r"^threat_\d{1,2}$", str(x))))]
        return df
    except Exception:
        return pd.DataFrame()


def render():
    page_header("Statistics & Health", "Operational metrics, coverage analytics, and system diagnostics", "📊")

    df = load_real_data()
    status = read_status()
    pipeline_status = status.get("pipeline_status", "unknown")

    metric_row(
        [
            ("Threats", str(df["threat_id"].nunique() if not df.empty else 0), "Campaigns tracked"),
            ("Queries", str(len(df) if not df.empty else 0), "Detection rules"),
            ("Platforms", str(df["platform"].nunique() if not df.empty else 0), "SIEM targets"),
            ("Pipeline", pipeline_status.upper(), "Current state"),
        ]
    )

    if not df.empty:
        r2c1, r2c2 = st.columns(2)

        if "created_at" in df.columns:
            df["date"] = pd.to_datetime(df["created_at"], errors="coerce").dt.date
            daily = df.groupby("date").size().reset_index(name="Queries")
            fig_line = px.area(daily, x="date", y="Queries", color_discrete_sequence=["#00d4aa"])
            fig_line.update_layout(**PLOTLY_LAYOUT, title="Queries Generated Per Day")
            r2c1.plotly_chart(fig_line, use_container_width=True)

        if "technique" in df.columns:
            tech_df = (
                df[df["technique"].str.strip() != ""]["technique"].value_counts().head(10).reset_index()
            )
            tech_df.columns = ["Technique", "Count"]
            fig_bar = px.bar(tech_df, x="Technique", y="Count", color_discrete_sequence=["#6366f1"])
            fig_bar.update_layout(**PLOTLY_LAYOUT, title="Top MITRE ATT&CK Techniques")
            r2c2.plotly_chart(fig_bar, use_container_width=True)

        r3c1, r3c2 = st.columns(2)

        sev_color = {"CRITICAL": "#ef4444", "HIGH": "#fb923c", "MEDIUM": "#fbbf24", "LOW": "#00d4aa"}
        sev_df = df["severity"].value_counts().reset_index()
        sev_df.columns = ["Severity", "Count"]
        fig_sev = px.pie(
            sev_df, names="Severity", values="Count", color="Severity", color_discrete_map=sev_color, hole=0.4
        )
        fig_sev.update_layout(**PLOTLY_LAYOUT, title="Severity Distribution")
        r3c1.plotly_chart(fig_sev, use_container_width=True)

        plat_df = df["platform"].value_counts().reset_index()
        plat_df.columns = ["Platform", "Count"]
        fig_plat = px.bar(plat_df, x="Platform", y="Count", color="Platform")
        fig_plat.update_layout(**PLOTLY_LAYOUT, title="Platform Coverage", showlegend=False)
        r3c2.plotly_chart(fig_plat, use_container_width=True)
    else:
        st.markdown(
            '<div class="at-panel" style="text-align:center;padding:2rem;color:#64748b;">'
            "Statistics will appear after the first threat is processed.</div>",
            unsafe_allow_html=True,
        )

    st.markdown('<div class="at-panel-title" style="margin-top:1rem;">SYSTEM HEALTH</div>', unsafe_allow_html=True)
    hc1, hc2 = st.columns(2)
    crawl_hours = os.getenv("CRAWL_INTERVAL_HOURS", "6")
    stats = status.get("last_crawl_stats", {})

    with hc1:
        st.markdown(
            f"""
            <div class="at-panel">
                <div style="color:#94a3b8;font-size:0.85rem;line-height:2;">
                    <b style="color:#e2e8f0;">Last check</b> · {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}<br>
                    <b style="color:#e2e8f0;">Last crawl</b> · {(status.get('last_crawl_at') or 'Not yet')[:19]}<br>
                    <b style="color:#e2e8f0;">Interval</b> · Every {crawl_hours}h<br>
                    <b style="color:#e2e8f0;">SQLite</b> · {'Connected' if os.path.exists(DB_PATH) else 'Missing'}<br>
                    <b style="color:#e2e8f0;">Last cycle</b> · {stats.get('processed', 0)} processed, {stats.get('errors', 0)} errors
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    with hc2:
        try:
            import requests

            api_url = os.getenv("API_URL", "http://localhost:8000")
            resp = requests.get(f"{api_url}/health", timeout=3)
            api_ok = resp.status_code == 200
            api_data = resp.json() if api_ok else {}
            st.markdown(
                f"""
                <div class="at-panel">
                    <div class="at-panel-title">API · {api_url}</div>
                    <div style="color:{'#00d4aa' if api_ok else '#ef4444'};font-size:0.85rem;">
                        {'ONLINE' if api_ok else 'OFFLINE'} · v{api_data.get('version', '?')}
                        · Pipeline: {api_data.get('pipeline_status', '?')}
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        except Exception:
            st.markdown(
                '<div class="at-panel"><div class="at-panel-title">API</div>'
                '<div style="color:#ef4444;">OFFLINE — start API on port 8000</div></div>',
                unsafe_allow_html=True,
            )

        try:
            from memory.chromadb_client import (
                threat_reports_col,
                kql_library_col,
                processed_urls_col,
                sentinel_schema_col,
            )
            st.markdown(
                f"""
                <div class="at-panel">
                    <div class="at-panel-title">CHROMADB</div>
                    <div style="color:#94a3b8;font-size:0.85rem;line-height:2;">
                        threat_reports · <b style="color:#00d4aa;">{threat_reports_col.count()}</b><br>
                        kql_library · <b style="color:#00d4aa;">{kql_library_col.count()}</b><br>
                        processed_urls · <b style="color:#00d4aa;">{processed_urls_col.count()}</b><br>
                        sentinel_schema · <b style="color:#00d4aa;">{sentinel_schema_col.count()}</b>
                    </div>
                </div>
                """,
                unsafe_allow_html=True,
            )
        except Exception as e:
            st.warning(f"ChromaDB: {e}")

    st.markdown('<div class="at-panel-title" style="margin-top:1rem;">RECENT LOGS</div>', unsafe_allow_html=True)
    log_file = os.path.join(os.path.dirname(__file__), "..", "logs", "autothreat.log")
    if os.path.exists(log_file):
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
        level_filter = st.selectbox("Level", ["ALL", "INFO", "WARNING", "ERROR"], label_visibility="collapsed")
        filtered = [l for l in lines[-80:] if level_filter == "ALL" or f"| {level_filter}" in l]
        st.code("".join(filtered[-25:]), language="log")
    else:
        st.info("No log file found yet.")
