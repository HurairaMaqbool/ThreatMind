import streamlit as st
import os
import sys
from dotenv import load_dotenv

load_dotenv()

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from utils.system_status import read_status
from dashboard.ui import inject_theme, render_header, NAV_ICONS

st.set_page_config(
    page_title="ThreatMind | SOC Command Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_theme()

if "current_page" not in st.session_state:
    st.session_state.current_page = "Live Feed"
if "selected_threat_id" not in st.session_state:
    st.session_state.selected_threat_id = None

status = read_status()
pipeline_status = status.get("pipeline_status", "unknown")
last_crawl = status.get("last_crawl_at")
last_crawl_display = (
    last_crawl[:19].replace("T", " ") if last_crawl else "Waiting for first crawl..."
)

render_header(pipeline_status, last_crawl_display)

# ── Sidebar ──────────────────────────────────────────────────────────────────
with st.sidebar:
    st.markdown(
        """
        <div style="text-align:center;padding:1rem 0 1.5rem 0;">
            <div style="font-size:2.5rem;">🛡️</div>
            <div style="font-size:1.1rem;font-weight:700;color:#00d4aa;">ThreatMind</div>
            <div style="font-size:0.75rem;color:#64748b;margin-top:0.2rem;">Autonomous Threat Intelligence</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


    st.markdown('<div class="at-panel-title">NAVIGATION</div>', unsafe_allow_html=True)

    pages = ["Live Feed", "Threat Detail", "KQL Library", "Queries", "Statistics"]

    def nav_changed():
        st.session_state.current_page = st.session_state.nav_radio

    st.radio(
        "Navigation",
        pages,
        key="nav_radio",
        index=pages.index(st.session_state.current_page),
        on_change=nav_changed,
        format_func=lambda p: f"{NAV_ICONS.get(p, '•')}  {p}",
        label_visibility="collapsed",
    )

    st.markdown("---")
    stats = status.get("last_crawl_stats", {})
    st.markdown(
        f"""
        <div class="at-panel" style="padding:0.9rem;">
            <div class="at-panel-title">LAST CYCLE</div>
            <div style="font-size:0.8rem;color:#94a3b8;line-height:1.8;">
                Processed: <b style="color:#e2e8f0;">{stats.get('processed', '—')}</b><br>
                Huntable: <b style="color:#00d4aa;">{stats.get('huntable', '—')}</b><br>
                Alerts: <b style="color:#fbbf24;">{stats.get('alerts_sent', '—')}</b><br>
                Errors: <b style="color:#ef4444;">{stats.get('errors', '—')}</b>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    if st.button("↻  Refresh Data", use_container_width=True):
        st.cache_data.clear()
        st.rerun()

# ── Page routing ─────────────────────────────────────────────────────────────
page = st.session_state.current_page

if page == "Live Feed":
    import dashboard.page_live_feed as p_live_feed
    p_live_feed.render()
elif page == "Threat Detail":
    import dashboard.page_threat_detail as p_threat_detail
    p_threat_detail.render()
elif page == "KQL Library":
    import dashboard.page_kql_library as p_kql_library
    p_kql_library.render()
elif page == "Queries":
    import dashboard.page_queries as p_queries
    p_queries.render()
elif page == "Statistics":
    import dashboard.page_statistics as p_statistics
    p_statistics.render()
