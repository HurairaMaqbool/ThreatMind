"""Shared Streamlit UI theme and components for AutoThreat dashboard."""
import streamlit as st

THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');

html, body, [class*="css"] {
    font-family: 'Inter', sans-serif;
}

.stApp {
    background: linear-gradient(160deg, #070b14 0%, #0d1526 45%, #0a1018 100%);
}

.block-container {
    padding-top: 1.5rem;
    max-width: 1400px;
}

/* Sidebar */
section[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #0a1220 0%, #0d1a2d 100%);
    border-right: 1px solid rgba(0, 212, 170, 0.15);
}
section[data-testid="stSidebar"] .stRadio label {
    padding: 0.55rem 0.75rem;
    border-radius: 8px;
    transition: background 0.2s;
}
section[data-testid="stSidebar"] .stRadio label:hover {
    background: rgba(0, 212, 170, 0.08);
}

/* Header bar */
.at-header {
    background: linear-gradient(90deg, rgba(0,212,170,0.12) 0%, rgba(59,130,246,0.08) 100%);
    border: 1px solid rgba(0, 212, 170, 0.2);
    border-radius: 12px;
    padding: 1rem 1.5rem;
    margin-bottom: 1.5rem;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 0.75rem;
}
.at-logo {
    font-size: 1.35rem;
    font-weight: 700;
    color: #00d4aa;
    letter-spacing: -0.02em;
}
.at-logo span { color: #94a3b8; font-weight: 400; font-size: 0.85rem; margin-left: 0.5rem; }
.at-status-pill {
    display: inline-block;
    padding: 0.3rem 0.85rem;
    border-radius: 999px;
    font-size: 0.78rem;
    font-weight: 600;
    letter-spacing: 0.04em;
    text-transform: uppercase;
}
.at-status-idle { background: rgba(0,212,170,0.15); color: #00d4aa; border: 1px solid rgba(0,212,170,0.35); }
.at-status-running { background: rgba(251,191,36,0.15); color: #fbbf24; border: 1px solid rgba(251,191,36,0.35); }
.at-status-degraded { background: rgba(251,146,60,0.15); color: #fb923c; border: 1px solid rgba(251,146,60,0.35); }
.at-status-error { background: rgba(239,68,68,0.15); color: #ef4444; border: 1px solid rgba(239,68,68,0.35); }
.at-status-unknown { background: rgba(148,163,184,0.15); color: #94a3b8; border: 1px solid rgba(148,163,184,0.35); }

/* Metric cards */
.at-metric-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr)); gap: 1rem; margin-bottom: 1.5rem; }
.at-metric-card {
    background: rgba(15, 23, 42, 0.7);
    border: 1px solid rgba(51, 65, 85, 0.6);
    border-radius: 12px;
    padding: 1.1rem 1.25rem;
    backdrop-filter: blur(8px);
    transition: border-color 0.2s, transform 0.2s;
}
.at-metric-card:hover {
    border-color: rgba(0, 212, 170, 0.4);
    transform: translateY(-2px);
}
.at-metric-label { font-size: 0.72rem; color: #64748b; text-transform: uppercase; letter-spacing: 0.08em; font-weight: 600; }
.at-metric-value { font-size: 1.75rem; font-weight: 700; color: #f1f5f9; margin-top: 0.25rem; }
.at-metric-sub { font-size: 0.75rem; color: #475569; margin-top: 0.15rem; }

/* Page title */
.at-page-title {
    font-size: 1.6rem;
    font-weight: 700;
    color: #f1f5f9;
    margin-bottom: 0.25rem;
    display: flex;
    align-items: center;
    gap: 0.5rem;
}
.at-page-subtitle { color: #64748b; font-size: 0.9rem; margin-bottom: 1.25rem; }

/* Threat cards */
.at-threat-card {
    background: rgba(15, 23, 42, 0.6);
    border: 1px solid rgba(51, 65, 85, 0.5);
    border-radius: 10px;
    padding: 0.9rem 1.1rem;
    margin-bottom: 0.6rem;
    transition: border-color 0.2s;
}
.at-threat-card:hover { border-color: rgba(0, 212, 170, 0.35); }

/* Severity badges */
.at-sev { display: inline-block; padding: 0.2rem 0.6rem; border-radius: 6px; font-size: 0.72rem; font-weight: 700; letter-spacing: 0.05em; }
.at-sev-CRITICAL { background: rgba(239,68,68,0.2); color: #f87171; }
.at-sev-HIGH { background: rgba(251,146,60,0.2); color: #fb923c; }
.at-sev-MEDIUM { background: rgba(251,191,36,0.2); color: #fbbf24; }
.at-sev-LOW { background: rgba(0,212,170,0.2); color: #00d4aa; }

/* Section panel */
.at-panel {
    background: rgba(15, 23, 42, 0.5);
    border: 1px solid rgba(51, 65, 85, 0.45);
    border-radius: 12px;
    padding: 1.25rem;
    margin-bottom: 1rem;
}
.at-panel-title { font-size: 0.95rem; font-weight: 600; color: #cbd5e1; margin-bottom: 0.75rem; }

/* Code blocks */
.stCodeBlock, pre { font-family: 'JetBrains Mono', monospace !important; }

/* Hide Streamlit branding footer */
footer { visibility: hidden; }
</style>
"""

SEVERITY_COLORS = {
    "CRITICAL": "#ef4444",
    "HIGH": "#fb923c",
    "MEDIUM": "#fbbf24",
    "LOW": "#00d4aa",
}

NAV_ICONS = {
    "Live Feed": "📡",
    "Threat Detail": "🎯",
    "KQL Library": "📚",
    "Queries": "🔍",
    "Statistics": "📊",
}


def inject_theme():
    st.markdown(THEME_CSS, unsafe_allow_html=True)


def render_header(pipeline_status: str, last_crawl_display: str):
    status_class = {
        "idle": "at-status-idle",
        "running": "at-status-running",
        "degraded": "at-status-degraded",
        "error": "at-status-error",
    }.get(pipeline_status, "at-status-unknown")
    status_label = pipeline_status.upper() if pipeline_status != "unknown" else "STANDBY"

    st.markdown(
        f"""
        <div class="at-header">
            <div>
                <div class="at-logo">AutoThreat <span>v3.0 · Autonomous CTI</span></div>
                <div style="color:#64748b;font-size:0.8rem;margin-top:0.2rem;">Last crawl: {last_crawl_display}</div>
            </div>
            <div class="at-status-pill {status_class}">{status_label}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def page_header(title: str, subtitle: str = "", icon: str = ""):
    st.markdown(
        f'<div class="at-page-title">{icon} {title}</div>'
        f'<div class="at-page-subtitle">{subtitle}</div>',
        unsafe_allow_html=True,
    )


def metric_row(metrics: list[tuple[str, str, str]]):
    """Render a row of metric cards. Each tuple: (label, value, sub)."""
    cards = ""
    for label, value, sub in metrics:
        cards += f"""
        <div class="at-metric-card">
            <div class="at-metric-label">{label}</div>
            <div class="at-metric-value">{value}</div>
            <div class="at-metric-sub">{sub}</div>
        </div>"""
    st.markdown(f'<div class="at-metric-grid">{cards}</div>', unsafe_allow_html=True)


def severity_badge(severity: str) -> str:
    sev = severity.upper() if severity else "UNKNOWN"
    cls = f"at-sev at-sev-{sev}" if sev in SEVERITY_COLORS else "at-sev"
    return f'<span class="{cls}">{sev}</span>'


def threat_card_html(severity: str, title: str, meta: str) -> str:
    return f"""
    <div class="at-threat-card">
        {severity_badge(severity)}
        <span style="color:#f1f5f9;font-weight:600;margin-left:0.5rem;">{title}</span>
        <div style="color:#64748b;font-size:0.8rem;margin-top:0.35rem;">{meta}</div>
    </div>"""
