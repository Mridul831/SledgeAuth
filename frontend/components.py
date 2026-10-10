"""SOC Copilot UI — Ocean Theme with advanced features."""

import streamlit as st
import plotly.express as px
import pandas as pd

from api_client import (
    generate_voice_briefing,
    build_markdown_report,
    build_json_report,
    build_pdf_report,
)

SEVERITY_COLORS = {
    "Low": "#10b981",
    "Medium": "#f59e0b",
    "High": "#f97316",
    "Critical": "#dc2626",
}


# ============================================================
# MITRE ATT&CK MAPPING DATA
# ============================================================

MITRE_MAPPING = {
    "SSH_BRUTE_FORCE": {
        "technique_id": "T1110.001",
        "technique_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/001/",
    },
    "PRIVILEGED_ACTIVITY": {
        "technique_id": "T1548.003",
        "technique_name": "Abuse Elevation Control: Sudo and Sudo Caching",
        "tactic": "Privilege Escalation",
        "url": "https://attack.mitre.org/techniques/T1548/003/",
    },
    "LOGIN_FAILURE": {
        "technique_id": "T1110",
        "technique_name": "Brute Force",
        "tactic": "Credential Access",
        "url": "https://attack.mitre.org/techniques/T1110/",
    },
    "LOGIN_SUCCESS": {
        "technique_id": "T1078",
        "technique_name": "Valid Accounts",
        "tactic": "Defense Evasion",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
}


# ============================================================
# OCEAN THEME CSS
# ============================================================

GLASS_CSS = """
<style>
.stApp, [data-testid="stAppViewContainer"], [data-testid="stHeader"] {
    background: transparent !important;
}

[data-testid="stAppViewContainer"]::before {
    content: "";
    position: fixed;
    inset: 0;
    z-index: -1;
    background:
        radial-gradient(circle at 15% 20%, rgba(14, 165, 233, 0.35), transparent 45%),
        radial-gradient(circle at 85% 15%, rgba(6, 182, 212, 0.32), transparent 50%),
        radial-gradient(circle at 50% 90%, rgba(99, 102, 241, 0.28), transparent 55%),
        radial-gradient(circle at 90% 80%, rgba(34, 211, 238, 0.30), transparent 45%),
        linear-gradient(135deg, #bae6fd 0%, #c7d2fe 50%, #a5f3fc 100%);
    background-size: 200% 200%;
    animation: oceanMove 20s ease-in-out infinite;
}

@keyframes oceanMove {
    0%   { background-position: 0% 0%,   100% 0%, 50% 100%, 100% 100%; }
    50%  { background-position: 100% 50%, 0% 50%, 100% 0%,   0% 50%; }
    100% { background-position: 0% 0%,   100% 0%, 50% 100%, 100% 100%; }
}

[data-testid="stAppViewContainer"]::after {
    content: "";
    position: fixed;
    inset: 0;
    z-index: -1;
    background-image:
        radial-gradient(3px 3px at 20% 30%, rgba(255,255,255,0.8), transparent),
        radial-gradient(2px 2px at 60% 70%, rgba(14,165,233,0.7), transparent),
        radial-gradient(2.5px 2.5px at 80% 20%, rgba(6,182,212,0.7), transparent),
        radial-gradient(2px 2px at 30% 80%, rgba(99,102,241,0.6), transparent),
        radial-gradient(1.5px 1.5px at 90% 60%, rgba(255,255,255,0.7), transparent),
        radial-gradient(1.5px 1.5px at 10% 50%, rgba(34,211,238,0.7), transparent);
    animation: bubbleFloat 25s linear infinite;
    opacity: 0.9;
}

@keyframes bubbleFloat {
    from { transform: translateY(0)   translateX(0); }
    to   { transform: translateY(-80px) translateX(30px); }
}

.main .block-container {
    max-width: 100% !important;
    padding-left: 1.5rem !important;
    padding-right: 1.5rem !important;
    padding-top: 1rem !important;
    overflow-x: hidden !important;
}

[data-testid="stAppViewContainer"] {
    overflow-x: hidden !important;
}

[data-testid="stSidebar"] {
    min-width: 220px !important;
    max-width: 250px !important;
    width: 230px !important;
}

[data-testid="stHorizontalBlock"] {
    overflow: hidden !important;
    gap: 1rem !important;
}

section[data-testid="stSidebar"] {
    background: rgba(255, 255, 255, 0.55) !important;
    backdrop-filter: blur(24px) saturate(180%);
    -webkit-backdrop-filter: blur(24px) saturate(180%);
    border-right: 1px solid rgba(14, 165, 233, 0.25);
    box-shadow: 4px 0 32px rgba(14, 165, 233, 0.15);
}

section[data-testid="stSidebar"] * {
    color: #0c4a6e;
}

.glass-header {
    background: linear-gradient(135deg,
        rgba(255, 255, 255, 0.75),
        rgba(224, 242, 254, 0.65));
    backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border: 1px solid rgba(14, 165, 233, 0.3);
    border-radius: 20px;
    padding: 20px 26px;
    margin-bottom: 14px;
    box-shadow:
        0 12px 40px rgba(14, 165, 233, 0.20),
        inset 0 1px 0 rgba(255, 255, 255, 0.9);
    overflow: hidden;
}

.glass-header h1 {
    background: linear-gradient(90deg, #0891b2, #0284c7, #4f46e5);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-weight: 800;
    margin: 0;
    font-size: 26px;
    letter-spacing: 0.5px;
}

.glass-header .subtitle {
    color: #0e7490;
    font-size: 13px;
    margin-top: 6px;
    letter-spacing: 0.5px;
    font-weight: 500;
}

.glass-card {
    background: rgba(255, 255, 255, 0.7);
    backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border: 1px solid rgba(14, 165, 233, 0.25);
    border-radius: 16px;
    padding: 16px;
    box-shadow: 0 8px 32px rgba(14, 165, 233, 0.15);
    color: #0c4a6e;
}

section[data-testid="stSidebar"] .metric-glass,
.metric-glass {
    position: relative !important;
    background: rgba(255, 255, 255, 0.85) !important;
    backdrop-filter: blur(18px) saturate(180%) !important;
    -webkit-backdrop-filter: blur(18px) saturate(180%) !important;
    border: 1px solid rgba(14, 165, 233, 0.3) !important;
    border-radius: 14px !important;
    padding: 12px 16px !important;
    margin-bottom: 10px !important;
    box-shadow: 0 6px 24px rgba(14, 165, 233, 0.2),
                inset 0 1px 0 rgba(255, 255, 255, 1) !important;
    transition: all 0.35s cubic-bezier(0.4, 0, 0.2, 1) !important;
    overflow: hidden !important;
}

section[data-testid="stSidebar"] .metric-glass::before,
.metric-glass::before {
    content: "" !important;
    position: absolute !important;
    left: 0 !important;
    top: 0 !important;
    bottom: 0 !important;
    width: 5px !important;
    background: currentColor !important;
    box-shadow: 0 0 14px currentColor !important;
}

.metric-glass:hover {
    transform: translateX(4px) scale(1.02) !important;
    border-color: rgba(14, 165, 233, 0.6) !important;
    box-shadow: 0 10px 36px rgba(14, 165, 233, 0.35),
                inset 0 1px 0 rgba(255, 255, 255, 1) !important;
}

section[data-testid="stSidebar"] .metric-glass .value,
.metric-glass .value {
    font-size: 28px !important;
    font-weight: 800 !important;
    line-height: 1 !important;
    letter-spacing: -1px !important;
    background: transparent !important;
    -webkit-text-fill-color: currentColor !important;
}

section[data-testid="stSidebar"] .metric-glass .label,
.metric-glass .label {
    font-size: 11px !important;
    color: #0e7490 !important;
    -webkit-text-fill-color: #0e7490 !important;
    text-transform: uppercase !important;
    letter-spacing: 1.5px !important;
    margin-top: 6px !important;
    font-weight: 700 !important;
}

[data-testid="stMetric"] {
    background: rgba(255, 255, 255, 0.7);
    backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border: 1px solid rgba(14, 165, 233, 0.25);
    border-radius: 16px;
    padding: 14px 18px;
    box-shadow: 0 6px 24px rgba(14, 165, 233, 0.15);
    transition: all 0.3s ease;
}

[data-testid="stMetric"]:hover {
    border-color: rgba(14, 165, 233, 0.5);
    box-shadow: 0 10px 32px rgba(14, 165, 233, 0.25);
}

[data-testid="stMetricValue"] {
    background: linear-gradient(90deg, #0891b2, #0284c7, #4f46e5);
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    background-clip: text;
    font-weight: 800 !important;
    font-size: 34px !important;
}

[data-testid="stMetricLabel"] {
    color: #0e7490 !important;
    text-transform: uppercase;
    letter-spacing: 1.5px;
    font-size: 11px !important;
    font-weight: 700 !important;
}

.js-plotly-plot .plotly .main-svg {
    background: transparent !important;
}

.js-plotly-plot,
.plot-container,
.plotly {
    max-width: 100% !important;
    overflow: hidden !important;
    background: rgba(255, 255, 255, 0.7) !important;
    backdrop-filter: blur(20px) saturate(180%);
    -webkit-backdrop-filter: blur(20px) saturate(180%);
    border: 1px solid rgba(14, 165, 233, 0.25) !important;
    border-radius: 18px !important;
    box-shadow: 0 8px 32px rgba(14, 165, 233, 0.15);
    padding: 8px;
}

[data-testid="stDataFrame"] {
    background: rgba(255, 255, 255, 0.75) !important;
    backdrop-filter: blur(20px) saturate(180%);
    border-radius: 16px !important;
    border: 1px solid rgba(14, 165, 233, 0.25) !important;
    overflow-x: auto !important;
    box-shadow: 0 8px 32px rgba(14, 165, 233, 0.15);
    max-width: 100% !important;
}

[data-testid="stDataFrame"] > div {
    max-width: 100% !important;
}

.stButton > button {
    background: linear-gradient(135deg,
        rgba(14, 165, 233, 0.9),
        rgba(99, 102, 241, 0.9)) !important;
    border: 1px solid rgba(255, 255, 255, 0.5) !important;
    border-radius: 12px !important;
    color: #ffffff !important;
    font-weight: 600 !important;
    transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1) !important;
}

.stButton > button:hover {
    background: linear-gradient(135deg,
        rgba(14, 165, 233, 1),
        rgba(99, 102, 241, 1)) !important;
    box-shadow: 0 8px 28px rgba(14, 165, 233, 0.5),
                0 0 40px rgba(99, 102, 241, 0.35) !important;
    transform: translateY(-2px);
}

.badge-glow {
    padding: 5px 14px;
    border-radius: 20px;
    font-weight: 700;
    font-size: 12px;
    backdrop-filter: blur(10px);
    border: 1px solid currentColor;
    box-shadow: 0 0 18px currentColor;
    letter-spacing: 0.5px;
    background: rgba(255, 255, 255, 0.7);
    display: inline-block;
}

.streamlit-expanderHeader {
    background: rgba(255, 255, 255, 0.7) !important;
    backdrop-filter: blur(14px);
    border-radius: 12px !important;
    border: 1px solid rgba(14, 165, 233, 0.25) !important;
    color: #0c4a6e !important;
    font-weight: 600 !important;
}

details[data-testid="stExpander"] {
    background: rgba(255, 255, 255, 0.5) !important;
    backdrop-filter: blur(16px);
    border-radius: 14px !important;
    border: 1px solid rgba(14, 165, 233, 0.25) !important;
}

.stSelectbox > div > div,
.stTextInput > div > div > input {
    background: rgba(255, 255, 255, 0.8) !important;
    backdrop-filter: blur(12px);
    border: 1px solid rgba(14, 165, 233, 0.35) !important;
    border-radius: 12px !important;
    color: #0c4a6e !important;
}

.stAlert {
    background: rgba(255, 255, 255, 0.8) !important;
    backdrop-filter: blur(14px);
    border-radius: 14px !important;
    border: 1px solid rgba(14, 165, 233, 0.3) !important;
    color: #0c4a6e !important;
}

h1, h2, h3, h4 {
    color: #0c4a6e !important;
    letter-spacing: 0.3px;
}

p, span, label, div {
    color: #0c4a6e;
}

hr {
    border-color: rgba(14, 165, 233, 0.25) !important;
}

::-webkit-scrollbar { width: 8px; height: 8px; }
::-webkit-scrollbar-track { background: rgba(255, 255, 255, 0.4); }
::-webkit-scrollbar-thumb {
    background: linear-gradient(180deg, #06b6d4, #4f46e5);
    border-radius: 6px;
}
::-webkit-scrollbar-thumb:hover {
    background: linear-gradient(180deg, #0891b2, #6366f1);
}
</style>
"""


def inject_glass_css():
    st.markdown(GLASS_CSS, unsafe_allow_html=True)


# ============================================================
# SIDEBAR METRICS
# ============================================================

def render_sidebar_metrics(alerts):
    total = len(alerts)
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    medium = sum(1 for a in alerts if a.get("severity") == "Medium")
    low = sum(1 for a in alerts if a.get("severity") == "Low")

    st.markdown(
        f"""
        <div style='color:#0e7490;font-size:11px;letter-spacing:2px;
                    text-transform:uppercase;margin-bottom:6px;font-weight:700;'>
            Metrics
        </div>
        <div style='background:linear-gradient(135deg,#0891b2,#4f46e5);
                    -webkit-background-clip:text;-webkit-text-fill-color:transparent;
                    font-size:30px;font-weight:800;line-height:1;
                    letter-spacing:-1px;'>{total}</div>
        <div style='color:#0e7490;font-size:11px;margin-top:2px;
                    margin-bottom:14px;letter-spacing:1px;font-weight:600;'>
            Total Alerts
        </div>

        <div class="metric-glass" style="color:#dc2626;">
            <div class="value" style="color:#dc2626;">{critical}</div>
            <div class="label">Critical</div>
        </div>
        <div class="metric-glass" style="color:#f97316;">
            <div class="value" style="color:#f97316;">{high}</div>
            <div class="label">High</div>
        </div>
        <div class="metric-glass" style="color:#f59e0b;">
            <div class="value" style="color:#f59e0b;">{medium}</div>
            <div class="label">Medium</div>
        </div>
        <div class="metric-glass" style="color:#10b981;">
            <div class="value" style="color:#10b981;">{low}</div>
            <div class="label">Low</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# TOPBAR
# ============================================================

def render_topbar(use_mock: bool):
    col1, col2, col3 = st.columns([2.5, 1, 1])

    with col1:
        st.markdown(
            "<div class='glass-header'>"
            "<h1>🛡️ AI SOC Copilot</h1>"
            "<div class='subtitle'>"
            "Real-time threat detection · AI-powered investigation"
            "</div></div>",
            unsafe_allow_html=True,
        )

    with col2:
        if use_mock:
            st.markdown(
                "<div style='text-align:center;margin-top:22px;'>"
                "<span class='badge-glow' style='background:rgba(245,158,11,0.35);"
                "color:#b45309;'>◆ MOCK DATA</span></div>",
                unsafe_allow_html=True,
            )
        else:
            st.markdown(
                "<div style='text-align:center;margin-top:22px;'>"
                "<span class='badge-glow' style='background:rgba(16,185,129,0.35);"
                "color:#047857;'>● CONNECTED</span></div>",
                unsafe_allow_html=True,
            )

    with col3:
        health = st.session_state.get("health", {})
        st.markdown(
            f"<div style='text-align:center;margin-top:24px;color:#0e7490;"
            f"font-size:11px;letter-spacing:1px;text-transform:uppercase;"
            f"font-weight:700;'>Backend · {health.get('status', 'unknown')}</div>",
            unsafe_allow_html=True,
        )


# ============================================================
# NOTIFICATION BANNER
# ============================================================

def render_notification(new_count, total_count):
    if new_count <= 0:
        return
    st.markdown(
        f"<div style='background:linear-gradient(90deg,"
        f"rgba(16,185,129,0.15),rgba(14,165,233,0.15));"
        f"border:1px solid rgba(16,185,129,0.4);border-radius:12px;"
        f"padding:12px 18px;margin-bottom:16px;"
        f"box-shadow:0 4px 20px rgba(16,185,129,0.2);"
        f"display:flex;align-items:center;gap:12px;'>"
        f"<span style='font-size:22px;'>🔔</span>"
        f"<div style='flex:1;'>"
        f"<div style='font-weight:700;color:#047857;font-size:14px;'>"
        f"{new_count} new alert(s) detected!</div>"
        f"<div style='font-size:12px;color:#0e7490;margin-top:2px;'>"
        f"Total alerts: {total_count}</div>"
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


# ============================================================
# STATS
# ============================================================

def render_stats(alerts):
    total = len(alerts)
    high = sum(1 for a in alerts if a.get("severity") == "High")
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")

    c1, c2, c3 = st.columns(3)
    c1.metric("Total Alerts", total)
    c2.metric("High", high)
    c3.metric("Critical", critical)


# ============================================================
# HISTORICAL TRENDS
# ============================================================

def render_historical_trends(trends):
    if not trends:
        return

    hours = trends.get("hours", [])
    alerts = trends.get("alerts", [])
    critical = trends.get("critical", [])

    df = pd.DataFrame({
        "Hour": hours,
        "All Alerts": alerts,
        "Critical": critical,
    })

    fig = px.line(
        df,
        x="Hour",
        y=["All Alerts", "Critical"],
        markers=True,
        color_discrete_map={
            "All Alerts": "#0ea5e9",
            "Critical": "#dc2626",
        },
    )
    fig.update_layout(
        title=dict(
            text="📊 Alert Trends — Last 24 Hours",
            font=dict(size=15, color="#0c4a6e"),
            x=0.5,
            xanchor="center",
        ),
        plot_bgcolor="rgba(255,255,255,0.4)",
        paper_bgcolor="rgba(255,255,255,0.4)",
        font=dict(color="#0c4a6e", size=12),
        height=280,
        margin=dict(t=50, b=30, l=40, r=20),
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=-0.25,
            xanchor="center",
            x=0.5,
            bgcolor="rgba(255,255,255,0.6)",
            bordercolor="rgba(14,165,233,0.3)",
            borderwidth=1,
        ),
        xaxis=dict(
            title="Hour (UTC)",
            title_font=dict(color="#0c4a6e", size=12),
            tickfont=dict(color="#0c4a6e", size=11),
            gridcolor="rgba(14,165,233,0.12)",
        ),
        yaxis=dict(
            title="Alerts",
            title_font=dict(color="#0c4a6e", size=12),
            tickfont=dict(color="#0c4a6e", size=11),
            gridcolor="rgba(14,165,233,0.12)",
        ),
    )
    st.plotly_chart(
        fig,
        use_container_width=True,
        theme=None,
        config={"displayModeBar": False},
    )


# ============================================================
# SEVERITY CHARTS
# ============================================================

def render_severity_charts(alerts):
    if not alerts:
        st.info("No alerts to chart.")
        return

    counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    for a in alerts:
        sev = a.get("severity")
        if sev in counts:
            counts[sev] += 1

    df = pd.DataFrame(
        {"Severity": list(counts.keys()), "Count": list(counts.values())}
    )
    df = df[df["Count"] > 0]

    if df.empty:
        st.info("No alerts to chart.")
        return

    col1, col2 = st.columns(2, gap="medium")

    with col1:
        pie = px.pie(
            df,
            names="Severity",
            values="Count",
            color="Severity",
            color_discrete_map=SEVERITY_COLORS,
            hole=0.55,
        )
        pie.update_traces(
            textinfo="label+percent+value",
            textfont=dict(size=12, color="#0c4a6e"),
            marker=dict(line=dict(color="#ffffff", width=3)),
        )
        pie.update_layout(
            title=dict(
                text="Severity — Pie",
                font=dict(size=15, color="#0c4a6e"),
                x=0.5,
                xanchor="center",
            ),
            plot_bgcolor="rgba(255,255,255,0.4)",
            paper_bgcolor="rgba(255,255,255,0.4)",
            font=dict(color="#0c4a6e", size=12),
            height=300,
            margin=dict(t=50, b=20, l=10, r=10),
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.15,
                xanchor="center",
                x=0.5,
                bgcolor="rgba(255,255,255,0.6)",
                bordercolor="rgba(14,165,233,0.3)",
                borderwidth=1,
                font=dict(color="#0c4a6e", size=11),
            ),
        )
        st.plotly_chart(
            pie,
            use_container_width=True,
            theme=None,
            config={"displayModeBar": False},
        )

    with col2:
        bar = px.bar(
            df,
            x="Severity",
            y="Count",
            color="Severity",
            color_discrete_map=SEVERITY_COLORS,
            text="Count",
        )
        bar.update_traces(
            textposition="outside",
            textfont=dict(size=13, color="#0c4a6e"),
            marker=dict(line=dict(color="#ffffff", width=2)),
        )
        bar.update_layout(
            title=dict(
                text="Severity — Bar",
                font=dict(size=15, color="#0c4a6e"),
                x=0.5,
                xanchor="center",
            ),
            plot_bgcolor="rgba(255,255,255,0.4)",
            paper_bgcolor="rgba(255,255,255,0.4)",
            font=dict(color="#0c4a6e", size=12),
            height=300,
            margin=dict(t=50, b=40, l=30, r=20),
            showlegend=False,
            xaxis=dict(
                title_font=dict(color="#0c4a6e", size=12),
                tickfont=dict(color="#0c4a6e", size=11),
                gridcolor="rgba(14,165,233,0.15)",
            ),
            yaxis=dict(
                title="Count",
                title_font=dict(color="#0c4a6e", size=12),
                tickfont=dict(color="#0c4a6e", size=11),
                gridcolor="rgba(14,165,233,0.15)",
            ),
        )
        st.plotly_chart(
            bar,
            use_container_width=True,
            theme=None,
            config={"displayModeBar": False},
        )


# ============================================================
# BADGE
# ============================================================

def severity_badge(severity: str) -> str:
    color = SEVERITY_COLORS.get(severity, "#6b7280")
    return (
        f"<span class='badge-glow' style='background:{color}22;"
        f"color:{color};'>{severity}</span>"
    )


# ============================================================
# MITRE ATT&CK MAPPING
# ============================================================

def render_mitre_mapping(alert):
    rule = alert.get("rule_name", "")
    mapping = MITRE_MAPPING.get(rule)

    if not mapping:
        event_type = alert.get("event_type", "")
        mapping = MITRE_MAPPING.get(event_type)

    if not mapping:
        return

    st.markdown("**🎯 MITRE ATT&CK Mapping**")
    st.markdown(
        f"<div class='glass-card' style='margin-top:8px;padding:12px;'>"
        f"<div style='display:flex;justify-content:space-between;align-items:center;"
        f"flex-wrap:wrap;gap:10px;'>"
        f"<div>"
        f"<div style='font-size:11px;color:#0e7490;letter-spacing:1px;"
        f"text-transform:uppercase;font-weight:700;'>{mapping['tactic']}</div>"
        f"<div style='font-size:15px;font-weight:700;color:#0c4a6e;"
        f"margin-top:4px;'>{mapping['technique_id']} — {mapping['technique_name']}</div>"
        f"</div>"
        f"<a href='{mapping['url']}' target='_blank' "
        f"style='text-decoration:none;'>"
        f"<span class='badge-glow' style='background:rgba(14,165,233,0.15);"
        f"color:#0891b2;font-size:11px;'>View on MITRE ↗</span></a>"
        f"</div>"
        f"</div>",
        unsafe_allow_html=True,
    )


# ============================================================
# ALERT TIMELINE
# ============================================================

def render_alert_timeline(alert):
    evidence = alert.get("evidence", [])
    if not evidence:
        st.caption("No evidence to display.")
        return

    sorted_ev = sorted(
        evidence,
        key=lambda x: x.get("timestamp", "") if isinstance(x, dict) else str(x),
    )

    st.markdown("**📅 Alert Timeline**")

    parts = []
    parts.append(
        '<div style="position:relative;padding-left:24px;margin-top:12px;">'
        '<div style="position:absolute;left:8px;top:0;bottom:0;width:2px;'
        'background:linear-gradient(180deg,#0891b2,#4f46e5);"></div>'
    )

    for i, e in enumerate(sorted_ev):
        if isinstance(e, dict):
            ts = e.get("timestamp", "—")
            msg = e.get("message", "—")
        else:
            ts = "—"
            msg = str(e)

        color = "#0891b2" if i == 0 else "#4f46e5"

        parts.append(
            '<div style="position:relative;margin-bottom:16px;padding-left:8px;">'
            f'<div style="position:absolute;left:-20px;top:6px;width:12px;height:12px;'
            f'background:{color};border-radius:50%;'
            f'box-shadow:0 0 10px {color};'
            f'border:2px solid #fff;"></div>'
            f'<div style="font-size:11px;color:#0e7490;font-family:monospace;'
            f'letter-spacing:0.5px;margin-bottom:3px;">{ts}</div>'
            f'<div style="font-size:12px;color:#0c4a6e;line-height:1.4;">'
            f'{msg}</div>'
            '</div>'
        )

    parts.append('</div>')

    timeline_html = "".join(parts)
    st.markdown(timeline_html, unsafe_allow_html=True)


# ============================================================
# TABLE — with search + filter
# ============================================================

def render_alert_table(alerts, search_query="", severity_filter="All"):
    if not alerts:
        st.info("No alerts yet. Upload logs and run detection.")
        return None

    filtered = alerts

    if search_query:
        q = search_query.lower()
        filtered = [
            a for a in filtered
            if q in str(a.get("rule_name", "")).lower()
            or q in str(a.get("source_ip", "")).lower()
            or q in str(a.get("host", "")).lower()
            or q in str(a.get("username", "")).lower()
        ]

    if severity_filter and severity_filter != "All":
        filtered = [a for a in filtered if a.get("severity") == severity_filter]

    if not filtered:
        st.info(f"No alerts match your filters ({len(alerts)} total).")
        return None

    df = pd.DataFrame(
        [
            {
                "Rule": a.get("rule_name"),
                "Host": a.get("host") or "—",
                "Source IP": a.get("source_ip") or "—",
                "Events": a.get("event_count"),
                "Score": a.get("risk_score"),
                "Severity": a.get("severity"),
                "Status": a.get("status"),
                "_id": a.get("alert_id"),
            }
            for a in filtered
        ]
    )

    event = st.dataframe(
        df.drop(columns=["_id"]),
        use_container_width=True,
        hide_index=True,
        on_select="rerun",
        selection_mode="single-row",
        column_config={
            "Rule": st.column_config.TextColumn("Rule", width="medium"),
            "Host": st.column_config.TextColumn("Host", width="small"),
            "Source IP": st.column_config.TextColumn("Source IP", width="small"),
            "Events": st.column_config.NumberColumn("Events", width="small"),
            "Score": st.column_config.NumberColumn("Score", width="small"),
            "Severity": st.column_config.TextColumn("Severity", width="small"),
            "Status": st.column_config.TextColumn("Status", width="small"),
        },
    )

    selected_rows = (
        event.selection.get("rows", []) if hasattr(event, "selection") else []
    )
    if selected_rows:
        idx = selected_rows[0]
        return filtered[idx]
    return None


# ============================================================
# RISK INDICATOR
# ============================================================

def render_risk_indicator(score, severity):
    if score is None:
        st.write("Score: N/A")
        return

    safe = max(0, min(100, int(score)))
    color = SEVERITY_COLORS.get(severity, "#6b7280")

    st.markdown(
        f"""
        <div style="margin:14px 0;">
            <div style="background:rgba(255,255,255,0.7);border-radius:10px;
                        height:14px;overflow:hidden;
                        border:1px solid rgba(14,165,233,0.3);">
                <div style="background:linear-gradient(90deg,{color}aa,{color});
                            width:{safe}%;height:100%;
                            box-shadow:0 0 20px {color}88;
                            transition:width 0.6s cubic-bezier(0.4, 0, 0.2, 1);"></div>
            </div>
            <div style="display:flex;justify-content:space-between;
                        font-size:12px;margin-top:8px;color:#0c4a6e;">
                <span>Score: <b style="color:{color};font-size:14px;">{safe}</b>/100</span>
                <span>Band: <b style="color:{color};">{severity}</b></span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ============================================================
# AI BLOCK — all sections in glass cards
# ============================================================

def render_ai_block(ai_data, error, is_fallback):
    if error:
        st.error(f"AI analysis failed: {error}")
        return

    if not ai_data:
        return

    provider = ai_data.get("ai_provider", "unknown")

    provider_badge = {
        "gemini": "🌟 Gemini API",
        "ollama": "💻 Ollama (local LLM)",
        "backend": "🔧 Backend (FastAPI)",
        "fallback": "⚠️ Deterministic fallback",
        "mock": "🧪 Mock response",
    }.get(provider, f"❓ {provider}")

    if provider == "fallback" or is_fallback:
        st.warning(f"{provider_badge} — deterministic guidance only.")
    else:
        st.info(f"🤖 AI-generated analysis · {provider_badge}")

    # ---- Summary + Assessment in glass card ----
    st.markdown(
        f"<div class='glass-card' style='margin-top:12px;'>"
        f"<p><b style='color:#0891b2;'>Summary:</b> "
        f"{ai_data.get('alert_summary', '')}</p>"
        f"<p style='margin-bottom:0;'><b style='color:#4f46e5;'>Assessment:</b> "
        f"{ai_data.get('assessment', '')}</p>"
        f"</div>",
        unsafe_allow_html=True,
    )

    # ---- Observed Evidence in glass card ----
    observed = ai_data.get("observed_evidence", [])
    if observed:
        bullets = "".join(
            f"<li style='margin-bottom:6px;'>{item}</li>" for item in observed
        )
        st.markdown(
            f"<div class='glass-card' style='margin-top:12px;'>"
            f"<div style='font-weight:700;color:#0891b2;margin-bottom:8px;'>"
            f"📌 Observed Evidence</div>"
            f"<ul style='margin:0;padding-left:20px;'>{bullets}</ul>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # ---- Investigation Checklist in glass card ----
    checklist = ai_data.get("investigation_checklist", [])
    if checklist:
        bullets = "".join(
            f"<li style='margin-bottom:6px;'>☐ {item}</li>"
            for item in checklist
        )
        st.markdown(
            f"<div class='glass-card' style='margin-top:12px;'>"
            f"<div style='font-weight:700;color:#4f46e5;margin-bottom:8px;'>"
            f"✅ Investigation Checklist</div>"
            f"<ul style='margin:0;padding-left:20px;'>{bullets}</ul>"
            f"</div>",
            unsafe_allow_html=True,
        )

    # ---- Recommended Disposition in glass card ----
    disposition = ai_data.get("recommended_disposition", "")
    if disposition:
        st.markdown(
            f"<div class='glass-card' style='margin-top:12px;'>"
            f"<div style='font-weight:700;color:#047857;margin-bottom:6px;'>"
            f"🎯 Recommended Disposition</div>"
            f"<div style='color:#0c4a6e;'>{disposition}</div>"
            f"</div>",
            unsafe_allow_html=True,
        )


# ============================================================
# VOICE BRIEFING
# ============================================================

def render_voice_briefing(alert, ai_analysis):
    st.markdown("**🎙️ Voice Briefing (ElevenLabs)**")
    st.caption("Convert this alert into a spoken audio briefing.")

    if st.button("🔊 Generate & Play Briefing", use_container_width=True):
        if ai_analysis:
            text = (
                f"Security alert. {alert.get('rule_name', 'Unknown rule')}. "
                f"Severity: {alert.get('severity', 'Unknown')}. "
                f"Risk score {alert.get('risk_score', 0)} out of 100. "
                f"{ai_analysis.get('alert_summary', '')} "
                f"Recommended action: "
                f"{ai_analysis.get('recommended_disposition', '')}"
            )
        else:
            text = (
                f"Security alert. {alert.get('rule_name', 'Unknown rule')}. "
                f"Severity: {alert.get('severity', 'Unknown')}. "
                f"Host {alert.get('host', 'unknown')}. "
                f"Source I P {alert.get('source_ip', 'unknown')}. "
                f"{alert.get('event_count', 0)} events in "
                f"{alert.get('time_window_seconds', 0)} seconds."
            )

        with st.spinner("Generating audio..."):
            audio_bytes, err = generate_voice_briefing(text)

        if err == "missing_api_key":
            st.warning(
                "🔑 ElevenLabs API key not configured. "
                "Add `ELEVENLABS_API_KEY=...` to `.env` and restart.\n\n"
                f"**Briefing text that would be spoken:**\n\n_{text}_"
            )
        elif err:
            st.error(f"Voice generation failed: {err}")
        elif audio_bytes:
            st.audio(audio_bytes, format="audio/mp3")
            st.success("✅ Briefing generated. Press play above.")


# ============================================================
# EXPORT REPORT — single alert
# ============================================================

def render_export_report(alert, ai_analysis):
    st.markdown("**📄 Export Report**")
    st.caption("Download the full report in your preferred format.")

    md_report = build_markdown_report(alert, ai_analysis)
    json_report = build_json_report(alert, ai_analysis)

    try:
        pdf_bytes = build_pdf_report(alert, ai_analysis)
    except ImportError:
        pdf_bytes = None
        st.warning(
            "📦 PDF export requires `reportlab`. "
            "Install with: `pip install reportlab`"
        )
    except Exception as e:
        pdf_bytes = None
        st.warning(f"PDF generation failed: {e}")

    alert_id = alert.get("alert_id", "alert")

    if pdf_bytes:
        st.download_button(
            label="📄 Download PDF Report",
            data=pdf_bytes,
            file_name=f"soc_report_{alert_id}.pdf",
            mime="application/pdf",
            use_container_width=True,
        )

    st.download_button(
        label="📋 Download JSON",
        data=json_report,
        file_name=f"soc_report_{alert_id}.json",
        mime="application/json",
        use_container_width=True,
    )

    st.download_button(
        label="📝 Download Markdown",
        data=md_report,
        file_name=f"soc_report_{alert_id}.md",
        mime="text/markdown",
        use_container_width=True,
    )


# ============================================================
# ANALYTICS DASHBOARD
# ============================================================

def render_analytics(alerts):
    if not alerts:
        st.info("No alerts yet. Upload logs and run detection.")
        return

    st.markdown("### 📊 Security Analytics")

    # ============ Row 1: Top IPs + Top Hosts ============
    col1, col2 = st.columns(2)

    with col1:
        st.markdown("**🎯 Top Attacking IPs**")
        ip_counts = {}
        for a in alerts:
            ip = a.get("source_ip") or "unknown"
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

        ip_df = pd.DataFrame(
            sorted(ip_counts.items(), key=lambda x: -x[1]),
            columns=["Source IP", "Alerts"],
        )
        if not ip_df.empty:
            fig = px.bar(
                ip_df,
                x="Alerts",
                y="Source IP",
                orientation="h",
                color="Alerts",
                color_continuous_scale=["#a5f3fc", "#0891b2", "#4f46e5"],
                text="Alerts",
            )
            fig.update_layout(
                plot_bgcolor="rgba(255,255,255,0.4)",
                paper_bgcolor="rgba(255,255,255,0.4)",
                font=dict(color="#0c4a6e", size=11),
                height=300,
                margin=dict(t=20, b=20, l=20, r=20),
                showlegend=False,
                coloraxis_showscale=False,
                xaxis=dict(gridcolor="rgba(14,165,233,0.15)"),
                yaxis=dict(gridcolor="rgba(14,165,233,0.15)"),
            )
            fig.update_traces(textposition="outside")
            st.plotly_chart(
                fig,
                use_container_width=True,
                theme=None,
                config={"displayModeBar": False},
            )

    with col2:
        st.markdown("**🖥️ Most Targeted Hosts**")
        host_counts = {}
        for a in alerts:
            host = a.get("host") or "unknown"
            host_counts[host] = host_counts.get(host, 0) + 1

        host_df = pd.DataFrame(
            sorted(host_counts.items(), key=lambda x: -x[1]),
            columns=["Host", "Alerts"],
        )
        if not host_df.empty:
            fig = px.bar(
                host_df,
                x="Alerts",
                y="Host",
                orientation="h",
                color="Alerts",
                color_continuous_scale=["#a5f3fc", "#0891b2", "#4f46e5"],
                text="Alerts",
            )
            fig.update_layout(
                plot_bgcolor="rgba(255,255,255,0.4)",
                paper_bgcolor="rgba(255,255,255,0.4)",
                font=dict(color="#0c4a6e", size=11),
                height=300,
                margin=dict(t=20, b=20, l=20, r=20),
                showlegend=False,
                coloraxis_showscale=False,
                xaxis=dict(gridcolor="rgba(14,165,233,0.15)"),
                yaxis=dict(gridcolor="rgba(14,165,233,0.15)"),
            )
            fig.update_traces(textposition="outside")
            st.plotly_chart(
                fig,
                use_container_width=True,
                theme=None,
                config={"displayModeBar": False},
            )

    # ============ Row 2: Attack Types + Status ============
    col3, col4 = st.columns(2)

    with col3:
        st.markdown("**⚔️ Attack Types**")
        rule_counts = {}
        for a in alerts:
            rule = a.get("rule_name") or "Unknown"
            rule_counts[rule] = rule_counts.get(rule, 0) + 1

        if rule_counts:
            rule_df = pd.DataFrame(
                rule_counts.items(),
                columns=["Rule", "Count"],
            )
            fig = px.pie(
                rule_df,
                names="Rule",
                values="Count",
                hole=0.5,
                color_discrete_sequence=[
                    "#0891b2", "#4f46e5", "#f97316",
                    "#dc2626", "#10b981", "#f59e0b",
                ],
            )
            fig.update_layout(
                plot_bgcolor="rgba(255,255,255,0.4)",
                paper_bgcolor="rgba(255,255,255,0.4)",
                font=dict(color="#0c4a6e", size=11),
                height=300,
                margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.15,
                    xanchor="center",
                    x=0.5,
                    bgcolor="rgba(255,255,255,0.6)",
                ),
            )
            st.plotly_chart(
                fig,
                use_container_width=True,
                theme=None,
                config={"displayModeBar": False},
            )

    with col4:
        st.markdown("**📋 Alert Status**")
        status_counts = {}
        for a in alerts:
            status = a.get("status") or "Open"
            status_counts[status] = status_counts.get(status, 0) + 1

        if status_counts:
            status_df = pd.DataFrame(
                status_counts.items(),
                columns=["Status", "Count"],
            )
            fig = px.pie(
                status_df,
                names="Status",
                values="Count",
                hole=0.5,
                color_discrete_sequence=[
                    "#10b981", "#f59e0b", "#f97316", "#6b7280",
                ],
            )
            fig.update_layout(
                plot_bgcolor="rgba(255,255,255,0.4)",
                paper_bgcolor="rgba(255,255,255,0.4)",
                font=dict(color="#0c4a6e", size=11),
                height=300,
                margin=dict(t=20, b=20, l=20, r=20),
                legend=dict(
                    orientation="h",
                    yanchor="bottom",
                    y=-0.15,
                    xanchor="center",
                    x=0.5,
                    bgcolor="rgba(255,255,255,0.6)",
                ),
            )
            st.plotly_chart(
                fig,
                use_container_width=True,
                theme=None,
                config={"displayModeBar": False},
            )


# ============================================================
# CLEAR ALERTS BUTTON
# ============================================================

def render_clear_button():
    """Render a 'Clear All Alerts' button in the sidebar."""
    if st.button("🗑️ Clear All Alerts", use_container_width=True):
        import requests
        import os
        api_url = os.getenv("API_BASE_URL", "http://localhost:8000")
        try:
            r = requests.delete(
                f"{api_url}/api/alerts", timeout=10, verify=False
            )
            if r.status_code == 200:
                st.success(f"✅ {r.json().get('cleared', 0)} alerts cleared")
                st.rerun()
            else:
                st.error(f"Failed: {r.status_code}")
        except Exception as e:
            st.error(f"Error: {e}")