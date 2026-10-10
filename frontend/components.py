"""SOC Copilot UI — Ocean Theme."""

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

.stSelectbox > div > div {
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
# TABLE
# ============================================================

def render_alert_table(alerts):
    if not alerts:
        st.info("No alerts yet. Upload logs and run detection.")
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
            for a in alerts
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
        return alerts[idx]
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
# AI BLOCK
# ============================================================

def render_ai_block(ai_data, error, is_fallback):
    if error:
        st.error(f"AI analysis failed: {error}")
        return

    if not ai_data:
        return

    if is_fallback:
        st.warning("⚠️ Fallback output (AI unavailable) — deterministic guidance only.")
    else:
        st.info("🤖 AI-generated analysis")

    st.markdown(
        f"<div class='glass-card' style='margin-top:12px;'>"
        f"<p><b style='color:#0891b2;'>Summary:</b> {ai_data.get('alert_summary', '')}</p>"
        f"<p><b style='color:#4f46e5;'>Assessment:</b> {ai_data.get('assessment', '')}</p>"
        f"</div>",
        unsafe_allow_html=True,
    )

    st.markdown("**Observed Evidence**")
    for item in ai_data.get("observed_evidence", []):
        st.markdown(f"- {item}")

    st.markdown("**Investigation Checklist**")
    for item in ai_data.get("investigation_checklist", []):
        st.markdown(f"- {item}")

    st.markdown(
        f"**Recommended Disposition:** {ai_data.get('recommended_disposition', '')}"
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
# EXPORT REPORT — PDF / JSON / Markdown
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