"""AI SOC Copilot — Streamlit Dashboard (Member 4, Ocean Edition)"""

import os
import streamlit as st
from dotenv import load_dotenv

from api_client import (
    get_health,
    get_alerts,
    parse_logs,
    run_detection,
    analyze_alert,
    update_alert_status,
    get_historical_trends,
)
from components import (
    inject_glass_css,
    render_topbar,
    render_stats,
    render_severity_charts,
    render_alert_table,
    render_risk_indicator,
    render_ai_block,
    render_sidebar_metrics,
    render_historical_trends,
    render_voice_briefing,
    render_export_report,
    severity_badge,
)

load_dotenv()
USE_MOCK = os.getenv("USE_MOCK", "true").lower() == "true"

# ---------------- Page config ----------------
st.set_page_config(
    page_title="AI SOC Copilot",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

inject_glass_css()

# ---------------- Session state ----------------
if "health" not in st.session_state:
    st.session_state.health = get_health()
if "alerts" not in st.session_state:
    alerts, err = get_alerts()
    st.session_state.alerts = alerts
    st.session_state.alerts_error = err
if "selected" not in st.session_state:
    st.session_state.selected = None
if "ai_result" not in st.session_state:
    st.session_state.ai_result = None
if "ai_error" not in st.session_state:
    st.session_state.ai_error = None

# ---------------- Sidebar ----------------
with st.sidebar:
    render_sidebar_metrics(st.session_state.alerts or [])
    st.divider()

    st.markdown("### Navigation")
    page = st.radio(
        "Go to",
        ["Dashboard", "Upload Logs"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("### Quick Actions")
    if st.button("🔄 Refresh Alerts", use_container_width=True):
        alerts, err = get_alerts()
        st.session_state.alerts = alerts
        st.session_state.alerts_error = err
        st.session_state.selected = None
        st.session_state.ai_result = None
        st.session_state.ai_error = None
        st.rerun()

    st.divider()
    st.caption(f"API: {os.getenv('API_BASE_URL', 'http://localhost:8000')}")
    st.caption(f"Mock mode: {'ON' if USE_MOCK else 'OFF'}")

# ---------------- Header ----------------
render_topbar(USE_MOCK)
st.divider()


# ============================================================
# PAGE: DASHBOARD
# ============================================================
if page == "Dashboard":
    alerts = st.session_state.alerts or []
    err = st.session_state.get("alerts_error")

    if err:
        st.error(f"Failed to load alerts: {err}")

    # ---- Row 1: Stats ----
    render_stats(alerts)

    # ---- Row 2: Historical Trends (full width) ----
    trends, trends_err = get_historical_trends()
    if trends:
        render_historical_trends(trends)
    elif trends_err:
        st.warning(f"Could not load trends: {trends_err}")

    # ---- Row 3: Severity charts (pie + bar, side-by-side) ----
    render_severity_charts(alerts)

    # ---- Row 4: Alerts table (full width) ----
    st.markdown("### Alerts")
    selected = render_alert_table(alerts)
    if selected:
        st.session_state.selected = selected
        st.session_state.ai_result = None
        st.session_state.ai_error = None

    # ---- Row 5: Alert Details (full width, appears after click) ----
    alert = st.session_state.selected

    if alert:
        st.markdown("---")
        st.markdown("### 🔍 Alert Details")

        st.markdown(
            f"<div class='glass-card'>"
            f"<h4 style='margin-top:0;'>{alert.get('rule_name')}</h4>"
            f"<div style='display:flex;flex-wrap:wrap;gap:14px;"
            f"font-size:13px;color:#0c4a6e;margin:10px 0;align-items:center;'>"
            f"{severity_badge(alert.get('severity', 'Unknown'))}"
            f"<span>Host: <b>{alert.get('host') or '—'}</b></span>"
            f"<span>Source IP: <b>{alert.get('source_ip') or '—'}</b></span>"
            f"<span>User: <b>{alert.get('username') or '—'}</b></span>"
            f"<span>Events: <b>{alert.get('event_count')}</b></span>"
            f"<span>Window: <b>{alert.get('time_window_seconds')}s</b></span>"
            f"</div>"
            f"<div style='color:#0e7490;font-size:12px;'>"
            f"{alert.get('first_seen')} → {alert.get('last_seen')}"
            f"</div></div>",
            unsafe_allow_html=True,
        )

        render_risk_indicator(
            alert.get("risk_score"), alert.get("severity")
        )

        # --- Three columns: Evidence | AI | Voice + Export ---
        det_left, det_mid, det_right = st.columns([1, 1, 1], gap="large")

        with det_left:
            with st.expander(
                f"Evidence ({len(alert.get('evidence', []))})", expanded=True
            ):
                for e in alert.get("evidence", []):
                    st.markdown(
                        f"- `{e.get('timestamp')}` — {e.get('message')}"
                    )

            st.markdown("**Analyst Status** *(manual decision)*")
            current = alert.get("status", "Open")
            options = ["Open", "Investigating", "Escalated", "Closed"]
            new_status = st.selectbox(
                "Status",
                options,
                index=options.index(current) if current in options else 0,
                key=f"status_{alert.get('alert_id')}",
                label_visibility="collapsed",
            )
            if new_status != current:
                if st.button("Save Status"):
                    _, err2 = update_alert_status(
                        alert.get("alert_id"), new_status
                    )
                    if err2:
                        st.error(f"Failed: {err2}")
                    else:
                        for a in st.session_state.alerts:
                            if a.get("alert_id") == alert.get("alert_id"):
                                a["status"] = new_status
                        st.session_state.selected["status"] = new_status
                        st.success(f"Status → {new_status}")
                        st.rerun()

        with det_mid:
            st.markdown("**AI Investigation Guidance**")
            if st.button("🤖 Run AI Analysis", use_container_width=True):
                with st.spinner("Analyzing..."):
                    result, err3 = analyze_alert(alert)
                    st.session_state.ai_result = result
                    st.session_state.ai_error = err3

            is_fallback = (
                st.session_state.ai_result
                and st.session_state.ai_result.get("ai_fallback") is True
            )
            render_ai_block(
                st.session_state.ai_result,
                st.session_state.ai_error,
                is_fallback,
            )

        with det_right:
            render_voice_briefing(alert, st.session_state.ai_result)
            st.divider()
            render_export_report(alert, st.session_state.ai_result)

    else:
        st.info("👆 Select an alert from the table above to view details.")


# ============================================================
# PAGE: UPLOAD LOGS
# ============================================================
elif page == "Upload Logs":
    st.markdown("### Upload Logs & Run Detection")

    uploaded = st.file_uploader(
        "Choose a .log or .txt file", type=["log", "txt"]
    )

    c1, c2 = st.columns(2)
    with c1:
        if st.button(
            "Parse Logs", disabled=uploaded is None, use_container_width=True
        ):
            if uploaded:
                with st.spinner("Parsing..."):
                    result, err = parse_logs(uploaded)
                if err:
                    st.error(f"Parse failed: {err}")
                else:
                    count = (
                        len(result.get("parsed_events", [])) if result else 0
                    )
                    st.success(f"Parsed {count} events.")

    with c2:
        if st.button("Run Detection", use_container_width=True):
            with st.spinner("Detecting..."):
                result, err = run_detection()
            if err:
                st.error(f"Detection failed: {err}")
            else:
                alerts = result.get("alerts", []) if result else []
                st.session_state.alerts = alerts
                st.session_state.selected = None
                st.session_state.ai_result = None
                st.session_state.ai_error = None
                st.success(f"Detection produced {len(alerts)} alerts.")
                st.rerun()