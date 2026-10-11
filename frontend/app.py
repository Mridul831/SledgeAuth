"""AI SOC Copilot — Streamlit Dashboard (Member 4, Ocean Edition)"""

import os
import time
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
    build_all_alerts_markdown,
    build_all_alerts_json,
    build_all_alerts_pdf,
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
    render_mitre_mapping,
    render_alert_timeline,
    render_notification,
    render_analytics,
    render_clear_button,
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
    st.session_state.alerts = alerts if isinstance(alerts, list) else []
    st.session_state.alerts_error = err
if "parsed_events" not in st.session_state:
    st.session_state.parsed_events = []
if "selected" not in st.session_state:
    st.session_state.selected = None
if "ai_result" not in st.session_state:
    st.session_state.ai_result = None
if "ai_error" not in st.session_state:
    st.session_state.ai_error = None
if "last_alert_count" not in st.session_state:
    st.session_state.last_alert_count = 0

# ---------------- Sidebar ----------------
with st.sidebar:
    render_sidebar_metrics(st.session_state.alerts or [])
    st.divider()

    st.markdown("### Navigation")
    page = st.radio(
        "Go to",
        ["Dashboard", "Analytics", "Upload Logs"],
        label_visibility="collapsed",
    )

    st.divider()
    st.markdown("### Quick Actions")
    if st.button("🔄 Refresh Alerts", width="stretch"):
        alerts, err = get_alerts()
        new_alerts = alerts if isinstance(alerts, list) else []
        if len(new_alerts) > st.session_state.last_alert_count:
            st.session_state.new_alert_count = (
                len(new_alerts) - st.session_state.last_alert_count
            )
        st.session_state.alerts = new_alerts
        st.session_state.alerts_error = err
        st.session_state.last_alert_count = len(new_alerts)
        st.session_state.selected = None
        st.session_state.ai_result = None
        st.session_state.ai_error = None
        st.rerun()

    render_clear_button()

    st.divider()
    st.caption(f"API: {os.getenv('API_BASE_URL', 'http://localhost:8000')}")
    st.caption(f"Mock mode: {'ON' if USE_MOCK else 'OFF'}")

# ---------------- Header ----------------
render_topbar(USE_MOCK)

# ---------------- Notification banner ----------------
new_count = st.session_state.get("new_alert_count", 0)
if new_count > 0:
    render_notification(new_count, len(st.session_state.alerts or []))
    st.session_state.new_alert_count = 0

st.divider()


# ============================================================
# HELPER — render evidence safely
# ============================================================

def _render_evidence(evidence_items):
    if not evidence_items:
        st.caption("No evidence recorded.")
        return
    for e in evidence_items:
        if isinstance(e, dict):
            ts = e.get("timestamp", "—")
            msg = e.get("message", "—")
            st.markdown(f"- `{ts}` — {msg}")
        elif isinstance(e, str):
            st.markdown(f"- {e}")
        else:
            st.markdown(f"- {str(e)}")


# ============================================================
# PAGE: DASHBOARD
# ============================================================
if page == "Dashboard":
    alerts = st.session_state.alerts or []
    err = st.session_state.get("alerts_error")

    if err:
        st.error(f"Failed to load alerts: {err}")

    render_stats(alerts)

    trends, trends_err = get_historical_trends()
    if trends:
        render_historical_trends(trends)

    render_severity_charts(alerts)

    # ---- Bulk Export ----
    st.markdown("### 📦 Export All Alerts")
    if alerts:
        ec1, ec2, ec3 = st.columns(3)
        with ec1:
            st.download_button(
                "📄 Download All (PDF)",
                data=build_all_alerts_pdf(alerts),
                file_name=f"soc_all_alerts_{time.strftime('%Y%m%d_%H%M')}.pdf",
                mime="application/pdf",
                width="stretch",
            )
        with ec2:
            st.download_button(
                "📋 Download All (JSON)",
                data=build_all_alerts_json(alerts),
                file_name=f"soc_all_alerts_{time.strftime('%Y%m%d_%H%M')}.json",
                mime="application/json",
                width="stretch",
            )
        with ec3:
            st.download_button(
                "📝 Download All (MD)",
                data=build_all_alerts_markdown(alerts),
                file_name=f"soc_all_alerts_{time.strftime('%Y%m%d_%H%M')}.md",
                mime="text/markdown",
                width="stretch",
            )
    else:
        st.caption("No alerts to export yet.")

    # ---- Search & Filter ----
    st.markdown("### Alerts")

    fc1, fc2 = st.columns([2, 1])
    with fc1:
        search_query = st.text_input(
            "🔍 Search alerts (rule, IP, host, user)",
            placeholder="Type to search...",
            key="alert_search",
        )
    with fc2:
        severity_filter = st.selectbox(
            "🎯 Severity",
            ["All", "Critical", "High", "Medium", "Low"],
            key="severity_filter",
        )

    selected = render_alert_table(
        alerts,
        search_query=search_query,
        severity_filter=severity_filter,
    )
    if selected:
        st.session_state.selected = selected
        st.session_state.ai_result = None
        st.session_state.ai_error = None

    # ---- Alert Details ----
    alert = st.session_state.selected

    if alert:
        st.markdown("---")
        st.markdown("### 🔍 Alert Details")

        rule_name = alert.get("rule_name", "Unknown Rule")
        st.markdown(
            f"<div class='glass-card'>"
            f"<h4 style='margin-top:0;'>{rule_name}</h4>"
            f"<div style='display:flex;flex-wrap:wrap;gap:14px;"
            f"font-size:13px;color:#0c4a6e;margin:10px 0;align-items:center;'>"
            f"{severity_badge(alert.get('severity', 'Unknown'))}"
            f"<span>Host: <b>{alert.get('host') or '—'}</b></span>"
            f"<span>Source IP: <b>{alert.get('source_ip') or '—'}</b></span>"
            f"<span>User: <b>{alert.get('username') or '—'}</b></span>"
            f"<span>Events: <b>{alert.get('event_count', '—')}</b></span>"
            f"<span>Window: <b>{alert.get('time_window_seconds', '—')}s</b></span>"
            f"</div>"
            f"<div style='color:#0e7490;font-size:12px;'>"
            f"{alert.get('first_seen') or '—'} → {alert.get('last_seen') or '—'}"
            f"</div></div>",
            unsafe_allow_html=True,
        )

        render_risk_indicator(alert.get("risk_score"), alert.get("severity"))

        # ---- MITRE ATT&CK Mapping ----
        render_mitre_mapping(alert)

        det_left, det_mid, det_right = st.columns([1, 1, 1], gap="large")

        with det_left:
            render_alert_timeline(alert)

            st.markdown("**Analyst Status** *(manual decision)*")
            current = alert.get("status", "Open")
            options = ["Open", "Investigating", "Escalated", "Closed"]
            new_status = st.selectbox(
                "Status",
                options,
                index=options.index(current) if current in options else 0,
                key=f"status_{alert.get('alert_id', 'unknown')}",
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
            if st.button("🤖 Run AI Analysis", width="stretch"):
                with st.spinner("🧠 AI analyzing... (first call ~10s)"):
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

            # Export Report only visible AFTER AI analysis
            if st.session_state.ai_result is not None:
                render_export_report(alert, st.session_state.ai_result)
            else:
                st.markdown("**📄 Export Report**")
                st.caption(
                    "🔒 Run AI analysis first to unlock report export."
                )
                st.markdown(
                    "<div style='padding:12px;background:rgba(255,255,255,0.4);"
                    "border:1px dashed rgba(14,165,233,0.3);border-radius:10px;"
                    "text-align:center;color:#0e7490;font-size:12px;'>"
                    "Export buttons will appear after AI analysis</div>",
                    unsafe_allow_html=True,
                )

    else:
        st.info("👆 Select an alert from the table above to view details.")


# ============================================================
# PAGE: ANALYTICS
# ============================================================
elif page == "Analytics":
    alerts = st.session_state.alerts or []
    render_analytics(alerts)


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
            "Parse Logs", disabled=uploaded is None, width="stretch"
        ):
            if uploaded:
                with st.spinner("Parsing logs..."):
                    result, err = parse_logs(uploaded)
                if err:
                    st.error(f"Parse failed: {err}")
                else:
                    events = (
                        result.get("events", []) if result else []
                    )
                    st.session_state.parsed_events = events
                    count = len(events)
                    malformed = (
                        result.get("error_count", 0) if result else 0
                    )
                    st.success(
                        f"✅ Parsed {count} events ({malformed} malformed)"
                    )

    with c2:
        if st.button("Run Detection", width="stretch"):
            events = st.session_state.get("parsed_events", [])
            if not events:
                st.warning(
                    "⚠️ No parsed events found. Please **Parse Logs** first."
                )
            else:
                with st.spinner("Detecting..."):
                    result, err = run_detection(events)
                if err:
                    st.error(f"Detection failed: {err}")
                else:
                    alerts = (
                        result.get("alerts", []) if result else []
                    )
                    alerts = [a for a in alerts if isinstance(a, dict)]
                    total = (
                        result.get("total_events_processed", len(events))
                        if result else len(events)
                    )
                    time_ms = (
                        result.get("detection_time_ms", 0) if result else 0
                    )
                    prev_count = len(st.session_state.alerts or [])
                    st.session_state.alerts = alerts
                    st.session_state.last_alert_count = len(alerts)
                    if len(alerts) > prev_count:
                        st.session_state.new_alert_count = (
                            len(alerts) - prev_count
                        )
                    st.session_state.selected = None
                    st.session_state.ai_result = None
                    st.session_state.ai_error = None
                    st.success(
                        f"✅ Detection complete — "
                        f"{len(alerts)} alerts from {total} events "
                        f"({time_ms} ms)"
                    )
                    st.info(
                        "👉 Go to **Dashboard** in sidebar to view alerts."
                    )

    st.divider()
    st.caption(
        "💡 **Tip**: Try the sample file at "
        "`C:\\soc-copilot\\backend\\sample_data\\sample_auth.log`"
    )