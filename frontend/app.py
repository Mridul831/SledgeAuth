import streamlit as st
import api_client
from components import render_metrics, render_alert_card
from mock_data import MOCK_ALERTS

st.set_page_config(
    page_title="SledgeAuth - SOC Copilot",
    page_icon="🛡️",
    layout="wide"
)

st.title("🛡️ SledgeAuth - AI Security SOC Copilot")
st.markdown("Upload Linux authentication logs to detect threats, assess risk, and get AI-powered investigation guidance.")

# Initialize session state
if "alerts" not in st.session_state:
    st.session_state.alerts = []
if "using_mock" not in st.session_state:
    st.session_state.using_mock = False

# Sidebar - Log Ingestion
with st.sidebar:
    st.header("📂 Log Ingestion")
    
    upload_option = st.radio("Choose input method:", ["Upload File", "Paste Text"])
    
    log_content = ""
    if upload_option == "Upload File":
        uploaded_file = st.file_uploader("Choose a .log file", type=["log"])
        if uploaded_file is not None:
            log_content = uploaded_file.getvalue().decode("utf-8")
    else:
        log_content = st.text_area("Paste log content here:", height=200)
        
    if st.button("🚀 Parse & Detect Threats", use_container_width=True):
        if not log_content.strip():
            st.warning("Please provide log content first.")
        else:
            with st.spinner("Parsing logs and running detection..."):
                try:
                    # 1. Parse
                    parse_resp = api_client.parse_logs(log_content)
                    events = parse_resp.get("events", [])
                    st.info(f"Parsed {len(events)} events ({parse_resp.get('error_count', 0)} errors).")
                    
                    # 2. Detect
                    detect_resp = api_client.detect_threats(events)
                    new_alerts = detect_resp.get("alerts", [])
                    st.success(f"Detection complete. Generated {len(new_alerts)} alerts.")
                    
                    # 3. Refresh alert list
                    st.session_state.alerts = api_client.get_alerts().get("alerts", [])
                    st.session_state.using_mock = False
                    
                except ConnectionError as e:
                    st.error(f"Backend connection failed: {e}")
                    st.warning("⚠️ Falling back to mock data for demonstration.")
                    st.session_state.alerts = MOCK_ALERTS["alerts"]
                    st.session_state.using_mock = True

# Main Dashboard Area
if st.session_state.using_mock:
    st.warning("⚠️ **DEMO MODE:** Backend is unavailable. Displaying mock data.")
    
# Try to fetch latest alerts on load if session is empty
if not st.session_state.alerts:
    live_alerts = api_client.get_alerts()
    if live_alerts:
        st.session_state.alerts = live_alerts.get("alerts", [])
    else:
        st.session_state.alerts = MOCK_ALERTS["alerts"]
        st.session_state.using_mock = True

# Render Metrics
st.markdown("---")
render_metrics(st.session_state.alerts)
st.markdown("---")

# Render Alerts
st.subheader("🚨 Active Alerts")
if not st.session_state.alerts:
    st.info("No alerts found. Upload a suspicious log to begin.")
else:
    for alert in st.session_state.alerts:
        render_alert_card(alert, api_client)
        
# Footer
st.markdown("---")
st.caption("SledgeAuth MVP | Built for InnoHacks 24-Hour Hackathon")