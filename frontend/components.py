import streamlit as st

def severity_badge(severity: str) -> str:
    """Return a colored markdown badge based on severity."""
    colors = {
        "Low": "🟢 Low",
        "Medium": "🟡 Medium",
        "High": "🟠 High",
        "Critical": "🔴 Critical"
    }
    return colors.get(severity, severity)

def render_metrics(alerts: list):
    """Render top-level dashboard metrics."""
    total = len(alerts)
    critical = sum(1 for a in alerts if a.get("severity") == "Critical")
    high = sum(1 for a in alerts if a.get("severity") == "High")
    
    col1, col2, col3 = st.columns(3)
    col1.metric("Total Alerts", total)
    col2.metric("Critical Severity", critical)
    col3.metric("High Severity", high)

def render_alert_card(alert: dict, api_client):
    """Render a single alert card with details, evidence, and controls."""
    severity = alert.get("severity", "Low")
    rule_name = alert.get("rule_name", "Unknown Rule")
    source_ip = alert.get("source_ip", "N/A")
    score = alert.get("risk_score", 0)
    
    with st.expander(f"{severity_badge(severity)} | {rule_name} | {source_ip} (Score: {score})"):
        st.markdown(f"**Alert ID:** `{alert.get('alert_id')}`")
        st.markdown(f"**Timestamp:** {alert.get('timestamp')}")
        st.markdown(f"**Host:** {alert.get('host')}")
        st.markdown(f"**Event Count:** {alert.get('event_count')}")
        st.markdown(f"**MITRE ATT&CK:** {alert.get('mitre_attack', 'N/A')}")
        
        st.markdown("### 📋 Evidence")
        for ev in alert.get("evidence", []):
            st.markdown(f"- {ev}")
            
        # Analyst Status Control
        st.markdown("### ⚙️ Analyst Action")
        current_status = alert.get("status", "Open")
        status_options = ["Open", "Investigating", "Escalated", "Closed"]
        new_status = st.selectbox(
            "Update Status", 
            status_options, 
            index=status_options.index(current_status) if current_status in status_options else 0,
            key=f"status_{alert.get('alert_id')}"
        )
        if new_status != current_status:
            if st.button("Confirm Status Change", key=f"btn_{alert.get('alert_id')}"):
                try:
                    api_client.update_alert_status(alert.get("alert_id"), new_status)
                    st.success(f"Status updated to {new_status}")
                    st.rerun()
                except Exception as e:
                    st.error(f"Failed to update status: {e}")

        # AI Analysis Button
        st.markdown("### 🤖 AI Copilot Analysis")
        if st.button("Analyze with AI", key=f"ai_{alert.get('alert_id')}"):
            with st.spinner("Analyzing evidence..."):
                try:
                    ai_response = api_client.analyze_alert(alert)
                    
                    if ai_response.get("fallback_used"):
                        st.warning(f"⚠️ AI Fallback Used: {ai_response.get('error')}")
                    else:
                        st.success("AI Analysis Complete")
                        
                    st.markdown(f"**Summary:** {ai_response.get('alert_summary')}")
                    st.markdown(f"**Assessment:** {ai_response.get('assessment')}")
                    st.markdown(f"**Recommended Disposition:** {ai_response.get('recommended_disposition')}")
                    
                    st.markdown("**Investigation Checklist:**")
                    for item in ai_response.get("investigation_checklist", []):
                        st.checkbox(item, key=f"chk_{alert.get('alert_id')}_{item[:10]}")
                        
                except Exception as e:
                    st.error(f"AI analysis failed: {e}")