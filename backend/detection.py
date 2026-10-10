import uuid
from datetime import timedelta
from typing import List
from schemas import NormalizedEvent, Alert, EventType, AlertStatus
from risk_scoring import calculate_risk_score

def detect_brute_force(events: List[NormalizedEvent], threshold: int = 5, window_minutes: int = 5) -> List[Alert]:
    """
    Detects brute force attacks: >= threshold login_failures from same IP within window_minutes.
    """
    alerts = []
    
    # Group events by source_ip
    events_by_ip = {}
    for event in events:
        if event.source_ip:
            if event.source_ip not in events_by_ip:
                events_by_ip[event.source_ip] = []
            events_by_ip[event.source_ip].append(event)
            
    # Analyze each IP
    for ip, ip_events in events_by_ip.items():
        # Sort by timestamp
        ip_events.sort(key=lambda x: x.timestamp)
        
        failures = [e for e in ip_events if e.event_type == EventType.LOGIN_FAILURE]
        successes = [e for e in ip_events if e.event_type == EventType.LOGIN_SUCCESS]
        priv_activity = [e for e in ip_events if e.event_type == EventType.PRIVILEGE_CHANGE]
        
        # Sliding window check for failures
        for i in range(len(failures)):
            window_end = failures[i].timestamp + timedelta(minutes=window_minutes)
            window_failures = [f for f in failures if failures[i].timestamp <= f.timestamp <= window_end]
            
            if len(window_failures) >= threshold:
                # Check for corroborating successful login after the failures
                has_success_after = any(s.timestamp > window_failures[-1].timestamp for s in successes)
                
                # Check for privileged activity in the window
                has_priv = len(priv_activity) > 0
                
                # Calculate score
                score, severity = calculate_risk_score(
                    event_count=len(window_failures),
                    has_corroborating_login=has_success_after,
                    has_privileged_activity=has_priv
                )
                
                # Build evidence list
                evidence = [
                    f"{len(window_failures)} failed SSH logins from {ip} within {window_minutes} minutes",
                    f"Time window: {window_failures[0].timestamp} to {window_failures[-1].timestamp}"
                ]
                if has_success_after:
                    evidence.append("Corroborating successful login detected after failures")
                if has_priv:
                    evidence.append("Privileged activity detected from this IP")
                    
                # Create Alert
                alert = Alert(
                    alert_id=f"ALERT-{str(uuid.uuid4())[:8].upper()}",
                    timestamp=window_failures[0].timestamp,
                    host=window_failures[0].host,
                    rule_name="SSH_BRUTE_FORCE",
                    event_type=EventType.LOGIN_FAILURE,
                    source_ip=ip,
                    event_count=len(window_failures),
                    severity=severity,
                    risk_score=score,
                    evidence=evidence,
                    mitre_attack="T1110", # Brute Force
                    status=AlertStatus.OPEN
                )
                alerts.append(alert)
                break 
                
    return alerts

def detect_privileged_activity(events: List[NormalizedEvent]) -> List[Alert]:
    """
    Detects any privileged activity (sudo/su) as a separate informational alert.
    """
    alerts = []
    for event in events:
        if event.event_type == EventType.PRIVILEGE_CHANGE:
            alert = Alert(
                alert_id=f"ALERT-{str(uuid.uuid4())[:8].upper()}",
                timestamp=event.timestamp,
                host=event.host,
                rule_name="PRIVILEGED_ACTIVITY",
                event_type=EventType.PRIVILEGE_CHANGE,
                source_ip=event.source_ip,
                event_count=1,
                severity="Low", # Standalone privileged activity starts as Low
                risk_score=20,  # Base score for privileged activity
                evidence=[f"Privileged activity detected: {event.message}"],
                mitre_attack="T1548", # Abuse Elevation Control Mechanism
                status=AlertStatus.OPEN
            )
            alerts.append(alert)
    return alerts
