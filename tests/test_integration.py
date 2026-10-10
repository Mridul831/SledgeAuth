import pytest
from datetime import datetime, timedelta
from schemas import NormalizedEvent, EventType, DetectResponse
from detection import detect_brute_force, detect_privileged_activity

def create_event(ip, event_type, minutes_offset, message="test"):
    return NormalizedEvent(
        timestamp=datetime(2026, 10, 9, 12, 0, 0) + timedelta(minutes=minutes_offset),
        host="demo-linux-01",
        event_type=event_type,
        source_ip=ip,
        message=message
    )

def test_full_flow_returns_correct_schema():
    events = [
        create_event("203.0.113.25", EventType.LOGIN_FAILURE, i) for i in range(6)
    ]
    events.append(create_event("203.0.113.25", EventType.LOGIN_SUCCESS, 7))
    events.append(create_event("203.0.113.25", EventType.PRIVILEGE_CHANGE, 8, "sudo session opened"))
    
    bf_alerts = detect_brute_force(events)
    priv_alerts = detect_privileged_activity(events)
    
    assert len(bf_alerts) == 1
    bf = bf_alerts[0]
    assert bf.rule_name == "SSH_BRUTE_FORCE"
    assert bf.event_count == 6
    assert bf.risk_score == 85 
    assert bf.severity == "Critical"
    
    assert len(priv_alerts) == 1
    priv = priv_alerts[0]
    assert priv.rule_name == "PRIVILEGED_ACTIVITY"
    assert priv.risk_score == 20
    assert priv.severity == "Low"
    
    response = DetectResponse(alerts=bf_alerts + priv_alerts)
    json_data = response.model_dump()
    assert len(json_data["alerts"]) == 2
