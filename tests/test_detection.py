import pytest
from datetime import datetime, timedelta
from backend.schemas import NormalizedEvent, EventType, Severity
from backend.detection import detect_brute_force

def create_event(ip, event_type, minutes_offset):
    return NormalizedEvent(
        timestamp=datetime(2026, 10, 9, 12, 0, 0) + timedelta(minutes=minutes_offset),
        host="demo-linux-01",
        event_type=event_type,
        source_ip=ip,
        message="test"
    )

def test_no_brute_force_on_normal_login():
    events = [create_event("192.168.1.1", EventType.LOGIN_SUCCESS, 0)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 0

def test_brute_force_threshold_boundary():
    # Exactly 5 failures in 5 minutes should trigger
    events = [create_event("203.0.113.25", EventType.LOGIN_FAILURE, i) for i in range(5)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 1
    assert alerts[0].risk_score == 40
    assert alerts[0].severity == Severity.MEDIUM

def test_time_window_boundary():
    # 5 failures, but spaced out so only 4 fall in a 5-min window
    events = [
        create_event("203.0.113.25", EventType.LOGIN_FAILURE, 0),
        create_event("203.0.113.25", EventType.LOGIN_FAILURE, 1),
        create_event("203.0.113.25", EventType.LOGIN_FAILURE, 2),
        create_event("203.0.113.25", EventType.LOGIN_FAILURE, 3),
        create_event("203.0.113.25", EventType.LOGIN_FAILURE, 10), # Outside window
    ]
    alerts = detect_brute_force(events)
    assert len(alerts) == 0

def test_different_ips_not_combined():
    # 3 failures from IP A, 3 from IP B. Neither should trigger.
    events = [create_event("1.1.1.1", EventType.LOGIN_FAILURE, i) for i in range(3)]
    events += [create_event("2.2.2.2", EventType.LOGIN_FAILURE, i) for i in range(3)]
    alerts = detect_brute_force(events)
    assert len(alerts) == 0
