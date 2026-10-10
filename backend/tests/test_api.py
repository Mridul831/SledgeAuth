
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

from backend.main import app, ALERTS
from backend.schemas import Alert, AlertStatus, EventType, Severity


client = TestClient(app)


@pytest.fixture(autouse=True)
def clear_alert_store():
    """Prevent alert state from leaking between tests."""
    ALERTS.clear()
    yield
    ALERTS.clear()


def test_health_endpoint():
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    assert response.json()["version"] == "0.1.0"


def test_parse_json_log():
    response = client.post(
        "/api/logs/parse",
        json={
            "content": (
                "Oct 10 13:20:22 server-01 sshd[1234]: "
                "Failed password for admin from "
                "192.0.2.10 port 22 ssh2"
            )
        },
    )

    assert response.status_code == 200

    result = response.json()
    assert result["parsed_count"] == 1
    assert result["error_count"] == 0

    event = result["events"][0]
    assert event["host"] == "server-01"
    assert event["event_type"] == "login_failure"
    assert event["username"] == "admin"
    assert event["source_ip"] == "192.0.2.10"


def test_parse_uploaded_log_file():
    log_content = (
        "Oct 10 13:20:22 server-01 sshd[1234]: "
        "Accepted publickey for alice from "
        "192.0.2.15 port 22 ssh2"
    )

    response = client.post(
        "/api/logs/parse",
        files={
            "file": (
                "auth.log",
                log_content.encode("utf-8"),
                "text/plain",
            )
        },
    )

    assert response.status_code == 200

    result = response.json()
    assert result["parsed_count"] == 1
    assert result["error_count"] == 0
    assert result["events"][0]["event_type"] == "login_success"
    assert result["events"][0]["username"] == "alice"


def test_parse_malformed_line():
    response = client.post(
        "/api/logs/parse",
        json={"content": "this is not a supported syslog record"},
    )

    assert response.status_code == 200
    assert response.json()["parsed_count"] == 0
    assert response.json()["error_count"] == 1


def test_parse_request_missing_content():
    response = client.post(
        "/api/logs/parse",
        json={},
    )

    assert response.status_code == 400
    assert "detail" in response.json()


def test_get_alerts_initially_empty():
    response = client.get("/api/alerts")

    assert response.status_code == 200
    assert response.json() == {"alerts": []}


def test_update_unknown_alert_returns_404():
    response = client.patch(
        "/api/alerts/UNKNOWN-001/status",
        json={"status": "Investigating"},
    )

    assert response.status_code == 404


def test_update_existing_alert_status():
    alert = Alert(
        alert_id="ALERT-TEST-001",
        timestamp=datetime(2026, 10, 10, 13, 20, tzinfo=timezone.utc),
        host="server-01",
        rule_name="SSH_BRUTE_FORCE",
        event_type=EventType.LOGIN_FAILURE,
        source_ip="192.0.2.10",
        event_count=5,
        severity=Severity.HIGH,
        risk_score=65,
        evidence=["Five failed SSH login attempts from one IP"],
        status=AlertStatus.OPEN,
    )

    ALERTS[alert.alert_id] = alert

    response = client.patch(
        "/api/alerts/ALERT-TEST-001/status",
        json={"status": "Investigating"},
    )

    assert response.status_code == 200
    assert response.json()["alert_id"] == "ALERT-TEST-001"
    assert response.json()["status"] == "Investigating"

    # Confirm the updated status is also stored.
    assert ALERTS["ALERT-TEST-001"].status == AlertStatus.INVESTIGATING