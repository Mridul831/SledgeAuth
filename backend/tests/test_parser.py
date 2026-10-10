
from backend.parser import parse_auth_logs, parse_line
from backend.schemas import EventType


def test_failed_ssh_login():
    log = (
        "Oct 10 13:20:22 server-01 sshd[1234]: "
        "Failed password for admin from 192.0.2.10 port 22 ssh2"
    )

    events, errors = parse_auth_logs(log, current_year=2026)

    assert errors == 0
    assert len(events) == 1
    assert events[0].host == "server-01"
    assert events[0].event_type == EventType.LOGIN_FAILURE
    assert events[0].username == "admin"
    assert events[0].source_ip == "192.0.2.10"


def test_successful_ssh_login():
    log = (
        "Oct 10 13:21:22 server-01 sshd[1234]: "
        "Accepted publickey for alice from 192.0.2.15 port 22 ssh2"
    )

    event = parse_line(log, current_year=2026)

    assert event is not None
    assert event.event_type == EventType.LOGIN_SUCCESS
    assert event.username == "alice"
    assert event.source_ip == "192.0.2.15"


def test_missing_source_ip():
    log = (
        "Oct 10 13:22:22 server-01 sshd[1234]: "
        "Failed password for admin"
    )

    event = parse_line(log, current_year=2026)

    assert event is not None
    assert event.source_ip is None


def test_malformed_line_is_counted():
    events, errors = parse_auth_logs(
        "this is not a supported syslog record",
        current_year=2026,
    )

    assert events == []
    assert errors == 1


def test_empty_input():
    events, errors = parse_auth_logs("")

    assert events == []
    assert errors == 0
