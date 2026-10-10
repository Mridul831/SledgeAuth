# """Mock alerts — used when backend is not available."""

# MOCK_ALERTS = [
#     {
#         "alert_id": "a1b2c3d4-0001",
#         "rule_name": "Brute Force Login Attempt",
#         "event_type": "login_failure",
#         "host": "fin-ws-04",
#         "source_ip": "203.0.113.42",
#         "username": "root",
#         "event_count": 7,
#         "time_window_seconds": 300,
#         "first_seen": "2026-10-10T09:12:00Z",
#         "last_seen": "2026-10-10T09:16:30Z",
#         "risk_score": 88,
#         "severity": "Critical",
#         "status": "Open",
#         "evidence": [
#             {"timestamp": "2026-10-10T09:12:00Z", "message": "Failed password for root from 203.0.113.42"},
#             {"timestamp": "2026-10-10T09:12:45Z", "message": "Failed password for root from 203.0.113.42"},
#             {"timestamp": "2026-10-10T09:13:30Z", "message": "Failed password for root from 203.0.113.42"},
#             {"timestamp": "2026-10-10T09:14:10Z", "message": "Failed password for root from 203.0.113.42"},
#             {"timestamp": "2026-10-10T09:15:05Z", "message": "Failed password for root from 203.0.113.42"},
#             {"timestamp": "2026-10-10T09:16:00Z", "message": "Failed password for root from 203.0.113.42"},
#             {"timestamp": "2026-10-10T09:16:30Z", "message": "Failed password for root from 203.0.113.42"},
#         ],
#     },
#     {
#         "alert_id": "a1b2c3d4-0002",
#         "rule_name": "Privileged Activity After Failures",
#         "event_type": "privilege_change",
#         "host": "fin-ws-04",
#         "source_ip": "203.0.113.42",
#         "username": "admin",
#         "event_count": 3,
#         "time_window_seconds": 600,
#         "first_seen": "2026-10-10T09:20:00Z",
#         "last_seen": "2026-10-10T09:25:00Z",
#         "risk_score": 72,
#         "severity": "High",
#         "status": "Investigating",
#         "evidence": [
#             {"timestamp": "2026-10-10T09:20:00Z", "message": "sudo: admin : TTY=pts/0 ; COMMAND=/usr/bin/apt-get update"},
#             {"timestamp": "2026-10-10T09:22:00Z", "message": "sudo: admin : TTY=pts/0 ; COMMAND=/usr/bin/systemctl restart sshd"},
#             {"timestamp": "2026-10-10T09:25:00Z", "message": "user admin added to group sudo"},
#         ],
#     },
#     {
#         "alert_id": "a1b2c3d4-0003",
#         "rule_name": "Brute Force Login Attempt",
#         "event_type": "login_failure",
#         "host": "hr-ws-11",
#         "source_ip": "198.51.100.7",
#         "username": "jsmith",
#         "event_count": 5,
#         "time_window_seconds": 300,
#         "first_seen": "2026-10-10T10:01:00Z",
#         "last_seen": "2026-10-10T10:05:00Z",
#         "risk_score": 40,
#         "severity": "Medium",
#         "status": "Open",
#         "evidence": [
#             {"timestamp": "2026-10-10T10:01:00Z", "message": "Failed password for jsmith from 198.51.100.7"},
#             {"timestamp": "2026-10-10T10:02:00Z", "message": "Failed password for jsmith from 198.51.100.7"},
#             {"timestamp": "2026-10-10T10:03:00Z", "message": "Failed password for jsmith from 198.51.100.7"},
#             {"timestamp": "2026-10-10T10:04:00Z", "message": "Failed password for jsmith from 198.51.100.7"},
#             {"timestamp": "2026-10-10T10:05:00Z", "message": "Failed password for jsmith from 198.51.100.7"},
#         ],
#     },
#     {
#         "alert_id": "a1b2c3d4-0004",
#         "rule_name": "Repeated Login Failures",
#         "event_type": "login_failure",
#         "host": "db-srv-02",
#         "source_ip": "192.0.2.99",
#         "username": "postgres",
#         "event_count": 3,
#         "time_window_seconds": 300,
#         "first_seen": "2026-10-10T11:40:00Z",
#         "last_seen": "2026-10-10T11:42:00Z",
#         "risk_score": 18,
#         "severity": "Low",
#         "status": "Closed",
#         "evidence": [
#             {"timestamp": "2026-10-10T11:40:00Z", "message": "Failed password for postgres from 192.0.2.99"},
#             {"timestamp": "2026-10-10T11:41:00Z", "message": "Failed password for postgres from 192.0.2.99"},
#             {"timestamp": "2026-10-10T11:42:00Z", "message": "Failed password for postgres from 192.0.2.99"},
#         ],
#     },
# ]


# MOCK_COPILOT_RESPONSE = {
#     "alert_summary": (
#         "Repeated failed authentication attempts were observed from a single "
#         "source IP within a short time window, consistent with a brute-force pattern."
#     ),
#     "assessment": (
#         "The event pattern is consistent with a possible brute-force attempt. "
#         "This is an assessment based on the supplied evidence, not a confirmed attribution."
#     ),
#     "observed_evidence": [
#         "7 failed login attempts recorded in a 300-second window.",
#         "All attempts originated from source IP 203.0.113.42.",
#         "Targeted username: root on host fin-ws-04.",
#     ],
#     "investigation_checklist": [
#         "Verify whether the source IP is internal or external.",
#         "Check if any successful login followed the failures.",
#         "Review firewall/IDS logs for the same source IP.",
#         "Confirm the targeted account is not locked out.",
#     ],
#     "recommended_disposition": (
#         "Escalate to a human analyst for review. Do not auto-block or disable accounts."
#     ),
#     "ai_fallback": False,
# }


# Fallback data matching the exact backend schema
MOCK_ALERTS = {
    "alerts": [
        {
            "alert_id": "ALERT-A1B2C3D4",
            "timestamp": "2026-10-10T13:51:32",
            "host": "demo-linux-01",
            "rule_name": "SSH_BRUTE_FORCE",
            "event_type": "login_failure",
            "source_ip": "203.0.113.25",
            "event_count": 6,
            "severity": "Critical",
            "risk_score": 85,
            "evidence": [
                "6 failed SSH logins from 203.0.113.25 within 5 minutes",
                "Corroborating successful login detected after failures"
            ],
            "mitre_attack": "T1110",
            "status": "Open"
        },
        {
            "alert_id": "ALERT-X9Y8Z7W6",
            "timestamp": "2026-10-10T14:05:00",
            "host": "demo-linux-01",
            "rule_name": "PRIVILEGED_ACTIVITY",
            "event_type": "privilege_change",
            "source_ip": "192.168.1.10",
            "event_count": 1,
            "severity": "Low",
            "risk_score": 20,
            "evidence": [
                "Privileged activity detected: sudo session opened for user alice"
            ],
            "mitre_attack": "T1548",
            "status": "Open"
        }
    ]
}