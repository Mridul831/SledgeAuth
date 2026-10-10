
"""
Linux authentication log parser for SledgeAuth.

Supported input:
- Traditional syslog authentication lines, e.g.:
  Oct 10 13:20:22 server-01 sshd[1234]: Failed password ...
- ISO 8601 timestamped authentication lines, e.g.:
  2026-10-10T13:20:22Z server-01 sshd[1234]: Accepted password ...

Returns normalized events matching backend/schemas.py.
"""

import ipaddress
import re
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from .schemas import EventType, NormalizedEvent


# Traditional Linux syslog format. The year is not present in this format.
SYSLOG_PATTERN = re.compile(
    r"^(?P<month>Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r"\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.+)$"
)

# ISO 8601 timestamp followed by host and message.
ISO_SYSLOG_PATTERN = re.compile(
    r"^(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}"
    r"(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<message>.+)$"
)

# Match plausible IPv4 and IPv6 candidates; validate them with ipaddress.
IP_CANDIDATE_PATTERN = re.compile(
    r"(?<![0-9A-Za-z])"
    r"(?:\d{1,3}(?:\.\d{1,3}){3}|[0-9A-Fa-f]*:[0-9A-Fa-f:]+)"
    r"(?![0-9A-Za-z])"
)

USERNAME_PATTERNS = [
    re.compile(r"\bFailed password for invalid user (\S+)", re.IGNORECASE),
    re.compile(r"\bInvalid user (\S+)", re.IGNORECASE),
    re.compile(r"\bFailed password for (\S+)", re.IGNORECASE),
    re.compile(r"\bAccepted \S+ for (\S+)", re.IGNORECASE),
    re.compile(r"\bsession opened for user (\S+)", re.IGNORECASE),
    re.compile(r"\buser=([^\s;]+)", re.IGNORECASE),
    re.compile(r"\bsudo:\s+([\w.-]+)\s*:", re.IGNORECASE),
    re.compile(r"\bsu(?:\[\d+\])?:\s+\+?\s*(?:pam_unix\([^)]*\):\s*)?session opened for user (\S+)", re.IGNORECASE),
]


def normalize_timestamp(value: datetime) -> datetime:
    """Return a timezone-aware UTC datetime."""
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)

    return value.astimezone(timezone.utc)


def parse_timestamp(
    line: str,
    current_year: Optional[int] = None,
) -> Optional[Tuple[datetime, str, str]]:
    """
    Extract timestamp, host, and message from a supported log line.

    Traditional syslog records have no year or timezone. For this prototype,
    their year is assumed to be the current UTC year and their timestamp is
    interpreted as UTC. Use source-specific timezone/year information when
    available for historical or production analysis.
    """
    iso_match = ISO_SYSLOG_PATTERN.match(line)

    if iso_match:
        timestamp_text = iso_match.group("timestamp")

        try:
            value = timestamp_text.replace("Z", "+00:00")
            timestamp = normalize_timestamp(datetime.fromisoformat(value))
        except ValueError:
            return None

        return (
            timestamp,
            iso_match.group("host"),
            iso_match.group("message"),
        )

    syslog_match = SYSLOG_PATTERN.match(line)

    if not syslog_match:
        return None

    year = current_year if current_year is not None else datetime.now(
        timezone.utc
    ).year

    timestamp_text = (
        f"{year} "
        f"{syslog_match.group('month')} "
        f"{syslog_match.group('day')} "
        f"{syslog_match.group('time')}"
    )

    try:
        timestamp = datetime.strptime(
            timestamp_text,
            "%Y %b %d %H:%M:%S",
        ).replace(tzinfo=timezone.utc)
    except ValueError:
        return None

    return (
        timestamp,
        syslog_match.group("host"),
        syslog_match.group("message"),
    )


def classify_event(message: str) -> EventType:
    """Classify common Linux authentication messages deterministically."""
    text = message.lower()

    # Check failures first to avoid misclassifying failed authentication.
    failure_indicators = (
        "failed password",
        "failed publickey",
        "authentication failure",
        "invalid user",
        "authentication failed",
    )

    if any(indicator in text for indicator in failure_indicators):
        return EventType.LOGIN_FAILURE

    success_indicators = (
        "accepted password",
        "accepted publickey",
        "accepted keyboard-interactive",
    )

    if any(indicator in text for indicator in success_indicators):
        return EventType.LOGIN_SUCCESS

    privilege_indicators = (
        "sudo:",
        " su:",
        "user=root",
        "user=root ",
        "pam_unix(su:",
        "pam_unix(sudo:",
    )

    if any(indicator in text for indicator in privilege_indicators):
        return EventType.PRIVILEGE_CHANGE

    return EventType.OTHER


def extract_username(message: str) -> Optional[str]:
    """Extract a username from recognized Linux authentication messages."""
    for pattern in USERNAME_PATTERNS:
        match = pattern.search(message)

        if match:
            username = match.group(1).strip().rstrip(",:;")

            if username and username.lower() not in {
                "unknown",
                "(unknown",
            }:
                return username

    return None


def extract_source_ip(message: str) -> Optional[str]:
    """
    Extract and validate an IPv4 or IPv6 address.

    Missing or invalid addresses are returned as None, never fabricated.
    """
    for candidate in IP_CANDIDATE_PATTERN.findall(message):
        try:
            return str(ipaddress.ip_address(candidate))
        except ValueError:
            continue

    return None


def parse_line(
    raw_line: str,
    current_year: Optional[int] = None,
) -> Optional[NormalizedEvent]:
    """
    Parse one supported authentication log line.

    Returns None if the line is empty, malformed, or unsupported.
    """
    line = raw_line.strip()

    if not line:
        return None

    parsed = parse_timestamp(line, current_year=current_year)

    if parsed is None:
        return None

    timestamp, host, message = parsed

    return NormalizedEvent(
        timestamp=timestamp,
        host=host,
        event_type=classify_event(message),
        username=extract_username(message),
        source_ip=extract_source_ip(message),
        message=message,
        raw_log=raw_line,
    )


def parse_auth_logs(
    content: str,
    current_year: Optional[int] = None,
) -> Tuple[List[NormalizedEvent], int]:
    """
    Parse multiple Linux authentication log lines.

    Returns:
        A tuple containing:
        - A list of normalized events.
        - The number of non-empty lines that could not be parsed.

    Blank lines are ignored. Unsupported or malformed non-empty lines
    increment error_count but do not stop the remaining lines from parsing.
    """
    events: List[NormalizedEvent] = []
    error_count = 0

    if not content or not content.strip():
        return events, 0

    for raw_line in content.splitlines():
        if not raw_line.strip():
            continue

        event = parse_line(raw_line, current_year=current_year)

        if event is None:
            error_count += 1
            continue

        events.append(event)

    return events, error_count


# Compatibility aliases for convenient reuse by the API layer.
parse_file = parse_auth_logs