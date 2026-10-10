import re
from datetime import datetime
from typing import List, Tuple
from .schemas import NormalizedEvent, EventType

# Map month names to numbers for timestamp parsing
MONTH_MAP = {
    'Jan': 1, 'Feb': 2, 'Mar': 3, 'Apr': 4, 'May': 5, 'Jun': 6,
    'Jul': 7, 'Aug': 8, 'Sep': 9, 'Oct': 10, 'Nov': 11, 'Dec': 12
}

# Regex for SSH logs
# Example: Oct  9 10:15:22 demo-linux-01 sshd[1234]: Accepted password for alice from 192.168.1.10 port 22 ssh2
SSH_REGEX = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sshd\[\d+\]:\s+'
    r'(?P<status>Accepted|Failed)\s+\w+\s+for\s+(?P<user>\S+)\s+'
    r'from\s+(?P<ip>\S+)\s+port'
)

# Regex for Sudo logs
# Example: Oct  9 10:30:00 demo-linux-01 sudo: pam_unix(sudo:session): session opened for user alice by (uid=0)
SUDO_REGEX = re.compile(
    r'^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d+)\s+(?P<time>\d{2}:\d{2}:\d{2})\s+'
    r'(?P<host>\S+)\s+sudo:\s+.*'
    r'session opened for user\s+(?P<user>\S+)'
)

def parse_timestamp(month_str: str, day_str: str, time_str: str) -> datetime:
    """Helper to construct a datetime object. Assumes year 2026 for the hackathon."""
    month = MONTH_MAP.get(month_str, 1)
    day = int(day_str)
    time_parts = time_str.split(':')
    # Using 2026 to match the sample data context
    return datetime(2026, month, day, int(time_parts[0]), int(time_parts[1]), int(time_parts[2]))

def parse_auth_logs(content: str) -> Tuple[List[NormalizedEvent], int]:
    """
    Parses raw auth log content into NormalizedEvent objects.
    Returns a tuple: (list_of_events, error_count)
    """
    events = []
    error_count = 0

    for line in content.splitlines():
        raw_line = line.strip()
        if not raw_line:
            continue

        # 1. Try to match SSH format
        ssh_match = SSH_REGEX.match(raw_line)
        if ssh_match:
            try:
                groups = ssh_match.groupdict()
                timestamp = parse_timestamp(groups['month'], groups['day'], groups['time'])
                
                event_type = EventType.OTHER
                if groups['status'] == 'Accepted':
                    event_type = EventType.LOGIN_SUCCESS
                elif groups['status'] == 'Failed':
                    event_type = EventType.LOGIN_FAILURE
                    
                events.append(NormalizedEvent(
                    timestamp=timestamp,
                    host=groups['host'],
                    event_type=event_type,
                    username=groups['user'],
                    source_ip=groups['ip'],
                    message=f"{groups['status']} password for {groups['user']} from {groups['ip']}",
                    raw_log=raw_line
                ))
                continue
            except Exception:
                pass # Fall through to error count if parsing fails

        # 2. Try to match Sudo format
        sudo_match = SUDO_REGEX.match(raw_line)
        if sudo_match:
            try:
                groups = sudo_match.groupdict()
                timestamp = parse_timestamp(groups['month'], groups['day'], groups['time'])
                
                events.append(NormalizedEvent(
                    timestamp=timestamp,
                    host=groups['host'],
                    event_type=EventType.PRIVILEGE_CHANGE,
                    username=groups['user'],
                    source_ip=None, # Sudo doesn't log source IP in this format
                    message=f"Privileged session opened for {groups['user']}",
                    raw_log=raw_line
                ))
                continue
            except Exception:
                pass # Fall through to error count if parsing fails

        # 3. If no regex matched, count it as an error
        error_count += 1

    return events, error_count