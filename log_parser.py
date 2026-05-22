"""
Parse Linux auth log files into structured events.
Handles both /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS).
"""

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional


@dataclass
class LogEvent:
    """A single parsed auth log entry."""

    raw: str
    timestamp: Optional[datetime]
    hostname: str
    process: str
    pid: Optional[int]
    message: str
    event_type: str = "unknown"
    username: Optional[str] = None
    source_ip: Optional[str] = None
    port: Optional[int] = None
    extra: dict = field(default_factory=dict)


# Patterns for common auth log events
_PATTERNS: list[tuple[str, re.Pattern, dict]] = [
    (
        "ssh_failed_password",
        re.compile(
            r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)"
        ),
        {},
    ),
    (
        "ssh_accepted_password",
        re.compile(
            r"Accepted password for (\S+) from ([\d.]+) port (\d+)"
        ),
        {},
    ),
    (
        "ssh_accepted_publickey",
        re.compile(
            r"Accepted publickey for (\S+) from ([\d.]+) port (\d+)"
        ),
        {},
    ),
    (
        "ssh_invalid_user",
        re.compile(
            r"Invalid user (\S+) from ([\d.]+)"
        ),
        {},
    ),
    (
        "ssh_connection_closed",
        re.compile(
            r"Connection closed by (?:invalid user )?(?:(\S+) )?([\d.]+) port (\d+)"
        ),
        {},
    ),
    (
        "sudo_session",
        re.compile(
            r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)"
        ),
        {},
    ),
    (
        "sudo_failed",
        re.compile(
            r"sudo:\s+(\S+)\s+:.*authentication failure"
        ),
        {},
    ),
    (
        "su_session",
        re.compile(
            r"su(?:do)?:.*session opened for user (\S+)(?: by (\S+))?"
        ),
        {},
    ),
    (
        "useradd",
        re.compile(
            r"useradd.*new user.*name=(\S+)"
        ),
        {},
    ),
    (
        "passwd_change",
        re.compile(
            r"passwd.*password changed for (\S+)"
        ),
        {},
    ),
    (
        "pam_failure",
        re.compile(
            r"pam_unix.*authentication failure.*user=(\S+)"
        ),
        {},
    ),
    (
        "ssh_max_auth",
        re.compile(
            r"error: maximum authentication attempts exceeded.*from ([\d.]+) port (\d+)"
        ),
        {},
    ),
    (
        "root_login",
        re.compile(
            r"ROOT LOGIN.*FROM ([\d.]+)"
        ),
        {},
    ),
    (
        "cron_session",
        re.compile(
            r"cron.*session opened for user (\S+)"
        ),
        {},
    ),
]

# syslog timestamp formats
_TS_FORMATS = [
    "%b %d %H:%M:%S",
    "%b  %d %H:%M:%S",
    "%Y-%m-%dT%H:%M:%S",
]

# Line regex: "Mon DD HH:MM:SS hostname process[pid]: message"
_LINE_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:]+(?:\.\d+)?(?:[+-]\d{4}|Z)?)\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s+"
    r"(.+)$"
)


def _parse_timestamp(raw_ts: str) -> Optional[datetime]:
    """Attempt to parse a syslog timestamp string."""
    raw_ts = raw_ts.strip()
    current_year = datetime.now().year
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(raw_ts, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=current_year)
            return dt
        except ValueError:
            continue
    return None


def _classify_event(message: str) -> tuple[str, Optional[str], Optional[str], Optional[int]]:
    """
    Return (event_type, username, source_ip, port) by matching message against known patterns.
    """
    for event_type, pattern, _ in _PATTERNS:
        m = pattern.search(message)
        if m:
            groups = m.groups()
            username: Optional[str] = None
            source_ip: Optional[str] = None
            port: Optional[int] = None

            if event_type in ("ssh_failed_password", "ssh_accepted_password", "ssh_accepted_publickey"):
                username, source_ip = groups[0], groups[1]
                port = int(groups[2]) if groups[2] else None
            elif event_type == "ssh_invalid_user":
                username, source_ip = groups[0], groups[1]
            elif event_type == "ssh_connection_closed":
                username = groups[0]
                source_ip = groups[1]
                port = int(groups[2]) if groups[2] else None
            elif event_type in ("sudo_session", "sudo_failed"):
                username = groups[0]
            elif event_type == "su_session":
                username = groups[0]
            elif event_type in ("useradd", "passwd_change", "pam_failure", "cron_session"):
                username = groups[0]
            elif event_type == "ssh_max_auth":
                source_ip = groups[0]
                port = int(groups[1]) if groups[1] else None
            elif event_type == "root_login":
                source_ip = groups[0]
                username = "root"

            return event_type, username, source_ip, port

    return "other", None, None, None


def parse_line(line: str) -> Optional[LogEvent]:
    """
    Parse a single auth log line into a LogEvent.
    Returns None for blank or unparseable lines.
    """
    line = line.rstrip("\n")
    if not line.strip():
        return None

    m = _LINE_RE.match(line)
    if not m:
        return None

    raw_ts, hostname, process, pid_str, message = m.groups()
    timestamp = _parse_timestamp(raw_ts)
    pid = int(pid_str) if pid_str else None

    event_type, username, source_ip, port = _classify_event(message)

    return LogEvent(
        raw=line,
        timestamp=timestamp,
        hostname=hostname,
        process=process,
        pid=pid,
        message=message,
        event_type=event_type,
        username=username,
        source_ip=source_ip,
        port=port,
    )


def parse_file(path: str | Path) -> list[LogEvent]:
    """
    Read and parse an entire auth log file.
    Returns a list of successfully parsed LogEvent objects.
    """
    path = Path(path)
    events: list[LogEvent] = []

    with path.open("r", errors="replace") as fh:
        for line in fh:
            event = parse_line(line)
            if event:
                events.append(event)

    return events
