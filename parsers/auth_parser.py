"""Parse Linux auth log files into unified LogEvents.

Handles /var/log/auth.log (Debian/Ubuntu) and /var/log/secure (RHEL/CentOS).
event_type + pid + port are stored in LogEvent.extra so downstream detectors
can still discriminate SSH/sudo/useradd events without a schema change.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent


_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("ssh_failed_password",   re.compile(r"Failed password for (?:invalid user )?(\S+) from ([\d.]+) port (\d+)")),
    ("ssh_accepted_password", re.compile(r"Accepted password for (\S+) from ([\d.]+) port (\d+)")),
    ("ssh_accepted_publickey",re.compile(r"Accepted publickey for (\S+) from ([\d.]+) port (\d+)")),
    ("ssh_invalid_user",      re.compile(r"Invalid user (\S+) from ([\d.]+)")),
    ("ssh_connection_closed", re.compile(r"Connection closed by (?:invalid user )?(?:(\S+) )?([\d.]+) port (\d+)")),
    ("sudo_session",          re.compile(r"sudo:\s+(\S+)\s+:.*COMMAND=(.*)")),
    ("sudo_failed",           re.compile(r"sudo:\s+(\S+)\s+:.*authentication failure")),
    ("su_session",            re.compile(r"su(?:do)?:.*session opened for user (\S+)(?: by (\S+))?")),
    ("useradd",               re.compile(r"new user.*name=([^,\s]+)")),
    ("passwd_change",         re.compile(r"passwd.*password changed for (\S+)")),
    ("pam_failure",           re.compile(r"pam_unix.*authentication failure.*user=(\S+)")),
    ("ssh_max_auth",          re.compile(r"error: maximum authentication attempts exceeded.*from ([\d.]+) port (\d+)")),
    ("root_login",            re.compile(r"ROOT LOGIN.*FROM ([\d.]+)")),
    ("cron_session",          re.compile(r"cron.*session opened for user (\S+)")),
]

_LINE_RE = re.compile(
    r"^(\w{3}\s+\d+\s+\d+:\d+:\d+|\d{4}-\d{2}-\d{2}T[\d:]+(?:\.\d+)?(?:[+-]\d{4}|Z)?)\s+"
    r"(\S+)\s+"
    r"(\S+?)(?:\[(\d+)\])?:\s+"
    r"(.+)$"
)

_TS_FORMATS = ["%b %d %H:%M:%S", "%b  %d %H:%M:%S", "%Y-%m-%dT%H:%M:%S"]

_AUTH_SERVICES = {"sshd", "sudo", "su", "useradd", "passwd", "login", "cron", "pam_unix"}


def _parse_ts(raw: str) -> Optional[datetime]:
    """Parse a syslog timestamp string into a datetime, filling in the current year."""
    year = datetime.now().year
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(raw.strip(), fmt)
            if dt.year == 1900:
                dt = dt.replace(year=year)
            return dt
        except ValueError:
            continue
    return None


def _classify(message: str) -> tuple[str, str, str, Optional[int]]:
    """Return (event_type, user, ip, port) by matching message against known patterns."""
    for event_type, pattern in _PATTERNS:
        m = pattern.search(message)
        if not m:
            continue
        g = m.groups()
        user = ""
        ip = ""
        port: Optional[int] = None
        if event_type in ("ssh_failed_password", "ssh_accepted_password", "ssh_accepted_publickey"):
            user, ip = g[0], g[1]
            port = int(g[2]) if g[2] else None
        elif event_type == "ssh_invalid_user":
            user, ip = g[0], g[1]
        elif event_type == "ssh_connection_closed":
            user = g[0] or ""
            ip = g[1]
            port = int(g[2]) if g[2] else None
        elif event_type in ("sudo_session", "sudo_failed", "su_session",
                            "useradd", "passwd_change", "pam_failure", "cron_session"):
            user = g[0]
        elif event_type == "ssh_max_auth":
            ip = g[0]
            port = int(g[1]) if g[1] else None
        elif event_type == "root_login":
            ip = g[0]
            user = "root"
        return event_type, user, ip, port
    return "other", "", "", None


class AuthParser:
    """Parser for Linux auth log files producing unified LogEvents."""

    source_type = "auth"

    def sniff(self, first_lines: list[str]) -> bool:
        """Return True if the first lines look like auth log entries from known services."""
        for line in first_lines:
            s = line.strip()
            if not s or s.startswith("{"):
                continue
            m = _LINE_RE.match(s)
            if not m:
                continue
            service = m.group(3)
            if service in _AUTH_SERVICES:
                return True
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single auth log line into a LogEvent, or None if blank/unparseable."""
        line = line.rstrip("\n")
        if not line.strip():
            return None
        m = _LINE_RE.match(line)
        if not m:
            return None
        raw_ts, host, service, pid_str, message = m.groups()
        pid = int(pid_str) if pid_str else None
        event_type, user, ip, port = _classify(message)

        extra: dict = {"event_type": event_type}
        if pid is not None:
            extra["pid"] = pid
        if port is not None:
            extra["port"] = port

        return LogEvent(
            timestamp=_parse_ts(raw_ts),
            source="auth",
            host=host,
            service=service,
            level="warn" if event_type.endswith("_failed") or "failure" in event_type else "info",
            message=message,
            user=user,
            ip=ip,
            raw=line,
            extra=extra,
        )

    def parse_file(self, path: str | Path) -> list[LogEvent]:
        """Read and parse an entire auth log file into a list of LogEvents."""
        path = Path(path)
        events: list[LogEvent] = []
        with path.open("r", errors="replace") as fh:
            for line in fh:
                ev = self.parse_line(line)
                if ev:
                    events.append(ev)
        return events
