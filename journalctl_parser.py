"""Parse journalctl JSON output into LogEvent objects.

Usage:
    journalctl -u ssh -o json > ssh.json
    journalctl -u sshd --since today -o json > auth.json
    python main.py auth.json --format journalctl --no-ai
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from log_parser import LogEvent, _classify_event


def _parse_journalctl_ts(raw: str | int) -> Optional[datetime]:
    """Parse __REALTIME_TIMESTAMP (microseconds since epoch) to datetime."""
    try:
        ts_us = int(raw)
        return datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OSError):
        return None


def parse_journalctl_line(line: str) -> Optional[LogEvent]:
    """Parse one JSON line from `journalctl -o json` output."""
    line = line.strip()
    if not line:
        return None
    try:
        entry = json.loads(line)
    except json.JSONDecodeError:
        return None

    message = entry.get("MESSAGE", "")
    if isinstance(message, list):
        # journalctl encodes binary messages as arrays of ints
        try:
            message = bytes(message).decode("utf-8", errors="replace")
        except (TypeError, ValueError):
            message = ""
    if not message:
        return None

    timestamp = _parse_journalctl_ts(entry.get("__REALTIME_TIMESTAMP"))
    hostname = entry.get("_HOSTNAME", "")
    process = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM", "unknown")
    pid_raw = entry.get("_PID")
    pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None

    raw_line = f"{timestamp} {hostname} {process}[{pid}]: {message}" if pid else f"{timestamp} {hostname} {process}: {message}"

    event_type, username, source_ip, port = _classify_event(message)

    return LogEvent(
        raw=raw_line,
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


def parse_journalctl_file(path: str | Path) -> list[LogEvent]:
    """Read and parse a journalctl JSON export file."""
    path = Path(path)
    events: list[LogEvent] = []
    with path.open("r", errors="replace") as fh:
        for line in fh:
            event = parse_journalctl_line(line)
            if event:
                events.append(event)
    return events
