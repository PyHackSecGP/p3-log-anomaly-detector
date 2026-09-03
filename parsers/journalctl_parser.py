"""Parse `journalctl -o json` output into unified LogEvents."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from parsers.auth_parser import _classify
from parsers.base import LogEvent


def _parse_ts(raw) -> Optional[datetime]:
    try:
        ts_us = int(raw)
        return datetime.fromtimestamp(ts_us / 1_000_000, tz=timezone.utc).replace(tzinfo=None)
    except (ValueError, TypeError, OSError):
        return None


class JournalctlParser:
    source_type = "journalctl"

    def sniff(self, first_lines: list[str]) -> bool:
        for line in first_lines:
            s = line.strip()
            if not s:
                continue
            if not s.startswith("{"):
                return False
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                return False
            return "__REALTIME_TIMESTAMP" in obj or "_HOSTNAME" in obj
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.strip()
        if not line:
            return None
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            return None

        message = entry.get("MESSAGE", "")
        if isinstance(message, list):
            try:
                message = bytes(message).decode("utf-8", errors="replace")
            except (TypeError, ValueError):
                message = ""
        if not message:
            return None

        ts = _parse_ts(entry.get("__REALTIME_TIMESTAMP"))
        host = entry.get("_HOSTNAME", "")
        service = entry.get("SYSLOG_IDENTIFIER") or entry.get("_COMM", "unknown")
        pid_raw = entry.get("_PID")
        pid = int(pid_raw) if pid_raw and str(pid_raw).isdigit() else None

        event_type, user, ip, port = _classify(message)
        raw = f"{ts} {host} {service}[{pid}]: {message}" if pid else f"{ts} {host} {service}: {message}"

        extra: dict = {"event_type": event_type}
        if pid is not None:
            extra["pid"] = pid
        if port is not None:
            extra["port"] = port

        return LogEvent(
            timestamp=ts,
            source="journalctl",
            host=host,
            service=service,
            level="info",
            message=message,
            user=user,
            ip=ip,
            raw=raw,
            extra=extra,
        )

    def parse_file(self, path: str | Path) -> list[LogEvent]:
        path = Path(path)
        events: list[LogEvent] = []
        with path.open("r", errors="replace") as fh:
            for line in fh:
                ev = self.parse_line(line)
                if ev:
                    events.append(ev)
        return events
