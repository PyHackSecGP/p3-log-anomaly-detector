"""Parse nginx access logs (combined log format + optional $request_time) into LogEvents."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent

# Nginx combined format:
# $remote_addr - $remote_user [$time_local] "$request" $status $bytes_sent "$http_referer" "$http_user_agent"
# Optional trailing $request_time (seconds, decimal) appended by many configs.
_COMBINED_RE = re.compile(
    r'^(?P<ip>\S+)'           # remote_addr
    r' - (?P<user>\S+)'       # remote_user (- means anonymous)
    r' \[(?P<ts>[^\]]+)\]'    # time_local
    r' "(?P<method>\S+) (?P<path>\S+) \S+"'  # request line
    r' (?P<status>\d{3})'     # status
    r' (?P<bytes>\d+)'        # bytes_sent
    r' "(?P<referer>[^"]*)"'  # http_referer
    r' "(?P<ua>[^"]*)"'       # http_user_agent
    r'(?:\s+(?P<rt>[\d.]+))?'  # optional request_time
    r'\s*$'
)

_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _status_level(code: int) -> str:
    if code >= 500:
        return "error"
    if code >= 400:
        return "warn"
    return "info"


class NginxParser:
    """Parser for nginx combined-format access logs."""

    source_type = "nginx"

    def sniff(self, first_lines: list[str]) -> bool:
        """Return True if first non-empty line matches nginx combined format."""
        for line in first_lines:
            if line.strip():
                return _COMBINED_RE.match(line.strip()) is not None
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single nginx access log line."""
        line = line.strip()
        if not line:
            return None
        m = _COMBINED_RE.match(line)
        if not m:
            return None

        ts: Optional[datetime] = None
        try:
            ts = datetime.strptime(m.group("ts"), _TS_FMT)
        except ValueError:
            pass

        status = int(m.group("status"))
        rt = m.group("rt")
        latency_ms: Optional[float] = float(rt) * 1000 if rt else None
        user = m.group("user")

        return LogEvent(
            timestamp=ts,
            source=self.source_type,
            ip=m.group("ip"),
            user="" if user == "-" else user,
            level=_status_level(status),
            message=f'{m.group("method")} {m.group("path")} {status}',
            status_code=status,
            latency_ms=latency_ms,
            raw=line,
            extra={
                "method": m.group("method"),
                "path": m.group("path"),
                "bytes": int(m.group("bytes")),
                "referer": m.group("referer"),
                "user_agent": m.group("ua"),
            },
        )

    def parse_file(self, path: str | Path) -> list[LogEvent]:
        """Read and parse an entire nginx access log file."""
        events: list[LogEvent] = []
        try:
            with open(path, "r", errors="replace") as fh:
                for line in fh:
                    ev = self.parse_line(line)
                    if ev:
                        events.append(ev)
        except OSError:
            pass
        return events
