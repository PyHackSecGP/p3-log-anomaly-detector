"""Unified LogEvent dataclass + Parser protocol for all source-type parsers."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Optional, Protocol


@dataclass
class LogEvent:
    """Unified log event across all supported source types."""

    timestamp: Optional[datetime]
    source: str                       # "auth" | "nginx" | "syslog" | "docker" | "k8s" | "json" | "journalctl"
    host: str = ""
    service: str = ""
    level: str = "info"               # info | warn | error | critical
    message: str = ""
    user: str = ""
    ip: str = ""
    request_id: str = ""
    status_code: Optional[int] = None
    latency_ms: Optional[float] = None
    raw: str = ""
    extra: dict = field(default_factory=dict)

    # Compat properties so anomaly_detector.py works with both old and new schema
    @property
    def event_type(self) -> str:
        return self.extra.get("event_type", "")

    @property
    def source_ip(self) -> str:
        return self.ip

    @property
    def username(self) -> str:
        return self.user

    @property
    def hostname(self) -> str:
        return self.host


class Parser(Protocol):
    """Any log parser implements this protocol."""

    source_type: str

    def sniff(self, first_lines: list[str]) -> bool:
        """Return True if this parser can handle the given first non-empty lines."""
        ...

    def parse_line(self, line: str) -> Optional[LogEvent]:
        """Parse a single line into a LogEvent, or None if unparseable."""
        ...

    def parse_file(self, path: str | Path) -> list[LogEvent]:
        """Read and parse an entire file into LogEvents."""
        ...
