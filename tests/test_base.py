"""Unit tests for parsers.base.LogEvent + Parser protocol."""

from datetime import datetime

from parsers.base import LogEvent, Parser


def test_logevent_minimum_fields():
    ev = LogEvent(timestamp=datetime(2026, 9, 2, 12, 0, 0), source="auth")
    assert ev.source == "auth"
    assert ev.host == ""
    assert ev.level == "info"
    assert ev.extra == {}


def test_logevent_full_fields():
    ev = LogEvent(
        timestamp=datetime(2026, 9, 2, 12, 0, 0),
        source="nginx",
        host="web01",
        service="nginx",
        level="warn",
        message="404 GET /admin",
        ip="10.0.0.1",
        status_code=404,
        latency_ms=12.3,
        raw="raw line",
        extra={"path": "/admin"},
    )
    assert ev.status_code == 404
    assert ev.extra["path"] == "/admin"


def test_parser_protocol_is_runtime_checkable_via_duck_typing():
    class FakeParser:
        source_type = "fake"

        def sniff(self, first_lines):
            return True

        def parse_line(self, line):
            return None

        def parse_file(self, path):
            return []

    p = FakeParser()
    _p: Parser = p  # noqa: F841
    assert p.source_type == "fake"
