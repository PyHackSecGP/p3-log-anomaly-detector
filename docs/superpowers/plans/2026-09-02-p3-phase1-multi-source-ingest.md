# P3 Phase 1: Multi-Source Ingest + Common Event Schema — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Grow P3 from an auth-log-only tool into a multi-source log ingestor. Add parsers for nginx access logs, generic syslog, Docker container logs, Kubernetes pod logs, and generic JSON application logs. Normalize every input into one `LogEvent` dataclass so the existing anomaly engine works across all formats.

**Architecture:** New `parsers/` package with a `base.py` defining the unified `LogEvent` dataclass and a `Parser` protocol (`parse_line`, `parse_file`, `sniff`). Every format is a module implementing that protocol. A registry (`parsers/registry.py`) exposes `get_parser(name)` and `auto_detect(path)`. `main.py` gains a `--source-type` flag. `anomaly_detector.py` is updated to read new field names (`ip`, `user`, `host`) while keeping detection logic identical.

**Tech Stack:** Python 3.11 stdlib only (no new runtime deps). `pytest` added as dev dependency for tests.

**Reference:** Master plan at `docs/superpowers/plans/2026-09-02-p3-full-wishlist-master.md`. This document is the Phase 1 detailed TDD plan.

**Branch:** `feat/phase-1-multi-source` off `master`.

---

## File Structure

**New files:**
- `parsers/__init__.py` — package marker, re-exports `LogEvent`, `Parser`, `get_parser`, `auto_detect`
- `parsers/base.py` — `LogEvent` dataclass + `Parser` protocol
- `parsers/auth_parser.py` — new home for auth-log parsing (moved + adapted from `log_parser.py`)
- `parsers/journalctl_parser.py` — moved + adapted from top-level `journalctl_parser.py`
- `parsers/nginx_parser.py` — nginx access-log combined format
- `parsers/syslog_parser.py` — generic RFC 3164/5424 syslog
- `parsers/docker_parser.py` — `docker logs --timestamps` JSON output OR plain
- `parsers/k8s_parser.py` — kubelet/CRI log format
- `parsers/json_parser.py` — generic app JSON logs (one JSON per line)
- `parsers/registry.py` — `SOURCE_TYPES`, `get_parser`, `auto_detect`
- `tests/__init__.py`
- `tests/conftest.py` — fixture paths
- `tests/test_base.py`
- `tests/test_auth_parser.py`
- `tests/test_journalctl_parser.py`
- `tests/test_nginx_parser.py`
- `tests/test_syslog_parser.py`
- `tests/test_docker_parser.py`
- `tests/test_k8s_parser.py`
- `tests/test_json_parser.py`
- `tests/test_registry.py`
- `tests/test_integration_all_parsers.py`
- `tests/test_regression_auth.py`
- `tests/fixtures/auth.log`
- `tests/fixtures/journalctl.jsonl`
- `tests/fixtures/nginx_access.log`
- `tests/fixtures/syslog.log`
- `tests/fixtures/docker.log`
- `tests/fixtures/k8s.log`
- `tests/fixtures/app.jsonl`

**Modified files:**
- `main.py` — add `--source-type auto|auth|journalctl|nginx|syslog|docker|k8s|json` flag; dispatch through `parsers.get_parser`; keep `--format` as deprecated alias
- `anomaly_detector.py` — rename field access from `source_ip`→`ip`, `username`→`user`, `hostname`→`host`; read `event_type` from `LogEvent.extra["event_type"]` (auth parser populates it)
- `report_generator.py` — same field-rename pass; no behavioural change
- `journalctl_parser.py` (top-level) — becomes a thin shim re-exporting from `parsers.journalctl_parser` (back-compat)
- `log_parser.py` (top-level) — becomes a thin shim re-exporting from `parsers.auth_parser` (back-compat)
- `requirements.txt` — no change (stdlib only)
- `README.md` — new "Supported sources" section

**Deleted files:** None. Old modules stay as compatibility shims for one release.

---

## LogEvent schema (final, canonical)

```python
# parsers/base.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Protocol


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
```

Field-mapping cheat sheet (used across all parsers):

| Legacy auth field | New `LogEvent` field |
|---|---|
| `source_ip` | `ip` |
| `username` | `user` |
| `hostname` | `host` |
| `process` | `service` |
| `event_type` | `extra["event_type"]` |
| `pid` | `extra["pid"]` |
| `port` | `extra["port"]` |

---

## Tasks

### Task 0: Branch, pytest bootstrap, empty tests folder

**Files:**
- Create: `tests/__init__.py`, `tests/conftest.py`
- Modify: `.gitignore` (add `.pytest_cache/`)

- [ ] **Step 1: Create the feature branch**

```bash
cd ~/projects/p3-log-anomaly-detector
git checkout master
git pull origin master
git checkout -b feat/phase-1-multi-source
```

- [ ] **Step 2: Install pytest (system pip is fine)**

```bash
python3 -m pip install --user pytest
```

Expected: pytest 8.x installed.

- [ ] **Step 3: Create empty tests package**

Write `tests/__init__.py` with contents:

```python
```

Write `tests/conftest.py`:

```python
"""Shared pytest fixtures for P3 tests."""

from pathlib import Path

import pytest


@pytest.fixture
def fixtures_dir() -> Path:
    """Absolute path to tests/fixtures/."""
    return Path(__file__).parent / "fixtures"
```

- [ ] **Step 4: Update .gitignore**

Append these lines to `.gitignore` (do not remove any existing lines):

```
.pytest_cache/
__pycache__/
*.pyc
```

- [ ] **Step 5: Verify pytest runs (no tests yet)**

Run: `python3 -m pytest tests/ -v`
Expected: `no tests ran in 0.0Xs` (exit code 5 is acceptable).

- [ ] **Step 6: Commit**

```bash
git add tests/__init__.py tests/conftest.py .gitignore
git commit -m "chore: bootstrap pytest and tests/ folder for phase 1"
```

---

### Task 1: `LogEvent` dataclass + `Parser` protocol

**Files:**
- Create: `parsers/__init__.py`, `parsers/base.py`
- Test: `tests/test_base.py`

- [ ] **Step 1: Write the failing test**

Write `tests/test_base.py`:

```python
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
    # Duck-typed assignment must satisfy Parser protocol at type-check time
    _p: Parser = p  # noqa: F841
    assert p.source_type == "fake"
```

- [ ] **Step 2: Run the test to verify it fails**

Run: `python3 -m pytest tests/test_base.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'parsers'`.

- [ ] **Step 3: Create `parsers/__init__.py`**

```python
"""Multi-source log parsers for P3."""

from parsers.base import LogEvent, Parser

__all__ = ["LogEvent", "Parser"]
```

- [ ] **Step 4: Create `parsers/base.py`**

Copy the exact code from the "LogEvent schema (final, canonical)" section above into `parsers/base.py`.

- [ ] **Step 5: Run the test to verify it passes**

Run: `python3 -m pytest tests/test_base.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/__init__.py parsers/base.py tests/test_base.py
git commit -m "feat(parsers): add unified LogEvent dataclass and Parser protocol"
```

---

### Task 2: Auth parser adapted to new schema

**Files:**
- Create: `parsers/auth_parser.py`
- Create: `tests/fixtures/auth.log`
- Create: `tests/test_auth_parser.py`

- [ ] **Step 1: Create the fixture**

Write `tests/fixtures/auth.log`:

```
May 22 01:00:01 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2
May 22 01:00:02 web01 sshd[1234]: Accepted publickey for tony from 10.0.0.1 port 55000 ssh2
May 22 01:00:03 web01 sudo[9999]: tony : TTY=pts/0 ; PWD=/home/tony ; USER=root ; COMMAND=/bin/ls
May 22 01:00:04 web01 useradd[2222]: new user: name=hacker, UID=1337, GID=1337
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_auth_parser.py`:

```python
"""Auth-log parser tests using the unified LogEvent schema."""

from parsers.auth_parser import AuthParser


def test_parses_failed_password(fixtures_dir):
    parser = AuthParser()
    events = parser.parse_file(fixtures_dir / "auth.log")
    assert len(events) == 4

    e = events[0]
    assert e.source == "auth"
    assert e.host == "web01"
    assert e.service == "sshd"
    assert e.user == "root"
    assert e.ip == "192.168.1.100"
    assert e.extra["event_type"] == "ssh_failed_password"
    assert e.extra["pid"] == 1234
    assert e.extra["port"] == 22345


def test_parses_accepted_publickey(fixtures_dir):
    events = AuthParser().parse_file(fixtures_dir / "auth.log")
    e = events[1]
    assert e.extra["event_type"] == "ssh_accepted_publickey"
    assert e.user == "tony"
    assert e.ip == "10.0.0.1"


def test_parses_useradd(fixtures_dir):
    events = AuthParser().parse_file(fixtures_dir / "auth.log")
    e = events[3]
    assert e.extra["event_type"] == "useradd"
    assert e.user == "hacker"


def test_sniff_accepts_auth_lines():
    parser = AuthParser()
    assert parser.sniff([
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ]) is True


def test_sniff_rejects_json_lines():
    parser = AuthParser()
    assert parser.sniff(['{"MESSAGE": "hi"}']) is False


def test_parse_line_returns_none_for_blank():
    assert AuthParser().parse_line("") is None
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_auth_parser.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'parsers.auth_parser'`.

- [ ] **Step 4: Create `parsers/auth_parser.py`**

Write this file. It reuses the regex pattern list from the existing `log_parser.py` but emits new-schema `LogEvent`s:

```python
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
    ("useradd",               re.compile(r"useradd.*new user.*name=(\S+)")),
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
    """Return (event_type, user, ip, port)."""
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
    source_type = "auth"

    def sniff(self, first_lines: list[str]) -> bool:
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
        path = Path(path)
        events: list[LogEvent] = []
        with path.open("r", errors="replace") as fh:
            for line in fh:
                ev = self.parse_line(line)
                if ev:
                    events.append(ev)
        return events
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_auth_parser.py -v`
Expected: 6 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/auth_parser.py tests/fixtures/auth.log tests/test_auth_parser.py
git commit -m "feat(parsers): AuthParser producing unified LogEvent"
```

---

### Task 3: Journalctl parser adapted to new schema

**Files:**
- Create: `parsers/journalctl_parser.py`
- Create: `tests/fixtures/journalctl.jsonl`
- Create: `tests/test_journalctl_parser.py`

- [ ] **Step 1: Create the fixture**

Write `tests/fixtures/journalctl.jsonl` (one JSON object per line):

```
{"__REALTIME_TIMESTAMP":"1748049601000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","_PID":"1234","MESSAGE":"Failed password for root from 192.168.1.100 port 22345 ssh2"}
{"__REALTIME_TIMESTAMP":"1748049602000000","_HOSTNAME":"web01","SYSLOG_IDENTIFIER":"sshd","_PID":"1234","MESSAGE":"Accepted publickey for tony from 10.0.0.1 port 55000 ssh2"}
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_journalctl_parser.py`:

```python
from parsers.journalctl_parser import JournalctlParser


def test_parses_journalctl_json(fixtures_dir):
    events = JournalctlParser().parse_file(fixtures_dir / "journalctl.jsonl")
    assert len(events) == 2
    e = events[0]
    assert e.source == "journalctl"
    assert e.host == "web01"
    assert e.service == "sshd"
    assert e.user == "root"
    assert e.ip == "192.168.1.100"
    assert e.extra["event_type"] == "ssh_failed_password"


def test_sniff_matches_json_lines():
    p = JournalctlParser()
    assert p.sniff(['{"__REALTIME_TIMESTAMP":"1","MESSAGE":"hi"}']) is True


def test_sniff_rejects_syslog_lines():
    assert JournalctlParser().sniff([
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root"
    ]) is False


def test_ignores_blank_and_invalid_json():
    p = JournalctlParser()
    assert p.parse_line("") is None
    assert p.parse_line("not json") is None
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_journalctl_parser.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'parsers.journalctl_parser'`.

- [ ] **Step 4: Create `parsers/journalctl_parser.py`**

```python
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_journalctl_parser.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/journalctl_parser.py tests/fixtures/journalctl.jsonl tests/test_journalctl_parser.py
git commit -m "feat(parsers): JournalctlParser producing unified LogEvent"
```

---

### Task 4: Nginx access-log parser

**Files:**
- Create: `parsers/nginx_parser.py`
- Create: `tests/fixtures/nginx_access.log`
- Create: `tests/test_nginx_parser.py`

- [ ] **Step 1: Create the fixture (nginx combined format)**

Write `tests/fixtures/nginx_access.log`:

```
10.0.0.1 - - [02/Sep/2026:12:00:01 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "curl/8.0" 0.012
10.0.0.2 - alice [02/Sep/2026:12:00:02 +0000] "POST /login HTTP/1.1" 401 128 "-" "Mozilla/5.0" 0.245
10.0.0.3 - - [02/Sep/2026:12:00:03 +0000] "GET /admin HTTP/1.1" 404 320 "-" "sqlmap/1.7" 0.008
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_nginx_parser.py`:

```python
from parsers.nginx_parser import NginxParser


def test_parses_combined_format(fixtures_dir):
    events = NginxParser().parse_file(fixtures_dir / "nginx_access.log")
    assert len(events) == 3

    e0 = events[0]
    assert e0.source == "nginx"
    assert e0.ip == "10.0.0.1"
    assert e0.status_code == 200
    assert e0.latency_ms == 12.0
    assert e0.extra["method"] == "GET"
    assert e0.extra["path"] == "/index.html"
    assert e0.extra["user_agent"].startswith("curl")

    e1 = events[1]
    assert e1.user == "alice"
    assert e1.status_code == 401
    assert e1.level == "warn"

    e2 = events[2]
    assert e2.status_code == 404
    assert e2.extra["user_agent"].startswith("sqlmap")


def test_ignores_malformed_lines():
    p = NginxParser()
    assert p.parse_line("garbage line") is None
    assert p.parse_line("") is None


def test_sniff_matches_combined():
    p = NginxParser()
    assert p.sniff([
        '10.0.0.1 - - [02/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 512 "-" "curl"'
    ]) is True


def test_sniff_rejects_syslog():
    assert NginxParser().sniff([
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root"
    ]) is False
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_nginx_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 4: Create `parsers/nginx_parser.py`**

```python
"""Parse nginx access logs (combined format, optional trailing latency)."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent


_LINE_RE = re.compile(
    r'^(?P<ip>\S+)\s+\S+\s+(?P<user>\S+)\s+'
    r'\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>[A-Z]+)\s+(?P<path>\S+)\s+HTTP/[\d.]+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+'
    r'"(?P<agent>[^"]*)"'
    r'(?:\s+(?P<latency>[\d.]+))?'
)

_TS_FMT = "%d/%b/%Y:%H:%M:%S %z"


def _parse_ts(raw: str) -> Optional[datetime]:
    try:
        return datetime.strptime(raw, _TS_FMT).replace(tzinfo=None)
    except ValueError:
        return None


def _level_for(status: int) -> str:
    if status >= 500:
        return "error"
    if status >= 400:
        return "warn"
    return "info"


class NginxParser:
    source_type = "nginx"

    def sniff(self, first_lines: list[str]) -> bool:
        for line in first_lines:
            if _LINE_RE.match(line.strip()):
                return True
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.rstrip("\n")
        m = _LINE_RE.match(line)
        if not m:
            return None
        d = m.groupdict()
        status = int(d["status"])
        latency_ms: Optional[float] = None
        if d.get("latency"):
            latency_ms = float(d["latency"]) * 1000.0

        user = d["user"] if d["user"] != "-" else ""

        return LogEvent(
            timestamp=_parse_ts(d["ts"]),
            source="nginx",
            host="",
            service="nginx",
            level=_level_for(status),
            message=f'{d["method"]} {d["path"]} {status}',
            user=user,
            ip=d["ip"],
            status_code=status,
            latency_ms=latency_ms,
            raw=line,
            extra={
                "method": d["method"],
                "path": d["path"],
                "bytes": int(d["bytes"]),
                "referer": d["referer"],
                "user_agent": d["agent"],
            },
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_nginx_parser.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/nginx_parser.py tests/fixtures/nginx_access.log tests/test_nginx_parser.py
git commit -m "feat(parsers): NginxParser for combined access-log format"
```

---

### Task 5: Generic syslog parser (RFC 3164)

**Files:**
- Create: `parsers/syslog_parser.py`
- Create: `tests/fixtures/syslog.log`
- Create: `tests/test_syslog_parser.py`

- [ ] **Step 1: Create the fixture**

Write `tests/fixtures/syslog.log`:

```
Sep  2 12:00:01 web01 systemd[1]: Started Session 42 of user tony.
Sep  2 12:00:02 web01 dhclient[999]: bound to 10.0.0.5 -- renewal in 43200 seconds
Sep  2 12:00:03 web01 kernel: [123.45] segfault at 0 ip 0000 sp 0000 error 4
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_syslog_parser.py`:

```python
from parsers.syslog_parser import SyslogParser


def test_parses_rfc3164(fixtures_dir):
    events = SyslogParser().parse_file(fixtures_dir / "syslog.log")
    assert len(events) == 3

    e0 = events[0]
    assert e0.source == "syslog"
    assert e0.host == "web01"
    assert e0.service == "systemd"
    assert e0.extra["pid"] == 1
    assert "Started Session" in e0.message

    e2 = events[2]
    assert e2.service == "kernel"
    assert "segfault" in e2.message
    assert e2.level == "error"


def test_sniff_matches_syslog():
    p = SyslogParser()
    assert p.sniff(["Sep  2 12:00:01 web01 cron[999]: hello"]) is True


def test_sniff_rejects_json():
    assert SyslogParser().sniff(['{"MESSAGE":"hi"}']) is False


def test_ignores_blank_lines():
    assert SyslogParser().parse_line("") is None
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_syslog_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 4: Create `parsers/syslog_parser.py`**

```python
"""Parse generic RFC 3164 syslog lines into unified LogEvents.

Deliberately service-agnostic — no protocol-specific keyword extraction.
Use AuthParser for /var/log/auth.log; use this for everything else that
looks like `Mon DD HH:MM:SS host service[pid]: message`.
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent


_LINE_RE = re.compile(
    r"^(?P<ts>\w{3}\s+\d+\s+\d+:\d+:\d+)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>\S+?)(?:\[(?P<pid>\d+)\])?:\s+"
    r"(?P<message>.+)$"
)

_TS_FORMATS = ["%b %d %H:%M:%S", "%b  %d %H:%M:%S"]


def _parse_ts(raw: str) -> Optional[datetime]:
    year = datetime.now().year
    for fmt in _TS_FORMATS:
        try:
            dt = datetime.strptime(raw, fmt)
            if dt.year == 1900:
                dt = dt.replace(year=year)
            return dt
        except ValueError:
            continue
    return None


_LEVEL_KEYWORDS = {
    "error":  ("error", "failed", "failure", "segfault", "panic", "critical"),
    "warn":   ("warn", "warning", "denied", "refused", "timeout"),
}


def _guess_level(message: str) -> str:
    m = message.lower()
    for level, keywords in _LEVEL_KEYWORDS.items():
        if any(k in m for k in keywords):
            return level
    return "info"


class SyslogParser:
    source_type = "syslog"

    def sniff(self, first_lines: list[str]) -> bool:
        for line in first_lines:
            s = line.strip()
            if not s or s.startswith("{"):
                continue
            if _LINE_RE.match(s):
                return True
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.rstrip("\n")
        if not line.strip():
            return None
        m = _LINE_RE.match(line)
        if not m:
            return None
        d = m.groupdict()
        pid = int(d["pid"]) if d["pid"] else None
        extra: dict = {}
        if pid is not None:
            extra["pid"] = pid
        return LogEvent(
            timestamp=_parse_ts(d["ts"]),
            source="syslog",
            host=d["host"],
            service=d["service"],
            level=_guess_level(d["message"]),
            message=d["message"],
            raw=line,
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_syslog_parser.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/syslog_parser.py tests/fixtures/syslog.log tests/test_syslog_parser.py
git commit -m "feat(parsers): SyslogParser for RFC 3164 syslog lines"
```

---

### Task 6: Docker container-log parser

**Files:**
- Create: `parsers/docker_parser.py`
- Create: `tests/fixtures/docker.log`
- Create: `tests/test_docker_parser.py`

`docker logs --timestamps <container>` prefixes each line with an ISO-8601 timestamp then the container's stdout. This parser handles that format plus the Docker daemon JSON-file driver format (one JSON per line with `log`, `stream`, `time`).

- [ ] **Step 1: Create the fixture (mixed)**

Write `tests/fixtures/docker.log`:

```
2026-09-02T12:00:01.123456789Z stdout Starting api-service v1.2.3
2026-09-02T12:00:02.234567890Z stderr db connection refused
{"log":"handled request GET /health 200\n","stream":"stdout","time":"2026-09-02T12:00:03.345678901Z"}
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_docker_parser.py`:

```python
from parsers.docker_parser import DockerParser


def test_parses_docker_logs_timestamps_format(fixtures_dir):
    events = DockerParser().parse_file(fixtures_dir / "docker.log")
    assert len(events) == 3

    e0 = events[0]
    assert e0.source == "docker"
    assert e0.extra["stream"] == "stdout"
    assert "Starting" in e0.message

    e1 = events[1]
    assert e1.extra["stream"] == "stderr"
    assert e1.level == "error"


def test_parses_json_file_driver_format(fixtures_dir):
    events = DockerParser().parse_file(fixtures_dir / "docker.log")
    e2 = events[2]
    assert e2.extra["stream"] == "stdout"
    assert "GET /health" in e2.message


def test_sniff_matches_timestamped_line():
    p = DockerParser()
    assert p.sniff([
        "2026-09-02T12:00:01.123456789Z stdout hello"
    ]) is True


def test_sniff_matches_json_file_driver():
    p = DockerParser()
    assert p.sniff([
        '{"log":"hi\\n","stream":"stdout","time":"2026-09-02T12:00:03Z"}'
    ]) is True


def test_sniff_rejects_syslog():
    assert DockerParser().sniff([
        "Sep  2 12:00:01 web01 cron[999]: hi"
    ]) is False
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_docker_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 4: Create `parsers/docker_parser.py`**

```python
"""Parse Docker container logs (both `docker logs --timestamps` and JSON-file driver)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent


_TS_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<stream>stdout|stderr)\s+"
    r"(?P<message>.*)$"
)


def _parse_ts(raw: str) -> Optional[datetime]:
    raw = raw.rstrip("Z")
    if "." in raw:
        # Trim to microseconds (Python max) 6 fractional digits
        base, frac = raw.split(".", 1)
        raw = f"{base}.{frac[:6]}"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


class DockerParser:
    source_type = "docker"

    def sniff(self, first_lines: list[str]) -> bool:
        for line in first_lines:
            s = line.strip()
            if not s:
                continue
            if _TS_LINE_RE.match(s):
                return True
            if s.startswith("{"):
                try:
                    obj = json.loads(s)
                except json.JSONDecodeError:
                    continue
                if "log" in obj and "stream" in obj and "time" in obj:
                    return True
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.rstrip("\n")
        if not line.strip():
            return None

        if line.lstrip().startswith("{"):
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                return None
            message = obj.get("log", "").rstrip("\n")
            stream = obj.get("stream", "stdout")
            ts = _parse_ts(obj.get("time", "").rstrip("Z"))
            return LogEvent(
                timestamp=ts,
                source="docker",
                service="",
                level="error" if stream == "stderr" else "info",
                message=message,
                raw=line,
                extra={"stream": stream},
            )

        m = _TS_LINE_RE.match(line)
        if not m:
            return None
        d = m.groupdict()
        return LogEvent(
            timestamp=_parse_ts(d["ts"]),
            source="docker",
            service="",
            level="error" if d["stream"] == "stderr" else "info",
            message=d["message"],
            raw=line,
            extra={"stream": d["stream"]},
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_docker_parser.py -v`
Expected: 5 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/docker_parser.py tests/fixtures/docker.log tests/test_docker_parser.py
git commit -m "feat(parsers): DockerParser for --timestamps and JSON-file driver"
```

---

### Task 7: Kubernetes / CRI log parser

**Files:**
- Create: `parsers/k8s_parser.py`
- Create: `tests/fixtures/k8s.log`
- Create: `tests/test_k8s_parser.py`

CRI log format is: `TIMESTAMP STREAM TAG MESSAGE` (e.g. `2026-09-02T12:00:01.123456789Z stdout F Starting api-service`). Tag `F` = full line, `P` = partial.

- [ ] **Step 1: Create the fixture**

Write `tests/fixtures/k8s.log`:

```
2026-09-02T12:00:01.123456789Z stdout F Starting api-service v1.2.3
2026-09-02T12:00:02.234567890Z stderr F Panic: database connection lost
2026-09-02T12:00:03.345678901Z stdout P partial
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_k8s_parser.py`:

```python
from parsers.k8s_parser import KubernetesParser


def test_parses_cri_format(fixtures_dir):
    events = KubernetesParser().parse_file(fixtures_dir / "k8s.log")
    assert len(events) == 3

    e0 = events[0]
    assert e0.source == "k8s"
    assert e0.extra["stream"] == "stdout"
    assert e0.extra["tag"] == "F"
    assert "Starting" in e0.message

    e1 = events[1]
    assert e1.level == "error"
    assert "Panic" in e1.message


def test_sniff_matches_cri():
    p = KubernetesParser()
    assert p.sniff([
        "2026-09-02T12:00:01.123456789Z stdout F hi"
    ]) is True


def test_sniff_rejects_docker_two_field():
    # Docker `--timestamps` has no F/P tag column
    assert KubernetesParser().sniff([
        "2026-09-02T12:00:01.123456789Z stdout hi"
    ]) is False
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_k8s_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 4: Create `parsers/k8s_parser.py`**

```python
"""Parse Kubernetes / CRI container logs into unified LogEvents.

Format: `TIMESTAMP STREAM TAG MESSAGE`
Example: `2026-09-02T12:00:01.123456789Z stdout F Starting api-service`
"""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path
from typing import Optional

from parsers.base import LogEvent


_LINE_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?Z?)\s+"
    r"(?P<stream>stdout|stderr)\s+"
    r"(?P<tag>[FP])\s+"
    r"(?P<message>.*)$"
)


def _parse_ts(raw: str) -> Optional[datetime]:
    raw = raw.rstrip("Z")
    if "." in raw:
        base, frac = raw.split(".", 1)
        raw = f"{base}.{frac[:6]}"
    try:
        return datetime.fromisoformat(raw)
    except ValueError:
        return None


class KubernetesParser:
    source_type = "k8s"

    def sniff(self, first_lines: list[str]) -> bool:
        for line in first_lines:
            if _LINE_RE.match(line.strip()):
                return True
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        line = line.rstrip("\n")
        m = _LINE_RE.match(line)
        if not m:
            return None
        d = m.groupdict()
        return LogEvent(
            timestamp=_parse_ts(d["ts"]),
            source="k8s",
            service="",
            level="error" if d["stream"] == "stderr" else "info",
            message=d["message"],
            raw=line,
            extra={"stream": d["stream"], "tag": d["tag"]},
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_k8s_parser.py -v`
Expected: 3 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/k8s_parser.py tests/fixtures/k8s.log tests/test_k8s_parser.py
git commit -m "feat(parsers): KubernetesParser for CRI log format"
```

---

### Task 8: Generic JSON application-log parser

**Files:**
- Create: `parsers/json_parser.py`
- Create: `tests/fixtures/app.jsonl`
- Create: `tests/test_json_parser.py`

Handles one JSON object per line with common field names (`timestamp`/`time`/`ts`, `level`/`severity`, `message`/`msg`, `service`/`logger`, `host`/`hostname`, `user`/`user_id`, `ip`/`remote_addr`, `request_id`/`trace_id`, `status`/`status_code`, `latency_ms`/`duration_ms`). Unknown fields go into `extra`.

- [ ] **Step 1: Create the fixture**

Write `tests/fixtures/app.jsonl`:

```
{"timestamp":"2026-09-02T12:00:01Z","level":"info","service":"api","host":"web01","message":"request handled","user_id":"alice","remote_addr":"10.0.0.1","request_id":"req-1","status":200,"duration_ms":12.4,"tenant":"acme"}
{"time":"2026-09-02T12:00:02Z","severity":"error","logger":"api","msg":"database timeout","trace_id":"trc-2","status_code":500}
```

- [ ] **Step 2: Write the failing test**

Write `tests/test_json_parser.py`:

```python
from parsers.json_parser import JsonParser


def test_parses_canonical_keys(fixtures_dir):
    events = JsonParser().parse_file(fixtures_dir / "app.jsonl")
    assert len(events) == 2

    e0 = events[0]
    assert e0.source == "json"
    assert e0.service == "api"
    assert e0.host == "web01"
    assert e0.level == "info"
    assert e0.user == "alice"
    assert e0.ip == "10.0.0.1"
    assert e0.request_id == "req-1"
    assert e0.status_code == 200
    assert e0.latency_ms == 12.4
    assert e0.extra["tenant"] == "acme"


def test_parses_alternate_keys(fixtures_dir):
    events = JsonParser().parse_file(fixtures_dir / "app.jsonl")
    e1 = events[1]
    assert e1.service == "api"
    assert e1.level == "error"
    assert e1.request_id == "trc-2"
    assert e1.status_code == 500


def test_sniff_requires_dict_root():
    p = JsonParser()
    assert p.sniff(['{"level":"info","message":"hi"}']) is True
    assert p.sniff(["[1,2,3]"]) is False
    assert p.sniff(["not json"]) is False


def test_sniff_rejects_journalctl_shape():
    # journalctl uses __REALTIME_TIMESTAMP; JsonParser should defer
    assert JsonParser().sniff(['{"__REALTIME_TIMESTAMP":"1","MESSAGE":"hi"}']) is False
```

- [ ] **Step 3: Run to verify failure**

Run: `python3 -m pytest tests/test_json_parser.py -v`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 4: Create `parsers/json_parser.py`**

```python
"""Generic JSON application-log parser.

One JSON object per line. Maps common field aliases into the canonical
LogEvent schema; unrecognised keys flow through in `LogEvent.extra`.
"""

from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

from parsers.base import LogEvent


_TS_KEYS = ("timestamp", "time", "ts", "@timestamp")
_LEVEL_KEYS = ("level", "severity", "log_level")
_MSG_KEYS = ("message", "msg", "log")
_SERVICE_KEYS = ("service", "logger", "app", "component")
_HOST_KEYS = ("host", "hostname", "node")
_USER_KEYS = ("user", "user_id", "username")
_IP_KEYS = ("ip", "remote_addr", "client_ip", "src_ip")
_REQ_KEYS = ("request_id", "trace_id", "correlation_id", "req_id")
_STATUS_KEYS = ("status", "status_code", "http_status")
_LATENCY_KEYS = ("latency_ms", "duration_ms", "response_time_ms")

_ALL_MAPPED = set()
for group in (
    _TS_KEYS, _LEVEL_KEYS, _MSG_KEYS, _SERVICE_KEYS, _HOST_KEYS,
    _USER_KEYS, _IP_KEYS, _REQ_KEYS, _STATUS_KEYS, _LATENCY_KEYS,
):
    _ALL_MAPPED.update(group)


def _first(obj: dict, keys: tuple[str, ...]) -> Any:
    for k in keys:
        if k in obj and obj[k] not in ("", None):
            return obj[k]
    return None


def _parse_ts(raw: Any) -> Optional[datetime]:
    if raw is None:
        return None
    s = str(raw).rstrip("Z")
    try:
        return datetime.fromisoformat(s)
    except ValueError:
        return None


class JsonParser:
    source_type = "json"

    def sniff(self, first_lines: list[str]) -> bool:
        for line in first_lines:
            s = line.strip()
            if not s or not s.startswith("{"):
                continue
            try:
                obj = json.loads(s)
            except json.JSONDecodeError:
                return False
            if not isinstance(obj, dict):
                return False
            if "__REALTIME_TIMESTAMP" in obj:
                # Defer to JournalctlParser
                return False
            return True
        return False

    def parse_line(self, line: str) -> Optional[LogEvent]:
        s = line.strip()
        if not s or not s.startswith("{"):
            return None
        try:
            obj = json.loads(s)
        except json.JSONDecodeError:
            return None
        if not isinstance(obj, dict):
            return None

        ts = _parse_ts(_first(obj, _TS_KEYS))
        level_raw = _first(obj, _LEVEL_KEYS) or "info"
        message = _first(obj, _MSG_KEYS) or ""
        service = _first(obj, _SERVICE_KEYS) or ""
        host = _first(obj, _HOST_KEYS) or ""
        user = _first(obj, _USER_KEYS) or ""
        ip = _first(obj, _IP_KEYS) or ""
        req = _first(obj, _REQ_KEYS) or ""

        status_raw = _first(obj, _STATUS_KEYS)
        status_code: Optional[int] = None
        if status_raw is not None:
            try:
                status_code = int(status_raw)
            except (TypeError, ValueError):
                status_code = None

        latency_raw = _first(obj, _LATENCY_KEYS)
        latency_ms: Optional[float] = None
        if latency_raw is not None:
            try:
                latency_ms = float(latency_raw)
            except (TypeError, ValueError):
                latency_ms = None

        extra = {k: v for k, v in obj.items() if k not in _ALL_MAPPED}

        return LogEvent(
            timestamp=ts,
            source="json",
            host=str(host),
            service=str(service),
            level=str(level_raw).lower(),
            message=str(message),
            user=str(user),
            ip=str(ip),
            request_id=str(req),
            status_code=status_code,
            latency_ms=latency_ms,
            raw=s,
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
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_json_parser.py -v`
Expected: 4 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/json_parser.py tests/fixtures/app.jsonl tests/test_json_parser.py
git commit -m "feat(parsers): JsonParser for generic JSON application logs"
```

---

### Task 9: Parser registry + auto-detect

**Files:**
- Create: `parsers/registry.py`
- Create: `tests/test_registry.py`
- Modify: `parsers/__init__.py` (re-export)

- [ ] **Step 1: Write the failing test**

Write `tests/test_registry.py`:

```python
from parsers.registry import SOURCE_TYPES, auto_detect, get_parser


def test_source_types_exposes_all_parsers():
    assert set(SOURCE_TYPES) == {
        "auth", "journalctl", "nginx", "syslog", "docker", "k8s", "json",
    }


def test_get_parser_returns_expected_instance():
    p = get_parser("nginx")
    assert p.source_type == "nginx"


def test_get_parser_unknown_raises():
    import pytest
    with pytest.raises(ValueError):
        get_parser("unknown")


def test_auto_detect_auth(fixtures_dir):
    assert auto_detect(fixtures_dir / "auth.log") == "auth"


def test_auto_detect_nginx(fixtures_dir):
    assert auto_detect(fixtures_dir / "nginx_access.log") == "nginx"


def test_auto_detect_journalctl(fixtures_dir):
    assert auto_detect(fixtures_dir / "journalctl.jsonl") == "journalctl"


def test_auto_detect_docker(fixtures_dir):
    assert auto_detect(fixtures_dir / "docker.log") == "docker"


def test_auto_detect_k8s(fixtures_dir):
    assert auto_detect(fixtures_dir / "k8s.log") == "k8s"


def test_auto_detect_json(fixtures_dir):
    assert auto_detect(fixtures_dir / "app.jsonl") == "json"


def test_auto_detect_syslog(fixtures_dir):
    # syslog fixture is deliberately non-auth (cron/systemd/kernel);
    # auth.log fixture matches both — priority order ensures auth wins there.
    assert auto_detect(fixtures_dir / "syslog.log") == "syslog"
```

- [ ] **Step 2: Run to verify failure**

Run: `python3 -m pytest tests/test_registry.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'parsers.registry'`.

- [ ] **Step 3: Create `parsers/registry.py`**

```python
"""Parser registry + auto-detection.

`auto_detect` sniffs the first N non-empty lines and returns the source-type
name of the first parser that claims it. Detection order matters — the more
specific parsers (auth, journalctl, k8s, docker) get first refusal before the
generic syslog / json parsers.
"""

from __future__ import annotations

from pathlib import Path
from typing import Callable

from parsers.auth_parser import AuthParser
from parsers.base import Parser
from parsers.docker_parser import DockerParser
from parsers.journalctl_parser import JournalctlParser
from parsers.json_parser import JsonParser
from parsers.k8s_parser import KubernetesParser
from parsers.nginx_parser import NginxParser
from parsers.syslog_parser import SyslogParser


_FACTORIES: dict[str, Callable[[], Parser]] = {
    "auth":       AuthParser,
    "journalctl": JournalctlParser,
    "nginx":      NginxParser,
    "syslog":     SyslogParser,
    "docker":     DockerParser,
    "k8s":        KubernetesParser,
    "json":       JsonParser,
}

SOURCE_TYPES = tuple(_FACTORIES.keys())

# Auto-detect priority: specific first, generic last.
_DETECT_ORDER = ("auth", "journalctl", "nginx", "k8s", "docker", "json", "syslog")


def get_parser(source_type: str) -> Parser:
    """Return a parser instance for the given source type."""
    if source_type not in _FACTORIES:
        raise ValueError(
            f"Unknown source type: {source_type!r}. "
            f"Known: {', '.join(SOURCE_TYPES)}"
        )
    return _FACTORIES[source_type]()


def _peek(path: str | Path, n: int = 20) -> list[str]:
    p = Path(path)
    lines: list[str] = []
    with p.open("r", errors="replace") as fh:
        for line in fh:
            if line.strip():
                lines.append(line)
                if len(lines) >= n:
                    break
    return lines


def auto_detect(path: str | Path) -> str:
    """Return the source-type name that best matches the file, or 'syslog' as fallback."""
    lines = _peek(path)
    for name in _DETECT_ORDER:
        parser = _FACTORIES[name]()
        if parser.sniff(lines):
            return name
    return "syslog"
```

- [ ] **Step 4: Update `parsers/__init__.py`**

Overwrite `parsers/__init__.py`:

```python
"""Multi-source log parsers for P3."""

from parsers.base import LogEvent, Parser
from parsers.registry import SOURCE_TYPES, auto_detect, get_parser

__all__ = ["LogEvent", "Parser", "SOURCE_TYPES", "auto_detect", "get_parser"]
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_registry.py -v`
Expected: 10 passed.

- [ ] **Step 6: Commit**

```bash
git add parsers/registry.py parsers/__init__.py tests/test_registry.py
git commit -m "feat(parsers): registry with get_parser + auto_detect"
```

---

### Task 10: Update `anomaly_detector.py` for new schema

**Files:**
- Modify: `anomaly_detector.py`

The detector currently reads `ev.event_type`, `ev.source_ip`, `ev.username`, `ev.hostname`, `ev.raw`. Under the new schema, those become `ev.extra["event_type"]`, `ev.ip`, `ev.user`, `ev.host`, `ev.raw`. Behaviour must not change; every existing test outcome stays identical.

- [ ] **Step 1: Update the LogEvent import**

Change line 11 in `anomaly_detector.py` from:

```python
from log_parser import LogEvent
```

to:

```python
from parsers.base import LogEvent
```

- [ ] **Step 2: Rewrite `detect_brute_force` field access**

Inside `detect_brute_force`, replace the failure-classification block. Original:

```python
for ev in events:
    if ev.event_type in ("ssh_failed_password", "ssh_invalid_user", "pam_failure", "ssh_max_auth"):
        if ev.source_ip:
            failures[ev.source_ip].append(ev)
```

Replace with:

```python
for ev in events:
    et = ev.extra.get("event_type", "")
    if et in ("ssh_failed_password", "ssh_invalid_user", "pam_failure", "ssh_max_auth"):
        if ev.ip:
            failures[ev.ip].append(ev)
```

Then inside the sliding-window section, replace `e.username` with `e.user` in the `usernames` set comprehension.

- [ ] **Step 3: Rewrite `detect_privilege_escalation` field access**

Replace every occurrence in that function:
- `ev.event_type` → `ev.extra.get("event_type", "")`
- `ev.username` → `ev.user`
- `ev.source_ip` → `ev.ip`
- `e.username` → `e.user`
- `e.source_ip` → `e.ip`

- [ ] **Step 4: Rewrite `detect_unusual_ips` field access**

Replace every occurrence in that function:
- `ev.source_ip` → `ev.ip`
- `ev.event_type` → `ev.extra.get("event_type", "")`
- `ev.username` → `ev.user`

- [ ] **Step 5: Rewrite `run_detection` allowlist filter**

Replace:

```python
filtered = [
    e for e in events
    if (not allowlist_ips or e.source_ip not in allowlist_ips)
    and (not allowlist_users or e.username not in allowlist_users)
]
```

with:

```python
filtered = [
    e for e in events
    if (not allowlist_ips or e.ip not in allowlist_ips)
    and (not allowlist_users or e.user not in allowlist_users)
]
```

- [ ] **Step 6: Add a regression test**

Write `tests/test_anomaly_detector_new_schema.py`:

```python
"""Confirm anomaly detector still fires on unified LogEvents from AuthParser."""

from anomaly_detector import run_detection
from parsers.auth_parser import AuthParser


def test_brute_force_still_detected(tmp_path):
    log = tmp_path / "burst.log"
    lines = [
        f"May 22 01:00:0{i} web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2"
        for i in range(6)
    ]
    log.write_text("\n".join(lines) + "\n")

    events = AuthParser().parse_file(log)
    anomalies = run_detection(events)

    assert len(anomalies) >= 1
    assert any(a.category == "brute_force" for a in anomalies)
    assert any(a.source_ip == "192.168.1.100" for a in anomalies)


def test_allowlist_ip_suppresses(tmp_path):
    log = tmp_path / "burst.log"
    lines = [
        f"May 22 01:00:0{i} web01 sshd[1234]: Failed password for root from 10.0.0.1 port 22345 ssh2"
        for i in range(6)
    ]
    log.write_text("\n".join(lines) + "\n")
    events = AuthParser().parse_file(log)

    assert run_detection(events, allowlist_ips={"10.0.0.1"}) == []
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_anomaly_detector_new_schema.py -v`
Expected: 2 passed.

- [ ] **Step 8: Commit**

```bash
git add anomaly_detector.py tests/test_anomaly_detector_new_schema.py
git commit -m "refactor(detector): read new LogEvent field names (ip/user/host/extra)"
```

---

### Task 11: Update `report_generator.py` for new schema

**Files:**
- Modify: `report_generator.py`

The report generator reads `LogEvent` fields to format the log-sample section fed to the AI (`build_log_sample`). Only the auth-log context uses those fields; the anomaly-summary path uses `Anomaly` objects and needs no change.

- [ ] **Step 1: Update the import**

Change:

```python
from log_parser import LogEvent
```

to:

```python
from parsers.base import LogEvent
```

- [ ] **Step 2: Update field access in `build_log_sample`**

Search `report_generator.py` for `event_type`, `source_ip`, `username`, `hostname`. For each occurrence:
- `ev.event_type` → `ev.extra.get("event_type", "")`
- `ev.source_ip` → `ev.ip`
- `ev.username` → `ev.user`
- `ev.hostname` → `ev.host`

Do the same for JSON-report field mapping if present.

- [ ] **Step 3: Run existing tests to confirm nothing broke**

Run: `python3 -m pytest tests/ -v`
Expected: all tests still pass.

- [ ] **Step 4: Commit**

```bash
git add report_generator.py
git commit -m "refactor(report): read new LogEvent field names"
```

---

### Task 12: Compatibility shims for top-level `log_parser.py` and `journalctl_parser.py`

**Files:**
- Modify: `log_parser.py` (top level)
- Modify: `journalctl_parser.py` (top level)

The `.service` unit and any user cron jobs importing `log_parser` should keep working through Phase 1.

- [ ] **Step 1: Replace `log_parser.py` (top level) with a shim**

Overwrite `log_parser.py` with:

```python
"""Compatibility shim — moved to parsers.auth_parser."""

from parsers.auth_parser import AuthParser
from parsers.base import LogEvent

_parser = AuthParser()


def parse_line(line):
    return _parser.parse_line(line)


def parse_file(path):
    return _parser.parse_file(path)


__all__ = ["LogEvent", "parse_line", "parse_file"]
```

- [ ] **Step 2: Replace `journalctl_parser.py` (top level) with a shim**

Overwrite `journalctl_parser.py` with:

```python
"""Compatibility shim — moved to parsers.journalctl_parser."""

from parsers.journalctl_parser import JournalctlParser

_parser = JournalctlParser()


def parse_journalctl_line(line):
    return _parser.parse_line(line)


def parse_journalctl_file(path):
    return _parser.parse_file(path)


__all__ = ["parse_journalctl_line", "parse_journalctl_file"]
```

- [ ] **Step 3: Run every test**

Run: `python3 -m pytest tests/ -v`
Expected: all tests pass.

- [ ] **Step 4: Commit**

```bash
git add log_parser.py journalctl_parser.py
git commit -m "refactor: convert top-level parsers to compatibility shims"
```

---

### Task 13: `main.py` — `--source-type` flag + registry dispatch

**Files:**
- Modify: `main.py`

- [ ] **Step 1: Add the new import**

Add near the other imports:

```python
from parsers import SOURCE_TYPES, auto_detect, get_parser
```

Remove these two lines (no longer needed directly here):

```python
from journalctl_parser import parse_journalctl_file
from log_parser import parse_file
```

- [ ] **Step 2: Replace the `--format` argument with `--source-type`**

Find the block that adds `--format` (currently around lines 93-98). Replace with:

```python
parser.add_argument(
    "--source-type",
    choices=("auto",) + SOURCE_TYPES,
    default="auto",
    help="Log source type. 'auto' sniffs the first lines (default).",
)
parser.add_argument(
    "--format",
    choices=["auto", "auth", "journalctl"],
    default=None,
    help="[DEPRECATED] alias for --source-type; kept for back-compat.",
)
```

- [ ] **Step 3: Replace the format-detection + parse block in `main()`**

Find the block starting at `# Detect format` (currently around line 236) through the end of the parse block (currently around line 258). Replace with:

```python
# Resolve source type (--format is a deprecated alias)
source_type = args.source_type
if args.format and args.source_type == "auto":
    source_type = args.format
if source_type == "auto":
    source_type = auto_detect(log_path)
    print(f"Auto-detected source type: {source_type}", flush=True)

print(f"Parsing {log_path} (source: {source_type}) ...", flush=True)
try:
    parser_impl = get_parser(source_type)
except ValueError as exc:
    print(f"ERROR: {exc}", file=sys.stderr)
    return 1
events = parser_impl.parse_file(log_path)
print(f"  {len(events):,} events parsed.", flush=True)
```

- [ ] **Step 4: Manual smoke test — auth mode still works**

Run: `python3 main.py sample_auth.log --no-ai --no-color`
Expected: report prints, exit code 0, anomalies list matches the pre-Phase-1 behaviour.

- [ ] **Step 5: Manual smoke test — nginx mode works**

Run: `python3 main.py tests/fixtures/nginx_access.log --source-type nginx --no-ai --no-color`
Expected: exit code 0, 3 events parsed, report body prints.

- [ ] **Step 6: Manual smoke test — auto-detect works on JSON**

Run: `python3 main.py tests/fixtures/app.jsonl --no-ai --no-color`
Expected: `Auto-detected source type: json`, 2 events parsed.

- [ ] **Step 7: Commit**

```bash
git add main.py
git commit -m "feat(cli): --source-type flag with registry dispatch and auto-detect"
```

---

### Task 14: Integration test — all parsers on all fixtures

**Files:**
- Create: `tests/test_integration_all_parsers.py`

- [ ] **Step 1: Write the test**

```python
"""End-to-end integration: every source type produces LogEvents on its fixture."""

import pytest

from parsers import auto_detect, get_parser
from parsers.base import LogEvent


CASES = [
    ("auth.log", "auth"),
    ("journalctl.jsonl", "journalctl"),
    ("nginx_access.log", "nginx"),
    ("syslog.log", "syslog"),
    ("docker.log", "docker"),
    ("k8s.log", "k8s"),
    ("app.jsonl", "json"),
]


@pytest.mark.parametrize("filename,expected_source", CASES)
def test_auto_detect_matches(fixtures_dir, filename, expected_source):
    assert auto_detect(fixtures_dir / filename) == expected_source


@pytest.mark.parametrize("filename,expected_source", CASES)
def test_each_parser_produces_events(fixtures_dir, filename, expected_source):
    parser = get_parser(expected_source)
    events = parser.parse_file(fixtures_dir / filename)
    assert len(events) > 0
    for ev in events:
        assert isinstance(ev, LogEvent)
        assert ev.source == expected_source
        assert ev.raw != ""
```

- [ ] **Step 2: Run to verify pass**

Run: `python3 -m pytest tests/test_integration_all_parsers.py -v`
Expected: 14 passed.

- [ ] **Step 3: Commit**

```bash
git add tests/test_integration_all_parsers.py
git commit -m "test: integration coverage over every parser and fixture"
```

---

### Task 15: Regression test — sample_auth.log unchanged output

**Files:**
- Create: `tests/test_regression_auth.py`

Confirms the pre-Phase-1 sample log still yields the same anomaly categories and counts through the new pipeline.

- [ ] **Step 1: Write the test**

```python
"""Regression: sample_auth.log yields the same anomalies as before Phase 1."""

from pathlib import Path

from anomaly_detector import run_detection
from parsers import auto_detect, get_parser


REPO_ROOT = Path(__file__).parent.parent


def test_sample_auth_log_regression():
    log = REPO_ROOT / "sample_auth.log"
    assert log.exists(), "sample_auth.log must exist at repo root"

    assert auto_detect(log) == "auth"
    events = get_parser("auth").parse_file(log)
    assert len(events) > 20

    anomalies = run_detection(events)
    categories = {a.category for a in anomalies}
    assert "brute_force" in categories
    assert "privilege_escalation" in categories
    assert "unusual_ip" in categories
```

- [ ] **Step 2: Run to verify pass**

Run: `python3 -m pytest tests/test_regression_auth.py -v`
Expected: 1 passed.

- [ ] **Step 3: Run full suite**

Run: `python3 -m pytest tests/ -v`
Expected: at least 40 tests, all pass.

- [ ] **Step 4: Commit**

```bash
git add tests/test_regression_auth.py
git commit -m "test: sample_auth.log regression through new parsers pipeline"
```

---

### Task 16: README update — "Supported sources" section

**Files:**
- Modify: `README.md`

- [ ] **Step 1: Add a new "Supported sources" section**

Insert after the existing "Features" section (or before "Usage"). Content:

```markdown
## Supported sources

| `--source-type` | Description | Auto-detect |
|---|---|---|
| `auth` | `/var/log/auth.log`, `/var/log/secure` | ✅ |
| `journalctl` | `journalctl -o json` output | ✅ |
| `nginx` | nginx access log (combined format) | ✅ |
| `syslog` | Generic RFC 3164 syslog | ✅ (fallback) |
| `docker` | `docker logs --timestamps` + JSON-file driver | ✅ |
| `k8s` | Kubernetes/CRI container logs | ✅ |
| `json` | Generic JSON application logs (one object per line) | ✅ |

Pass `--source-type auto` (default) to sniff the format automatically, or
force a specific parser: `python main.py access.log --source-type nginx`.
```

- [ ] **Step 2: Add a quick example**

Under the Usage section, append:

````markdown
### Multi-source examples

```bash
# Analyze nginx access log
python3 main.py /var/log/nginx/access.log --source-type nginx --no-ai

# Analyze Docker container logs
docker logs --timestamps api > api.log
python3 main.py api.log --source-type docker --no-ai

# Auto-detect JSON app logs
python3 main.py /var/log/app/app.jsonl --no-ai
```
````

- [ ] **Step 3: Commit**

```bash
git add README.md
git commit -m "docs: document Phase 1 multi-source ingest in README"
```

---

### Task 17: Push branch + open PR (or merge to master)

- [ ] **Step 1: Push branch to both remotes**

```bash
git push -u origin feat/phase-1-multi-source
git push gitlab feat/phase-1-multi-source
```

- [ ] **Step 2: Full-suite green check before merge**

```bash
python3 -m pytest tests/ -v
```

Expected: ≥ 40 passed, 0 failed.

- [ ] **Step 3: Merge to master**

```bash
git checkout master
git merge --no-ff feat/phase-1-multi-source
git push origin master
git push gitlab master
```

- [ ] **Step 4: Tag Phase 1 shipment**

```bash
git tag -a phase-1-multi-source -m "Phase 1: multi-source ingest + unified LogEvent"
git push origin phase-1-multi-source
git push gitlab phase-1-multi-source
```

---

## Success Criteria (Phase 1 done)

- `python3 main.py fixtures/nginx.log --source-type nginx --no-ai` produces a same-shape report as auth mode ✅
- `python3 main.py sample_auth.log --no-ai` still works (regression) ✅
- ≥ 40 unit + integration + regression tests passing ✅
- README section documents every supported source ✅
- Branch `feat/phase-1-multi-source` merged to `master` on both remotes ✅

## Ship Notes (post-merge, out of scope for this plan)

Draft the LinkedIn / Dev.to post per master plan: "P3 now ingests nginx, syslog, Docker, k8s, JSON — one anomaly engine, six log formats." Save under `docs/blog/phase-1.md` in a follow-up commit.
