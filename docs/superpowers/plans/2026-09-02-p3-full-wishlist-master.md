# P3 Full Wishlist — 4-Phase Master Plan

> **Bookmarked 2026-09-02.** Not yet started. Execute one phase per session; each phase writes its own detailed TDD plan when begun.

**Goal:** Grow P3 from a rule-based auth-log anomaly detector into a full log-intelligence platform: multi-source ingest → baseline learning → statistical anomalies → correlation → incident grouping → agentic investigator.

**Reference:** Wishlist from ChatGPT conversation (2026-09-02). Each phase addresses a subset of the 8 wishlist items.

**Approach:** Ship phase-by-phase, one session per phase. Each phase produces a shippable increment with its own LinkedIn/Dev.to post. Do NOT try to ship all four in one session.

---

## Current State (baseline)

- Repo: https://github.com/PyHackSecGP/p3-log-anomaly-detector, local `~/projects/p3-log-anomaly-detector/`
- ~1,850 lines Python 3.11 stdlib. No third-party deps.
- Files: `log_parser.py`, `journalctl_parser.py`, `anomaly_detector.py`, `report_generator.py`, `ollama_client.py`, `abuseipdb.py`, `allowlist.py`, `slack_alerts.py`, `email_alerts.py`, `main.py`.
- Rule-based detection for SSH brute force, credential stuffing, sudo/su failures, useradd, root logins. MITRE ATT&CK IDs + confidence scores + AbuseIPDB enrichment + allowlist + Slack/Discord/email + watch mode + systemd unit.
- **Missing:** multi-source ingest, statistical baselines, cross-service correlation, incident grouping, timeline, agentic investigator.

## Wishlist Coverage Map (before/after)

| # | Wishlist item | Current | After Phase 1 | Phase 2 | Phase 3 | Phase 4 |
|---|---|---|---|---|---|---|
| 1 | Multi-source ingest (.log, JSON, Docker, k8s, app logs) | 🟡 auth only | ✅ | ✅ | ✅ | ✅ |
| 2 | Baseline learning (per-service normals) | ❌ | ❌ | ✅ | ✅ | ✅ |
| 3 | Detect anomaly types: volume/freq/novelty/sequence/timing/behavior/cross-service | 🟡 freq+seq | 🟡 | ✅ | ✅ | ✅ |
| 4 | Explain anomaly (narrative) | ✅ Ollama | ✅ | ✅ | ✅ | ✅✅ |
| 5 | Correlate multi-service events | ❌ | ❌ | ❌ | ✅ | ✅ |
| 6 | Group duplicates into incidents | ❌ | ❌ | ❌ | ✅ | ✅ |
| 7 | Investigator timeline + Q&A | ❌ | ❌ | ❌ | 🟡 timeline | ✅ Q&A |
| 8 | Prioritize (rarity + impact + context) | 🟡 severity + MITRE + AbuseIPDB | 🟡 | ✅ | ✅ | ✅ |

---

## Phase 1: Multi-source ingest + common event schema (3-4 days)

**Goal:** Accept nginx access logs, syslog, Docker container logs, Kubernetes pod logs, JSON application logs. Normalize into a single `LogEvent` dataclass.

**New files:**
- `parsers/__init__.py` (package)
- `parsers/base.py` — `LogEvent` dataclass + `Parser` protocol
- `parsers/nginx_parser.py`
- `parsers/syslog_parser.py`
- `parsers/docker_parser.py`
- `parsers/k8s_parser.py`
- `parsers/json_parser.py`

**Modify:**
- `main.py` — new `--source-type auto|auth|nginx|syslog|docker|k8s|json` flag
- `anomaly_detector.py` — accept `list[LogEvent]` instead of raw auth-log dicts
- Existing `log_parser.py` (auth) + `journalctl_parser.py` move under `parsers/`

**`LogEvent` schema:**
```python
@dataclass
class LogEvent:
    timestamp: datetime
    source: str         # e.g. "auth", "nginx", "docker/api-service"
    host: str
    service: str
    level: str          # info|warn|error|critical
    message: str
    user: str = ""
    ip: str = ""
    request_id: str = ""
    status_code: int | None = None
    latency_ms: float | None = None
    raw: str = ""
    extra: dict = field(default_factory=dict)
```

**Tests:** 1 unit test per parser + one integration test that runs all parsers on `tests/fixtures/` and asserts a valid `LogEvent` list.

**Success criteria:**
- `python3 main.py fixtures/nginx.log --source-type nginx --no-ai` produces same-shape report as auth mode
- Existing auth mode still works (regression suite passes)
- ≥ 10 unit tests

**Ship:** LinkedIn post — "P3 now ingests nginx, syslog, Docker, k8s, JSON — one anomaly engine, six log formats."

---

## Phase 2: Baseline learning + statistical anomalies (3-4 days)

**Goal:** Move from hardcoded thresholds to statistical detection. Learn per-source, per-service, per-user baselines. Detect volume/frequency/novelty/timing anomalies.

**New files:**
- `stats/__init__.py`
- `stats/baseline.py` — rolling window stats (count, mean, stddev) per `(source, service, user, ip)` key
- `stats/detectors.py` — `VolumeAnomaly`, `FrequencyAnomaly`, `NoveltyAnomaly`, `TimingAnomaly`
- `stats/store.py` — persist baselines to `~/.p3/baselines.json` so watch mode learns over days

**Modify:**
- `anomaly_detector.py` — new detection pipeline: `stats + rules + correlation` (correlation added Phase 3)
- `main.py` — flags `--learn` (write baseline), `--baseline PATH` (read), `--z-threshold FLOAT`

**Detection approach:**
- **Volume:** count events per (source, service) per hour. Detect z-score > 3 or Tukey outlier via IQR.
- **Frequency:** events per (user or ip) per 5min. Same z-score approach.
- **Novelty:** hash(source, service, message-template). Alert on first occurrence after 7-day observation window.
- **Timing:** activity outside typical per-service hours (learn active window per service).

**Tests:** unit for `RollingStats`, unit per detector, integration that seeds a baseline then triggers each anomaly.

**Success criteria:**
- Given 7 days of "normal" nginx logs + 1 day with 10× error rate, volume anomaly fires
- New error message not seen in prior 7 days fires novelty anomaly
- Rule-based detection from Phase-0 still works alongside stats (both are additive)

**Ship:** Post — "P3 no longer needs you to hard-code thresholds. Baseline learning + z-score/IQR detects volume, novelty, timing anomalies across all sources."

---

## Phase 3: Correlator + incident grouping + timeline (3-4 days)

**Goal:** Turn N related events into 1 incident. Show correlated sequences across services. Build a timeline per incident.

**New files:**
- `correlator/__init__.py`
- `correlator/graph.py` — build event graph keyed on shared (ip, user, request_id, host) within a time window
- `correlator/grouper.py` — cluster anomalies + related events into `Incident` objects
- `correlator/timeline.py` — order events per incident, format for report + JSON export

**New model:**
```python
@dataclass
class Incident:
    id: str
    severity: str
    started_at: datetime
    ended_at: datetime | None
    affected_services: list[str]
    events: list[LogEvent]
    anomalies: list[Anomaly]
    likely_cause: str = ""   # populated Phase 4 by LLM
    root_events: list[str] = field(default_factory=list)  # top events explaining the cause
    confidence: float = 0.0
```

**Modify:**
- `main.py` — flag `--correlate` (default on)
- `report_generator.py` — new incident-oriented report + timeline table

**Correlation rules (v1):**
- Two anomalies from different services within 60s sharing (ip OR user OR host) → link.
- N ≥ 3 auth failures + 1 successful login same ip → single "credential stuffing" incident.
- Volume anomaly on api + latency anomaly on db within 5min → "database contention" incident.
- Group events sharing (request_id OR trace_id) into same incident regardless of service.

**Tests:** fixtures with cross-service log sets, assert one incident per known scenario, correct event count.

**Success criteria:**
- 4,832-event fixture (DB pool exhaustion cascade) → 1 incident with 7 affected services, timeline sorted
- Auth-only credential-stuffing fixture → 1 incident with fail→success sequence in timeline

**Ship:** Post — "P3 now groups thousands of log events into single actionable incidents with cross-service correlation and investigator timelines."

---

## Phase 4: Agentic investigator (2-3 days)

**Goal:** Reuse `agent-core` (same as P1/P2 agentic mode). New `--agentic-investigate` CLI. Agent answers investigator questions using tools that query the incident store.

**New files:**
- `agent/__init__.py`
- `agent/session.py` — session store for loaded incidents + user query context
- `agent/tools.py` — @tool functions:
  - `list_incidents(session_id, since=None, severity=None)`
  - `get_incident(session_id, incident_id)`
  - `get_timeline(session_id, incident_id)`
  - `events_before(session_id, incident_id, seconds=300)`
  - `events_related(session_id, event_id_or_ip_or_user)`
  - `explain_incident(session_id, incident_id)` — LLM narrative from Ollama
  - `suggest_root_cause(session_id, incident_id)` — LLM ranks root_events
  - `list_iocs(session_id, incident_id)` — extract IPs/users/hashes across the incident
  - `ask_user(question)` — reuse P2 pattern for follow-ups
- `agent/investigator_agent.py` — `InvestigatorAgent` wrapping `agent_core.Agent`

**Modify:**
- `main.py` — `--agentic-investigate --incident INC-42` OR `--agentic-investigate` (opens general Q&A over most recent incidents)
- `requirements.txt` — add `agent-core @ ...` (fix path from `file://` to git URL before shipping)

**System prompt:** Analyst persona. Rules: use tools, never invent events, cite event IDs when asserting facts, produce answers formatted with timeline where relevant.

**Tests:** mock provider, verify tool call sequence for canned questions ("what happened before INC-42?", "which IPs correlate?", "root cause?").

**Success criteria:**
- `python3 main.py /var/log/auth.log --agentic-investigate` opens interactive session, agent answers ≥ 3 investigator questions correctly on a fixture incident
- All existing modes still work

**Ship:** Post — "P3 investigator mode: ask 'what happened before this?' and get a cited timeline. Full P1/P2/P3 agentic-mode trilogy done."

---

## Cross-Cutting Concerns

- **No breaking changes** to CLI defaults across phases — existing users' cron jobs keep working.
- **TDD** every phase. Unit + integration + at least one fixture-driven acceptance test per phase.
- **One branch per phase**: `feat/phase-1-multi-source`, `feat/phase-2-baselines`, etc. Merge to master after review.
- **Docs**: README section per phase, writeup appendix per phase.
- **Push targets**: github + gitlab (Forgejo). Same dual-remote setup as other projects.
- **agent-core requirements pin**: before Phase 4, replace `file:///home/tony/projects/agent-core` with a git URL so external users can install.

---

## Not in scope (won't do)

- GUI / web dashboard
- Distributed collection (Beats, Fluent Bit, etc.) — P3 is a single-node analyzer
- SIEM integration (Splunk / Elastic connectors)
- Machine learning models beyond simple statistics (no LSTMs, no isolation forests)
- Real-time streaming — batch + watch mode is enough

---

## Next Session Handoff

When resuming, start a session with:

> "Begin P3 Phase 1: multi-source ingest per plan at `~/projects/p3-log-anomaly-detector/docs/superpowers/plans/2026-09-02-p3-full-wishlist-master.md`. Write the detailed TDD plan for Phase 1 first, then execute subagent-driven."

That gives fresh context and the phase-specific TDD plan gets written in that session using `superpowers:writing-plans`.
