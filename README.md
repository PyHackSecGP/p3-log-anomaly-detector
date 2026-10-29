# P3 Log Anomaly Detector — AI-assisted SSH/web log anomaly hunter

![tests](https://img.shields.io/badge/tests-64_passing-brightgreen)
![python](https://img.shields.io/badge/python-3.11+-blue)
![sarif](https://img.shields.io/badge/SARIF-2.1.0-informational)
![mitre](https://img.shields.io/badge/MITRE_ATT%26CK-8_techniques-red)
![deps](https://img.shields.io/badge/third_party_deps-0-success)

> Linux auth and nginx log analysis with MITRE ATT&CK mapping, statistical
> baselining, and an agentic local-LLM investigation loop that can block IPs
> and lock accounts autonomously.

Built to answer a real frustration: `grep` for brute force isn't enough when
the attacker succeeds on attempt 8, escalates to root, and creates a backdoor
account — all in 7 minutes. This tool chains those events together and lets a
local Ollama model investigate without phoning home.

---

## 60-Second Overview

Every Linux box leaks attack signals into `/var/log/auth.log` the moment it
touches the internet: SSH brute force, invalid-user probes, sudo failures,
`useradd` for backdoor accounts. Web-facing boxes leak more into
`/var/log/nginx/access.log`: scanner user-agents, 4xx floods, admin-panel
probing.

**What it detects** — SSH brute force (single + distributed), credential
stuffing success, user enumeration, sudo abuse, su-to-root, direct root
logins, backdoor account creation, off-hours logins, web scanners, 4xx
flooding, sensitive-path probing, high-error-rate behaviour.

**Who runs it** — a one-person SOC, a homelabber with a Pi facing the
internet, a tier-1 analyst who wants `auth.log` to tell them something before
their SIEM licence renewal does. It fits in a cron job or a `systemd`
service.

**Why not Splunk / Wazuh / ELK** — those are great. They are also expensive,
heavy, and send data to a central indexer. This tool is a single Python
process, zero third-party dependencies, local LLM via Ollama, no cloud
exfiltration. It writes SARIF so you can still feed it to GitHub Security,
DefectDojo, or Splunk later.

---

## For Interviewers

### Problem Statement

Every Linux box with port 22 open is already under constant brute-force
pressure. Commercial SIEMs are priced for enterprises; small teams and
homelabbers either run nothing or run a stack heavier than the asset it
protects. This project is a lightweight, open, locally-runnable analyser
designed for a tier-1 analyst to own end-to-end: parse → detect → map to
MITRE ATT&CK → investigate with a local LLM → alert → optionally remediate.
It must stay inside the host it's analysing and must not add new attack
surface.

### Skills Demonstrated

- **Log parsing** — hand-written regex-based parsers for three formats (auth
  syslog, journalctl JSON, nginx combined/common) behind a unified
  `LogEvent` dataclass + `Parser` protocol.
- **Rule-based detection** — 11 rules across SSH and web layers producing
  structured, confidence-scored findings.
- **Statistical baselining** — 30-day rolling z-score per event type and
  hour-of-day in SQLite; adaptive severity downgrade for normal noise.
- **MITRE ATT&CK mapping** — every rule tagged with a T-code, catalog in
  JSON, plaintext heatmap reporter grouped by tactic.
- **LLM tool-calling agent loop** — real multi-turn `/api/chat` with Ollama,
  6-tool interface, bounded step budget, forced-conclude fallback.
- **SARIF 2.1.0 export** — compatible with GitHub code scanning, DefectDojo,
  Splunk ingestion.
- **AbuseIPDB enrichment** — IP reputation lookup with graceful degradation
  when no key is set.
- **Systemd service design** — tail-based watch mode with
  rotation-aware position tracking, inode-change detection, persistent
  state in SQLite, unit file included.
- **Dry-run safe remediation** — `iptables -I INPUT -j DROP` and
  `passwd -l` wrapped behind `--act` and `--dry-run` with an audit log.
- **Zero third-party Python dependencies** — stdlib only (`sqlite3`,
  `urllib`, `smtplib`, `re`, `argparse`, `dataclasses`).

### Architecture

```
                      /var/log/auth.log
                      /var/log/nginx/access.log
                      journalctl -o json
                              │
                              ▼
   ┌───────────────────────────────────────────────────┐
   │              parsers/{auth,journalctl,nginx}       │
   │   regex + strptime  ──►  unified LogEvent dataclass│
   └───────────────────────────────────────────────────┘
                              │
                              ▼
   ┌───────────────────────────────────────────────────┐
   │        Rule detectors (11 rules, MITRE-tagged)     │
   │   anomaly_detector.py   nginx_detector.py          │
   │        │                                           │
   │        ▼                                           │
   │  baseline.py — z-score per (category, hour)        │
   │  SQLite rolling 30-day history                     │
   │        │                                           │
   │        ▼                                           │
   │  Severity downgrade when z < 2.0 on known normal   │
   └───────────────────────────────────────────────────┘
                              │
                              ▼
                        List[Anomaly]
                              │
             ┌────────────────┼─────────────────┐
             │                │                 │
             ▼                ▼                 ▼
       ┌──────────┐    ┌──────────────┐   ┌──────────────┐
       │  MITRE   │    │ AbuseIPDB    │   │  LLM Agent   │
       │  mapper  │    │ enrichment   │   │ (optional)   │
       │  heatmap │    │ score/geo    │   │  /api/chat   │
       └──────────┘    └──────────────┘   │  6 tools     │
                                          │  MAX_STEPS=6 │
                                          └──────┬───────┘
                                                 │
                              ┌──────────────────┴────────────┐
                              ▼                               ▼
                       ┌──────────────┐              ┌──────────────────┐
                       │  Reports     │              │  Alerts/Actions  │
                       │  text/json   │              │  slack/discord   │
                       │  SARIF 2.1.0 │              │  smtp email      │
                       │  heatmap     │              │  iptables -j DROP│
                       └──────────────┘              │  passwd -l user  │
                                                     └──────────────────┘
```

### Design Decisions & Trade-offs

- **Ollama (local) as default LLM, not Claude/OpenAI** — auth logs contain
  usernames, IPs, and internal hostnames. Local inference eliminates cloud
  data exfiltration. The LLM interface is pluggable, but shipping with a
  cloud default was a non-starter for the threat model this tool addresses.
- **Z-score baselining, not an ML model** — a trained anomaly model needs
  per-host retraining and silently rots. A rolling mean/stdev per
  (category, hour-of-day) explains itself in one sentence
  (`z=4.7 at 03:00 → 4.7 std devs above this host's 3am average`), fits in
  stdlib `sqlite3`, warms up in 3 days, and has no false negatives during
  warmup. Ponytail take: picked the boring algorithm that is correct on
  edge cases and shows its work.
- **Agentic mode (tool loop), not single-shot prompt** — chained kill chains
  need pivoting (`search_ip` → `check_lateral_movement` → `get_timeline`).
  A single prompt can't request context it doesn't already have in the
  initial dump. The agent uses real `/api/chat` multi-turn messages, not
  prompt concatenation. Capped at `MAX_STEPS = 6` to bound runtime.
- **No PyYAML dependency** — the allowlist format is intentionally a
  simple `key: value` and `  - item` subset so a 20-line stdlib parser
  reads it. Zero third-party deps = installs in air-gapped environments
  with system Python only.
- **Plaintext MITRE heatmap, not HTML dashboard** — the primary consumer is
  a tier-1 analyst looking at `tail -f` or a terminal `cat` of the report.
  Full-block Unicode bars render in every TTY, every email client, every
  Slack code block. An HTML dashboard would be another port to protect.
- **SARIF 2.1.0 instead of a custom JSON schema** — SARIF is already
  consumed by GitHub Security tab, DefectDojo, Splunk, and most SIEMs.
  Reusing it means other tools get integration for free.

### Metrics

| Metric | Value |
|---|---|
| Detection rules | 11 (7 auth, 4 nginx) |
| MITRE ATT&CK techniques | 8 (T1078, T1083, T1110, T1136, T1190, T1548, T1589, T1595) |
| Tests | 64 passing |
| Output formats | 3 (text, JSON, SARIF 2.1.0) |
| Alert channels | 2 (SMTP email, Slack/Discord webhook) |
| Supported log formats | 3 (auth syslog, journalctl JSON, nginx) |
| Third-party deps | 0 (stdlib only) |
| Agent tools | 6 (`search_ip`, `search_user`, `get_timeline`, `check_lateral_movement`, `get_anomaly_context`, `conclude`) |
| Baseline window | 30 days rolling, per-hour, per-category |

---

## Quick Start

```bash
git clone https://github.com/PyHackSecGP/p3-log-anomaly-detector
cd p3-log-anomaly-detector

# 3-command demo — no dependencies, no root, no network:
python main.py --generate-sample
python main.py sample_auth.log --no-ai
python main.py sample_auth.log --no-ai --mitre-report
```

With local Ollama (no cloud, no API keys):

```bash
python main.py sample_auth.log \
  --url http://localhost:11434 \
  --model llama3.1:8b
```

Agentic mode — LLM drives its own investigation:

```bash
python main.py sample_auth.log --agentic \
  --url http://localhost:11434 \
  --model llama3.1:8b
```

Preview remediation without executing (safe to run):

```bash
python main.py sample_auth.log --agentic --act --dry-run
```

Execute remediation — block IPs + lock accounts (needs root):

```bash
sudo python main.py /var/log/auth.log \
  --agentic --act \
  --allowlist allowlist.yaml \
  --url http://localhost:11434
```

---

## Detection Rules Catalog

| Rule ID prefix | Category | MITRE | Logic summary |
|---|---|---|---|
| `BF-xxx` | brute_force | T1110 Brute Force | ≥5 SSH failures from one IP within 10 min; severity scales to 20 / 50 |
| `IP-xxx` (stuff) | unusual_ip | T1110 Brute Force | SSH success from an IP that had prior failures (credential-stuffing success) |
| `IP-xxx` (dist) | unusual_ip | T1110 Brute Force | >10 unique IPs each contributing to ≥20 total SSH failures (distributed BF) |
| `PE-xxx` (sudo) | privilege_escalation | T1548 Abuse Elevation Control Mechanism | Repeated sudo-auth failures per user; MEDIUM at 2, HIGH at 5, CRITICAL at 10 |
| `PE-xxx` (su) | privilege_escalation | T1548 Abuse Elevation Control Mechanism | `su` session opened as root |
| `PE-xxx` (useradd) | privilege_escalation | T1136 Create Account | `useradd` invocation detected (backdoor account creation) |
| `PE-xxx` (root) | privilege_escalation | T1078 Valid Accounts | Direct SSH login as `root` |
| `OH-xxx` | off_hours_login | T1078 Valid Accounts | Successful SSH login between 02:00–05:00 local time |
| `UE-xxx` | user_enumeration | T1589 Gather Victim Identity Information | ≥8 distinct invalid usernames from one source IP |
| `WEB-xxx` | web_scanning | T1595 Active Scanning | ≥3 requests with known scanner UA (sqlmap, nikto, nuclei, ffuf, gobuster, …) |
| `WEB-4XX-xxx` | web_scanning | T1595 Active Scanning | ≥20 4xx responses from a single IP (directory brute force / fuzzing) |
| `WEB-PROBE-xxx` | web_scanning | T1083 File and Directory Discovery | ≥5 distinct sensitive paths probed by one IP (`/admin`, `/.env`, `/.git`, …) |
| `WEB-ERR-xxx` | web_scanning | T1190 Exploit Public-Facing Application | ≥60% error rate across ≥10 requests from one IP |

---

## Examples

### 1. `sample_auth.log` — rule-based run + heatmap

```bash
$ python main.py --generate-sample
Sample log written to: sample_auth.log

$ python main.py sample_auth.log --no-ai --mitre-report
Parsing sample_auth.log (format: auth) ...
  31 events parsed.
Running anomaly detection ...
  6 anomalies found.

═══════════════════════════════════════════════════════════════════
  AI LOG ANOMALY DETECTOR — SECURITY REPORT
═══════════════════════════════════════════════════════════════════
  Anomalies: CRITICAL: 1  HIGH: 3  MEDIUM: 2  LOW: 0
═══════════════════════════════════════════════════════════════════

[IP-001] CRITICAL — Successful login after 8 failures from 203.0.113.42 [T1110] 40% conf
  IP 203.0.113.42 had 8 failed attempts before successfully authenticating.
  Possible credential stuffing or brute force success.
  IP: 203.0.113.42  |  Count: 9  |  01:00:01 → 01:05:00

[PE-001] HIGH — su to root detected [T1548] 85% conf
  Session opened as root via su by user 'backup'.

[PE-002] HIGH — New user account created [T1136] 100% conf
  useradd called 1 time(s). User: hacker (UID 1337).

[OH-001] MEDIUM — Off-hours login from 203.0.113.9 [T1078] 70% conf
  SSH login at 02:00. User: tony.

MITRE ATT&CK Coverage
=====================
Total events: 6  |  Unique techniques: 4

[Credential Access]
  T1110    Brute Force                                   2  ██
[Persistence]
  T1136    Create Account                                1  █
[Privilege Escalation]
  T1078    Valid Accounts                                1  █
  T1548    Abuse Elevation Control Mechanism             2  ██
```

### 2. Watch mode — long-running daemon

```bash
sudo python main.py /var/log/auth.log \
  --watch --interval 60 \
  --allowlist allowlist.yaml \
  --webhook "$SLACK_WEBHOOK_URL" \
  --url http://localhost:11434
```

Output (continuous):

```
Watch mode: tailing /var/log/auth.log (format: auth) every 60s. Ctrl+C to stop.
[14:03:11] 42 new events, 0 anomaly(ies) — no new HIGH/CRITICAL
[14:04:11] No new log lines
[14:05:11] 2 new HIGH/CRITICAL anomaly(ies)
```

Position + inode tracked in `~/.p3_watch_state.sqlite`. Rotation (inode
change or file shrink) resets position to 0 automatically. Seen anomaly
IDs are persisted — restarts never re-alert on the same finding.

### 3. Agentic mode — LLM tool loop with Ollama

```bash
python main.py sample_auth.log --agentic \
  --url http://localhost:11434 \
  --model llama3.1:8b
```

Agent output (abridged):

```
AGENTIC THREAT ASSESSMENT
─────────────────────────────────────────────────────────────────
Risk Level: CRITICAL

  IP 203.0.113.42 brute-forced 'backup' (8 fails → success at 01:05),
  escalated to root via su after 3 sudo failures, then created backdoor
  account 'hacker' (UID 1337). Full kill chain in 7 minutes:
  Initial Access [T1110] → Privilege Escalation [T1548] → Persistence [T1136]

Indicators of Compromise:
  • 203.0.113.42 (attacker source IP)
  • backup (compromised credential)
  • hacker (backdoor account, UID 1337)

Recommendations:
  → passwd -l backup
  → userdel -r hacker
  → iptables -I INPUT -s 203.0.113.42 -j DROP
  → grep -r hacker /etc/sudoers /etc/cron* /etc/passwd

Investigation Trace:
  Step 1: search_ip(ip='203.0.113.42')
    ↳ 9 events: 8 failures then accepted password at 01:05:00
  Step 2: check_lateral_movement(username='backup')
    ↳ Single source IP — no lateral movement detected
  Step 3: get_timeline(anchor='2026-05-22T01:05:00', before_min=5, after_min=5)
    ↳ Kill chain: fail×8 → login → sudo fail×3 → su root → useradd hacker
  Step 4: get_anomaly_context(anomaly_id='PE-002')
    ↳ useradd hacker UID=1337 at 01:07:00
  Step 5: conclude(risk_level='CRITICAL', ...)
```

With `--act`, each IOC matching an IP triggers `block_ip`; each matching a
username triggers `lock_user`. With `--act --dry-run` the agent prints
what it *would* do and exits without touching `iptables` or `passwd`.

---

## Technical Reference

### Install

```bash
git clone https://github.com/PyHackSecGP/p3-log-anomaly-detector
cd p3-log-anomaly-detector
python3 -m venv .venv && source .venv/bin/activate   # optional
# No pip install needed — stdlib only.

# For tests:
pip install pytest
pytest tests/ -v
```

Python 3.11+ required (uses PEP 604 `|` type unions, `dataclass`,
`sqlite3`).

### CLI Flags

| Flag | Default | Description |
|---|---|---|
| `LOG_FILE` | auto-detect | Path to log file (`/var/log/auth.log`, `/var/log/secure`, or any file) |
| `--url URL` | `$OLLAMA_HOST` or `http://localhost:11434` | Ollama server URL |
| `--model MODEL` | `llama3.1:8b` | Ollama model name |
| `--no-ai` | off | Skip Ollama; emit rule-based findings only |
| `--agentic` | off | Multi-step LLM investigation via tool calls |
| `--act` | off | Execute remediation (block IPs, lock users). **Requires root.** |
| `--dry-run` | off | Preview what `--act` would do without executing |
| `--allowlist FILE` | none | YAML of trusted IPs/users to suppress before detection |
| `--abuseipdb API_KEY` | none | AbuseIPDB key for IP reputation enrichment (or `ABUSEIPDB_API_KEY` env) |
| `--webhook URL` | none | Slack or Discord webhook URL for HIGH/CRITICAL alerts (or `ALERT_WEBHOOK_URL` env) |
| `--email` | off | SMTP email alert (configure via `ALERT_SMTP_*` env vars) |
| `--watch` | off | Tail mode: scan only new bytes every `--interval` seconds |
| `--interval SECS` | 60 | Scan interval for watch mode |
| `--json FILE` | none | Save JSON report to `FILE` |
| `--sarif FILE` | none | Save SARIF 2.1.0 report to `FILE` |
| `--out FILE` | none | Save plaintext report to `FILE` |
| `--format` | `auto` | Force log format: `auto` \| `auth` \| `journalctl` \| `nginx` |
| `--generate-sample` | off | Write `sample_auth.log` for local testing, then exit |
| `--mitre-report` | off | Print MITRE ATT&CK heatmap after detection |
| `--list-models` | off | List available Ollama models and exit |
| `--verbose`, `-v` | off | Verbose output (e.g. AbuseIPDB lookup detail) |
| `--no-color` | off | Disable ANSI color codes |

Exit codes: `0` clean / `1` HIGH severity present / `2` CRITICAL present /
`1` on hard error (printed to stderr).

### Statistical Baseline Details

- **Storage** — SQLite file at `~/.p3_baseline.sqlite`.
- **Granularity** — one row per `(category, hour_of_day, date)` with a
  rolling counter.
- **Window** — 30 days (older rows pruned on `record`).
- **Warmup** — baseline-driven downgrades activate only after at least
  3 days of history for the category. During warmup, raw rule severity is
  preserved — no false negatives.
- **Z-score threshold** — anomaly flagged when
  `(count - mean) / stdev >= 2.0`. Below the threshold, severity drops one
  rung (`HIGH → MEDIUM`, `MEDIUM → LOW`). `CRITICAL` is never downgraded.
- **Explanation emitted in the finding** — e.g.
  `[Baseline: z=0.3 — normal for this host, severity downgraded]`.

### Allowlist YAML Format

```yaml
trusted_ips:
  - 203.0.113.1       # jump box
  - 203.0.113.2       # monitoring agent

trusted_users:
  - prometheus
  - ansible
  - backup-agent
```

Parser is a 20-line stdlib loader (`allowlist.py`). Only the two keys
above are read. Comments (`#`) and blank lines are ignored. Allowlisted
entries are filtered **before** detection runs — they never produce
findings.

### MITRE Mapping File Schema

`mitre_mapping.json`:

```json
{
  "T1110": {
    "name": "Brute Force",
    "tactic": "Credential Access",
    "url": "https://attack.mitre.org/techniques/T1110/",
    "rules": ["ssh_brute_force", "credential_stuffing_ip_distribution"]
  }
}
```

Keys:

- Top-level key is the T-code (string, exact as on attack.mitre.org).
- `name` — human-readable technique name.
- `tactic` — one of the 14 ATT&CK tactics (Reconnaissance, Initial Access,
  …). Used to group the heatmap.
- `url` — canonical ATT&CK URL (for SARIF `helpUri` and report linking).
- `rules` — list of internal rule identifiers that emit this T-code.

`mitre.py` exposes `load_mapping()`, `get_technique(code)`,
`summarize_coverage(anomalies)`, and `render_heatmap(summary)`.

### Agent Tool Interface

Each turn the model MUST reply with exactly one JSON object. The agent
executes the tool and feeds the result back as the next user message. The
loop terminates on `conclude` or at `MAX_STEPS = 6`.

| Tool | Args | Returns |
|---|---|---|
| `search_ip` | `{"ip": "<ip>"}` | All log events from this source IP |
| `search_user` | `{"username": "<user>"}` | All log events associated with this username |
| `get_timeline` | `{"anchor": "<ISO-datetime>", "before_min": N, "after_min": N}` | Events in a time window around the anchor |
| `check_lateral_movement` | `{"username": "<user>"}` | Unique source IPs the user authed from; flags multi-IP success |
| `get_anomaly_context` | `{"anomaly_id": "<id>"}` | Raw log lines stored for the anomaly (e.g. `BF-001`) |
| `conclude` | `{"risk_level": "...", "summary": "...", "iocs": [...], "recommendations": [...]}` | Finish with final threat assessment |

Duplicate tool-call protection: identical `(action, args)` pairs are
rejected with `(duplicate tool call — skipped)` so the model can't burn
step budget on repeats.

### SARIF Output + GitHub Integration

```bash
python main.py /var/log/auth.log --no-ai --sarif findings.sarif
```

Each anomaly becomes one `result` entry with:

- `ruleId` = `anomaly_id` prefix (e.g. `BF`, `PE`, `WEB-PROBE`)
- `level` = `error` (CRITICAL/HIGH) or `warning` (MEDIUM) or `note` (LOW)
- `message.text` = anomaly description
- `properties.mitre_id` + `properties.mitre_name`
- `properties.confidence`

Compatible consumers tested: GitHub Security tab (upload as code-scanning
artifact), DefectDojo (import SARIF findings), Splunk SARIF ingestion,
any OASIS SARIF 2.1.0 reader.

GitHub Actions snippet:

```yaml
- name: Run P3 Log Anomaly Detector
  run: python main.py /var/log/auth.log --no-ai --sarif results.sarif

- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

### Alert Channels

**Slack / Discord webhook** — HIGH or CRITICAL findings post a formatted
message. Set `--webhook URL` or `ALERT_WEBHOOK_URL`. Payload shape is
auto-detected: Discord URLs use embeds, Slack URLs use blocks.

**SMTP email** — `--email` flag. Configure via env:

```bash
export ALERT_SMTP_HOST=smtp.example.com
export ALERT_SMTP_PORT=587
export ALERT_SMTP_USER=alerts@example.com
export ALERT_SMTP_PASS=...
export ALERT_SMTP_FROM=alerts@example.com
export ALERT_SMTP_TO=soc@example.com
```

Only CRITICAL and HIGH findings trigger alerts — MEDIUM and LOW are
report-only to prevent fatigue.

### Watch Mode + State File

- **Position tracking** — SQLite at `~/.p3_watch_state.sqlite` records
  `(log_path, inode, byte_offset)`.
- **Rotation handling** — if the inode has changed OR the current file
  size is smaller than the stored offset, offset resets to 0 and the full
  (rotated) file is re-read from the top.
- **Seen anomaly IDs** — persisted per `log_path`. Restarts of the daemon
  do not re-alert on findings already shipped.
- **Scan loop** — every `--interval` seconds: read new bytes → parse →
  detect → filter out seen IDs → alert on new HIGH/CRITICAL.

### systemd Service Install

```ini
# /etc/systemd/system/p3-anomaly-detector.service
[Unit]
Description=P3 Log Anomaly Detector (watch mode)
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/opt/p3-log-anomaly-detector
Environment=ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
ExecStart=/usr/bin/python3 /opt/p3-log-anomaly-detector/main.py \
          /var/log/auth.log --watch --interval 60 \
          --allowlist /etc/p3/allowlist.yaml \
          --url http://localhost:11434
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now p3-anomaly-detector
sudo journalctl -u p3-anomaly-detector -f
```

### Testing

```bash
pip install pytest
pytest tests/ -v
```

64 tests covering: all 11 detection rules, agent tool dispatch,
`/api/chat` message structure enforcement, SARIF schema validity, parser
sniff/parse for all three formats, baseline z-score math, allowlist
loader, MITRE mapping + heatmap render.

### Extending

**Add a detection rule.** Open `anomaly_detector.py` (or
`nginx_detector.py` for web rules). Add a function returning
`list[Anomaly]`, append it to `run_detection()`, pick an `anomaly_id`
prefix, set `mitre_id` + `mitre_name`. Add a test under
`tests/test_anomaly_detector.py`.

**Add a parser.** Create `parsers/<source>_parser.py` implementing the
`Parser` protocol in `parsers/base.py` (`sniff`, `parse_line`,
`parse_file`). Wire it in `main.py` alongside the existing three. All
downstream detectors operate on the unified `LogEvent` dataclass, so no
other code needs changing.

**Add a MITRE technique.** Append to `mitre_mapping.json` with
`name`, `tactic`, `url`, `rules`. Set `mitre_id` on the Anomaly in the
rule that produces it. Heatmap and SARIF output pick it up automatically.

---

## Why This Was Built

Writeup for the career angle: tier-1 SOC work is 80% log review and 20%
triage. The 80% is where open-source tooling has thinned out — Splunk and
Wazuh dominate the top end; `grep | sort | uniq -c` dominates the bottom
end; there is a gap in the middle for small teams who want *something
that reasons about chained events* without buying an enterprise SIEM.

Three learning goals drove the design:

1. **Agentic LLM patterns on real data** — proving tool-loop investigation
   is viable with a local 8B model, not just a GPT-4 demo.
2. **MITRE ATT&CK fluency** — every finding tagged with a T-code so the
   output speaks the same language as every incident report, every
   adversary emulation plan, every red-team debrief.
3. **Lean stack discipline** — no dependencies means it runs on a
   stripped-down Alpine container, an air-gapped Pi, a cloud VM where
   `pip install` is a security review event. Stdlib-only is a feature.

Shipped as MVP; next milestones in order: Suricata/Zeek flow ingestion,
Falco auditd events, allowlist regex support, Prometheus metrics
endpoint.

---

## FAQ

**Q: Does this replace a SIEM?**
A: No. It's a lightweight analyser you run beside one, or instead of one
when buying a SIEM is overkill. SARIF output means findings flow into
whatever system you already have.

**Q: Why Ollama specifically?**
A: Because auth logs leak usernames, IPs, and host identifiers that
belong on-host. Ollama runs locally and the interface is a plain HTTP
JSON API that's trivial to swap. You can point `--url` at any
OpenAI-compatible endpoint, including a hosted LLM, if you accept the
exfiltration trade-off.

**Q: What happens if Ollama is unreachable?**
A: The tool falls back to rule-based detection and prints a warning.
Agentic mode fails closed — if no model responds, the agent produces an
`UNKNOWN` risk-level report, not a false negative.

**Q: Is `--act` safe to run in production?**
A: Not without `--dry-run` first. `--act` executes `iptables -I INPUT -s
<ip> -j DROP` and `passwd -l <user>` as root. Always validate IOCs with
`--dry-run` on a representative log sample first, use `--allowlist` to
protect your own jump boxes and automation accounts, and keep an audit
log of every executed action (`actions.py` writes one).

**Q: How does it handle log rotation?**
A: Watch mode stores `(inode, byte_offset)` in SQLite. On every scan it
re-stats the file; if the inode changed or the file shrunk, offset resets
to 0. No events are missed and none are re-emitted.

**Q: Why no PyYAML, no `requests`, no `click`?**
A: Every dependency is a supply-chain risk and an install-time failure
mode. The allowlist format is a trivial subset parsed by stdlib; HTTP is
`urllib.request`; argparse is already in stdlib. Zero deps means `python
main.py` works on any 3.11+ box without a `pip install` step — critical
for air-gapped and locked-down environments.

**Q: Can I use this for compliance evidence?**
A: SARIF output is auditable and timestamped. The audit log for `--act`
mode records every executed remediation with timestamp, action, target,
and the originating anomaly ID. For stricter compliance (SOC 2, PCI DSS)
you'd want to append-only ship the SARIF + audit log to immutable
storage; this tool emits them, it does not store them for you.

**Q: Does the agent see the full log, or just anomalies?**
A: The initial context contains the top 10 anomalies (with MITRE IDs,
confidence, IPs, usernames). The agent then pulls full event detail on
demand via `search_ip`, `search_user`, `get_timeline`, and
`get_anomaly_context`. This keeps the prompt small — critical for 8B
local models with small context windows.

---

## License

MIT. See `LICENSE`.
