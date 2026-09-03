# P3 — AI Log Anomaly Detector

> Linux auth log analysis with MITRE ATT&CK mapping, statistical baselining, and an agentic LLM investigation loop that can block IPs and lock accounts autonomously.

Built to answer a real frustration: grep for brute force isn't enough when the attacker succeeds on attempt 8, escalates to root, and creates a backdoor account — all in 7 minutes. This tool chains those events together and lets a local LLM investigate without phoning home.

---

## What it does

```
/var/log/auth.log ──► Parse ──► Detect ──► Baseline ──► AI Agent ──► Block/Alert
                                  │            │              │
                              9 rules      z-score       6 tool calls
                              MITRE IDs   30-day hist   real /api/chat
```

1. **Parses** auth logs, journalctl JSON, nginx access logs (auto-detected)
2. **Detects** attacks with 9 rule-based detectors mapped to MITRE ATT&CK techniques + confidence scores
3. **Baselines** counts against 30-day rolling history — if 50 SSH failures/hour is normal for your system, severity adjusts automatically
4. **Agents** an LLM through a real multi-step investigation: pivot on IPs, check timelines, look for lateral movement, correlate events
5. **Acts** — optionally blocks source IPs via `iptables` and locks compromised accounts via `passwd -l`

Zero third-party Python dependencies. Runs entirely on your network with local Ollama.

---

## Quick start

```bash
git clone https://github.com/PyHackSecGP/p3-log-anomaly-detector
cd p3-log-anomaly-detector

# Zero setup — generate a sample attack log and run:
python main.py --generate-sample
python main.py sample_auth.log --no-ai
```

**With local Ollama (no cloud, no API keys):**
```bash
python main.py sample_auth.log \
  --url http://YOUR_OLLAMA_IP:11434 \
  --model hermes3:70b
```

**Agentic mode — LLM drives its own investigation:**
```bash
python main.py sample_auth.log \
  --agentic \
  --url http://YOUR_OLLAMA_IP:11434 \
  --model hermes3:70b
```

**Preview remediation without executing (safe to run):**
```bash
python main.py sample_auth.log \
  --agentic --act --dry-run \
  --url http://YOUR_OLLAMA_IP:11434
```

**Execute remediation — block IPs + lock accounts (needs root):**
```bash
sudo python main.py /var/log/auth.log \
  --agentic --act \
  --allowlist allowlist.yaml \
  --url http://YOUR_OLLAMA_IP:11434
```

---

## Example output

### Rule-based report

```
═══════════════════════════════════════════════════════════════════
  AI LOG ANOMALY DETECTOR — SECURITY REPORT
═══════════════════════════════════════════════════════════════════
  Anomalies: CRITICAL: 1  HIGH: 3  MEDIUM: 2  LOW: 0
═══════════════════════════════════════════════════════════════════

[IP-001] CRITICAL — Successful login after 8 failures from 192.168.1.100 [T1110] 40% conf
  IP 192.168.1.100 had 8 failed attempts before successfully authenticating.
  Possible credential stuffing or brute force success.
  IP: 192.168.1.100  |  Count: 9  |  01:00:01 → 01:05:00

[PE-001] HIGH — su to root detected [T1548] 85% conf
  Session opened as root via su by user 'backup'.

[PE-002] HIGH — New user account created [T1136] 100% conf
  useradd called 1 time(s). User: hacker (UID 1337).

[OH-001] MEDIUM — Off-hours login from 10.0.1.1 [T1078] 70% conf
  SSH login at 02:00. User: tony. [Baseline: z=0.3 — normal, severity downgraded]
```

### Agentic investigation

The agent uses real multi-turn conversation (`/api/chat`) to drive its own investigation:

```
AGENTIC THREAT ASSESSMENT
─────────────────────────────────────────────────────────────────
Risk Level: CRITICAL

  IP 192.168.1.100 brute-forced 'backup' (8 fails → success at 01:05),
  escalated to root via su after 3 sudo failures, then created backdoor
  account 'hacker' (UID 1337). Full kill chain in 7 minutes:
  Initial Access [T1110] → Privilege Escalation [T1548] → Persistence [T1136]

Indicators of Compromise:
  • 192.168.1.100 (attacker source IP)
  • backup (compromised credential)
  • hacker (backdoor account, UID 1337)

Recommendations:
  → passwd -l backup
  → userdel -r hacker
  → iptables -I INPUT -s 192.168.1.100 -j DROP
  → grep -r hacker /etc/sudoers /etc/cron* /etc/passwd

Investigation Trace:
  Step 1: search_ip(ip='192.168.1.100')
    ↳ 9 events: 8 failures then accepted password at 01:05:00
  Step 2: check_lateral_movement(username='backup')
    ↳ Single source IP — no lateral movement detected
  Step 3: get_timeline(anchor='2026-05-22T01:05:00', before=5, after=5)
    ↳ Kill chain: fail×8 → login → sudo fail×3 → su root → useradd hacker
  Step 4: get_anomaly_context(anomaly_id='PE-003')
    ↳ useradd hacker UID=1337 at 01:07:00

Actions taken (--act mode):
  → BLOCKED 192.168.1.100 via iptables -I INPUT -s 192.168.1.100 -j DROP
  → LOCKED account 'backup' via passwd -l backup
```

---

## Detection rules

| ID format | MITRE | Rule | Severity |
|---|---|---|---|
| `BF-xxx` | T1110 | SSH brute force — ≥5 failures from one IP in 10 min | MEDIUM→CRITICAL |
| `IP-xxx` | T1110 | Distributed brute force — ≥10 IPs, ≥20 total failures | HIGH |
| `IP-xxx` | T1110 | Credential stuffing — success after prior failures from same IP | CRITICAL |
| `PE-xxx` | T1548 | Privilege escalation — sudo/su failures, su-to-root | HIGH |
| `PE-xxx` | T1136 | Account creation — useradd called | HIGH |
| `PE-xxx` | T1078 | Root login — direct SSH as root | CRITICAL |
| `OH-xxx` | T1078 | Off-hours login — SSH success 02:00–05:00 | MEDIUM |
| `UE-xxx` | T1589 | User enumeration — ≥8 distinct invalid usernames from one IP | MEDIUM→HIGH |
| `WEB-xxx` | T1595 | Web scanner — known scanner user agent (sqlmap, nikto, ffuf…) | HIGH |
| `WEB-4XX-xxx` | T1595 | 4xx flood — ≥20 client errors from one IP | MEDIUM→HIGH |
| `WEB-PROBE-xxx` | T1083 | Sensitive path probing — ≥5 admin/config paths hit | HIGH |

---

## Statistical baseline

After 3 days, the tool learns what's normal for **your** system:

```
Your system at noon: 200 SSH failures/hour (automation, scanners — normal)
Your system at 3am:  0 SSH failures/hour

Same 200 failures arrive at 3am → z-score = 4.7 → CRITICAL (real attack)
Same 200 failures arrive at noon → z-score = 0.1 → downgraded to MEDIUM (noise)
```

SQLite stores hourly counts per event type. 30-day rolling window. Minimum 3 days before baseline adjustments activate — no false negatives during the learning period.

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `LOG_FILE` | auto-detect | Path to log (`/var/log/auth.log`, `/var/log/secure`, or pass a file) |
| `--url URL` | `$OLLAMA_HOST` or `localhost:11434` | Ollama server URL (`OLLAMA_HOST` env var sets the default) |
| `--model MODEL` | `llama3.1:8b` | Model for AI analysis |
| `--no-ai` | off | Skip Ollama — rule-based output only |
| `--agentic` | off | Multi-step LLM investigation via tool calls |
| `--act` | off | Execute remediation (block IPs, lock users) — **requires root** |
| `--dry-run` | off | Show what `--act` would do without executing anything |
| `--allowlist FILE` | none | YAML of trusted IPs/users to suppress |
| `--abuseipdb KEY` | none | AbuseIPDB IP reputation enrichment |
| `--webhook URL` | none | Slack/Discord webhook for HIGH/CRITICAL alerts |
| `--email` | off | SMTP email alert |
| `--watch` | off | Tail mode — scan new bytes every `--interval` seconds |
| `--interval N` | 60 | Seconds between watch-mode scans |
| `--json FILE` | none | Save JSON report |
| `--sarif FILE` | none | Save SARIF 2.1.0 (GitHub Security tab, DefectDojo, Splunk) |
| `--out FILE` | none | Save plain text report |
| `--format` | auto | `auto` \| `auth` \| `journalctl` \| `nginx` |
| `--generate-sample` | off | Write `sample_auth.log` for local testing |

---

## Watch mode

```bash
sudo python main.py /var/log/auth.log \
  --watch --interval 60 \
  --allowlist allowlist.yaml \
  --webhook "$SLACK_WEBHOOK" \
  --url http://YOUR_OLLAMA_IP:11434
```

- **Tail-based**: only reads new bytes since last scan (byte position + inode tracked in SQLite)
- **Rotation-aware**: inode change or file shrink resets position to 0
- **Persistent state**: seen anomaly IDs survive daemon restarts — no duplicate alerts
- **Systemd ready**: `p3-anomaly-detector.service` included

---

## SARIF output

```bash
python main.py /var/log/auth.log --no-ai --sarif findings.sarif
```

Compatible with:
- GitHub Security tab (upload as code scanning artifact)
- DefectDojo (import SARIF findings)
- Splunk SIEM (SARIF ingestion)
- Any OASIS SARIF 2.1.0 consumer

---

## Architecture

```
main.py                  Entry point, watch daemon, alert orchestration
parsers/
  auth_parser.py         /var/log/auth.log → LogEvent
  journalctl_parser.py   journalctl JSON   → LogEvent
  nginx_parser.py        nginx access log  → LogEvent
  base.py                Unified LogEvent dataclass + Parser protocol
anomaly_detector.py      8 auth detection rules, MITRE IDs, confidence scores
nginx_detector.py        4 web detection rules
baseline.py              SQLite z-score baseline (30-day rolling, per-hour)
ollama_client.py         Ollama /api/generate + /api/chat
agent.py                 LogAnalysisAgent — 6-tool /api/chat investigation loop
actions.py               block_ip (iptables), lock_user (passwd -l), audit log
report_generator.py      Text, JSON, SARIF 2.1.0 output
state.py                 SQLite watch state (file positions, seen anomaly IDs)
```

---

## Tests

```bash
pip install pytest
pytest tests/ -v
```

54 tests covering: all detection rules, agent tool dispatch, `/api/chat` enforcement,
conversation message structure, SARIF schema, parser sniff/parse, baseline logic.

---

## Allowlist

Edit `allowlist.yaml` to suppress trusted sources before running against live logs:

```yaml
trusted_ips:
  - 10.0.1.1       # jump box
  - 192.168.1.1    # monitoring agent

trusted_users:
  - prometheus
  - ansible
  - backup-agent
```
