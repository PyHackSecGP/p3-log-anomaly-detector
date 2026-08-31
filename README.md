# P3 — AI Log Anomaly Detector

Parses Linux auth logs, runs rule-based anomaly detection with MITRE ATT&CK mapping, and sends findings to a local Ollama LLM for AI-powered threat assessment. Alerts via Slack, Discord, or email. Runs as a systemd daemon in watch mode.

---

## Features

- **Log parsing** — `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL/CentOS), journalctl JSON export
- **Detection rules** with MITRE ATT&CK IDs and confidence scores:
  - SSH brute force — sliding window, per-IP (`T1110`)
  - Distributed brute force / botnet patterns (`T1110`)
  - Credential stuffing — failures followed by successful login from same IP (`T1110`)
  - `sudo`/`su` failures and privilege escalation (`T1548`)
  - New user account creation via `useradd` (`T1136`)
  - Direct root logins (`T1078`)
- **AI threat assessment** via local Ollama — structured report, IOC extraction, mitigations
- **IP reputation** via AbuseIPDB — abuse score + country code per finding
- **Known-good allowlist** — `allowlist.yaml` suppresses trusted IPs and users (jump boxes, monitoring agents)
- **Alerting** — Slack webhook, Discord webhook, email (SMTP)
- **Watch mode** — daemon that tails the log and fires alerts on new CRITICAL/HIGH findings
- **Outputs** — color terminal report, JSON, plain text
- **Zero third-party dependencies** — Python 3.11+ stdlib only

---

## Quickstart

```bash
# Generate a sample log and run without Ollama
python3 main.py --generate-sample
python3 main.py sample_auth.log --no-ai

# Run against live system logs with AI
sudo python3 main.py /var/log/auth.log --url http://YOUR_OLLAMA_IP:11434 --model llama3.2:3b

# Save both text and JSON reports
sudo python3 main.py /var/log/auth.log --no-ai --out report.txt --json report.json

# With AbuseIPDB enrichment
sudo python3 main.py /var/log/auth.log --no-ai --abuseipdb YOUR_KEY

# With known-good allowlist
sudo python3 main.py /var/log/auth.log --no-ai --allowlist allowlist.yaml

# Alert to Slack on CRITICAL/HIGH findings
sudo python3 main.py /var/log/auth.log --no-ai \
  --webhook https://hooks.slack.com/services/...

# Watch mode — continuous scan every 60s, alerts on new findings
sudo python3 main.py /var/log/auth.log --watch --interval 60 --no-ai \
  --allowlist allowlist.yaml \
  --webhook https://hooks.slack.com/services/...
```

---

## Flags

| Flag | Default | Description |
|---|---|---|
| `LOG_FILE` | auto-detect | Path to auth log (`/var/log/auth.log` or `/var/log/secure`) |
| `--url URL` | `http://localhost:11434` | Ollama server URL (or set `OLLAMA_HOST`) |
| `--model MODEL` | `llama3.1:8b` | Ollama model for AI analysis |
| `--no-ai` | off | Skip AI — rule-based findings only |
| `--format` | `auto` | `auto` \| `auth` \| `journalctl` |
| `--allowlist FILE` | none | YAML file of trusted IPs/users to skip |
| `--abuseipdb KEY` | none | AbuseIPDB API key (or `ABUSEIPDB_API_KEY` env var) |
| `--webhook URL` | none | Slack or Discord webhook URL (or `ALERT_WEBHOOK_URL`) |
| `--email` | off | Send SMTP email alert (configure via `ALERT_SMTP_*` env vars) |
| `--watch` | off | Watch mode: re-scan every `--interval` seconds |
| `--interval SECS` | `60` | Scan interval in watch mode |
| `--json FILE` | none | Save JSON report to file |
| `--out FILE` | none | Save plain text report to file |
| `--no-color` | off | Disable ANSI colors |
| `--verbose / -v` | off | Show per-IP AbuseIPDB lookup results |
| `--list-models` | off | List models on Ollama server and exit |
| `--generate-sample` | off | Write `sample_auth.log` for testing and exit |

---

## Alerting

### Slack / Discord Webhook

Works with any Slack incoming webhook or Discord webhook URL — auto-detected by URL:

```bash
# Slack
export ALERT_WEBHOOK_URL=https://hooks.slack.com/services/T.../B.../...
# Discord
export ALERT_WEBHOOK_URL=https://discord.com/api/webhooks/.../.../

python3 main.py /var/log/auth.log --no-ai --webhook "$ALERT_WEBHOOK_URL"
```

Alerts fire on CRITICAL and HIGH findings only. Message includes severity, MITRE ID, confidence, source IP, AbuseIPDB score, and AI assessment summary (truncated to 800 chars).

### Email (SMTP)

```bash
export ALERT_SMTP_HOST=smtp.gmail.com
export ALERT_SMTP_PORT=587
export ALERT_SMTP_USER=you@gmail.com
export ALERT_SMTP_PASS=your_app_password    # Gmail App Password
export ALERT_TO=alerts@yourdomain.com

python3 main.py /var/log/auth.log --email
```

---

## Allowlist

`allowlist.yaml` — skip events from trusted sources:

```yaml
trusted_ips:
  - 10.0.1.1        # jump box
  - 192.168.1.1     # monitoring agent

trusted_users:
  - prometheus
  - ansible
  - backup
```

Pass via `--allowlist allowlist.yaml`. Allowlisted events are silently skipped before detection runs.

---

## Watch Mode / Daemon

Run as a persistent background process that tails the log and fires alerts on new HIGH/CRITICAL findings:

```bash
python3 main.py /var/log/auth.log --watch --interval 60 --no-ai \
  --allowlist allowlist.yaml \
  --webhook "$ALERT_WEBHOOK_URL"
```

Tracks seen anomaly IDs across scans — only alerts on *new* findings, not the same event every 60 seconds.

### systemd Service

```bash
# Copy files
sudo cp -r . /opt/p3-log-anomaly-detector/
sudo cp p3-anomaly-detector.service /etc/systemd/system/

# Set env vars (webhook URL, Ollama host, etc.)
sudo systemctl edit p3-anomaly-detector
# Add:
# [Service]
# Environment=ALERT_WEBHOOK_URL=https://hooks.slack.com/services/...
# Environment=OLLAMA_HOST=http://YOUR_OLLAMA_IP:11434

sudo systemctl daemon-reload
sudo systemctl enable --now p3-anomaly-detector
sudo systemctl status p3-anomaly-detector
```

---

## Detection Rules

### Brute Force — `T1110`
- ≥5 SSH failures from one IP within 10 minutes
- Severity: MEDIUM (5+) → HIGH (20+) → CRITICAL (50+)
- Confidence scales with attempt count

### Distributed Brute Force — `T1110`
- ≥10 unique source IPs with combined ≥20 failures
- Indicates botnet/distributed attack, not single-IP brute force

### Credential Stuffing — `T1110`
- Successful login from an IP with prior failures in same session
- Always CRITICAL — indicates a brute force that succeeded

### Privilege Escalation — `T1548`
- `sudo` authentication failures per user
- `su` sessions opened as root

### Account Creation — `T1136`
- `useradd` calls — always HIGH, confidence 1.0

### Root Login — `T1078`
- Direct SSH login as root — always CRITICAL, confidence 1.0

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | No anomalies / all low severity |
| `1` | HIGH severity anomalies found |
| `2` | CRITICAL severity anomalies found |

Use in cron for scripted alerting:

```bash
python3 main.py /var/log/auth.log --no-ai --json /tmp/auth-daily.json
status=$?
if [ "$status" -ge 1 ]; then
    mail -s "ALERT: auth anomalies" you@email.com < /tmp/auth-daily.json
fi
```

---

## Architecture

```
main.py                 CLI entry point, watch mode, alert orchestration
log_parser.py           Auth log → LogEvent objects (syslog format)
journalctl_parser.py    journalctl JSON export → LogEvent objects
anomaly_detector.py     Rule engine → Anomaly objects with MITRE IDs + confidence
ollama_client.py        Ollama REST client (scheme-validated, no file:// risk)
report_generator.py     Text + JSON report builder
email_alerts.py         SMTP alerting
slack_alerts.py         Slack + Discord webhook alerting
abuseipdb.py            IP reputation enrichment via AbuseIPDB API
allowlist.py            YAML allowlist loader
allowlist.yaml          Trusted IPs and users (edit for your environment)
suppressions.yaml       P1 suppression rules for SAST scan results
p3-anomaly-detector.service  systemd unit for watch-mode daemon
```

### Anomaly Schema

| Field | Type | Description |
|---|---|---|
| `anomaly_id` | `str` | Unique ID per run (`BF-001`, `PE-002`, etc.) |
| `severity` | `str` | `CRITICAL \| HIGH \| MEDIUM \| LOW \| INFO` |
| `category` | `str` | `brute_force \| privilege_escalation \| unusual_ip` |
| `mitre_id` | `str` | ATT&CK technique ID (`T1110`, `T1548`, etc.) |
| `mitre_name` | `str` | ATT&CK technique name |
| `confidence` | `float` | 0–1 detection confidence (scales with event count) |
| `source_ip` | `str` | Source IP address if applicable |
| `username` | `str` | Username if applicable |
| `abuse_score` | `int` | AbuseIPDB confidence score (−1 = not checked) |
| `geo_country` | `str` | Country code from AbuseIPDB |
