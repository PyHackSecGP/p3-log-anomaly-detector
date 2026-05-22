# P3 — AI Log Anomaly Detector

Parses Linux auth logs, runs rule-based anomaly detection, and sends findings to a local Ollama LLM for AI-powered threat assessment.

## Features

- Parses `/var/log/auth.log` (Debian/Ubuntu) and `/var/log/secure` (RHEL/CentOS)
- Detects:
  - SSH brute-force attacks (sliding window, per-IP threshold)
  - Distributed brute force / botnet patterns
  - Credential stuffing (failures followed by successful login from same IP)
  - `su`/`sudo` failures and privilege escalation
  - New user creation (`useradd`)
  - Direct root logins
- AI analysis via local Ollama — structured threat assessment, IOC extraction, recommendations
- Outputs color terminal report + optional JSON export
- Zero third-party dependencies (Python 3.11+ stdlib only)

## Quickstart

```bash
# Generate a sample log and run (no Ollama needed to test)
python main.py --generate-sample
python main.py sample_auth.log --no-ai

# Run against your system logs with AI
sudo python main.py /var/log/auth.log --url http://localhost:11434 --model llama3.2:3b

# Use claw-core endpoint
python main.py /var/log/auth.log --url http://100.126.22.55:11434 --model llama3.1:70b

# Save reports
python main.py /var/log/auth.log --out report.txt --json report.json
```

## Options

| Flag | Description |
|------|-------------|
| `LOG_FILE` | Path to auth log (auto-detects `/var/log/auth.log` if omitted) |
| `--url URL` | Ollama server URL (default: `http://localhost:11434`) |
| `--model MODEL` | Model name (default: `llama3.1:8b`) |
| `--no-ai` | Skip AI analysis, rule-based findings only |
| `--json FILE` | Save JSON report to file |
| `--out FILE` | Save plain text report to file |
| `--no-color` | Disable ANSI colors |
| `--list-models` | List models on Ollama server |
| `--generate-sample` | Write `sample_auth.log` for testing |

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | No anomalies / clean |
| 1 | HIGH severity anomalies found |
| 2 | CRITICAL severity anomalies found |

## Project Structure

```
p3-log-anomaly-detector/
├── main.py              # CLI entry point
├── log_parser.py        # Auth log parser → LogEvent objects
├── anomaly_detector.py  # Rule-based detection engine
├── ollama_client.py     # Ollama API client
├── report_generator.py  # Text + JSON report builder
├── requirements.txt     # No deps (stdlib only)
├── sample_auth.log      # Generated test log
├── README.md
└── writeup.md
```

## Detection Rules

### Brute Force (`brute_force`)
- **Threshold**: ≥5 failed SSH attempts from one IP within 10 minutes
- **Severity**: scales from MEDIUM (5+) → HIGH (20+) → CRITICAL (50+)

### Privilege Escalation (`privilege_escalation`)
- `sudo` authentication failures (per user)
- `su` sessions opened for root
- `useradd` new account creation
- Direct root logins via SSH

### Unusual IPs (`unusual_ip`)
- Successful auth from an IP with prior failures (credential stuffing indicator)
- ≥10 unique source IPs with combined ≥20 failures (distributed botnet)
