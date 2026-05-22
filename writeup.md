# P3 — AI Log Anomaly Detector: Technical Writeup

## What I Built

A Python tool that ingests Linux auth logs, runs multi-rule anomaly detection, and feeds findings into a local LLM (via Ollama) for contextual threat assessment. No paid APIs, no cloud, no third-party libraries.

## Problem It Solves

Auth logs are noisy. A busy server might have thousands of SSH failures per day. The challenge isn't detecting that failures happened — it's distinguishing a port scan from a targeted brute force, and flagging the moment that brute force succeeds.

Traditional SIEM rules answer "how many failures?" I added: "what happened *after* the failures?"

## Architecture

```
auth.log ──► log_parser.py ──► LogEvent objects
                                      │
                              anomaly_detector.py
                              (3 detection engines)
                                      │
                              ┌───────┴───────┐
                              │               │
                        report_generator  ollama_client
                              │               │
                         text/JSON      AI threat assessment
                              └───────┬───────┘
                                   main.py (CLI)
```

## Detection Logic

**Brute Force**: Sliding window algorithm — for each source IP, walks through failures chronologically and checks if any 10-minute window contains ≥5 failures. This catches bursts without triggering on slow distributed attacks.

**Credential Stuffing**: Cross-correlates failure events with success events per IP. If an IP has ≥1 failure *before* its first success, that's flagged CRITICAL. This is the highest-value detection because it means the attack worked.

**Distributed Brute Force**: Aggregates all unique source IPs. If >10 IPs contributed ≥20 total failures, flags a botnet pattern. Single-IP thresholds miss this entirely.

**Privilege Escalation**: Tracks `sudo` failures, `su root` sessions, `useradd`, and direct root logins. These are post-exploitation indicators — if brute force already succeeded, these show what came next.

## AI Integration

Findings are serialized to structured text (anomaly ID, severity, description, timestamps, source IPs) and sent to Ollama as a single prompt. The system message constrains the model to produce five specific sections: threat assessment, key findings, attack pattern analysis, recommendations, and IOCs.

This works better than asking the model to analyze raw logs directly because:
1. Rule-based pre-filtering removes noise
2. Structured input produces structured output
3. The model focuses on *interpretation* not *detection*

The client gracefully handles Ollama being unreachable — falls back to rule-only report without crashing.

## What I Learned

- Syslog timestamp parsing is messier than it looks — the year is absent in most formats, and single-digit days use padding inconsistently (`May  5` vs `May 5`).
- Sliding window detection vs. fixed window: fixed windows miss attacks that straddle the boundary. Sliding windows catch them but can double-count. This implementation limits to one anomaly per IP to avoid that.
- Exit codes as severity signals: using exit code 2 for CRITICAL lets this tool integrate cleanly into CI/CD pipelines or cron jobs that alert on non-zero exits.

## Next Improvements

- GeoIP lookup for source IPs (flag logins from unexpected countries)
- Baseline model: learn "normal" login times per user, flag off-hours access
- Integration with fail2ban or iptables for automated blocking
- Watch mode: tail the log file in real-time instead of batch processing
- MITRE ATT&CK tagging on each anomaly (T1110 — Brute Force, T1078 — Valid Accounts)
