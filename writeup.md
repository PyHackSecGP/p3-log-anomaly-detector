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

---

## Interview Guide

### One-Line Pitch

"I built a Python tool that parses Linux auth logs, runs rule-based detection, then sends findings to a local LLM for threat assessment — no cloud APIs, no dependencies, pure stdlib."

### The Flow (explain this end-to-end)

1. **Parse** — regex extracts structured `LogEvent` objects from each log line: timestamp, hostname, source IP, username, event type
2. **Detect** — three rule engines run in sequence: brute force (sliding window), privilege escalation (sudo/su/useradd/root login), unusual IPs (credential stuffing, distributed botnet)
3. **Enrich** — findings are serialized to structured text and sent to a local Ollama LLM with a constrained security analyst prompt
4. **Report** — colored terminal output, plain text file, or JSON; exit code reflects highest severity (2=CRITICAL, 1=HIGH, 0=clean)

### Common Interview Questions

**"Why rule-based + AI instead of just AI?"**
> Rule-based detection is deterministic and fast — it catches the obvious stuff with zero hallucination risk. The LLM layer adds context: attack pattern analysis, IOC extraction, specific mitigations. One without the other is weaker.

**"Why no pip dependencies?"**
> Pure stdlib — `urllib`, `re`, `dataclasses`, `json`. Runs anywhere Python 3.11+ is installed. No supply chain risk, no virtual env setup needed.

**"What does the LLM actually add?"**
> It receives the structured anomaly summary and sample raw log lines, then returns: overall risk rating, attack pattern analysis, immediate recommendations, and IPs/usernames to block. The model focuses on interpretation, not detection — that separation is intentional.

**"Walk me through the brute force detection."**
> It's a sliding window algorithm. For each source IP, events are sorted by timestamp. Starting from each failure event, I expand a 10-minute window forward and count failures inside it. If the count hits the threshold, it fires. This catches burst attacks without triggering on slow distributed ones, and avoids the boundary problem you get with fixed windows.

**"What's your highest-severity detection and why?"**
> Successful login after prior failures from the same IP — I cross-correlate failure and success events per IP and check if failures preceded the first success. That's flagged CRITICAL because it means the attack worked. Everything else is potential; this one is confirmed.

**"What would you add next?"**
> Journald support, GeoIP enrichment on source IPs, a watch mode for real-time tailing, and MITRE ATT&CK technique tagging (T1110 for brute force, T1078 for valid accounts used post-compromise).

### Technical Depth to Show

- **Sliding window vs fixed window** — fixed windows miss attacks that straddle the boundary; sliding windows catch them but can double-count, so this implementation limits to one anomaly per IP
- **Severity scoring** — count thresholds map to CRITICAL/HIGH/MEDIUM/LOW, making exit codes useful in CI/monitoring pipelines
- **Graceful LLM fallback** — if Ollama is unreachable, drops to rule-only report without crashing; no hard dependency on AI being available
- **Timestamp parsing edge cases** — syslog omits the year, and single-digit days use inconsistent padding (`May  5` vs `May 5`); handled by trying multiple strptime formats and injecting the current year
