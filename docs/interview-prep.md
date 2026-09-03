# P3 — Interview Prep Notes

## 30-Second Pitch

> "P3 is an AI-powered Linux log anomaly detector. It parses auth and nginx logs, maps every finding to a MITRE ATT&CK technique with a confidence score, then runs a statistical z-score baseline against 30-day history to cut false positives. The agentic mode puts a local LLM in a real multi-turn investigation loop — it pivots on IPs, checks timelines, looks for lateral movement, and produces a final report with IOCs and remediation commands. In --act mode it actually executes — blocks IPs via iptables, locks compromised accounts. Everything runs locally on Ollama, no data leaves the network."

---

## Questions they will ask — with your answers

---

### Architecture

**Q: Walk me through how the agentic loop works.**

A: The agent uses Ollama's `/api/chat` endpoint — real multi-turn conversation with a role-based message list (system, user, assistant). The system prompt defines 6 tools in JSON schema format: `search_ip`, `search_user`, `get_timeline`, `check_lateral_movement`, `get_anomaly_context`, `conclude`. Each turn I ask the model to return exactly one JSON object representing its next tool call. I execute that tool, append the result as the next user message, and repeat until the model calls `conclude` or we hit the step limit. The reasoning trace is fully visible in the output — every tool call and result is logged.

**Q: Why /api/chat instead of /api/generate?**

A: `/api/generate` is single-turn — you send a prompt, you get a response. For multi-turn investigation you need the model to maintain context across turns: what it already investigated, what it found, what it still wants to check. `/api/chat` sends the full message history each call so the model can reason about prior results. Using `/api/generate` with concatenated strings is just prompt stuffing — the model doesn't understand conversation structure the same way.

**Q: How does the tool-calling work without structured output (OpenAI tool_call format)?**

A: The system prompt instructs the model to respond with exactly one JSON object in a specific schema. I use `json.JSONDecoder().raw_decode()` to find and extract the first valid JSON object from anywhere in the response. If the model returns prose, I send back "respond with only a JSON tool call" as the next user message and retry. This works reliably with hermes3:70b and qwen3.5 because the instruction is clear and the schema is simple. For production I'd add a structured output constraint via `format: json` in newer Ollama versions.

---

### Detection

**Q: What's the difference between your detection and a traditional SIEM rule?**

A: Traditional SIEM rules are static: "5 failures in 10 minutes = alert." My tool does that too as a floor, but then layers z-score statistical baselining on top. After 3 days of data, it knows what's normal for that specific host at that specific hour of day. A system that normally sees 200 SSH failures at noon gets those downgraded from HIGH to MEDIUM — that's scanner noise, not an attack. The same 200 failures at 3am stay CRITICAL because z-score is 4.7 standard deviations above the 3am baseline. Traditional SIEMs need manual threshold tuning per environment. This self-calibrates.

**Q: You said MITRE ATT&CK mapping — what does that actually mean in your code?**

A: Every `Anomaly` object has `mitre_id` and `mitre_name` fields populated at detection time. For example, `detect_brute_force()` hardcodes `T1110` (Brute Force), `detect_privilege_escalation()` uses `T1548` (Abuse Elevation Control Mechanism) for sudo failures and `T1136` (Create Account) for useradd. These map directly to ATT&CK technique IDs so a SOC analyst can look up the full technique, sub-techniques, and mitigations immediately from the finding.

**Q: How do you handle false positives?**

A: Three layers. First, the allowlist — `allowlist.yaml` suppresses events from trusted IPs and users entirely before detection runs (jump boxes, monitoring agents). Second, the z-score baseline downgrades severity for counts that are statistically normal for that host. Third, the agentic mode can override — the LLM sees context that rules don't: if 200 failures come from your own scanner IP, it'll note that in its analysis even if the rule fires.

**Q: What about the cold-start problem — what happens on day 1?**

A: On day 1 the baseline has no history so `has_history()` returns False and severity adjustments don't activate. It runs pure rule-based. This is intentional — I'd rather have false positives during the learning period than false negatives. After 3 days of data the baseline takes over. If you onboard a new server, the first 3 days are noisy, then it self-calibrates. I documented this as a known limitation — I don't pretend the z-score works on day 1.

---

### Engineering

**Q: You said zero third-party dependencies — why?**

A: Operational constraint. Security tools often run on hardened systems with restricted package installations. If it needs `pip install X` it might not run in production. All parsing, detection, baseline, and state management use Python stdlib: `sqlite3`, `json`, `re`, `statistics`, `urllib`. The only optional integration is Ollama via HTTP — and that's a network call, not a package dependency.

**Q: How does watch mode handle large log files?**

A: It doesn't re-read the file — it tails. `state.py` stores the last byte position and inode in SQLite per log file. Each scan seeks to that position, reads only new bytes, then saves the new position. Log rotation is handled by checking if the current inode changed or if the file shrank — in either case we reset to position 0. This means watch mode is O(new_data) not O(file_size) regardless of how large the log gets.

**Q: How do you handle log rotation?**

A: Two signals: inode change (the OS gave the log file a new inode after rotation) or file size shrink (position > current size). Either condition resets the read position to 0 on the new/reset file. Tracked per log file in SQLite so it survives daemon restarts.

**Q: Why SQLite for state instead of a file or Redis?**

A: SQLite is stdlib (`import sqlite3`), transactional, survives concurrent access, and doesn't require a running service. Redis would require infrastructure. A JSON file would have race conditions if multiple processes hit it. SQLite is the right fit for a single-host daemon that needs persistence without operational overhead.

**Q: What's in SARIF output and why does it matter?**

A: SARIF 2.1.0 is the standard format for security findings — GitHub Security tab, DefectDojo, Splunk, and dozens of other tools ingest it natively. My SARIF maps each anomaly to a result with rule ID (MITRE technique), severity, physical location (log file), logical location (IP or username), confidence, and raw event context. It means findings from this tool can flow directly into an existing SOC workflow without any glue code.

---

### Security engineering questions

**Q: The --act flag runs iptables automatically — isn't that dangerous?**

A: Yes, and it's gated deliberately. `--act` requires explicit opt-in and root. More importantly, `--dry-run` exists so you can see exactly what it would execute before anything runs. In production I'd add a human-approval step — the agent concludes, emails the IOC list, waits for confirmation before executing. The current design is right for a homelab or CTF environment, not for a production SOC without that approval gate. I'd be honest about that in any deployment conversation.

**Q: What prevents the agent from blocking a legitimate IP?**

A: The allowlist. If an IP is in `allowlist.yaml`, events from that IP are suppressed before detection runs — the agent never sees them. For `--act` without `--dry-run` there's also the confidence score threshold — I only act on HIGH/CRITICAL findings where confidence is meaningful. The audit log in `~/.local/share/p3-anomaly/actions.log` records every action taken. For a production deployment you'd add human-in-the-loop before executing.

**Q: How would you scale this to handle 50 servers?**

A: Three changes. One: push log shipping to a central collector (Fluentd, Vector) and run P3 against the aggregated stream. Two: replace the SQLite baseline with a time-series DB (InfluxDB or Prometheus) for cross-host baselining. Three: the agent currently runs inline — for 50 hosts you'd queue anomaly batches and run agents in parallel workers. The core detection and agent logic wouldn't change, just the ingestion and storage layer.

---

## Scenario walkthroughs

### Scenario 1 — Credential stuffing attack

**Setup**: Attacker brute-forces SSH, succeeds on attempt 8, escalates to root, creates backdoor.

**What the tool does**:
- `detect_brute_force`: fires on 8 failures from same IP in 10 min → `BF-001 MEDIUM`
- `detect_unusual_ips`: success after failures → `IP-001 CRITICAL`
- `detect_privilege_escalation`: su-to-root, useradd → `PE-001 HIGH`, `PE-002 HIGH`
- Agent step 1: `search_ip("192.168.1.100")` — sees the failure-to-success pattern
- Agent step 2: `check_lateral_movement("backup")` — single IP, no lateral movement
- Agent step 3: `get_timeline(anchor=login_time, before=5, after=10)` — sees full kill chain
- Agent concludes: CRITICAL, names all 3 IOCs, recommends block + lock + grep cron

**Talking point**: "The agent connected dots across 4 separate rule findings into one coherent narrative — that's the value of the investigation loop over a list of independent alerts."

---

### Scenario 2 — Baseline in action

**Setup**: Your backup agent runs nightly SSH connection tests — generates 100 "failures" (testing connectivity, not auth). Normal rule would fire CRITICAL.

**What the tool does**:
- Week 1 (learning): CRITICAL fires on the backup agent every night — noisy
- Week 2 onwards: baseline z-score = 0.1 for `ssh_failed_password` at 2am → downgraded to MEDIUM
- Allowlist the backup agent IP → silent completely

**Talking point**: "This is why static thresholds fail in production. 100 failures at 2am from your monitoring system looks identical to 100 failures from an attacker until the baseline has context."

---

### Scenario 3 — Nginx web scanning

**Setup**: Someone runs sqlmap against your login page, generating 400 4xx errors.

**What the tool does**:
- `detect_scanner_uas`: sqlmap UA detected → `WEB-001 HIGH`
- `detect_4xx_flood`: 400 errors from same IP → `WEB-4XX-001 HIGH`
- `detect_sensitive_path_probing`: `/admin`, `/.env`, `/wp-admin` all hit → `WEB-PROBE-001 HIGH`
- With `--agentic`: agent searches the IP across all events, finds it started probing 20 minutes before the scanner ran (reconnaissance phase visible in timeline)

**Talking point**: "Web scanner detection is often missing from auth-focused tools. Running both parsers gives you the full picture — especially when an attacker recons via web before attempting SSH."

---

## Tricky questions and how to handle them

**Q: The z-score baseline isn't real ML — it's just statistics.**

A: Correct. I'd push back on calling it "not real" — z-score is a well-established statistical method used in production anomaly detection. What it doesn't do is detect novel patterns without rules. If an entirely new attack type appears with event counts that look normal, the baseline won't catch it. Rules handle the known patterns; the LLM agent is supposed to provide the novel reasoning. I'm transparent about that in the README — I call it statistical baselining, not ML.

**Q: You're running a local LLM — how do you validate the agent doesn't hallucinate IOCs?**

A: The agent can only return IOCs from the data it was shown. It doesn't invent IPs — the `search_ip` tool searches the actual event list, and the initial context contains the real anomaly data. Hallucination risk is in the narrative (the summary text) not the structured fields. If I were productionizing this I'd add a validation step: check every string in `iocs` against the source event list before acting on it.

**Q: Why not use OpenAI GPT-4 instead of local Ollama?**

A: Two reasons. One: data privacy — auth logs contain usernames, IPs, and behavioural patterns. Sending that to a third-party API is a security risk, not just a policy question. Two: cost and availability — Ollama runs on your infrastructure, no rate limits, no API key rotation, no outage dependency. For a SOC tool that runs 24/7 in watch mode, local inference is the right choice. The tradeoff is model quality — GPT-4 reasons better — but hermes3:70b is good enough for structured tool-calling.
