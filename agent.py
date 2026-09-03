"""
Agentic log analysis loop.

LogAnalysisAgent drives a multi-step investigation using real multi-turn
conversation via Ollama /api/chat. Each turn the model returns one JSON
tool call; the agent executes it and feeds results back as the next user
message. This is genuine tool-use — not prompt concatenation.

Supported tools: search_ip, search_user, get_timeline,
check_lateral_movement, get_anomaly_context, conclude.

Optional --act mode executes remediation actions (block_ip, lock_user)
via actions.py when the agent's conclusion includes HIGH/CRITICAL findings.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from anomaly_detector import Anomaly
from parsers.base import LogEvent
from ollama_client import OllamaClient

MAX_STEPS = 6
_MAX_EVENTS_PER_RESULT = 20

_SYSTEM_PROMPT = """\
You are an expert Linux security analyst performing an autonomous log investigation.
You will be shown security anomalies detected in auth or web logs.
Investigate findings using the tools below, then deliver a final threat assessment.

Available tools — respond with exactly ONE JSON object per turn, no prose before or after:

{"action": "search_ip", "args": {"ip": "<ip>"}}
  → All log events from this source IP.

{"action": "search_user", "args": {"username": "<user>"}}
  → All log events associated with this username.

{"action": "get_timeline", "args": {"anchor": "<ISO-datetime>", "before_min": <int>, "after_min": <int>}}
  → Events in a time window around the anchor timestamp.

{"action": "check_lateral_movement", "args": {"username": "<user>"}}
  → Unique source IPs a user authenticated from; flags multi-IP logins.

{"action": "get_anomaly_context", "args": {"anomaly_id": "<id>"}}
  → Raw log lines stored for an anomaly (e.g. "BF-001").

{"action": "conclude", "args": {
    "risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>",
    "summary": "<narrative>",
    "iocs": ["<ip-or-user>", ...],
    "recommendations": ["<action>", ...]
}}
  → Finish investigation with final threat assessment.

Rules:
- ONE JSON object only. No text before or after the JSON.
- Investigate HIGH/CRITICAL findings first.
- After 5 tool calls you MUST call conclude.
- Do not repeat identical tool calls.
"""


@dataclass
class AgentStep:
    """One step in the agent's reasoning trace."""
    step: int
    tool: str
    args: dict[str, Any]
    result_summary: str


@dataclass
class AgentReport:
    """Final output of the agent's analysis."""
    risk_level: str
    summary: str
    iocs: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)
    steps: list[AgentStep] = field(default_factory=list)
    actions_taken: list[str] = field(default_factory=list)
    raw_conclusion: str = ""


def _extract_json(text: str) -> Optional[dict]:
    """Extract first valid JSON object from model output."""
    decoder = json.JSONDecoder()
    for i in range(len(text)):
        if text[i] == "{":
            try:
                obj, _ = decoder.raw_decode(text, i)
                if isinstance(obj, dict):
                    return obj
            except json.JSONDecodeError:
                continue
    return None


def _fmt_events(events: list[LogEvent], limit: int = _MAX_EVENTS_PER_RESULT) -> str:
    lines = []
    for ev in events[:limit]:
        ts = ev.timestamp.isoformat() if ev.timestamp else "??:??:??"
        lines.append(
            f"  [{ts}] {ev.event_type or ev.extra.get('method','?')} "
            f"| user={ev.user or '-'} | ip={ev.ip or '-'} | {ev.message[:80]}"
        )
    if len(events) > limit:
        lines.append(f"  ... ({len(events) - limit} more events)")
    return "\n".join(lines) if lines else "  (no events found)"


class LogAnalysisAgent:
    """
    Multi-step agentic log analyst using real /api/chat multi-turn conversation.

    Investigation loop:
      1. Send anomaly context + system prompt to /api/chat
      2. Model returns ONE JSON tool call
      3. Agent executes the tool, appends result as next user message
      4. Repeat until model calls 'conclude' or MAX_STEPS reached
      5. Optionally execute remediation actions via actions.py
    """

    def __init__(self, client: OllamaClient, act: bool = False, dry_run: bool = False) -> None:
        """
        Args:
            client: Configured OllamaClient.
            act: If True, execute remediation actions (block IPs, lock users)
                 when conclusion is HIGH or CRITICAL.
            dry_run: If True with act, log what would happen without executing.
        """
        self.client = client
        self.act = act
        self.dry_run = dry_run
        self.steps: list[AgentStep] = []
        self._called_tools: set[str] = set()

    def analyze(self, events: list[LogEvent], anomalies: list[Anomaly]) -> AgentReport:
        """
        Run the agentic investigation loop.

        Args:
            events: All parsed log events.
            anomalies: Rule-based findings with MITRE IDs and confidence scores.

        Returns:
            AgentReport with risk level, IOCs, recommendations, trace, and
            any remediation actions taken.
        """
        self.steps = []
        self._called_tools = set()

        # Real multi-turn conversation — messages list passed to /api/chat
        messages: list[dict] = [
            {"role": "system", "content": _SYSTEM_PROMPT},
            {"role": "user", "content": self._initial_context(anomalies)},
        ]

        for step_num in range(1, MAX_STEPS + 1):
            response = self._call_llm(messages)
            parsed = _extract_json(response)

            # Append model response to conversation history
            messages.append({"role": "assistant", "content": response})

            if not parsed or "action" not in parsed:
                messages.append({
                    "role": "user",
                    "content": "Respond with ONLY a single JSON tool call. No prose.",
                })
                continue

            action = parsed.get("action", "")
            args = parsed.get("args", {})

            if action == "conclude":
                report = AgentReport(
                    risk_level=args.get("risk_level", "UNKNOWN"),
                    summary=args.get("summary", ""),
                    iocs=args.get("iocs", []),
                    recommendations=args.get("recommendations", []),
                    steps=self.steps,
                    raw_conclusion=response,
                )
                if self.act or self.dry_run:
                    report.actions_taken = self._execute_actions(report)
                return report

            result = self._execute_tool(action, args, events, anomalies)
            self.steps.append(AgentStep(
                step=step_num,
                tool=action,
                args=args,
                result_summary=result[:300],
            ))
            # Feed tool result back as the next user message
            messages.append({"role": "user", "content": f"Tool result:\n{result}"})

        return self._force_conclude(messages)

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _initial_context(self, anomalies: list[Anomaly]) -> str:
        lines = [f"## Detected Anomalies ({len(anomalies)} total)\n"]
        for a in anomalies[:10]:
            lines.append(
                f"[{a.anomaly_id}] {a.severity} | {a.title}\n"
                f"  MITRE: {a.mitre_id} — {a.mitre_name}\n"
                f"  {a.description}\n"
                f"  Confidence: {a.confidence:.0%}"
                + (f" | IP: {a.source_ip}" if a.source_ip else "")
                + (f" | User: {a.username}" if a.username else "")
                + "\n"
            )
        if len(anomalies) > 10:
            lines.append(f"... and {len(anomalies) - 10} more.\n")
        lines.append("Investigate the highest-severity findings first. Use tools, then conclude.")
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM call — uses /api/chat for genuine multi-turn
    # ------------------------------------------------------------------

    def _call_llm(self, messages: list[dict]) -> str:
        try:
            return self.client.chat(messages)
        except RuntimeError:
            return (
                '{"action": "conclude", "args": {'
                '"risk_level": "UNKNOWN", "summary": "LLM unavailable.", '
                '"iocs": [], "recommendations": []}}'
            )

    # ------------------------------------------------------------------
    # Tool execution
    # ------------------------------------------------------------------

    def _execute_tool(
        self,
        action: str,
        args: dict,
        events: list[LogEvent],
        anomalies: list[Anomaly],
    ) -> str:
        call_key = f"{action}:{json.dumps(args, sort_keys=True)}"
        if call_key in self._called_tools:
            return "(duplicate tool call — skipped)"
        self._called_tools.add(call_key)

        if action == "search_ip":
            ip = args.get("ip", "")
            found = [e for e in events if e.ip == ip]
            return f"Events from IP {ip} ({len(found)} total):\n{_fmt_events(found)}"

        if action == "search_user":
            user = args.get("username", "")
            found = [e for e in events if e.user == user]
            return f"Events for user '{user}' ({len(found)} total):\n{_fmt_events(found)}"

        if action == "get_timeline":
            anchor_str = args.get("anchor", "")
            before = int(args.get("before_min", 5))
            after = int(args.get("after_min", 5))
            try:
                anchor = datetime.fromisoformat(anchor_str)
                start = anchor - timedelta(minutes=before)
                end = anchor + timedelta(minutes=after)
                found = [e for e in events if e.timestamp and start <= e.timestamp <= end]
                return (
                    f"Timeline [{anchor_str} -{before}/+{after}min] ({len(found)} events):\n"
                    + _fmt_events(found)
                )
            except (ValueError, TypeError):
                return f"Invalid anchor timestamp: {anchor_str!r}"

        if action == "check_lateral_movement":
            user = args.get("username", "")
            all_ips = {e.ip for e in events if e.user == user and e.ip}
            success_ips = {
                e.ip for e in events
                if e.user == user
                and e.event_type in ("ssh_accepted_password", "ssh_accepted_publickey")
                and e.ip
            }
            lateral = len(success_ips) > 1
            return (
                f"User '{user}': {len(all_ips)} unique IP(s) total.\n"
                f"  All IPs: {', '.join(sorted(all_ips)) or 'none'}\n"
                f"  Successful login IPs: {', '.join(sorted(success_ips)) or 'none'}\n"
                f"  {'LATERAL MOVEMENT INDICATOR — multiple successful-login source IPs.' if lateral else 'Single successful-login IP.'}"
            )

        if action == "get_anomaly_context":
            anomaly_id = args.get("anomaly_id", "")
            target = next((a for a in anomalies if a.anomaly_id == anomaly_id), None)
            if not target:
                return f"Anomaly '{anomaly_id}' not found."
            raw_lines = "\n".join(f"  {r}" for r in target.raw_events)
            return (
                f"Anomaly {anomaly_id} — {target.title}\n"
                f"  Severity: {target.severity} | Confidence: {target.confidence:.0%}\n"
                f"  MITRE: {target.mitre_id} ({target.mitre_name})\n"
                f"  Raw events:\n{raw_lines or '  (none stored)'}"
            )

        return f"Unknown tool: {action!r}"

    def _force_conclude(self, messages: list[dict]) -> AgentReport:
        messages.append({
            "role": "user",
            "content": (
                "Step limit reached. Call conclude NOW with your assessment:\n"
                '{"action": "conclude", "args": {"risk_level": "...", '
                '"summary": "...", "iocs": [], "recommendations": []}}'
            ),
        })
        response = self._call_llm(messages)
        parsed = _extract_json(response)
        if parsed and parsed.get("action") == "conclude":
            args = parsed.get("args", {})
            report = AgentReport(
                risk_level=args.get("risk_level", "UNKNOWN"),
                summary=args.get("summary", response),
                iocs=args.get("iocs", []),
                recommendations=args.get("recommendations", []),
                steps=self.steps,
                raw_conclusion=response,
            )
            if self.act or self.dry_run:
                report.actions_taken = self._execute_actions(report)
            return report
        return AgentReport(
            risk_level="UNKNOWN",
            summary=response or "Agent did not produce a conclusion.",
            steps=self.steps,
        )

    # ------------------------------------------------------------------
    # Remediation actions (--act mode)
    # ------------------------------------------------------------------

    def _execute_actions(self, report: AgentReport) -> list[str]:
        """Execute remediation actions when risk is HIGH or CRITICAL."""
        if report.risk_level not in ("CRITICAL", "HIGH"):
            return []

        try:
            from actions import block_ip, lock_user
        except ImportError:
            return ["actions.py not found — remediation skipped"]

        taken: list[str] = []
        dry = self.dry_run
        for ioc in report.iocs:
            # IPs look like digits and dots
            if all(c.isdigit() or c == "." for c in ioc) and ioc.count(".") == 3:
                taken.append(block_ip(ioc, dry_run=dry))
            else:
                taken.append(lock_user(ioc, dry_run=dry))
        return taken
