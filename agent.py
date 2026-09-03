"""
Agentic log analysis loop.

LogAnalysisAgent drives a multi-step investigation using tool calls guided by
a local Ollama LLM. Each step the model picks one tool from a defined set;
the agent executes it and feeds results back until the model calls 'conclude'
or the step limit is reached.

Tool-calling works by prompting the model to emit a single JSON object per turn.
This approach is model-agnostic and works reliably with hermes3, qwen3.5, llama3.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Optional

from anomaly_detector import Anomaly
from log_parser import LogEvent
from ollama_client import OllamaClient


MAX_STEPS = 6
_MAX_EVENTS_PER_RESULT = 20


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
    raw_conclusion: str = ""


_TOOL_SCHEMA = """\
Available tools — respond with exactly ONE JSON object per turn, no prose:

{"action": "search_ip", "args": {"ip": "<ip>"}}
  → All events from a specific source IP.

{"action": "search_user", "args": {"username": "<user>"}}
  → All events associated with a username.

{"action": "get_timeline", "args": {"anchor": "<ISO-datetime>", "before_min": <int>, "after_min": <int>}}
  → Events in a time window around the anchor timestamp.

{"action": "check_lateral_movement", "args": {"username": "<user>"}}
  → Unique source IPs a user authenticated from; flags multi-IP logins.

{"action": "get_anomaly_context", "args": {"anomaly_id": "<id>"}}
  → Raw log lines for an anomaly ID (e.g. "BF-001").

{"action": "conclude", "args": {"risk_level": "<CRITICAL|HIGH|MEDIUM|LOW>", "summary": "<text>", "iocs": ["<ip>", ...], "recommendations": ["<action>", ...]}}
  → Finish investigation with final threat assessment.

Rules:
- ONE JSON object only. No text before or after the JSON.
- After 5 tool calls you MUST call conclude.
- Do not repeat identical tool calls.
"""


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
    """Format LogEvents as compact text for LLM context."""
    lines = []
    for ev in events[:limit]:
        ts = ev.timestamp.isoformat() if ev.timestamp else "??:??:??"
        lines.append(
            f"  [{ts}] {ev.event_type or '?'} | user={ev.username or '-'}"
            f" | ip={ev.source_ip or '-'} | {ev.message[:80]}"
        )
    if len(events) > limit:
        lines.append(f"  ... ({len(events) - limit} more events)")
    return "\n".join(lines) if lines else "  (no events found)"


class LogAnalysisAgent:
    """
    Multi-step agentic log analyst.

    Investigation loop:
      1. Build prompt with anomaly context + tool schema
      2. Ask LLM which tool to call next
      3. Execute the tool, feed results back
      4. Repeat until model calls 'conclude' or MAX_STEPS reached
    """

    def __init__(self, client: OllamaClient) -> None:
        """
        Args:
            client: Configured OllamaClient pointing to a running Ollama server.
        """
        self.client = client
        self.steps: list[AgentStep] = []
        self._called_tools: set[str] = set()

    def analyze(self, events: list[LogEvent], anomalies: list[Anomaly]) -> AgentReport:
        """
        Run the agentic investigation loop.

        Args:
            events: All parsed log events.
            anomalies: Rule-based findings with MITRE IDs and confidence scores.

        Returns:
            AgentReport with risk level, IOCs, recommendations, and full reasoning trace.
        """
        self.steps = []
        self._called_tools = set()

        conversation: list[dict] = [
            {"role": "system", "content": self._system_prompt()},
            {"role": "user", "content": self._initial_context(anomalies)},
        ]

        for step_num in range(1, MAX_STEPS + 1):
            response = self._call_llm(conversation)
            parsed = _extract_json(response)

            conversation.append({"role": "assistant", "content": response})

            if not parsed or "action" not in parsed:
                conversation.append({
                    "role": "user",
                    "content": "Respond with ONLY a single JSON tool call. No prose.",
                })
                continue

            action = parsed.get("action", "")
            args = parsed.get("args", {})

            if action == "conclude":
                return AgentReport(
                    risk_level=args.get("risk_level", "UNKNOWN"),
                    summary=args.get("summary", ""),
                    iocs=args.get("iocs", []),
                    recommendations=args.get("recommendations", []),
                    steps=self.steps,
                    raw_conclusion=response,
                )

            result = self._execute_tool(action, args, events, anomalies)
            self.steps.append(AgentStep(
                step=step_num,
                tool=action,
                args=args,
                result_summary=result[:300],
            ))
            conversation.append({"role": "user", "content": f"Tool result:\n{result}"})

        return self._force_conclude(conversation)

    # ------------------------------------------------------------------
    # Prompt builders
    # ------------------------------------------------------------------

    def _system_prompt(self) -> str:
        return (
            "You are an expert Linux security analyst performing an autonomous log "
            "investigation. You will be shown security anomalies detected in auth "
            "logs. Investigate using the provided tools, then deliver a final threat "
            "assessment.\n\n" + _TOOL_SCHEMA
        )

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
        lines.append(
            "Investigate the highest-severity findings first. "
            "Use tools to gather evidence, then conclude."
        )
        return "\n".join(lines)

    # ------------------------------------------------------------------
    # LLM call
    # ------------------------------------------------------------------

    def _call_llm(self, conversation: list[dict]) -> str:
        """Flatten conversation history into a single Ollama prompt."""
        parts = []
        for msg in conversation:
            parts.append(f"[{msg['role'].upper()}]\n{msg['content']}")
        prompt = "\n\n".join(parts) + "\n\n[ASSISTANT]"
        try:
            return self.client.generate(prompt)
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
        """Dispatch a tool call and return its result as a string."""
        call_key = f"{action}:{json.dumps(args, sort_keys=True)}"
        if call_key in self._called_tools:
            return "(duplicate tool call — skipped)"
        self._called_tools.add(call_key)

        if action == "search_ip":
            ip = args.get("ip", "")
            found = [e for e in events if e.source_ip == ip]
            return f"Events from IP {ip} ({len(found)} total):\n{_fmt_events(found)}"

        if action == "search_user":
            user = args.get("username", "")
            found = [e for e in events if e.username == user]
            return f"Events for user '{user}' ({len(found)} total):\n{_fmt_events(found)}"

        if action == "get_timeline":
            anchor_str = args.get("anchor", "")
            before = int(args.get("before_min", 5))
            after = int(args.get("after_min", 5))
            try:
                anchor = datetime.fromisoformat(anchor_str)
                start = anchor - timedelta(minutes=before)
                end = anchor + timedelta(minutes=after)
                found = [
                    e for e in events
                    if e.timestamp and start <= e.timestamp <= end
                ]
                return (
                    f"Timeline [{anchor_str} -{before}/+{after}min] ({len(found)} events):\n"
                    + _fmt_events(found)
                )
            except (ValueError, TypeError):
                return f"Invalid anchor timestamp: {anchor_str!r}"

        if action == "check_lateral_movement":
            user = args.get("username", "")
            all_ips = {e.source_ip for e in events if e.username == user and e.source_ip}
            success_ips = {
                e.source_ip for e in events
                if e.username == user
                and e.event_type in ("ssh_accepted_password", "ssh_accepted_publickey")
                and e.source_ip
            }
            lateral = len(success_ips) > 1
            return (
                f"User '{user}': {len(all_ips)} unique IP(s) total.\n"
                f"  All IPs seen: {', '.join(sorted(all_ips)) or 'none'}\n"
                f"  Successful login IPs: {', '.join(sorted(success_ips)) or 'none'}\n"
                f"  {'⚠ LATERAL MOVEMENT INDICATOR — multiple successful-login IPs.' if lateral else 'Single successful-login IP — no lateral movement detected.'}"
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

    def _force_conclude(self, conversation: list[dict]) -> AgentReport:
        """Force a conclusion when MAX_STEPS is reached."""
        conversation.append({
            "role": "user",
            "content": (
                "Step limit reached. You MUST call conclude NOW.\n"
                '{"action": "conclude", "args": {"risk_level": "...", '
                '"summary": "...", "iocs": [], "recommendations": []}}'
            ),
        })
        response = self._call_llm(conversation)
        parsed = _extract_json(response)
        if parsed and parsed.get("action") == "conclude":
            args = parsed.get("args", {})
            return AgentReport(
                risk_level=args.get("risk_level", "UNKNOWN"),
                summary=args.get("summary", response),
                iocs=args.get("iocs", []),
                recommendations=args.get("recommendations", []),
                steps=self.steps,
                raw_conclusion=response,
            )
        return AgentReport(
            risk_level="UNKNOWN",
            summary=response or "Agent did not produce a conclusion.",
            steps=self.steps,
        )
