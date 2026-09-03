"""Tests for LogAnalysisAgent — tool dispatch, JSON extraction, conversation flow."""

from datetime import datetime
from unittest.mock import MagicMock, patch

import pytest

from agent import LogAnalysisAgent, AgentReport, _extract_json, _fmt_events
from anomaly_detector import Anomaly
from parsers.base import LogEvent


# ------------------------------------------------------------------
# _extract_json
# ------------------------------------------------------------------

class TestExtractJson:
    def test_clean_json(self):
        result = _extract_json('{"action": "conclude", "args": {}}')
        assert result == {"action": "conclude", "args": {}}

    def test_json_with_leading_prose(self):
        text = 'Sure! Here is my response:\n{"action": "search_ip", "args": {"ip": "1.2.3.4"}}'
        result = _extract_json(text)
        assert result["action"] == "search_ip"

    def test_nested_json(self):
        text = '{"action": "conclude", "args": {"risk_level": "HIGH", "iocs": ["1.1.1.1"]}}'
        result = _extract_json(text)
        assert result["args"]["risk_level"] == "HIGH"
        assert result["args"]["iocs"] == ["1.1.1.1"]

    def test_returns_none_for_plain_text(self):
        assert _extract_json("I have no JSON here at all.") is None

    def test_returns_none_for_empty_string(self):
        assert _extract_json("") is None

    def test_picks_first_valid_json(self):
        text = '{"action": "search_ip", "args": {"ip": "1.2.3.4"}} {"action": "other"}'
        result = _extract_json(text)
        assert result["action"] == "search_ip"


# ------------------------------------------------------------------
# Fixtures
# ------------------------------------------------------------------

def make_event(event_type="ssh_failed_password", ip="1.2.3.4", user="root") -> LogEvent:
    return LogEvent(
        timestamp=datetime(2026, 9, 2, 12, 0, 0),
        source="auth",
        ip=ip,
        user=user,
        message="test event",
        raw="raw line",
        extra={"event_type": event_type},
    )


def make_anomaly(anomaly_id="BF-001", severity="HIGH", source_ip="1.2.3.4") -> Anomaly:
    return Anomaly(
        anomaly_id=anomaly_id,
        severity=severity,
        category="brute_force",
        title=f"Test anomaly {anomaly_id}",
        description="Test description",
        mitre_id="T1110",
        mitre_name="Brute Force",
        confidence=0.8,
        source_ip=source_ip,
    )


def mock_client(responses: list[str]) -> MagicMock:
    """Build a mock OllamaClient that returns responses in sequence."""
    client = MagicMock()
    client.chat.side_effect = responses
    return client


# ------------------------------------------------------------------
# Tool dispatch
# ------------------------------------------------------------------

class TestToolDispatch:
    def setup_method(self):
        self.events = [
            make_event("ssh_failed_password", ip="1.2.3.4", user="root"),
            make_event("ssh_accepted_password", ip="1.2.3.4", user="root"),
        ]
        self.anomalies = [make_anomaly()]

    def _run_single_tool(self, tool_json: str) -> AgentReport:
        conclude = '{"action": "conclude", "args": {"risk_level": "HIGH", "summary": "done", "iocs": [], "recommendations": []}}'
        client = mock_client([tool_json, conclude])
        agent = LogAnalysisAgent(client)
        return agent.analyze(self.events, self.anomalies)

    def test_search_ip_dispatched(self):
        report = self._run_single_tool(
            '{"action": "search_ip", "args": {"ip": "1.2.3.4"}}'
        )
        assert len(report.steps) == 1
        assert report.steps[0].tool == "search_ip"
        assert "1.2.3.4" in report.steps[0].result_summary

    def test_search_user_dispatched(self):
        report = self._run_single_tool(
            '{"action": "search_user", "args": {"username": "root"}}'
        )
        assert report.steps[0].tool == "search_user"

    def test_get_anomaly_context_dispatched(self):
        report = self._run_single_tool(
            '{"action": "get_anomaly_context", "args": {"anomaly_id": "BF-001"}}'
        )
        assert report.steps[0].tool == "get_anomaly_context"
        assert "BF-001" in report.steps[0].result_summary

    def test_unknown_tool_returns_error_string(self):
        report = self._run_single_tool(
            '{"action": "nonexistent_tool", "args": {}}'
        )
        assert "Unknown tool" in report.steps[0].result_summary

    def test_duplicate_tool_call_skipped(self):
        same = '{"action": "search_ip", "args": {"ip": "1.2.3.4"}}'
        conclude = '{"action": "conclude", "args": {"risk_level": "LOW", "summary": "ok", "iocs": [], "recommendations": []}}'
        client = mock_client([same, same, conclude])
        agent = LogAnalysisAgent(client)
        report = agent.analyze(self.events, self.anomalies)
        results = [s.result_summary for s in report.steps]
        assert any("duplicate" in r for r in results)


# ------------------------------------------------------------------
# Conversation flow
# ------------------------------------------------------------------

class TestConversationFlow:
    def test_conclude_returns_report(self):
        conclude = '{"action": "conclude", "args": {"risk_level": "CRITICAL", "summary": "Attack confirmed", "iocs": ["1.2.3.4"], "recommendations": ["block 1.2.3.4"]}}'
        client = mock_client([conclude])
        agent = LogAnalysisAgent(client)
        report = agent.analyze([make_event()], [make_anomaly()])

        assert isinstance(report, AgentReport)
        assert report.risk_level == "CRITICAL"
        assert report.summary == "Attack confirmed"
        assert "1.2.3.4" in report.iocs
        assert len(report.steps) == 0  # concluded immediately

    def test_prose_response_prompts_retry(self):
        """When model returns prose instead of JSON, agent asks again."""
        prose = "I think the IP looks suspicious and you should block it."
        conclude = '{"action": "conclude", "args": {"risk_level": "MEDIUM", "summary": "noted", "iocs": [], "recommendations": []}}'
        client = mock_client([prose, conclude])
        agent = LogAnalysisAgent(client)
        report = agent.analyze([make_event()], [make_anomaly()])
        # Should have retried and eventually concluded
        assert report.risk_level == "MEDIUM"

    def test_uses_api_chat_not_generate(self):
        """Agent must use client.chat(), not client.generate()."""
        conclude = '{"action": "conclude", "args": {"risk_level": "LOW", "summary": "ok", "iocs": [], "recommendations": []}}'
        client = mock_client([conclude])
        agent = LogAnalysisAgent(client)
        agent.analyze([make_event()], [make_anomaly()])

        client.chat.assert_called()
        client.generate.assert_not_called()

    def test_chat_receives_proper_message_list(self):
        """Messages passed to chat() must be role-based dicts, not a flat string."""
        conclude = '{"action": "conclude", "args": {"risk_level": "LOW", "summary": "ok", "iocs": [], "recommendations": []}}'
        client = mock_client([conclude])
        agent = LogAnalysisAgent(client)
        agent.analyze([make_event()], [make_anomaly()])

        call_args = client.chat.call_args[0][0]
        assert isinstance(call_args, list)
        assert all(isinstance(m, dict) for m in call_args)
        assert all("role" in m and "content" in m for m in call_args)
        roles = {m["role"] for m in call_args}
        assert "system" in roles
        assert "user" in roles

    def test_max_steps_forces_conclude(self):
        """If model never calls conclude, agent forces it after MAX_STEPS."""
        tool = '{"action": "search_ip", "args": {"ip": "9.9.9.9"}}'
        forced_conclude = '{"action": "conclude", "args": {"risk_level": "HIGH", "summary": "forced", "iocs": [], "recommendations": []}}'
        # Return tool calls then a forced conclude (MAX_STEPS + 1 + 1 for force)
        client = mock_client([tool] * 10 + [forced_conclude])
        agent = LogAnalysisAgent(client)
        report = agent.analyze([make_event()], [make_anomaly()])
        assert isinstance(report, AgentReport)
