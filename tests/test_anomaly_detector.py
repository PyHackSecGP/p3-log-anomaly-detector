"""Tests for rule-based anomaly detection — the core detection logic."""

from datetime import datetime, timedelta

import pytest

from anomaly_detector import (
    detect_brute_force,
    detect_off_hours_logins,
    detect_privilege_escalation,
    detect_unusual_ips,
    detect_user_enumeration,
    run_detection,
)
from parsers.base import LogEvent


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def make_auth_event(
    event_type: str,
    ip: str = "1.2.3.4",
    user: str = "testuser",
    ts: datetime = None,
    message: str = "",
) -> LogEvent:
    return LogEvent(
        timestamp=ts or datetime(2026, 9, 2, 12, 0, 0),
        source="auth",
        host="web01",
        service="sshd",
        ip=ip,
        user=user,
        message=message or f"{event_type} event",
        raw=f"Sep  2 12:00:00 web01 sshd[1]: {event_type}",
        extra={"event_type": event_type, "pid": 1234},
    )


def make_events(event_type: str, count: int, ip: str = "1.2.3.4", user: str = "root") -> list[LogEvent]:
    base = datetime(2026, 9, 2, 12, 0, 0)
    return [
        make_auth_event(event_type, ip=ip, user=user, ts=base + timedelta(seconds=i))
        for i in range(count)
    ]


# ------------------------------------------------------------------
# detect_brute_force
# ------------------------------------------------------------------

class TestDetectBruteForce:
    def test_triggers_at_threshold(self):
        events = make_events("ssh_failed_password", 5)
        anomalies = detect_brute_force(events)
        assert len(anomalies) == 1
        assert anomalies[0].mitre_id == "T1110"
        assert anomalies[0].source_ip == "1.2.3.4"

    def test_below_threshold_no_alert(self):
        events = make_events("ssh_failed_password", 4)
        assert detect_brute_force(events) == []

    def test_severity_scales_with_count(self):
        events = make_events("ssh_failed_password", 25)
        anomalies = detect_brute_force(events)
        assert anomalies[0].severity == "HIGH"

        events = make_events("ssh_failed_password", 55)
        anomalies = detect_brute_force(events)
        assert anomalies[0].severity == "CRITICAL"

    def test_multiple_ips_each_get_own_anomaly(self):
        events = make_events("ssh_failed_password", 6, ip="10.0.0.1")
        events += make_events("ssh_failed_password", 6, ip="10.0.0.2")
        anomalies = detect_brute_force(events)
        ips = {a.source_ip for a in anomalies}
        assert "10.0.0.1" in ips
        assert "10.0.0.2" in ips

    def test_sliding_window_respected(self):
        base = datetime(2026, 9, 2, 12, 0, 0)
        # 3 events within window, then a gap, then 3 more — never 5 in one window
        events = [
            make_auth_event("ssh_failed_password", ts=base + timedelta(minutes=i))
            for i in [0, 1, 2, 15, 16, 17]
        ]
        assert detect_brute_force(events) == []

    def test_invalid_user_counts_as_failure(self):
        events = make_events("ssh_invalid_user", 5)
        anomalies = detect_brute_force(events)
        assert len(anomalies) == 1


# ------------------------------------------------------------------
# detect_privilege_escalation
# ------------------------------------------------------------------

class TestDetectPrivilegeEscalation:
    def test_sudo_failures_trigger(self):
        events = make_events("sudo_failed", 3, user="alice")
        anomalies = detect_privilege_escalation(events)
        assert any(a.category == "privilege_escalation" for a in anomalies)

    def test_useradd_always_high(self):
        events = [make_auth_event("useradd", user="hacker")]
        anomalies = detect_privilege_escalation(events)
        useradd = [a for a in anomalies if a.mitre_id == "T1136"]
        assert len(useradd) == 1
        assert useradd[0].severity == "HIGH"

    def test_root_login_always_critical(self):
        events = [make_auth_event("root_login", ip="5.5.5.5", user="root")]
        anomalies = detect_privilege_escalation(events)
        root = [a for a in anomalies if a.mitre_id == "T1078"]
        assert len(root) == 1
        assert root[0].severity == "CRITICAL"

    def test_su_to_root_detected(self):
        events = [make_auth_event("su_session", user="root")]
        anomalies = detect_privilege_escalation(events)
        assert any(a.title.startswith("su to root") for a in anomalies)


# ------------------------------------------------------------------
# detect_unusual_ips
# ------------------------------------------------------------------

class TestDetectUnusualIPs:
    def test_success_after_failures_is_critical(self):
        base = datetime(2026, 9, 2, 12, 0, 0)
        events = [
            make_auth_event("ssh_failed_password", ts=base + timedelta(seconds=i))
            for i in range(5)
        ]
        events.append(make_auth_event(
            "ssh_accepted_password",
            ts=base + timedelta(seconds=10),
        ))
        anomalies = detect_unusual_ips(events)
        assert any(a.severity == "CRITICAL" for a in anomalies)

    def test_success_without_prior_failures_no_alert(self):
        events = [make_auth_event("ssh_accepted_password")]
        assert detect_unusual_ips(events) == []


# ------------------------------------------------------------------
# detect_off_hours_logins
# ------------------------------------------------------------------

class TestDetectOffHoursLogins:
    def test_triggers_at_3am(self):
        ts = datetime(2026, 9, 2, 3, 0, 0)
        events = [make_auth_event("ssh_accepted_password", ts=ts)]
        anomalies = detect_off_hours_logins(events)
        assert len(anomalies) == 1
        assert anomalies[0].mitre_id == "T1078"

    def test_no_trigger_at_noon(self):
        ts = datetime(2026, 9, 2, 12, 0, 0)
        events = [make_auth_event("ssh_accepted_password", ts=ts)]
        assert detect_off_hours_logins(events) == []

    def test_failed_logins_not_flagged(self):
        ts = datetime(2026, 9, 2, 3, 0, 0)
        events = [make_auth_event("ssh_failed_password", ts=ts)]
        assert detect_off_hours_logins(events) == []


# ------------------------------------------------------------------
# detect_user_enumeration
# ------------------------------------------------------------------

class TestDetectUserEnumeration:
    def test_triggers_at_threshold(self):
        events = [
            make_auth_event("ssh_invalid_user", ip="9.9.9.9", user=f"user{i}")
            for i in range(8)
        ]
        anomalies = detect_user_enumeration(events)
        assert len(anomalies) == 1
        assert anomalies[0].mitre_id == "T1589"

    def test_below_threshold_no_alert(self):
        events = [
            make_auth_event("ssh_invalid_user", ip="9.9.9.9", user=f"user{i}")
            for i in range(7)
        ]
        assert detect_user_enumeration(events) == []


# ------------------------------------------------------------------
# run_detection (integration)
# ------------------------------------------------------------------

class TestRunDetection:
    def test_allowlist_ip_suppressed(self):
        events = make_events("ssh_failed_password", 10, ip="10.0.0.1")
        anomalies = run_detection(events, allowlist_ips={"10.0.0.1"})
        assert all(a.source_ip != "10.0.0.1" for a in anomalies)

    def test_allowlist_user_suppressed(self):
        events = make_events("sudo_failed", 5, user="prometheus")
        anomalies = run_detection(events, allowlist_users={"prometheus"})
        pe = [a for a in anomalies if a.category == "privilege_escalation"]
        assert not any(a.username == "prometheus" for a in pe)

    def test_sorted_by_severity(self):
        events = (
            make_events("ssh_failed_password", 6)
            + [make_auth_event("root_login", user="root")]
        )
        anomalies = run_detection(events)
        severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        scores = [severity_order.get(a.severity, 99) for a in anomalies]
        assert scores == sorted(scores)

    def test_empty_events_returns_empty(self):
        assert run_detection([]) == []
