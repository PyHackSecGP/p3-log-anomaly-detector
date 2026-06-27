"""
Rule-based anomaly detection on parsed auth log events.
Produces structured findings before AI enrichment.
"""

from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from log_parser import LogEvent


BRUTE_FORCE_THRESHOLD = 5      # failed attempts from same IP within window
BRUTE_FORCE_WINDOW_MIN = 10    # minutes
DISTRIBUTED_BF_THRESHOLD = 20  # total failures across all IPs within window


@dataclass
class Anomaly:
    """A detected security anomaly."""

    anomaly_id: str
    severity: str          # CRITICAL, HIGH, MEDIUM, LOW, INFO
    category: str
    title: str
    description: str
    source_ip: Optional[str] = None
    username: Optional[str] = None
    count: int = 1
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    raw_events: list[str] = field(default_factory=list)
    mitre_id: str = ""       # ATT&CK technique ID, e.g. "T1110"
    mitre_name: str = ""     # ATT&CK technique name
    confidence: float = 0.0  # 0.0–1.0 detection confidence
    abuse_score: int = -1    # AbuseIPDB confidence score, -1 = not checked
    abuse_reports: int = -1  # AbuseIPDB total report count
    geo_country: str = ""    # country code from AbuseIPDB


def _severity_label(count: int, thresholds: tuple[int, int, int]) -> str:
    """Map a count to a severity label using thresholds (crit, high, med)."""
    crit, high, med = thresholds
    if count >= crit:
        return "CRITICAL"
    if count >= high:
        return "HIGH"
    if count >= med:
        return "MEDIUM"
    return "LOW"


def detect_brute_force(events: list[LogEvent]) -> list[Anomaly]:
    """
    Detect SSH brute-force attacks: >= BRUTE_FORCE_THRESHOLD failures
    from the same IP within BRUTE_FORCE_WINDOW_MIN minutes.
    """
    failures: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        if ev.event_type in ("ssh_failed_password", "ssh_invalid_user", "pam_failure", "ssh_max_auth"):
            if ev.source_ip:
                failures[ev.source_ip].append(ev)

    anomalies: list[Anomaly] = []
    seq = 1

    for ip, ip_events in failures.items():
        ip_events.sort(key=lambda e: e.timestamp or datetime.min)

        # Sliding window check
        window_end_idx = 0
        for i, ev in enumerate(ip_events):
            if ev.timestamp is None:
                continue
            window_end = ev.timestamp + timedelta(minutes=BRUTE_FORCE_WINDOW_MIN)
            window_events = [
                e for e in ip_events[i:]
                if e.timestamp and e.timestamp <= window_end
            ]
            if len(window_events) >= BRUTE_FORCE_THRESHOLD:
                severity = _severity_label(len(window_events), (50, 20, BRUTE_FORCE_THRESHOLD))
                usernames = {e.username for e in window_events if e.username}
                anomalies.append(Anomaly(
                    anomaly_id=f"BF-{seq:03d}",
                    severity=severity,
                    category="brute_force",
                    mitre_id="T1110",
                    mitre_name="Brute Force",
                    confidence=min(1.0, round(len(window_events) / 50, 2)),
                    title=f"SSH Brute Force from {ip}",
                    description=(
                        f"{len(window_events)} failed login attempts from {ip} "
                        f"within {BRUTE_FORCE_WINDOW_MIN} minutes. "
                        f"Targeted users: {', '.join(usernames) or 'unknown'}."
                    ),
                    source_ip=ip,
                    username=", ".join(usernames) or None,
                    count=len(window_events),
                    first_seen=window_events[0].timestamp,
                    last_seen=window_events[-1].timestamp,
                    raw_events=[e.raw for e in window_events[:5]],
                ))
                seq += 1
                break  # one anomaly per IP

    return anomalies


def detect_privilege_escalation(events: list[LogEvent]) -> list[Anomaly]:
    """
    Detect privilege escalation attempts: sudo failures, su to root,
    new user creation, password changes by non-root.
    """
    anomalies: list[Anomaly] = []
    seq = 1

    sudo_failures: dict[str, list[LogEvent]] = defaultdict(list)
    sudo_successes: dict[str, list[LogEvent]] = defaultdict(list)
    su_roots: list[LogEvent] = []
    user_creates: list[LogEvent] = []
    passwd_changes: list[LogEvent] = []
    root_logins: list[LogEvent] = []

    for ev in events:
        if ev.event_type == "sudo_failed":
            if ev.username:
                sudo_failures[ev.username].append(ev)
        elif ev.event_type == "sudo_session":
            if ev.username:
                sudo_successes[ev.username].append(ev)
        elif ev.event_type == "su_session" and ev.username == "root":
            su_roots.append(ev)
        elif ev.event_type == "useradd":
            user_creates.append(ev)
        elif ev.event_type == "passwd_change":
            passwd_changes.append(ev)
        elif ev.event_type == "root_login":
            root_logins.append(ev)

    # Sudo failures
    for user, evs in sudo_failures.items():
        severity = _severity_label(len(evs), (10, 5, 2))
        anomalies.append(Anomaly(
            anomaly_id=f"PE-{seq:03d}",
            severity=severity,
            category="privilege_escalation",
            mitre_id="T1548",
            mitre_name="Abuse Elevation Control Mechanism",
            confidence=min(1.0, round(len(evs) / 10, 2)),
            title=f"Repeated sudo failures by {user}",
            description=f"User '{user}' failed sudo authentication {len(evs)} time(s).",
            username=user,
            count=len(evs),
            first_seen=evs[0].timestamp,
            last_seen=evs[-1].timestamp,
            raw_events=[e.raw for e in evs[:3]],
        ))
        seq += 1

    # Su to root
    if su_roots:
        anomalies.append(Anomaly(
            anomaly_id=f"PE-{seq:03d}",
            severity="HIGH",
            category="privilege_escalation",
            mitre_id="T1548",
            mitre_name="Abuse Elevation Control Mechanism",
            confidence=0.85,
            title="su to root detected",
            description=f"Session opened as root {len(su_roots)} time(s) via su.",
            username="root",
            count=len(su_roots),
            first_seen=su_roots[0].timestamp,
            last_seen=su_roots[-1].timestamp,
            raw_events=[e.raw for e in su_roots[:3]],
        ))
        seq += 1

    # New user creation
    if user_creates:
        usernames = [e.username for e in user_creates if e.username]
        anomalies.append(Anomaly(
            anomaly_id=f"PE-{seq:03d}",
            severity="HIGH",
            category="privilege_escalation",
            mitre_id="T1136",
            mitre_name="Create Account",
            confidence=1.0,
            title=f"New user account(s) created",
            description=f"useradd was called {len(user_creates)} time(s). Users: {', '.join(usernames)}.",
            count=len(user_creates),
            first_seen=user_creates[0].timestamp,
            last_seen=user_creates[-1].timestamp,
            raw_events=[e.raw for e in user_creates],
        ))
        seq += 1

    # Root logins
    if root_logins:
        ips = {e.source_ip for e in root_logins if e.source_ip}
        anomalies.append(Anomaly(
            anomaly_id=f"PE-{seq:03d}",
            severity="CRITICAL",
            category="privilege_escalation",
            mitre_id="T1078",
            mitre_name="Valid Accounts",
            confidence=1.0,
            title="Direct root login detected",
            description=f"Root logins from IPs: {', '.join(ips)}. Count: {len(root_logins)}.",
            source_ip=", ".join(ips) or None,
            username="root",
            count=len(root_logins),
            first_seen=root_logins[0].timestamp,
            last_seen=root_logins[-1].timestamp,
            raw_events=[e.raw for e in root_logins],
        ))
        seq += 1

    return anomalies


def detect_unusual_ips(events: list[LogEvent]) -> list[Anomaly]:
    """
    Flag IPs with mixed success/failure patterns and IPs with only failures.
    Also flags IPs that successfully authenticated after prior failures (possible
    credential stuffing success).
    """
    ip_failures: dict[str, list[LogEvent]] = defaultdict(list)
    ip_successes: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        if not ev.source_ip:
            continue
        if ev.event_type in ("ssh_failed_password", "ssh_invalid_user", "pam_failure"):
            ip_failures[ev.source_ip].append(ev)
        elif ev.event_type in ("ssh_accepted_password", "ssh_accepted_publickey"):
            ip_successes[ev.source_ip].append(ev)

    anomalies: list[Anomaly] = []
    seq = 1

    # IPs that failed then succeeded (possible credential stuffing)
    for ip in set(ip_failures) & set(ip_successes):
        fails = ip_failures[ip]
        successes = ip_successes[ip]
        # Only flag if failures preceded the success
        first_success = min((e.timestamp for e in successes if e.timestamp), default=None)
        failures_before = [
            e for e in fails if e.timestamp and first_success and e.timestamp < first_success
        ]
        if failures_before:
            anomalies.append(Anomaly(
                anomaly_id=f"IP-{seq:03d}",
                severity="CRITICAL",
                category="unusual_ip",
                mitre_id="T1110",
                mitre_name="Brute Force",
                confidence=min(1.0, round(len(failures_before) / 20, 2)),
                title=f"Successful login after {len(failures_before)} failures from {ip}",
                description=(
                    f"IP {ip} had {len(failures_before)} failed attempts before "
                    f"successfully authenticating — possible credential stuffing or "
                    f"brute force success."
                ),
                source_ip=ip,
                count=len(failures_before) + len(successes),
                first_seen=failures_before[0].timestamp,
                last_seen=successes[-1].timestamp,
                raw_events=[e.raw for e in failures_before[:3]] + [e.raw for e in successes[:2]],
            ))
            seq += 1

    # IPs with high failure volume (already covered by brute_force, skip overlap)
    # Distributed brute force: many IPs each with a few failures
    all_failure_ips = list(ip_failures.keys())
    total_distributed = sum(len(v) for v in ip_failures.values())
    if len(all_failure_ips) > 10 and total_distributed >= DISTRIBUTED_BF_THRESHOLD:
        anomalies.append(Anomaly(
            anomaly_id=f"IP-{seq:03d}",
            severity="HIGH",
            category="unusual_ip",
            mitre_id="T1110",
            mitre_name="Brute Force",
            confidence=min(1.0, round(len(all_failure_ips) / 30, 2)),
            title=f"Distributed brute force from {len(all_failure_ips)} IPs",
            description=(
                f"{total_distributed} total failed attempts spread across "
                f"{len(all_failure_ips)} unique source IPs — indicates a distributed "
                f"or botnet-driven attack."
            ),
            count=total_distributed,
            raw_events=[],
        ))
        seq += 1

    return anomalies


def run_detection(
    events: list[LogEvent],
    allowlist_ips: set[str] | None = None,
    allowlist_users: set[str] | None = None,
) -> list[Anomaly]:
    """Run all detection rules and return deduplicated anomaly list sorted by severity.

    Events from allowlisted IPs or users are silently skipped so trusted
    hosts (jump boxes, monitoring agents) don't generate noise.
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    filtered = events
    if allowlist_ips or allowlist_users:
        filtered = [
            e for e in events
            if (not allowlist_ips or e.source_ip not in allowlist_ips)
            and (not allowlist_users or e.username not in allowlist_users)
        ]

    all_anomalies = (
        detect_brute_force(filtered)
        + detect_privilege_escalation(filtered)
        + detect_unusual_ips(filtered)
    )

    all_anomalies.sort(key=lambda a: severity_order.get(a.severity, 99))
    return all_anomalies
