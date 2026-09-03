"""
Detection rules for nginx access logs.

Works with parsers.base.LogEvent produced by NginxParser.
Detects web-layer attacks: scanning, 4xx floods, admin probing, injection attempts.
"""

from __future__ import annotations

from collections import defaultdict
from typing import Optional

from anomaly_detector import Anomaly
from parsers.base import LogEvent

_SCANNER_UAS = {
    "sqlmap", "nikto", "nmap", "masscan", "nuclei", "gobuster",
    "dirbuster", "wfuzz", "ffuf", "hydra", "burpsuite", "zgrab",
    "python-requests", "go-http-client", "curl/7",
}

_SENSITIVE_PATHS = {
    "/admin", "/administrator", "/.env", "/.git", "/wp-admin",
    "/wp-login.php", "/phpmyadmin", "/manager/html", "/actuator",
    "/api/v1/users", "/console", "/.aws", "/config", "/backup",
    "/shell", "/cmd", "/webshell",
}

_4XX_FLOOD_THRESHOLD = 20    # per IP per scan window
_SCANNER_THRESHOLD = 3       # distinct scanner UA requests
_PATH_PROBE_THRESHOLD = 5    # distinct sensitive paths from one IP
_ERROR_RATE_THRESHOLD = 0.6  # >60% error rate = suspicious


def detect_scanner_uas(events: list[LogEvent]) -> list[Anomaly]:
    """
    Detect known scanner/tool user agents in nginx access logs.
    MITRE T1595 — Active Scanning.
    """
    scanner_hits: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        ua = ev.extra.get("user_agent", "").lower()
        for sig in _SCANNER_UAS:
            if sig in ua:
                scanner_hits[ev.ip].append(ev)
                break

    anomalies: list[Anomaly] = []
    seq = 1
    for ip, evs in scanner_hits.items():
        if len(evs) >= _SCANNER_THRESHOLD:
            uas = {ev.extra.get("user_agent", "") for ev in evs}
            anomalies.append(Anomaly(
                anomaly_id=f"WEB-{seq:03d}",
                severity="HIGH",
                category="web_scanning",
                mitre_id="T1595",
                mitre_name="Active Scanning",
                confidence=min(1.0, round(len(evs) / 20, 2)),
                title=f"Web scanner detected from {ip}",
                description=(
                    f"IP {ip} made {len(evs)} request(s) with known scanner user agent(s): "
                    f"{', '.join(list(uas)[:3])}."
                ),
                source_ip=ip,
                count=len(evs),
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                raw_events=[e.raw for e in evs[:3]],
            ))
            seq += 1
    return anomalies


def detect_4xx_flood(events: list[LogEvent]) -> list[Anomaly]:
    """
    Detect IPs generating high volumes of 4xx errors — directory bruteforce or fuzzing.
    MITRE T1595.003 — Wordlist Scanning.
    """
    errors_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        if ev.status_code and 400 <= ev.status_code < 500:
            if ev.ip:
                errors_by_ip[ev.ip].append(ev)

    anomalies: list[Anomaly] = []
    seq = 1
    for ip, evs in errors_by_ip.items():
        if len(evs) >= _4XX_FLOOD_THRESHOLD:
            codes = {ev.status_code for ev in evs}
            severity = "HIGH" if len(evs) >= 50 else "MEDIUM"
            anomalies.append(Anomaly(
                anomaly_id=f"WEB-4XX-{seq:03d}",
                severity=severity,
                category="web_scanning",
                mitre_id="T1595",
                mitre_name="Active Scanning",
                confidence=min(1.0, round(len(evs) / 100, 2)),
                title=f"4xx flood from {ip} ({len(evs)} errors)",
                description=(
                    f"IP {ip} generated {len(evs)} 4xx error(s) — "
                    f"possible directory bruteforce or fuzzing. "
                    f"Status codes seen: {', '.join(str(c) for c in sorted(codes))}."
                ),
                source_ip=ip,
                count=len(evs),
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                raw_events=[e.raw for e in evs[:3]],
            ))
            seq += 1
    return anomalies


def detect_sensitive_path_probing(events: list[LogEvent]) -> list[Anomaly]:
    """
    Detect IPs probing multiple sensitive paths (admin panels, config files, etc.).
    MITRE T1083 — File and Directory Discovery.
    """
    path_hits: dict[str, set[str]] = defaultdict(set)
    path_events: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        path = ev.extra.get("path", "").lower().split("?")[0]
        for sensitive in _SENSITIVE_PATHS:
            if path.startswith(sensitive):
                if ev.ip:
                    path_hits[ev.ip].add(path)
                    path_events[ev.ip].append(ev)
                break

    anomalies: list[Anomaly] = []
    seq = 1
    for ip, paths in path_hits.items():
        if len(paths) >= _PATH_PROBE_THRESHOLD:
            evs = path_events[ip]
            anomalies.append(Anomaly(
                anomaly_id=f"WEB-PROBE-{seq:03d}",
                severity="HIGH",
                category="web_scanning",
                mitre_id="T1083",
                mitre_name="File and Directory Discovery",
                confidence=min(1.0, round(len(paths) / 10, 2)),
                title=f"Sensitive path probing from {ip} ({len(paths)} paths)",
                description=(
                    f"IP {ip} probed {len(paths)} sensitive path(s): "
                    f"{', '.join(list(paths)[:5])}."
                ),
                source_ip=ip,
                count=len(paths),
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                raw_events=[e.raw for e in evs[:3]],
            ))
            seq += 1
    return anomalies


def detect_high_error_rate(events: list[LogEvent]) -> list[Anomaly]:
    """
    Flag IPs where >60% of requests result in errors (4xx/5xx).
    Indicates automated probing or misconfigured attack tools.
    MITRE T1190 — Exploit Public-Facing Application.
    """
    total_by_ip: dict[str, int] = defaultdict(int)
    errors_by_ip: dict[str, int] = defaultdict(int)
    events_by_ip: dict[str, list[LogEvent]] = defaultdict(list)

    for ev in events:
        if not ev.ip or not ev.status_code:
            continue
        total_by_ip[ev.ip] += 1
        events_by_ip[ev.ip].append(ev)
        if ev.status_code >= 400:
            errors_by_ip[ev.ip] += 1

    anomalies: list[Anomaly] = []
    seq = 1
    for ip, total in total_by_ip.items():
        if total < 10:
            continue
        errors = errors_by_ip.get(ip, 0)
        rate = errors / total
        if rate >= _ERROR_RATE_THRESHOLD:
            evs = events_by_ip[ip]
            anomalies.append(Anomaly(
                anomaly_id=f"WEB-ERR-{seq:03d}",
                severity="MEDIUM",
                category="web_scanning",
                mitre_id="T1190",
                mitre_name="Exploit Public-Facing Application",
                confidence=round(rate, 2),
                title=f"High error rate from {ip} ({rate:.0%} of {total} requests)",
                description=(
                    f"IP {ip} had {rate:.0%} error rate ({errors}/{total} requests returned 4xx/5xx). "
                    f"Indicates automated probing or attack tool."
                ),
                source_ip=ip,
                count=errors,
                first_seen=evs[0].timestamp,
                last_seen=evs[-1].timestamp,
                raw_events=[e.raw for e in evs[:3]],
            ))
            seq += 1
    return anomalies


def run_nginx_detection(
    events: list[LogEvent],
    allowlist_ips: Optional[set[str]] = None,
) -> list[Anomaly]:
    """
    Run all nginx detection rules.

    Args:
        events: LogEvents from NginxParser.
        allowlist_ips: Source IPs to skip.

    Returns:
        Sorted anomaly list (CRITICAL first).
    """
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    filtered = events
    if allowlist_ips:
        filtered = [e for e in events if e.ip not in allowlist_ips]

    all_anomalies = (
        detect_scanner_uas(filtered)
        + detect_4xx_flood(filtered)
        + detect_sensitive_path_probing(filtered)
        + detect_high_error_rate(filtered)
    )

    all_anomalies.sort(key=lambda a: severity_order.get(a.severity, 99))
    return all_anomalies
