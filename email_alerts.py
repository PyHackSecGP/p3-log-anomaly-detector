"""Email alerting for high-severity anomaly findings.

Config via environment variables:
    ALERT_SMTP_HOST   — SMTP server hostname (e.g. smtp.gmail.com)
    ALERT_SMTP_PORT   — port, default 587
    ALERT_SMTP_USER   — SMTP username / sender address
    ALERT_SMTP_PASS   — SMTP password or app password
    ALERT_TO          — recipient address
    ALERT_FROM        — sender display address (defaults to ALERT_SMTP_USER)

Gmail setup: create an App Password at myaccount.google.com/apppasswords
"""
from __future__ import annotations

import os
import smtplib
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from typing import Optional

from anomaly_detector import Anomaly


def _build_subject(anomalies: list[Anomaly], log_path: str) -> str:
    critical = sum(1 for a in anomalies if a.severity == "CRITICAL")
    high = sum(1 for a in anomalies if a.severity == "HIGH")
    if critical:
        level = f"CRITICAL ({critical} findings)"
    elif high:
        level = f"HIGH ({high} findings)"
    else:
        level = f"{len(anomalies)} anomalies"
    return f"[P3-ALERT] {level} in {log_path}"


def _build_body(anomalies: list[Anomaly], log_path: str, ai_assessment: Optional[str]) -> str:
    lines = [
        f"Log file: {log_path}",
        f"Total anomalies: {len(anomalies)}",
        "",
        "=" * 60,
        "DETECTED ANOMALIES",
        "=" * 60,
    ]
    for a in anomalies:
        conf = f"  confidence={a.confidence:.0%}" if a.confidence > 0 else ""
        mitre = f"  [{a.mitre_id}]" if a.mitre_id else ""
        abuse = f"  AbuseIPDB={a.abuse_score}%" if a.abuse_score >= 0 else ""
        lines.append(f"\n[{a.anomaly_id}] {a.severity} — {a.title}{mitre}{conf}{abuse}")
        lines.append(f"  {a.description}")
        if a.source_ip:
            lines.append(f"  IP: {a.source_ip}" + (f" ({a.geo_country})" if a.geo_country else ""))
        if a.username:
            lines.append(f"  User: {a.username}")

    if ai_assessment:
        lines += ["", "=" * 60, "AI THREAT ASSESSMENT", "=" * 60, "", ai_assessment]

    return "\n".join(lines)


def send_alert(
    anomalies: list[Anomaly],
    log_path: str,
    ai_assessment: Optional[str] = None,
    smtp_host: Optional[str] = None,
    smtp_port: int = 587,
    smtp_user: Optional[str] = None,
    smtp_pass: Optional[str] = None,
    to_addr: Optional[str] = None,
    from_addr: Optional[str] = None,
    verbose: bool = False,
) -> bool:
    """Send an email alert. Returns True on success, False on failure.

    Falls back to env vars for all parameters not explicitly provided.
    """
    host = smtp_host or os.environ.get("ALERT_SMTP_HOST", "")
    port = smtp_port or int(os.environ.get("ALERT_SMTP_PORT", "587"))
    user = smtp_user or os.environ.get("ALERT_SMTP_USER", "")
    password = smtp_pass or os.environ.get("ALERT_SMTP_PASS", "")
    to = to_addr or os.environ.get("ALERT_TO", "")
    sender = from_addr or os.environ.get("ALERT_FROM", user)

    if not all([host, user, password, to]):
        if verbose:
            print("  [email] Missing SMTP config — skipping alert.")
        return False

    subject = _build_subject(anomalies, log_path)
    body = _build_body(anomalies, log_path, ai_assessment)

    msg = MIMEMultipart()
    msg["From"] = sender
    msg["To"] = to
    msg["Subject"] = subject
    msg.attach(MIMEText(body, "plain"))

    try:
        with smtplib.SMTP(host, port, timeout=15) as smtp:
            smtp.ehlo()
            smtp.starttls()
            smtp.login(user, password)
            smtp.sendmail(sender, [to], msg.as_string())
        if verbose:
            print(f"  [email] Alert sent to {to}")
        return True
    except (smtplib.SMTPException, OSError) as exc:
        if verbose:
            print(f"  [email] Send failed: {exc}")
        return False
