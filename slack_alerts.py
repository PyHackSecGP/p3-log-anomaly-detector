"""Slack and Discord webhook alerting for high-severity anomaly findings.

Supports both Slack incoming webhooks and Discord webhooks — detection is
automatic based on the URL. Set ALERT_WEBHOOK_URL env var or pass --webhook.

Slack:   https://hooks.slack.com/services/...
Discord: https://discord.com/api/webhooks/...
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from typing import Optional

from anomaly_detector import Anomaly

_SEVERITY_EMOJI = {
    "CRITICAL": ":rotating_light:",
    "HIGH":     ":warning:",
    "MEDIUM":   ":large_yellow_circle:",
    "LOW":      ":large_blue_circle:",
    "INFO":     ":information_source:",
}
_TIMEOUT = 10


def _build_text(anomalies: list[Anomaly], log_path: str, ai_assessment: Optional[str]) -> str:
    critical = sum(1 for a in anomalies if a.severity == "CRITICAL")
    high = sum(1 for a in anomalies if a.severity == "HIGH")

    if critical:
        header = f":rotating_light: *P3 ALERT — CRITICAL* | {log_path}"
    elif high:
        header = f":warning: *P3 ALERT — HIGH* | {log_path}"
    else:
        header = f":shield: *P3 Alert* | {log_path}"

    lines = [header, ""]
    for a in anomalies:
        emoji = _SEVERITY_EMOJI.get(a.severity, ":shield:")
        mitre = f"  `{a.mitre_id}`" if a.mitre_id else ""
        conf = f"  {a.confidence:.0%} conf" if a.confidence > 0 else ""
        abuse = f"  AbuseIPDB:{a.abuse_score}%" if a.abuse_score >= 0 else ""
        lines.append(f"{emoji} *[{a.anomaly_id}] {a.severity}* — {a.title}{mitre}{conf}{abuse}")
        lines.append(f"  {a.description}")
        if a.source_ip:
            geo = f" ({a.geo_country})" if a.geo_country else ""
            lines.append(f"  IP: `{a.source_ip}`{geo}")
        if a.username:
            lines.append(f"  User: `{a.username}`")
        lines.append("")

    if ai_assessment:
        # Truncate AI assessment — webhooks have message length limits
        summary = ai_assessment[:800] + ("…" if len(ai_assessment) > 800 else "")
        lines += [":brain: *AI Assessment (summary)*", summary, ""]

    return "\n".join(lines)


def _build_payload(webhook_url: str, text: str) -> bytes:
    """Build JSON payload for Slack or Discord based on URL."""
    if "discord.com" in webhook_url:
        # Discord uses 'content'; max 2000 chars
        payload = {"content": text[:2000]}
    else:
        # Slack incoming webhook
        payload = {"text": text}
    return json.dumps(payload).encode("utf-8")


def send_webhook(
    anomalies: list[Anomaly],
    log_path: str,
    ai_assessment: Optional[str] = None,
    webhook_url: Optional[str] = None,
    verbose: bool = False,
) -> bool:
    """POST alert to Slack or Discord webhook. Returns True on success."""
    url = webhook_url or os.environ.get("ALERT_WEBHOOK_URL", "")
    if not url:
        if verbose:
            print("  [webhook] No ALERT_WEBHOOK_URL set — skipping.")
        return False

    text = _build_text(anomalies, log_path, ai_assessment)
    payload = _build_payload(url, text)

    req = urllib.request.Request(
        url,
        data=payload,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:  # nosec B310 — URL from config
            status = resp.status
        if verbose:
            print(f"  [webhook] Alert sent (HTTP {status})")
        return True
    except (urllib.error.URLError, OSError) as exc:
        if verbose:
            print(f"  [webhook] Send failed: {exc}")
        return False
