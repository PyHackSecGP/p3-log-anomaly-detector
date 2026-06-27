"""
Generate human-readable and JSON summary reports from detected anomalies.
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Optional

from anomaly_detector import Anomaly
from log_parser import LogEvent


SEVERITY_COLORS = {
    "CRITICAL": "\033[91m",   # red
    "HIGH":     "\033[93m",   # yellow
    "MEDIUM":   "\033[94m",   # blue
    "LOW":      "\033[96m",   # cyan
    "INFO":     "\033[37m",   # grey
}
RESET = "\033[0m"
BOLD  = "\033[1m"


def _colorize(text: str, severity: str) -> str:
    """Wrap text in ANSI color codes for the given severity."""
    color = SEVERITY_COLORS.get(severity, "")
    return f"{color}{text}{RESET}"


def _fmt_dt(dt: Optional[datetime]) -> str:
    """Format a datetime for display, or return 'N/A'."""
    if dt is None:
        return "N/A"
    return dt.strftime("%Y-%m-%d %H:%M:%S")


def build_anomaly_summary_text(anomalies: list[Anomaly]) -> str:
    """
    Build a plain-text anomaly summary suitable for feeding into the AI model.
    No ANSI codes — clean text only.
    """
    if not anomalies:
        return "No anomalies detected."

    lines: list[str] = []
    for a in anomalies:
        mitre = f"  [{a.mitre_id}]" if a.mitre_id else ""
        lines.append(f"[{a.anomaly_id}] {a.severity} — {a.title}{mitre}")
        lines.append(f"  Category: {a.category}")
        lines.append(f"  {a.description}")
        if a.source_ip:
            lines.append(f"  Source IP: {a.source_ip}")
        if a.username:
            lines.append(f"  Username: {a.username}")
        lines.append(f"  Count: {a.count}")
        lines.append(f"  First seen: {_fmt_dt(a.first_seen)}  Last seen: {_fmt_dt(a.last_seen)}")
        lines.append("")
    return "\n".join(lines)


def build_log_sample(events: list[LogEvent], max_lines: int = 20) -> str:
    """
    Extract a representative sample of raw log lines for AI context.
    Prioritises failed and escalation events.
    """
    priority_types = {
        "ssh_failed_password", "ssh_invalid_user", "sudo_failed",
        "root_login", "useradd", "ssh_max_auth", "pam_failure",
    }
    priority = [e.raw for e in events if e.event_type in priority_types]
    sample = priority[:max_lines] if priority else [e.raw for e in events[:max_lines]]
    return "\n".join(sample)


def generate_text_report(
    events: list[LogEvent],
    anomalies: list[Anomaly],
    ai_assessment: Optional[str],
    log_path: str,
    model_used: str,
    colored: bool = True,
) -> str:
    """
    Produce the full terminal-friendly text report.

    Args:
        events: All parsed log events.
        anomalies: Detected anomalies.
        ai_assessment: AI model response text, or None if unavailable.
        log_path: Path to the analyzed log file.
        model_used: Ollama model name.
        colored: Whether to include ANSI color codes.
    """
    def c(text: str, sev: str) -> str:
        return _colorize(text, sev) if colored else text

    def bold(text: str) -> str:
        return f"{BOLD}{text}{RESET}" if colored else text

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    counts = {s: sum(1 for a in anomalies if a.severity == s)
              for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")}

    lines: list[str] = [
        "",
        bold("=" * 65),
        bold("  AI LOG ANOMALY DETECTOR — SECURITY REPORT"),
        bold("=" * 65),
        f"  Log file : {log_path}",
        f"  Generated: {now}",
        f"  Model    : {model_used}",
        f"  Events   : {len(events):,} parsed",
        f"  Anomalies: "
        + "  ".join(
            c(f"{sev}: {counts[sev]}", sev) if counts[sev] else f"{sev}: 0"
            for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW")
        ),
        bold("=" * 65),
        "",
    ]

    if not anomalies:
        lines.append("  No anomalies detected in the provided log file.")
    else:
        lines.append(bold("DETECTED ANOMALIES"))
        lines.append("-" * 65)
        for a in anomalies:
            mitre_tag = f" \033[2m[{a.mitre_id}]\033[0m" if (colored and a.mitre_id) else (f" [{a.mitre_id}]" if a.mitre_id else "")
            header = f"  [{a.anomaly_id}] {c(a.severity, a.severity)} — {a.title}{mitre_tag}"
            lines.append(header)
            lines.append(f"    {a.description}")
            details: list[str] = []
            if a.source_ip:
                details.append(f"IP: {a.source_ip}")
            if a.username:
                details.append(f"User: {a.username}")
            details.append(f"Count: {a.count}")
            details.append(f"Window: {_fmt_dt(a.first_seen)} → {_fmt_dt(a.last_seen)}")
            lines.append("    " + "  |  ".join(details))
            if a.raw_events:
                lines.append("    Sample events:")
                for raw in a.raw_events[:2]:
                    lines.append(f"      {raw[:120]}")
            lines.append("")

    if ai_assessment:
        lines.append(bold("AI THREAT ASSESSMENT"))
        lines.append("-" * 65)
        for line in ai_assessment.splitlines():
            lines.append(f"  {line}")
        lines.append("")

    lines.append(bold("=" * 65))
    lines.append("")
    return "\n".join(lines)


def generate_json_report(
    events: list[LogEvent],
    anomalies: list[Anomaly],
    ai_assessment: Optional[str],
    log_path: str,
    model_used: str,
) -> str:
    """
    Produce a machine-readable JSON report.
    """
    report = {
        "generated_at": datetime.now().isoformat(),
        "log_file": log_path,
        "model": model_used,
        "stats": {
            "total_events": len(events),
            "total_anomalies": len(anomalies),
            "by_severity": {
                s: sum(1 for a in anomalies if a.severity == s)
                for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            },
            "by_category": {},
        },
        "anomalies": [],
        "ai_assessment": ai_assessment,
    }

    # Category breakdown
    for a in anomalies:
        report["stats"]["by_category"][a.category] = (
            report["stats"]["by_category"].get(a.category, 0) + 1
        )

    for a in anomalies:
        report["anomalies"].append({
            "id": a.anomaly_id,
            "severity": a.severity,
            "category": a.category,
            "mitre_id": a.mitre_id,
            "mitre_name": a.mitre_name,
            "title": a.title,
            "description": a.description,
            "source_ip": a.source_ip,
            "username": a.username,
            "count": a.count,
            "first_seen": _fmt_dt(a.first_seen),
            "last_seen": _fmt_dt(a.last_seen),
            "sample_events": a.raw_events[:3],
        })

    return json.dumps(report, indent=2)


def save_report(content: str, output_path: str | Path) -> None:
    """Write report content to a file."""
    Path(output_path).write_text(content, encoding="utf-8")
