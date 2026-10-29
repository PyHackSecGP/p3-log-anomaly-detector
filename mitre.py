"""MITRE ATT&CK mapping + coverage reporting.

Catalogs the techniques used by this detector's rules. Loads from
mitre_mapping.json (sibling file). Emits plaintext heatmap grouped by tactic.
"""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

_DEFAULT_MAPPING_PATH = Path(__file__).parent / "mitre_mapping.json"


def load_mapping(path: Path | str | None = None) -> dict[str, dict[str, Any]]:
    """Load the MITRE technique catalog from JSON."""
    p = Path(path) if path else _DEFAULT_MAPPING_PATH
    with p.open() as f:
        return json.load(f)


def get_technique(code: str, mapping: dict[str, dict[str, Any]] | None = None) -> dict[str, Any]:
    """Return technique entry for a T-code. Returns a stub if unknown."""
    m = mapping if mapping is not None else load_mapping()
    if code in m:
        return {"id": code, **m[code]}
    return {"id": code, "name": "Unknown", "tactic": "Unknown", "url": "", "rules": []}


def summarize_coverage(
    anomalies: list[Any],
    mapping: dict[str, dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Count T-code occurrences in anomalies, grouped by tactic."""
    m = mapping if mapping is not None else load_mapping()
    counts: Counter[str] = Counter()
    for a in anomalies:
        tid = getattr(a, "mitre_id", "") or (a.get("mitre_id", "") if isinstance(a, dict) else "")
        if tid:
            counts[tid] += 1

    tactics: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for tid, cnt in counts.items():
        tech = get_technique(tid, m)
        tactics[tech["tactic"]].append({"id": tid, "name": tech["name"], "count": cnt})

    return {
        "total_events": sum(counts.values()),
        "unique_techniques": len(counts),
        "by_tactic": {t: sorted(items, key=lambda x: -x["count"]) for t, items in tactics.items()},
    }


def render_heatmap(summary: dict[str, Any]) -> str:
    """Render a plaintext ATT&CK heatmap from summarize_coverage() output."""
    if summary["total_events"] == 0:
        return "MITRE ATT&CK Coverage\n=====================\n(no techniques observed)\n"

    lines = [
        "MITRE ATT&CK Coverage",
        "=====================",
        f"Total events: {summary['total_events']}  |  "
        f"Unique techniques: {summary['unique_techniques']}",
        "",
    ]
    for tactic in sorted(summary["by_tactic"]):
        lines.append(f"[{tactic}]")
        for item in summary["by_tactic"][tactic]:
            bar = "█" * min(item["count"], 40)
            lines.append(f"  {item['id']:<8} {item['name']:<42} {item['count']:>4}  {bar}")
        lines.append("")
    return "\n".join(lines)
