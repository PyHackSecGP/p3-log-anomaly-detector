"""Tests for mitre.py — mapping, coverage, heatmap rendering."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

import mitre


@dataclass
class _FakeAnomaly:
    mitre_id: str


def test_load_mapping_default():
    m = mitre.load_mapping()
    assert "T1110" in m
    assert m["T1110"]["name"] == "Brute Force"
    assert m["T1110"]["tactic"] == "Credential Access"
    assert m["T1110"]["url"].startswith("https://attack.mitre.org/")


def test_load_mapping_custom_path(tmp_path: Path):
    p = tmp_path / "custom.json"
    p.write_text(json.dumps({"T9999": {"name": "Test", "tactic": "Fake", "url": "", "rules": []}}))
    m = mitre.load_mapping(p)
    assert m == {"T9999": {"name": "Test", "tactic": "Fake", "url": "", "rules": []}}


def test_get_technique_known():
    t = mitre.get_technique("T1548")
    assert t["id"] == "T1548"
    assert t["name"] == "Abuse Elevation Control Mechanism"
    assert t["tactic"] == "Privilege Escalation"


def test_get_technique_unknown_returns_stub():
    t = mitre.get_technique("T9999")
    assert t["id"] == "T9999"
    assert t["name"] == "Unknown"
    assert t["tactic"] == "Unknown"
    assert t["url"] == ""


def test_summarize_coverage_counts_by_tactic():
    anomalies = [
        _FakeAnomaly("T1110"),
        _FakeAnomaly("T1110"),
        _FakeAnomaly("T1548"),
        _FakeAnomaly("T1136"),
    ]
    s = mitre.summarize_coverage(anomalies)
    assert s["total_events"] == 4
    assert s["unique_techniques"] == 3
    assert any(t["id"] == "T1110" and t["count"] == 2 for t in s["by_tactic"]["Credential Access"])
    assert "Privilege Escalation" in s["by_tactic"]
    assert "Persistence" in s["by_tactic"]


def test_summarize_coverage_empty():
    s = mitre.summarize_coverage([])
    assert s["total_events"] == 0
    assert s["unique_techniques"] == 0
    assert s["by_tactic"] == {}


def test_summarize_coverage_handles_dict_anomalies():
    s = mitre.summarize_coverage([{"mitre_id": "T1083"}, {"mitre_id": "T1083"}])
    assert s["total_events"] == 2
    assert s["unique_techniques"] == 1


def test_summarize_coverage_unknown_tcode_grouped_as_unknown():
    s = mitre.summarize_coverage([_FakeAnomaly("T9999")])
    assert "Unknown" in s["by_tactic"]
    assert s["by_tactic"]["Unknown"][0]["id"] == "T9999"


def test_render_heatmap_empty():
    out = mitre.render_heatmap({"total_events": 0, "unique_techniques": 0, "by_tactic": {}})
    assert "no techniques observed" in out


def test_render_heatmap_formats_tactics_and_bars():
    summary = mitre.summarize_coverage(
        [_FakeAnomaly("T1110"), _FakeAnomaly("T1110"), _FakeAnomaly("T1548")]
    )
    out = mitre.render_heatmap(summary)
    assert "MITRE ATT&CK Coverage" in out
    assert "[Credential Access]" in out
    assert "[Privilege Escalation]" in out
    assert "T1110" in out
    assert "T1548" in out
    assert "Brute Force" in out
    assert "█" in out
