"""AbuseIPDB IP reputation lookup. Requires free API key from abuseipdb.com.

Set ABUSEIPDB_API_KEY env var or pass api_key directly.
Free tier: 1000 checks/day.
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from typing import Optional

from anomaly_detector import Anomaly

_API_URL = "https://api.abuseipdb.com/api/v2/check"
_TIMEOUT = 10


def check_ip(ip: str, api_key: str) -> dict:
    """Query AbuseIPDB for a single IP. Returns parsed response dict or empty on error."""
    params = urllib.parse.urlencode({"ipAddress": ip, "maxAgeInDays": 90})
    url = f"{_API_URL}?{params}"
    req = urllib.request.Request(
        url,
        headers={
            "Key": api_key,
            "Accept": "application/json",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=_TIMEOUT) as resp:
            return json.loads(resp.read()).get("data", {})
    except (urllib.error.URLError, json.JSONDecodeError):
        return {}


def enrich_anomalies(
    anomalies: list[Anomaly],
    api_key: Optional[str] = None,
    verbose: bool = False,
) -> list[Anomaly]:
    """Query AbuseIPDB for each unique IP in anomalies and store scores in-place.

    Deduplicates IPs so each is only checked once.
    """
    key = api_key or os.environ.get("ABUSEIPDB_API_KEY", "")
    if not key:
        return anomalies

    # Collect unique IPs from anomalies that have one
    unique_ips: set[str] = set()
    for a in anomalies:
        if a.source_ip and "," not in a.source_ip:  # skip multi-IP strings
            unique_ips.add(a.source_ip)

    ip_cache: dict[str, dict] = {}
    for ip in unique_ips:
        if verbose:
            print(f"  [AbuseIPDB] Checking {ip} ...", end=" ", flush=True)
        data = check_ip(ip, key)
        ip_cache[ip] = data
        if verbose:
            score = data.get("abuseConfidenceScore", "?")
            print(f"score={score}")

    # Apply enrichment to anomalies
    for a in anomalies:
        if a.source_ip and a.source_ip in ip_cache:
            data = ip_cache[a.source_ip]
            a.abuse_score = data.get("abuseConfidenceScore", -1)
            a.abuse_reports = data.get("totalReports", -1)
            a.geo_country = data.get("countryCode", "")

    return anomalies
