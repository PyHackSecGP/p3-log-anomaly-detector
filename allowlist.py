"""Known-good allowlist loader. Uses stdlib only (no PyYAML dependency)."""
from __future__ import annotations

import re
from pathlib import Path


def load_allowlist(path: str) -> tuple[set[str], set[str]]:
    """Parse a simple YAML allowlist file and return (ips, users) sets.

    Only handles the flat-list subset of YAML needed here — no PyYAML required.

    Expected format:
        ips:
          - 10.0.1.1
          - 192.168.1.0/24  # NOTE: CIDR ranges are stored as-is for future use
        users:
          - tony
          - deploy
    """
    text = Path(path).read_text(encoding="utf-8")
    ips: set[str] = set()
    users: set[str] = set()

    current_section = None
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped == "ips:":
            current_section = "ips"
        elif stripped == "users:":
            current_section = "users"
        elif stripped.startswith("- ") and current_section:
            value = stripped[2:].split("#")[0].strip()
            if value:
                if current_section == "ips":
                    ips.add(value)
                else:
                    users.add(value)

    return ips, users
