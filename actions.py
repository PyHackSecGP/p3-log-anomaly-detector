"""
Remediation actions executed by the agent in --act mode.

All actions are logged, idempotent, and reversible. Each function returns
a result string describing what was done or why it was skipped.

Safety: actions only run when explicitly requested via --agentic --act.
        The agent never calls these automatically without user consent.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)

_ACTION_LOG = Path.home() / ".local" / "share" / "p3-anomaly" / "actions.log"
_BLOCKED_IPS_FILE = Path.home() / ".local" / "share" / "p3-anomaly" / "blocked_ips.txt"


def _log_action(action: str, target: str, result: str) -> None:
    _ACTION_LOG.parent.mkdir(parents=True, exist_ok=True)
    with open(_ACTION_LOG, "a") as fh:
        fh.write(f"[{datetime.now().isoformat()}] {action} | target={target} | {result}\n")


def block_ip(ip: str, dry_run: bool = False) -> str:
    """
    Block a source IP using iptables INPUT chain DROP rule.

    Idempotent — checks if the rule already exists before adding.
    Appends the IP to a local blocked IPs list for audit trail.

    Args:
        ip: IPv4 address to block.
        dry_run: If True, log the action but don't execute.

    Returns:
        Result string describing the action taken.
    """
    if not ip or not all(c.isdigit() or c == "." for c in ip):
        return f"block_ip: invalid IP address '{ip}' — skipped"

    # Check if already blocked
    _BLOCKED_IPS_FILE.parent.mkdir(parents=True, exist_ok=True)
    existing = set()
    if _BLOCKED_IPS_FILE.exists():
        existing = set(_BLOCKED_IPS_FILE.read_text().splitlines())

    if ip in existing:
        result = f"block_ip: {ip} already blocked — skipped"
        _log_action("block_ip", ip, result)
        return result

    if dry_run or not shutil.which("iptables"):
        result = f"block_ip: {'dry-run' if dry_run else 'iptables not found'} — would run: iptables -I INPUT -s {ip} -j DROP"
        _log_action("block_ip", ip, result)
        return result

    if os.geteuid() != 0:
        result = f"block_ip: not root — would run: iptables -I INPUT -s {ip} -j DROP (run with sudo --act)"
        _log_action("block_ip", ip, result)
        return result

    try:
        # Check if rule already exists in iptables
        check = subprocess.run(
            ["iptables", "-C", "INPUT", "-s", ip, "-j", "DROP"],
            capture_output=True, timeout=10,
        )
        if check.returncode == 0:
            result = f"block_ip: iptables rule for {ip} already exists"
        else:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True, timeout=10,
            )
            with open(_BLOCKED_IPS_FILE, "a") as fh:
                fh.write(f"{ip}\n")
            result = f"block_ip: BLOCKED {ip} via iptables -I INPUT -s {ip} -j DROP"
        _log_action("block_ip", ip, result)
        return result
    except subprocess.CalledProcessError as exc:
        result = f"block_ip: iptables failed for {ip}: {exc.stderr.decode().strip()}"
        _log_action("block_ip", ip, result)
        return result
    except Exception as exc:
        result = f"block_ip: error blocking {ip}: {exc}"
        _log_action("block_ip", ip, result)
        return result


def lock_user(username: str, dry_run: bool = False) -> str:
    """
    Lock a compromised user account using passwd -l.

    Prevents password-based logins without deleting the account or its data.
    Uses usermod -L as fallback if passwd is unavailable.

    Args:
        username: Linux username to lock.
        dry_run: If True, log the action but don't execute.

    Returns:
        Result string describing the action taken.
    """
    if not username or not username.replace("-", "").replace("_", "").isalnum():
        return f"lock_user: invalid username '{username}' — skipped"

    # Never lock root or system users
    protected = {"root", "daemon", "bin", "sys", "sync", "nobody"}
    if username in protected:
        result = f"lock_user: '{username}' is a protected account — skipped"
        _log_action("lock_user", username, result)
        return result

    if dry_run or os.geteuid() != 0:
        result = f"lock_user: {'dry-run' if dry_run else 'not root'} — would run: passwd -l {username}"
        _log_action("lock_user", username, result)
        return result

    cmd = ["passwd", "-l", username] if shutil.which("passwd") else ["usermod", "-L", username]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=10)
        result = f"lock_user: LOCKED account '{username}' via {' '.join(cmd)}"
        _log_action("lock_user", username, result)
        return result
    except subprocess.CalledProcessError as exc:
        result = f"lock_user: failed to lock '{username}': {exc.stderr.decode().strip()}"
        _log_action("lock_user", username, result)
        return result
    except Exception as exc:
        result = f"lock_user: error locking '{username}': {exc}"
        _log_action("lock_user", username, result)
        return result


def list_blocked_ips() -> list[str]:
    """Return list of IPs previously blocked by this tool."""
    if not _BLOCKED_IPS_FILE.exists():
        return []
    return [ip.strip() for ip in _BLOCKED_IPS_FILE.read_text().splitlines() if ip.strip()]
