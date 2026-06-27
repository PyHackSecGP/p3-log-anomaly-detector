"""
AI Log Anomaly Detector — entry point.

Usage:
  python main.py [LOG_FILE] [OPTIONS]

Examples:
  python main.py /var/log/auth.log
  python main.py /var/log/auth.log --model llama3.2:3b --json report.json
  python main.py sample_auth.log --no-ai
  python main.py /var/log/auth.log --url http://100.126.22.55:11434
"""

import argparse
import sys
from pathlib import Path

from allowlist import load_allowlist
from anomaly_detector import run_detection
from log_parser import parse_file
from ollama_client import OllamaClient, DEFAULT_BASE_URL, DEFAULT_MODEL
from report_generator import (
    build_anomaly_summary_text,
    build_log_sample,
    generate_json_report,
    generate_text_report,
    save_report,
)

# Common log paths to auto-detect when no file is given
_DEFAULT_LOG_PATHS = [
    "/var/log/auth.log",
    "/var/log/secure",
    "/var/log/auth.log.1",
]


def find_default_log() -> str | None:
    """Return the first readable default auth log path."""
    for p in _DEFAULT_LOG_PATHS:
        if Path(p).is_file():
            return p
    return None


def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""
    parser = argparse.ArgumentParser(
        description="AI-powered Linux auth log anomaly detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "log_file",
        nargs="?",
        help="Path to auth log file (default: auto-detect /var/log/auth.log or /var/log/secure)",
    )
    parser.add_argument(
        "--url",
        default=DEFAULT_BASE_URL,
        metavar="URL",
        help=f"Ollama server URL (default: {DEFAULT_BASE_URL})",
    )
    parser.add_argument(
        "--model",
        default=DEFAULT_MODEL,
        metavar="MODEL",
        help=f"Ollama model name (default: {DEFAULT_MODEL})",
    )
    parser.add_argument(
        "--no-ai",
        action="store_true",
        help="Skip AI analysis, output rule-based findings only",
    )
    parser.add_argument(
        "--json",
        metavar="FILE",
        dest="json_out",
        help="Also save a JSON report to FILE",
    )
    parser.add_argument(
        "--out",
        metavar="FILE",
        dest="text_out",
        help="Save text report to FILE (also prints to stdout)",
    )
    parser.add_argument(
        "--allowlist",
        metavar="FILE",
        default=None,
        help="YAML allowlist file of trusted IPs/users to skip (default: none)",
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable ANSI color codes in output",
    )
    parser.add_argument(
        "--list-models",
        action="store_true",
        help="List available Ollama models and exit",
    )
    parser.add_argument(
        "--generate-sample",
        action="store_true",
        help="Generate a sample auth.log for testing and exit",
    )
    return parser.parse_args()


def generate_sample_log(output_path: str = "sample_auth.log") -> None:
    """Write a realistic sample auth log for testing."""
    sample_lines = [
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:02 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:03 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:04 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:05 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:06 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:07 web01 sshd[1234]: Failed password for root from 192.168.1.100 port 22345 ssh2",
        "May 22 01:00:08 web01 sshd[1234]: Failed password for admin from 192.168.1.100 port 22346 ssh2",
        "May 22 01:00:09 web01 sshd[1234]: Invalid user test from 10.0.0.5",
        "May 22 01:00:10 web01 sshd[1234]: Invalid user deploy from 10.0.0.5",
        "May 22 01:00:11 web01 sshd[1234]: Invalid user ubuntu from 10.0.0.5",
        "May 22 01:00:12 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.50 port 5555 ssh2",
        "May 22 01:00:13 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.51 port 5556 ssh2",
        "May 22 01:00:14 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.52 port 5557 ssh2",
        "May 22 01:00:15 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.53 port 5558 ssh2",
        "May 22 01:00:16 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.54 port 5559 ssh2",
        "May 22 01:00:17 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.55 port 5560 ssh2",
        "May 22 01:00:18 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.56 port 5561 ssh2",
        "May 22 01:00:19 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.57 port 5562 ssh2",
        "May 22 01:00:20 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.58 port 5563 ssh2",
        "May 22 01:00:21 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.59 port 5564 ssh2",
        "May 22 01:00:22 web01 sshd[1234]: Failed password for invalid user oracle from 172.16.0.60 port 5565 ssh2",
        "May 22 01:05:00 web01 sshd[5678]: Accepted password for backup from 192.168.1.100 port 44444 ssh2",
        "May 22 01:05:01 web01 sudo[9999]: backup : TTY=pts/0 ; PWD=/home/backup ; USER=root ; COMMAND=/bin/bash",
        "May 22 01:05:02 web01 sudo[9999]: pam_unix(sudo:auth): authentication failure; logname=backup uid=1002",
        "May 22 01:05:03 web01 sudo[9999]: pam_unix(sudo:auth): authentication failure; logname=backup uid=1002",
        "May 22 01:05:04 web01 sudo[9999]: pam_unix(sudo:auth): authentication failure; logname=backup uid=1002",
        "May 22 01:06:00 web01 su[1111]: pam_unix(su:session): session opened for user root by backup(uid=1002)",
        "May 22 01:07:00 web01 useradd[2222]: new user: name=hacker, UID=1337, GID=1337",
        "May 22 01:07:30 web01 passwd[3333]: pam_unix(passwd:chroot): password changed for hacker",
        "May 22 02:00:00 web01 sshd[4444]: Accepted publickey for tony from 10.0.1.1 port 55000 ssh2",
        "May 22 02:01:00 web01 cron[5555]: pam_unix(cron:session): session opened for user root by (uid=0)",
    ]
    Path(output_path).write_text("\n".join(sample_lines) + "\n", encoding="utf-8")
    print(f"Sample log written to: {output_path}")


def main() -> int:
    """Main entry point. Returns exit code."""
    args = parse_args()
    colored = not args.no_color and sys.stdout.isatty()

    # --generate-sample mode
    if args.generate_sample:
        generate_sample_log()
        return 0

    # --list-models mode
    if args.list_models:
        client = OllamaClient(base_url=args.url, model=args.model)
        models = client.list_models()
        if models:
            print("Available models:")
            for m in models:
                print(f"  {m}")
        else:
            print("Could not reach Ollama or no models found.")
        return 0

    # Resolve log file
    log_path = args.log_file or find_default_log()
    if not log_path:
        print(
            "ERROR: No log file specified and could not auto-detect "
            "/var/log/auth.log or /var/log/secure.\n"
            "Pass a log file as argument: python main.py /path/to/auth.log\n"
            "Or generate a sample:        python main.py --generate-sample",
            file=sys.stderr,
        )
        return 1

    if not Path(log_path).is_file():
        print(f"ERROR: Log file not found: {log_path}", file=sys.stderr)
        return 1

    # Parse
    print(f"Parsing {log_path} ...", flush=True)
    events = parse_file(log_path)
    print(f"  {len(events):,} events parsed.", flush=True)

    if not events:
        print("No parseable events found. Check the log format.", file=sys.stderr)
        return 1

    # Load allowlist if provided
    allowlist_ips: set[str] = set()
    allowlist_users: set[str] = set()
    if args.allowlist:
        try:
            allowlist_ips, allowlist_users = load_allowlist(args.allowlist)
            print(
                f"Allowlist loaded: {len(allowlist_ips)} IPs, "
                f"{len(allowlist_users)} users from {args.allowlist}",
                flush=True,
            )
        except (OSError, ValueError) as exc:
            print(f"  WARNING: Could not load allowlist: {exc}", flush=True)

    # Detect anomalies
    print("Running anomaly detection ...", flush=True)
    anomalies = run_detection(events, allowlist_ips=allowlist_ips or None, allowlist_users=allowlist_users or None)
    print(f"  {len(anomalies)} anomalies found.", flush=True)

    # AI analysis
    ai_assessment: str | None = None
    model_used = args.model

    if not args.no_ai:
        client = OllamaClient(base_url=args.url, model=args.model)
        print(f"Connecting to Ollama at {args.url} ...", flush=True)

        if not client.is_available():
            print(
                f"  WARNING: Ollama not reachable at {args.url}. "
                "Falling back to rule-based report only.",
                flush=True,
            )
        else:
            # Auto-select model if default isn't available
            available = client.list_models()
            if available and args.model not in available:
                model_used = available[0]
                print(f"  Model '{args.model}' not found. Using '{model_used}'.", flush=True)
                client.model = model_used

            if anomalies:
                print(f"  Sending {len(anomalies)} anomalies to {model_used} for analysis ...", flush=True)
                summary = build_anomaly_summary_text(anomalies)
                sample = build_log_sample(events)
                try:
                    ai_assessment = client.analyze_anomalies(summary, sample)
                    print("  AI analysis complete.", flush=True)
                except RuntimeError as exc:
                    print(f"  WARNING: AI analysis failed: {exc}", flush=True)
            else:
                print("  No anomalies to analyze. Skipping AI.", flush=True)

    # Generate reports
    text_report = generate_text_report(
        events, anomalies, ai_assessment,
        log_path=log_path,
        model_used=model_used,
        colored=colored,
    )
    print(text_report)

    if args.text_out:
        # Save without color codes
        plain_report = generate_text_report(
            events, anomalies, ai_assessment,
            log_path=log_path,
            model_used=model_used,
            colored=False,
        )
        save_report(plain_report, args.text_out)
        print(f"Text report saved: {args.text_out}")

    if args.json_out:
        json_report = generate_json_report(
            events, anomalies, ai_assessment,
            log_path=log_path,
            model_used=model_used,
        )
        save_report(json_report, args.json_out)
        print(f"JSON report saved: {args.json_out}")

    # Exit code reflects highest severity
    if any(a.severity == "CRITICAL" for a in anomalies):
        return 2
    if any(a.severity == "HIGH" for a in anomalies):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
