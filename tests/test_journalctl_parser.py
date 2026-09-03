from parsers.journalctl_parser import JournalctlParser


def test_parses_journalctl_json(fixtures_dir):
    events = JournalctlParser().parse_file(fixtures_dir / "journalctl.jsonl")
    assert len(events) == 2
    e = events[0]
    assert e.source == "journalctl"
    assert e.host == "web01"
    assert e.service == "sshd"
    assert e.user == "root"
    assert e.ip == "192.168.1.100"
    assert e.extra["event_type"] == "ssh_failed_password"


def test_sniff_matches_json_lines():
    p = JournalctlParser()
    assert p.sniff(['{"__REALTIME_TIMESTAMP":"1","MESSAGE":"hi"}']) is True


def test_sniff_rejects_syslog_lines():
    assert JournalctlParser().sniff([
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root"
    ]) is False


def test_ignores_blank_and_invalid_json():
    p = JournalctlParser()
    assert p.parse_line("") is None
    assert p.parse_line("not json") is None
