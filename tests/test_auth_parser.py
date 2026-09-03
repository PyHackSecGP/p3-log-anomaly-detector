"""Auth-log parser tests using the unified LogEvent schema."""

from parsers.auth_parser import AuthParser


def test_parses_failed_password(fixtures_dir):
    parser = AuthParser()
    events = parser.parse_file(fixtures_dir / "auth.log")
    assert len(events) == 4

    e = events[0]
    assert e.source == "auth"
    assert e.host == "web01"
    assert e.service == "sshd"
    assert e.user == "root"
    assert e.ip == "192.168.1.100"
    assert e.extra["event_type"] == "ssh_failed_password"
    assert e.extra["pid"] == 1234
    assert e.extra["port"] == 22345


def test_parses_accepted_publickey(fixtures_dir):
    events = AuthParser().parse_file(fixtures_dir / "auth.log")
    e = events[1]
    assert e.extra["event_type"] == "ssh_accepted_publickey"
    assert e.user == "tony"
    assert e.ip == "10.0.0.1"


def test_parses_useradd(fixtures_dir):
    events = AuthParser().parse_file(fixtures_dir / "auth.log")
    e = events[3]
    assert e.extra["event_type"] == "useradd"
    assert e.user == "hacker"


def test_sniff_accepts_auth_lines():
    parser = AuthParser()
    assert parser.sniff([
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root from 1.2.3.4 port 22 ssh2"
    ]) is True


def test_sniff_rejects_json_lines():
    parser = AuthParser()
    assert parser.sniff(['{"MESSAGE": "hi"}']) is False


def test_parse_line_returns_none_for_blank():
    assert AuthParser().parse_line("") is None
