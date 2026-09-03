from parsers.nginx_parser import NginxParser


def test_parses_combined_format(fixtures_dir):
    events = NginxParser().parse_file(fixtures_dir / "nginx_access.log")
    assert len(events) == 3

    e0 = events[0]
    assert e0.source == "nginx"
    assert e0.ip == "10.0.0.1"
    assert e0.status_code == 200
    assert e0.latency_ms == 12.0
    assert e0.extra["method"] == "GET"
    assert e0.extra["path"] == "/index.html"
    assert e0.extra["user_agent"].startswith("curl")

    e1 = events[1]
    assert e1.user == "alice"
    assert e1.status_code == 401
    assert e1.level == "warn"

    e2 = events[2]
    assert e2.status_code == 404
    assert e2.extra["user_agent"].startswith("sqlmap")


def test_ignores_malformed_lines():
    p = NginxParser()
    assert p.parse_line("garbage line") is None
    assert p.parse_line("") is None


def test_sniff_matches_combined():
    p = NginxParser()
    assert p.sniff([
        '10.0.0.1 - - [02/Sep/2026:12:00:01 +0000] "GET / HTTP/1.1" 200 512 "-" "curl"'
    ]) is True


def test_sniff_rejects_syslog():
    assert NginxParser().sniff([
        "May 22 01:00:01 web01 sshd[1234]: Failed password for root"
    ]) is False
