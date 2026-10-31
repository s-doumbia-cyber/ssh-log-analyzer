from log_analyzer.parser import parse_line


def test_failed_password_valid_user():
    e = parse_line("Oct 28 02:14:00 web-server sshd[1234]: Failed password for root from 203.0.113.45 port 51234 ssh2", 2026)
    assert e.event_type == "FAILED"
    assert e.user == "root"
    assert e.ip == "203.0.113.45"
    assert e.port == 51234
    assert not e.invalid_user


def test_failed_password_invalid_user():
    e = parse_line("Oct 28 05:03:00 web-server sshd[99]: Failed password for invalid user oracle from 192.0.2.77 port 40000 ssh2", 2026)
    assert e.event_type == "FAILED"
    assert e.user == "oracle"
    assert e.invalid_user


def test_accepted_publickey():
    e = parse_line("Oct 28 09:00:01 web-server sshd[42]: Accepted publickey for soule from 10.0.0.15 port 50000 ssh2", 2026)
    assert e.event_type == "ACCEPTED"
    assert e.user == "soule"
    assert e.timestamp.year == 2026 and e.timestamp.hour == 9


def test_unrelated_line_is_ignored():
    assert parse_line("Oct 28 03:01:00 web-server CRON[555]: pam_unix(cron:session): session opened for user root", 2026) is None
