from datetime import datetime, timedelta

from log_analyzer.detector import BruteForceDetector
from log_analyzer.models import LogEvent

START = datetime(2026, 10, 28, 2, 0, 0)


def fails(ip, n, every_seconds, users=("root",)):
    return [LogEvent(START + timedelta(seconds=i * every_seconds), "FAILED", users[i % len(users)], ip)
            for i in range(n)]


def test_fast_attack_is_detected():
    alerts = BruteForceDetector(threshold=10, window_minutes=5).detect(fails("203.0.113.1", 50, 1))
    assert any(a.rule == "Brute force" and a.ip == "203.0.113.1" for a in alerts)


def test_few_failures_do_not_alert():
    alerts = BruteForceDetector(threshold=10, window_minutes=5).detect(fails("10.0.0.15", 3, 30))
    assert alerts == []


def test_slow_attack_stays_under_window():
    # 20 failures but one every 2 minutes -> never 10 inside 5 minutes
    alerts = BruteForceDetector(threshold=10, window_minutes=5).detect(fails("198.51.100.9", 20, 120))
    assert not any(a.rule == "Brute force" for a in alerts)


def test_success_after_brute_force_is_critical():
    events = fails("203.0.113.200", 30, 2, users=("deploy",))
    events.append(LogEvent(START + timedelta(seconds=70), "ACCEPTED", "deploy", "203.0.113.200"))
    alerts = BruteForceDetector().detect(events)
    assert alerts[0].severity == "CRITICAL"
    assert "deploy" in alerts[0].users


def test_password_spraying():
    users = ("root", "admin", "test", "oracle", "pi", "git")
    alerts = BruteForceDetector(spray_users=5).detect(fails("192.0.2.77", 6, 60, users=users))
    assert any(a.rule.startswith("Password spraying") for a in alerts)


def test_low_and_slow_is_caught_by_total_limit():
    alerts = BruteForceDetector(threshold=10, window_minutes=5, total_limit=20).detect(fails("198.51.100.9", 25, 120))
    assert any(a.rule == "Low-and-slow brute force" for a in alerts)
