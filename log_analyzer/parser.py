"""Parse Linux SSH authentication logs (/var/log/auth.log) into LogEvent objects."""
import re
from datetime import datetime

from .models import LogEvent

# Common prefix of every syslog line:  "Nov  1 03:12:45 server sshd[1234]: ..."
PREFIX = (r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+"
          r"(?P<time>\d{2}:\d{2}:\d{2})\s+\S+\s+sshd\[\d+\]:\s+")

PATTERNS = {
    "FAILED": re.compile(
        PREFIX + r"Failed (?:password|publickey) for "
        r"(?P<invalid>invalid user )?(?P<user>\S+) "
        r"from (?P<ip>[\d.]+) port (?P<port>\d+)"),
    "ACCEPTED": re.compile(
        PREFIX + r"Accepted (?:password|publickey) for (?P<user>\S+) "
        r"from (?P<ip>[\d.]+) port (?P<port>\d+)"),
    "INVALID_USER": re.compile(
        PREFIX + r"Invalid user (?P<user>\S*) from (?P<ip>[\d.]+)(?: port (?P<port>\d+))?"),
}


def parse_line(line, year):
    """Convert one log line into a LogEvent, or return None if the line is not relevant."""
    for event_type, pattern in PATTERNS.items():
        match = pattern.search(line)
        if match:
            ts = datetime.strptime(
                f"{year} {match['month']} {match['day']} {match['time']}", "%Y %b %d %H:%M:%S")
            groups = match.groupdict()
            return LogEvent(
                timestamp=ts,
                event_type=event_type,
                user=groups.get("user") or "(empty)",
                ip=groups["ip"],
                port=int(groups.get("port") or 0),
                invalid_user=bool(groups.get("invalid")) or event_type == "INVALID_USER",
                raw=line.rstrip("\n"),
            )
    return None


def parse_file(path, year=None):
    """Read a log file and return (events, stats). Unreadable lines are counted, not fatal."""
    year = year or datetime.now().year
    events, total, skipped = [], 0, 0
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            total += 1
            event = parse_line(line, year)
            if event:
                events.append(event)
            else:
                skipped += 1
    events.sort(key=lambda e: e.timestamp)
    return events, {"total_lines": total, "parsed_events": len(events), "ignored_lines": skipped}
