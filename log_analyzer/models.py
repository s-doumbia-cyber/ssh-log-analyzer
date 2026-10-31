"""Data models used across the analyzer."""
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class LogEvent:
    """One authentication event extracted from an auth.log line."""
    timestamp: datetime
    event_type: str          # "FAILED", "ACCEPTED" or "INVALID_USER"
    user: str
    ip: str
    port: int = 0
    invalid_user: bool = False
    raw: str = ""


@dataclass
class Alert:
    """A suspicious activity found by the detector."""
    severity: str            # "CRITICAL", "HIGH" or "MEDIUM"
    rule: str                # name of the detection rule
    ip: str
    first_seen: datetime
    last_seen: datetime
    attempts: int
    users: set = field(default_factory=set)
    details: str = ""

    def to_row(self):
        """Return the alert as a flat dictionary (for CSV / JSON export)."""
        return {
            "severity": self.severity,
            "rule": self.rule,
            "ip": self.ip,
            "first_seen": self.first_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "last_seen": self.last_seen.strftime("%Y-%m-%d %H:%M:%S"),
            "attempts": self.attempts,
            "users": ", ".join(sorted(self.users)),
            "details": self.details,
        }
