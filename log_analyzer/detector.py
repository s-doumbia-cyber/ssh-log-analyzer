"""Detection rules for SSH attacks."""
from collections import defaultdict, deque
from datetime import timedelta

from .models import Alert

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}


class BruteForceDetector:
    """Apply four detection rules to a list of LogEvent objects.

    1. Brute force      : >= threshold failed logins from one IP inside a time window.
    2. Password spraying: one IP trying >= spray_users different usernames.
    3. Low and slow     : >= total_limit failures over the whole log, too slow for rule 1.
    4. Compromise       : a successful login from an IP that was attacking before.
    """

    def __init__(self, threshold=10, window_minutes=5, spray_users=5, total_limit=20):
        self.threshold = threshold
        self.window = timedelta(minutes=window_minutes)
        self.spray_users = spray_users
        self.total_limit = total_limit

    def detect(self, events):
        failures = defaultdict(list)       # ip -> list of failed events
        successes = defaultdict(list)      # ip -> list of accepted events
        for e in events:
            if e.event_type == "ACCEPTED":
                successes[e.ip].append(e)
            elif e.event_type == "FAILED":
                failures[e.ip].append(e)

        alerts = []
        brute_ips = {}
        for ip, fails in failures.items():
            alert = self._brute_force(ip, fails)
            if alert:
                alerts.append(alert)
                brute_ips[ip] = alert
            elif len(fails) >= self.total_limit:
                alert = Alert("MEDIUM", "Low-and-slow brute force", ip, fails[0].timestamp,
                              fails[-1].timestamp, len(fails), {e.user for e in fails},
                              "Too slow for the time window, but too many failures in total")
                alerts.append(alert)
                brute_ips[ip] = alert
            alert = self._spraying(ip, fails)
            if alert:
                alerts.append(alert)

        for ip, accepted in successes.items():
            if ip in brute_ips:
                start = brute_ips[ip].first_seen
                later = [a for a in accepted if a.timestamp >= start]
                if later:
                    a = later[0]
                    alerts.append(Alert(
                        "CRITICAL", "Successful login after attack", ip, start, a.timestamp,
                        brute_ips[ip].attempts, {a.user},
                        f"Login as '{a.user}' succeeded at {a.timestamp:%H:%M:%S}"
                        " - account likely compromised"))

        alerts.sort(key=lambda a: (SEVERITY_ORDER[a.severity], -a.attempts))
        return alerts

    def _brute_force(self, ip, fails):
        """Sliding window: keep the failures of the last `window` and check their count."""
        window, best = deque(), []
        for e in fails:
            window.append(e)
            while e.timestamp - window[0].timestamp > self.window:
                window.popleft()
            if len(window) > len(best):
                best = list(window)
        if len(best) >= self.threshold:
            users = {e.user for e in fails}
            minutes = int(self.window.total_seconds() // 60)
            return Alert("HIGH", "Brute force", ip, fails[0].timestamp, fails[-1].timestamp,
                         len(fails), users, f"Peak of {len(best)} failures in {minutes} min")
        return None

    def _spraying(self, ip, fails):
        users = {e.user for e in fails}
        if len(users) >= self.spray_users:
            return Alert("MEDIUM", "Password spraying / user enumeration", ip,
                         fails[0].timestamp, fails[-1].timestamp, len(fails), users,
                         f"{len(users)} different usernames tried")
        return None
