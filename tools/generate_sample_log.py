"""Generate a realistic sample auth.log for testing (no real server needed).

Attacker IPs come from the RFC 5737 documentation ranges (192.0.2.0/24,
198.51.100.0/24, 203.0.113.0/24), so they never point to a real machine.

    python tools/generate_sample_log.py --out samples/auth.log
"""
import argparse
import random
from datetime import datetime, timedelta

HOST = "web-server"
LEGIT_USERS = {"soule": "10.0.0.15", "admin_ops": "10.0.0.22", "deploy": "10.0.0.30"}
COMMON_USERS = ["root", "admin", "test", "user", "ubuntu", "oracle", "postgres", "git",
                "guest", "pi", "ftpuser", "support", "mysql", "www-data", "deploy"]


def fmt(ts, pid, msg):
    return f"{ts:%b} {ts.day:>2} {ts:%H:%M:%S} {HOST} sshd[{pid}]: {msg}"


def failed(ts, user, ip, invalid=False):
    pid, port = random.randint(1000, 65000), random.randint(30000, 65000)
    lines = []
    if invalid:
        lines.append(fmt(ts, pid, f"Invalid user {user} from {ip} port {port}"))
    inv = "invalid user " if invalid else ""
    lines.append(fmt(ts, pid, f"Failed password for {inv}{user} from {ip} port {port} ssh2"))
    return lines


def accepted(ts, user, ip, method="password"):
    pid, port = random.randint(1000, 65000), random.randint(30000, 65000)
    return [fmt(ts, pid, f"Accepted {method} for {user} from {ip} port {port} ssh2")]


def generate(day, seed=42):
    random.seed(seed)
    out = []  # list of (timestamp, line)

    def add(ts, lines):
        out.extend((ts, line) for line in lines)

    # 1. Normal activity: employees log in, sometimes mistype their password once
    for user, ip in LEGIT_USERS.items():
        for _ in range(random.randint(4, 7)):
            ts = day + timedelta(hours=random.randint(8, 19), minutes=random.randint(0, 59), seconds=random.randint(0, 59))
            if random.random() < 0.3:
                add(ts - timedelta(seconds=20), failed(ts - timedelta(seconds=20), user, ip))
            add(ts, accepted(ts, user, ip, random.choice(["password", "publickey"])))

    # 2. Internet background noise: many bots trying 1-3 times
    for i in range(40):
        ip = f"198.51.100.{random.randint(1, 254)}"
        ts = day + timedelta(minutes=random.randint(0, 24 * 60 - 1))
        for k in range(random.randint(1, 3)):
            u = random.choice(COMMON_USERS)
            t = ts + timedelta(seconds=10 * k)
            add(t, failed(t, u, ip, invalid=u not in ("root",)))

    # 3. Attacker A - fast brute force on root at night (about 2 tries per second)
    ts = day + timedelta(hours=2, minutes=14)
    for k in range(420):
        t = ts + timedelta(seconds=k * 0.5)
        add(t, failed(t, "root", "203.0.113.45"))

    # 4. Attacker B - password spraying: many usernames, few passwords each
    ts = day + timedelta(hours=5, minutes=3)
    for k, u in enumerate(COMMON_USERS * 6):
        t = ts + timedelta(seconds=k * 3)
        add(t, failed(t, u, "192.0.2.77", invalid=u not in ("root", "deploy")))

    # 5. Attacker C - brute force on 'deploy' that finally SUCCEEDS (weak password)
    ts = day + timedelta(hours=14, minutes=40)
    for k in range(95):
        t = ts + timedelta(seconds=k * 2)
        add(t, failed(t, "deploy", "203.0.113.200"))
    t = ts + timedelta(seconds=95 * 2 + 3)
    add(t, accepted(t, "deploy", "203.0.113.200"))

    # 6. Attacker D - "low and slow": 1 try every 2 minutes, stays under the window threshold
    ts = day + timedelta(hours=20)
    for k in range(25):
        t = ts + timedelta(minutes=2 * k)
        add(t, failed(t, "admin", "198.51.100.250", invalid=True))

    # Unrelated system lines, to show the parser ignores them
    for h in range(0, 24, 3):
        t = day + timedelta(hours=h, minutes=1)
        out.append((t, f"{t:%b} {t.day:>2} {t:%H:%M:%S} {HOST} CRON[{random.randint(1000, 9999)}]: "
                       f"pam_unix(cron:session): session opened for user root(uid=0)"))

    out.sort(key=lambda x: x[0])
    return [line for _, line in out]


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--out", default="samples/auth.log")
    p.add_argument("--date", default="2026-10-28", help="day to simulate (YYYY-MM-DD)")
    a = p.parse_args()
    lines = generate(datetime.strptime(a.date, "%Y-%m-%d"))
    with open(a.out, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")
    print(f"Wrote {len(lines)} lines to {a.out}")
