"""Statistics, terminal summary, CSV/JSON export and charts."""
import csv
import json
import os
from collections import Counter

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

COLORS = {"CRITICAL": "\033[1;41;97m", "HIGH": "\033[1;91m", "MEDIUM": "\033[1;93m"}
RESET = "\033[0m"


def statistics(events):
    failed = [e for e in events if e.event_type == "FAILED"]
    accepted = [e for e in events if e.event_type == "ACCEPTED"]
    return {
        "failed": len(failed),
        "accepted": len(accepted),
        "invalid_user_lines": sum(1 for e in events if e.event_type == "INVALID_USER"),
        "unique_ips": len({e.ip for e in events}),
        "top_ips": Counter(e.ip for e in failed).most_common(10),
        "top_users": Counter(e.user for e in failed).most_common(10),
        "per_hour": Counter(e.timestamp.hour for e in failed),
    }


def print_summary(file_stats, stats, alerts, color=True):
    c = (lambda k: COLORS[k]) if color else (lambda k: "")
    r = RESET if color else ""
    line = "=" * 62
    print(line)
    print("  SSH LOG ANALYZER - Brute-Force Attack Detection Report")
    print(line)
    print(f"  Lines read          : {file_stats['total_lines']}")
    print(f"  Auth events parsed  : {file_stats['parsed_events']}")
    print(f"  Failed logins       : {stats['failed']}")
    print(f"  Successful logins   : {stats['accepted']}")
    print(f"  Unique IP addresses : {stats['unique_ips']}")
    print("-" * 62)
    print("  Top 5 attacking IPs (failed logins)")
    for ip, n in stats["top_ips"][:5]:
        print(f"    {ip:<18} {n:>5}  " + "#" * min(30, n // 10 + 1))
    print("-" * 62)
    print(f"  ALERTS: {len(alerts)}")
    for a in alerts:
        print(f"  {c(a.severity)}[{a.severity}]{r} {a.rule} - {a.ip}")
        print(f"      {a.attempts} attempts | {a.first_seen:%H:%M:%S} -> {a.last_seen:%H:%M:%S} | {a.details}")
    print(line)


def export(alerts, stats, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    rows = [a.to_row() for a in alerts]
    with open(os.path.join(out_dir, "alerts.csv"), "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0]) if rows else ["severity"])
        writer.writeheader()
        writer.writerows(rows)
    summary = {k: v for k, v in stats.items() if k != "per_hour"}
    summary["per_hour"] = {str(h): n for h, n in sorted(stats["per_hour"].items())}
    summary["alerts"] = rows
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(summary, f, indent=2)


def make_charts(stats, out_dir):
    os.makedirs(out_dir, exist_ok=True)
    plt.rcParams.update({"axes.spines.top": False, "axes.spines.right": False, "font.size": 10})
    navy, red = "#1f3a5f", "#d1495b"

    ips = stats["top_ips"][::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh([i for i, _ in ips], [n for _, n in ips], color=navy)
    ax.set_xlabel("Failed login attempts")
    ax.set_title("Top attacking IP addresses")
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, "top_ips.png"), dpi=200); plt.close(fig)

    hours = list(range(24))
    fig, ax = plt.subplots(figsize=(7, 3.4))
    ax.bar(hours, [stats["per_hour"].get(h, 0) for h in hours], color=red)
    ax.set_xticks(hours[::2])
    ax.set_xlabel("Hour of the day"); ax.set_ylabel("Failed logins")
    ax.set_title("Failed SSH logins per hour")
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, "per_hour.png"), dpi=200); plt.close(fig)

    users = stats["top_users"][::-1]
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.barh([u for u, _ in users], [n for _, n in users], color="#e09f3e")
    ax.set_xlabel("Failed login attempts")
    ax.set_title("Most targeted usernames")
    fig.tight_layout(); fig.savefig(os.path.join(out_dir, "top_users.png"), dpi=200); plt.close(fig)
