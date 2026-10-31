"""Command-line entry point.

Example:
    python main.py samples/auth.log --threshold 10 --window 5 --out output
"""
import argparse
import sys

from log_analyzer import BruteForceDetector, parse_file
from log_analyzer import reporter


def build_args():
    p = argparse.ArgumentParser(
        description="Detect SSH brute-force attacks in a Linux auth.log file.")
    p.add_argument("logfile", help="path to the auth.log file")
    p.add_argument("--threshold", type=int, default=10,
                   help="failed logins that trigger a brute-force alert (default 10)")
    p.add_argument("--window", type=int, default=5,
                   help="time window in minutes (default 5)")
    p.add_argument("--spray", type=int, default=5,
                   help="distinct usernames that trigger a spraying alert (default 5)")
    p.add_argument("--total", type=int, default=20,
                   help="total failures that trigger a low-and-slow alert (default 20)")
    p.add_argument("--year", type=int, default=None,
                   help="year of the log (auth.log lines have no year)")
    p.add_argument("--out", default="output",
                   help="folder for CSV, JSON and charts (default: output)")
    p.add_argument("--no-color", action="store_true",
                   help="disable coloured terminal output")
    return p.parse_args()


def main():
    args = build_args()
    try:
        events, file_stats = parse_file(args.logfile, args.year)
    except FileNotFoundError:
        print(f"Error: file '{args.logfile}' not found.")
        return 1
    if not events:
        print("No SSH authentication events found in this file.")
        return 0

    detector = BruteForceDetector(args.threshold, args.window, args.spray, args.total)
    alerts = detector.detect(events)
    stats = reporter.statistics(events)

    reporter.print_summary(file_stats, stats, alerts, color=not args.no_color)
    reporter.export(alerts, stats, args.out)
    reporter.make_charts(stats, args.out)
    print(f"Results saved in '{args.out}/' (alerts.csv, report.json, charts)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
