"""SSH Log Analyzer - detect brute-force attacks in Linux authentication logs."""
from .parser import parse_file, parse_line
from .detector import BruteForceDetector
from .models import LogEvent, Alert

__version__ = "1.0.0"
__all__ = ["parse_file", "parse_line", "BruteForceDetector", "LogEvent", "Alert"]
