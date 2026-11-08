"""
SOC Log Sentinel - Enterprise Detection Engineering & Incident Triage Engine
Author: Mohammad Hassan Jalal
License: MIT
"""

__version__ = "2.0.0"
__author__ = "Mohammad Hassan Jalal"

from .parser import LogEntry, LogParser, parse_log_file
from .engine import DetectionEngine, Rule, Alert
from .report import IncidentReporter

__all__ = [
    "__version__",
    "__author__",
    "LogEntry",
    "LogParser",
    "parse_log_file",
    "DetectionEngine",
    "Rule",
    "Alert",
    "IncidentReporter",
]
