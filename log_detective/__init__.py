"""Terminal-Native Log Detective package."""

from __future__ import annotations

__version__ = "1.0.0"
__author__ = "Log Detective Hackathon Team"

from .models import (
    LogEvent,
    LogCluster,
    TimelineEvent,
    CrashInvestigation,
    AnalysisReport,
    LogSeverity,
)
from .parser import StreamLogParser, parse_json_log_line, parse_plaintext_log_line
from .normalizer import normalize_message, extract_primary_exception

# Teammate 2 module (Drain clustering)
try:
    from .clustering import ErrorClusterer
except ImportError:
    ErrorClusterer = None

# Teammate 3 modules (Causal RCA & Analyzer)
try:
    from .causal import CausalReconstructor
except ImportError:
    CausalReconstructor = None

try:
    from .analyzer import LogDetectiveAnalyzer
except ImportError:
    LogDetectiveAnalyzer = None

__all__ = [
    "LogEvent",
    "LogCluster",
    "TimelineEvent",
    "CrashInvestigation",
    "AnalysisReport",
    "LogSeverity",
    "StreamLogParser",
    "parse_json_log_line",
    "parse_plaintext_log_line",
    "normalize_message",
    "extract_primary_exception",
    "ErrorClusterer",
    "CausalReconstructor",
    "LogDetectiveAnalyzer",
]
