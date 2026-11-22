from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional


@dataclass
class LogEvent:
    source: str
    line: int
    timestamp: Optional[datetime]
    severity: str
    message: str
    service: str = "unknown"
    trace_id: str = ""
    stack: List[str] = field(default_factory=list)
    physical_lines: int = 1
    ground_truth_cluster: str = ""
    ground_truth_first: bool = False

    def display(self) -> str:
        when = self.timestamp.isoformat(sep=" ") if self.timestamp else "time unknown"
        return f"{when}  {self.severity:<8} [{self.service}] {self.message}  ({self.source}:{self.line})"


@dataclass
class ErrorCluster:
    cluster_id: int
    template: List[str]
    count: int = 0
    first_timestamp: Optional[datetime] = None
    first_source: str = ""
    first_line: int = 0
    severity: str = "ERROR"
    services: Dict[str, int] = field(default_factory=dict)
    examples: List[str] = field(default_factory=list)

    @property
    def pattern(self) -> str:
        return " ".join(self.template)


@dataclass
class CrashSequence:
    crash: LogEvent
    context: List[LogEvent] = field(default_factory=list)


@dataclass
class AnalysisResult:
    files: List[str]
    bytes_read: int = 0
    lines_read: int = 0
    events_read: int = 0
    errors_read: int = 0
    warnings_read: int = 0
    clusters: List[ErrorCluster] = field(default_factory=list)
    crashes: List[CrashSequence] = field(default_factory=list)
    untracked_patterns: int = 0
    elapsed_seconds: float = 0.0
    dataset_metrics: Dict[str, object] = field(default_factory=dict)
