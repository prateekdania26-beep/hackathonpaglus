"""Core data models for Terminal-Native Log Detective."""

from __future__ import annotations
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional, Set, Dict, Any


class LogSeverity(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARN = "WARN"
    ERROR = "ERROR"
    FATAL = "FATAL"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def from_str(cls, val: str) -> "LogSeverity":
        v = (val or "").upper().strip()
        if v in ("DEBUG", "TRACE", "VERBOSE"):
            return cls.DEBUG
        if v in ("INFO", "NOTICE"):
            return cls.INFO
        if v in ("WARN", "WARNING"):
            return cls.WARN
        if v in ("ERROR", "ERR"):
            return cls.ERROR
        if v in ("FATAL", "CRITICAL", "PANIC", "EMERGENCY", "EMERG", "ALERT", "CRIT"):
            return cls.FATAL
        return cls.UNKNOWN

    @property
    def is_error_or_higher(self) -> bool:
        return self in (LogSeverity.ERROR, LogSeverity.FATAL)

    @property
    def is_fatal(self) -> bool:
        return self == LogSeverity.FATAL


@dataclass(slots=True)
class LogEvent:
    """Represents a single parsed log event, potentially stitched with a multi-line stack trace."""
    line_number: int
    byte_offset: int
    timestamp_raw: Optional[str] = None
    timestamp_epoch: Optional[float] = None
    level: LogSeverity = LogSeverity.UNKNOWN
    component: Optional[str] = None
    trace_id: Optional[str] = None
    raw_message: str = ""
    clean_message: str = ""
    stack_trace: Optional[str] = None
    metadata: Dict[str, Any] = field(default_factory=dict)

    @property
    def is_error(self) -> bool:
        return self.level.is_error_or_higher or bool(self.stack_trace)

    @property
    def is_crash(self) -> bool:
        if self.level == LogSeverity.FATAL:
            return True
        low = self.clean_message.lower()
        if any(term in low for term in ("out of memory", "oomkiller", "panic:", "sigkill", "fatal error", "segmentation fault", "process terminated")):
            return True
        return False


@dataclass
class LogCluster:
    """Represents a cluster of similar log error messages aggregated by normalized template."""
    cluster_id: int
    template: str
    tokens: List[str]
    count: int = 0
    first_seen_line: int = 0
    first_seen_timestamp: Optional[str] = None
    first_seen_epoch: Optional[float] = None
    first_seen_raw: str = ""
    first_seen_stack_trace: Optional[str] = None
    last_seen_line: int = 0
    last_seen_timestamp: Optional[str] = None
    sample_messages: List[str] = field(default_factory=list)
    affected_components: Set[str] = field(default_factory=set)
    severity: LogSeverity = LogSeverity.ERROR
    is_crash_pattern: bool = False
    context_before_first_seen: List[str] = field(default_factory=list)

    @property
    def rate_per_second(self) -> float:
        """Calculate frequency if epoch timestamps are present."""
        if self.first_seen_epoch and hasattr(self, "last_seen_epoch") and self.last_seen_epoch:
            dt = self.last_seen_epoch - self.first_seen_epoch
            if dt > 0:
                return round(self.count / dt, 2)
        return 0.0


@dataclass
class TimelineEvent:
    """An event reconstructed in a causal sequence leading up to a failure or crash."""
    line_number: int
    timestamp: Optional[str]
    epoch: Optional[float]
    level: LogSeverity
    component: Optional[str]
    message: str
    cluster_id: Optional[int] = None
    is_patient_zero: bool = False
    significance: str = "context"  # 'trigger', 'degradation', 'cascade', 'crash', 'context'
    stack_snippet: Optional[str] = None


@dataclass
class CrashInvestigation:
    """Deep forensic reconstruction of a crash event and its causal precursors."""
    crash_id: int
    crash_line: int
    crash_timestamp: Optional[str]
    crash_message: str
    crash_cluster_id: Optional[int]
    stack_trace: Optional[str]
    preceding_timeline: List[TimelineEvent]
    patient_zero_clusters: List[LogCluster]
    cascading_cluster_ids: List[int]
    root_cause_hypothesis: str
    confidence_score: float  # 0.0 - 1.0
    blast_radius_summary: str


@dataclass
class AnalysisReport:
    """Comprehensive diagnostic report produced by Log Detective."""
    source_path: str
    total_lines_read: int = 0
    total_bytes_read: int = 0
    total_events_parsed: int = 0
    total_errors: int = 0
    total_custom_errors: int = 0
    total_warnings: int = 0
    total_crashes: int = 0
    total_clusters: int = 0
    elapsed_seconds: float = 0.0
    lines_per_second: float = 0.0
    bytes_per_second: float = 0.0
    peak_memory_mb: float = 0.0
    clusters: List[LogCluster] = field(default_factory=list)
    patient_zeros: List[LogCluster] = field(default_factory=list)
    crash_investigations: List[CrashInvestigation] = field(default_factory=list)
    log_format_breakdown: Dict[str, int] = field(default_factory=dict)
