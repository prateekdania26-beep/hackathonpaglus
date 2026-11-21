"""Streaming multi-format log reader and parser with multi-line stack trace stitching."""

from __future__ import annotations
import io
import os
import re
from datetime import datetime
from typing import Iterator, Optional, Tuple, Dict, Any, List
import orjson
from .models import LogEvent, LogSeverity

# High-efficiency regexes for level detection
RE_LEVEL_EXTRACT = re.compile(
    r'\b(DEBUG|INFO|NOTICE|WARN(?:ING)?|ERR(?:OR)?|FATAL|CRIT(?:ICAL)?|PANIC|EMERG(?:ENCY)?|ALERT|SEVERE)\b',
    re.IGNORECASE
)

# Heuristic error indicators for logs without explicit level tags
RE_ERROR_HEURISTICS = re.compile(
    r'\b(?:[a-zA-Z0-9_\.]*(?:Exception|Error|Panic|Fault|Failure)|failed|failure|fatal|panic|segfault|sigkill|sigsegv|denied|timeout|timed out|refused|crash|deadlock|unhandled|broken pipe|connection reset)\b|"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^"]+"\s+5\d{2}\b|status[=:\s]+5\d{2}|"status":\s*5\d{2}|\b5\d{2}\s+\d+\b',
    re.IGNORECASE
)
RE_WARN_HEURISTICS = re.compile(
    r'\b(warn|warning|degraded|slow query|retry|retrying|backpressure|deprecated)\b|"(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+[^"]+"\s+4\d{2}\b|status[=:\s]+4\d{2}',
    re.IGNORECASE
)

# Timestamp regex patterns
RE_ISO_TIMESTAMP = re.compile(
    r'(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)'
)
RE_APACHE_TIMESTAMP = re.compile(
    r'\[(\d{2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}(?:\s+[+-]\d{4})?)\]'
)
RE_SYSLOG_TIMESTAMP = re.compile(
    r'([A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})'
)
RE_BRACKET_TIMESTAMP = re.compile(
    r'\[(\d{4}[-/]\d{2}[-/]\d{2}[ T]\d{2}:\d{2}:\d{2}(?:\.\d+)?)\]'
)
RE_TIME_ONLY = re.compile(
    r'\b(\d{2}:\d{2}:\d{2}(?:\.\d+)?)\b'
)

# Stack trace indicators
STACK_START_KEYWORDS = (
    "traceback (most recent call last):",
    "panic:",
    "fatal error:",
    "exception in thread",
    "caused by:",
    "goroutine ",
    "unhandled exception:",
    "runtime.gopanic",
    "stack backtrace:"
)

STACK_CONTINUATION_PATTERNS = (
    re.compile(r'^\s+at\s+[\w\.\$/<>]+\('),           # Java/C#/Node "   at com.example..."
    re.compile(r'^\s+File\s+"[^"]+",\s+line\s+\d+'),    # Python '  File "...", line 12'
    re.compile(r'^\s+[a-zA-Z0-9_\.\-/]+\.go:\d+'),      # Go '   /path/main.go:42'
    re.compile(r'^\s+\.\.\.\s+\d+\s+more'),             # Java '... 15 more'
    re.compile(r'^(?:Caused by:|[a-zA-Z0-9_\.]+(?:Exception|Error):)'), # Java caused by / chained
    re.compile(r'^\s*[\}\]\)]\s*$'),                    # JSON trailing block
)


def parse_timestamp_to_epoch(ts_str: str) -> Optional[float]:
    """Parse common timestamp string formats to UTC epoch seconds."""
    if not ts_str:
        return None
    
    clean_ts = ts_str.replace("T", " ").rstrip("Z")
    if "." in clean_ts:
        parts = clean_ts.split(".")
        sub = parts[1]
        sub = re.split(r'[\+\- ]', sub)[0]
        sub = (sub + "000000")[:6]
        clean_ts = f"{parts[0]}.{sub}"
        fmt = "%Y-%m-%d %H:%M:%S.%f"
    else:
        fmt = "%Y-%m-%d %H:%M:%S"

    try:
        dt = datetime.strptime(clean_ts[:26], fmt)
        return dt.timestamp()
    except Exception:
        pass

    # Try Apache format: 01/Mar/2026:14:00:00
    try:
        ts_part = ts_str.split()[0]
        dt = datetime.strptime(ts_part, "%d/%b/%Y:%H:%M:%S")
        return dt.timestamp()
    except Exception:
        pass

    return None


def is_stack_trace_line(line: str, in_stack: bool = False) -> bool:
    """Detect if a raw line is part of a multi-line stack trace or unhandled error trace."""
    stripped = line.strip()
    if not stripped:
        return in_stack
    
    lower = stripped.lower()
    for kw in STACK_START_KEYWORDS:
        if lower.startswith(kw):
            return True

    if in_stack:
        if line.startswith((" ", "\t")):
            return True
        if any(lower.startswith(kw) for kw in ("caused by:", "reason:", "error:", "exception:")):
            return True
        if re.match(r'^[a-zA-Z0-9_\.]+(?:Exception|Error|Fault|Failure|Warning|Panic):', stripped):
            return True

    # Indented lines (2+ spaces or tab) are classic stack trace body
    if line.startswith(("    ", "\t", "  ")):
        for pat in STACK_CONTINUATION_PATTERNS:
            if pat.search(line):
                return True
        if any(term in stripped for term in (", in ", "at ", "line ")):
            return True

    for pat in STACK_CONTINUATION_PATTERNS:
        if pat.search(stripped):
            return True

    return False


def parse_json_log_line(line_str: str, line_no: int, offset: int) -> Optional[LogEvent]:
    """Attempt fast JSON parse using orjson."""
    if not (line_str.startswith("{") and line_str.endswith("}")):
        return None

    try:
        data = orjson.loads(line_str)
        if not isinstance(data, dict):
            return None
    except Exception:
        return None

    # Extract timestamp
    ts_raw = None
    for k in ("time", "timestamp", "@timestamp", "ts", "datetime", "date"):
        if k in data and data[k]:
            ts_raw = str(data[k])
            break

    # Extract level
    lvl_val = "INFO"
    for k in ("level", "severity", "log_level", "lvl"):
        if k in data and data[k]:
            lvl_val = str(data[k])
            break

    # Extract message
    msg = ""
    for k in ("msg", "message", "error", "err", "log", "text", "description"):
        if k in data and data[k]:
            msg = str(data[k])
            break
    if not msg:
        msg = line_str

    # Extract component / service
    comp = None
    for k in ("service", "app", "logger", "caller", "component", "thread", "name"):
        if k in data and data[k]:
            comp = str(data[k])
            break

    # Extract trace / request ID
    trace_id = None
    for k in ("trace_id", "traceId", "request_id", "requestId", "req_id", "correlation_id", "span_id"):
        if k in data and data[k]:
            trace_id = str(data[k])
            break

    # Extract stack trace if explicitly in JSON
    stack_trace = None
    for k in ("stack", "stack_trace", "stacktrace", "traceback", "exception"):
        if k in data and data[k]:
            stack_val = data[k]
            stack_trace = stack_val if isinstance(stack_val, str) else str(stack_val)
            break

    epoch = parse_timestamp_to_epoch(ts_raw) if ts_raw else None
    level = LogSeverity.from_str(lvl_val)

    # Status code heuristics in JSON
    for k in ("status", "statusCode", "status_code", "http_status"):
        if k in data and data[k]:
            try:
                code = int(data[k])
                if code >= 500 and not level.is_error_or_higher:
                    level = LogSeverity.ERROR
                elif code >= 400 and level == LogSeverity.UNKNOWN:
                    level = LogSeverity.WARN
            except Exception:
                pass

    if "error" in data and data["error"] and not level.is_error_or_higher:
        level = LogSeverity.ERROR

    # Check text heuristics
    if level == LogSeverity.INFO or level == LogSeverity.UNKNOWN:
        if RE_ERROR_HEURISTICS.search(msg):
            level = LogSeverity.ERROR
        elif RE_WARN_HEURISTICS.search(msg):
            level = LogSeverity.WARN

    return LogEvent(
        line_number=line_no,
        byte_offset=offset,
        timestamp_raw=ts_raw,
        timestamp_epoch=epoch,
        level=level,
        component=comp,
        trace_id=trace_id,
        raw_message=line_str,
        clean_message=msg,
        stack_trace=stack_trace,
        metadata={"format": "json"}
    )


def parse_plaintext_log_line(line_str: str, line_no: int, offset: int) -> LogEvent:
    """Parse unstructured plain-text, syslog, Apache, or bracketed log format."""
    ts_raw = None
    epoch = None
    level = LogSeverity.UNKNOWN
    clean_msg = line_str
    comp = None

    # 1. Search for timestamps
    m_ts = (
        RE_ISO_TIMESTAMP.search(line_str)
        or RE_BRACKET_TIMESTAMP.search(line_str)
        or RE_APACHE_TIMESTAMP.search(line_str)
        or RE_SYSLOG_TIMESTAMP.search(line_str)
        or RE_TIME_ONLY.search(line_str)
    )
    if m_ts:
        ts_raw = m_ts.group(1)
        epoch = parse_timestamp_to_epoch(ts_raw)

    # 2. Search for explicit log level
    m_lvl = RE_LEVEL_EXTRACT.search(line_str)
    if m_lvl:
        level = LogSeverity.from_str(m_lvl.group(1))

    # 3. Clean message
    clean_msg = line_str
    if ts_raw and ts_raw in clean_msg:
        idx = clean_msg.find(ts_raw) + len(ts_raw)
        clean_msg = clean_msg[idx:].lstrip(" :]>-")

    if m_lvl:
        lvl_token = m_lvl.group(1)
        clean_msg = clean_msg.replace(f"[{lvl_token}]", "").replace(f"<{lvl_token}>", "")
        if clean_msg.startswith(lvl_token):
            clean_msg = clean_msg[len(lvl_token):].lstrip(" :]>-")

    # 4. Extract component e.g. [worker-1] or [billing-service]
    m_bracket = re.search(r'\[([a-zA-Z0-9_\.\-]+)\]', clean_msg)
    if m_bracket:
        comp = m_bracket.group(1)
        clean_msg = clean_msg.replace(m_bracket.group(0), "").strip()

    # 5. Heuristic error inference if level wasn't explicitly stated
    if level == LogSeverity.UNKNOWN or level == LogSeverity.INFO:
        if RE_ERROR_HEURISTICS.search(line_str):
            level = LogSeverity.ERROR
        elif RE_WARN_HEURISTICS.search(line_str):
            level = LogSeverity.WARN

    # Check for panic / fatal keywords
    if any(k in line_str.lower() for k in ("panic:", "fatal error", "out of memory", "sigkill", "sigsegv")):
        level = LogSeverity.FATAL

    return LogEvent(
        line_number=line_no,
        byte_offset=offset,
        timestamp_raw=ts_raw,
        timestamp_epoch=epoch,
        level=level,
        component=comp,
        raw_message=line_str,
        clean_message=clean_msg.strip(),
        metadata={"format": "plain"}
    )


class StreamLogParser:
    """
    Constant-memory streaming log iterator.
    Processes arbitrarily large files (gigabytes to terabytes)
    in O(1) memory by streaming lines through an assembler buffer.
    """

    def __init__(self, file_path: str, buffer_size: int = 4 * 1024 * 1024):
        self.file_path = file_path
        self.buffer_size = buffer_size
        self.total_bytes = os.path.getsize(file_path) if os.path.exists(file_path) else 0

    def iterate_events(self) -> Iterator[LogEvent]:
        """Stream parsed events from the log file, stitching multi-line stack traces."""
        if not os.path.exists(self.file_path):
            raise FileNotFoundError(f"Log file not found: {self.file_path}")

        current_event: Optional[LogEvent] = None
        stack_accumulator: List[str] = []

        with io.open(self.file_path, "r", encoding="utf-8", errors="replace", buffering=self.buffer_size) as f:
            line_no = 0
            byte_offset = 0

            for raw_line in f:
                line_no += 1
                line_bytes = len(raw_line.encode("utf-8", errors="replace"))
                line = raw_line.rstrip("\r\n")

                if not line:
                    byte_offset += line_bytes
                    continue

                # Check if this line is part of a multi-line stack trace
                if is_stack_trace_line(line, in_stack=bool(stack_accumulator)) and current_event is not None:
                    stack_accumulator.append(line)
                    byte_offset += line_bytes
                    if len(stack_accumulator) > 120:
                        current_event.stack_trace = "\n".join(stack_accumulator)
                        yield current_event
                        current_event = None
                        stack_accumulator = []
                    continue

                # Flush pending event if any
                if current_event is not None:
                    if stack_accumulator:
                        current_event.stack_trace = "\n".join(stack_accumulator)
                        if current_event.level == LogSeverity.UNKNOWN:
                            current_event.level = LogSeverity.ERROR
                        stack_accumulator = []
                    yield current_event
                    current_event = None

                # Parse the new line
                stripped = line.strip()
                event = parse_json_log_line(stripped, line_no, byte_offset)
                if event is None:
                    event = parse_plaintext_log_line(line, line_no, byte_offset)

                if is_stack_trace_line(line):
                    event.level = LogSeverity.ERROR
                    stack_accumulator.append(line)

                current_event = event
                byte_offset += line_bytes

            # Flush final pending event at EOF
            if current_event is not None:
                if stack_accumulator:
                    current_event.stack_trace = "\n".join(stack_accumulator)
                    if current_event.level == LogSeverity.UNKNOWN:
                        current_event.level = LogSeverity.ERROR
                yield current_event
