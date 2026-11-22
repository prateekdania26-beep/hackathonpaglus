"""Streaming parser for JSON-lines and common timestamped text logs."""

from __future__ import annotations

import json
import re
import csv
import shlex
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional, Sequence

from .models import LogEvent

LEVELS = {"TRACE", "DEBUG", "INFO", "WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"}
ISO_PREFIX = re.compile(
    r"^(?P<time>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?)\s+(?P<rest>.*)$"
)
BRACKETED = re.compile(r"^\[(?P<service>[^\]]+)\]\s+(?P<rest>.*)$")
LEVEL_PREFIX = re.compile(r"^(?P<level>TRACE|DEBUG|INFO|WARN|WARNING|ERROR|FATAL|CRITICAL)\b\s*(?:[-:]\s*)?(?P<message>.*)$", re.I)
NGINX_ACCESS = re.compile(r'^\S+\s+\S+\s+\S+\s+\[(?P<time>[^\]]+)\]\s+"(?P<method>[A-Z]+)\s+(?P<path>\S+)(?:\s+[^\"]*)?"\s+(?P<status>\d{3})\b')
SYSLOG = re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+(?P<service>[\w./-]+)(?:\[\d+\])?:\s*(?P<rest>.*)$")
SYSLOG_TEXT = re.compile(r"^(?P<time>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<rest>.*)$")
DAY_MONTH_TEXT = re.compile(r"^(?P<time>\d{1,2}/[A-Z][a-z]{2}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})\s+(?P<rest>.*)$")
EXCEPTION_START = re.compile(r"^(?:[\w.$]+(?:Exception|Error|Failure|Panic|Fault)\b|Traceback \(most recent call last\):|panic:|fatal error:)", re.I)


def parse_timestamp(value: object) -> Optional[datetime]:
    if not isinstance(value, str) or not value.strip():
        return None
    candidate = value.strip()
    if candidate.endswith("Z"):
        candidate = candidate[:-1] + "+00:00"
    try:
        return datetime.fromisoformat(candidate)
    except ValueError:
        return None


def _from_json(line: str, source: str, number: int) -> Optional[LogEvent]:
    try:
        item = json.loads(line)
    except (json.JSONDecodeError, TypeError):
        return None
    if not isinstance(item, dict):
        return None
    message = item.get("message", item.get("msg", item.get("event", "")))
    if message is None or str(message) == "":
        return None
    severity = str(item.get("level", item.get("severity", "INFO"))).upper()
    stamp = item.get("timestamp", item.get("time", item.get("ts")))
    service = item.get("service", item.get("component", "unknown"))
    trace = item.get("trace_id", item.get("request_id", item.get("correlation_id", "")))
    event = LogEvent(source, number, parse_timestamp(stamp), severity, str(message), str(service), str(trace or ""))
    stack = item.get("stack", item.get("stack_trace", ""))
    if stack:
        event.stack.extend(str(stack).splitlines())
    return event


def _from_text(line: str, source: str, number: int) -> Optional[LogEvent]:
    match = ISO_PREFIX.match(line)
    if not match:
        return None
    timestamp = parse_timestamp(match.group("time"))
    rest = match.group("rest").strip()
    service = "unknown"
    level_match = LEVEL_PREFIX.match(rest)
    if level_match:
        severity = level_match.group("level").upper()
        message = level_match.group("message").strip()
    else:
        severity = "INFO"
        message = rest
    bracketed = BRACKETED.match(message)
    if bracketed:
        service = bracketed.group("service").strip()
        message = bracketed.group("rest").strip()
    return LogEvent(source, number, timestamp, severity, message, service)


def _from_nginx(line: str, source: str, number: int) -> Optional[LogEvent]:
    match = NGINX_ACCESS.match(line)
    if not match:
        return None
    try:
        stamp = datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        stamp = None
    status = int(match.group("status"))
    severity = "ERROR" if status >= 500 else "WARN" if status >= 400 else "INFO"
    message = f"HTTP {match.group('method')} {match.group('path')} returned {status}"
    return LogEvent(source, number, stamp, severity, message, "nginx")


def _from_syslog(line: str, source: str, number: int) -> Optional[LogEvent]:
    match = SYSLOG.match(line)
    if not match:
        return None
    try:
        stamp = datetime.strptime(match.group("time"), "%b %d %H:%M:%S").replace(year=datetime.now().year)
    except ValueError:
        stamp = None
    rest = match.group("rest").strip()
    level_match = LEVEL_PREFIX.match(rest)
    if level_match:
        severity, message = level_match.group("level").upper(), level_match.group("message").strip()
    else:
        severity, message = "INFO", rest
    return LogEvent(source, number, stamp, severity, message, match.group("service"))


def _from_date_text(line: str, source: str, number: int) -> Optional[LogEvent]:
    match = DAY_MONTH_TEXT.match(line)
    if match:
        try:
            stamp = datetime.strptime(match.group("time"), "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            stamp = None
        rest = match.group("rest").strip()
    else:
        match = SYSLOG_TEXT.match(line)
        if not match:
            return None
        try:
            stamp = datetime.strptime(match.group("time"), "%b %d %H:%M:%S").replace(year=datetime.now().year)
        except ValueError:
            stamp = None
        rest = match.group("rest").strip()
    service = "unknown"
    bracketed = BRACKETED.match(rest)
    if bracketed:
        service = bracketed.group("service").strip()
        rest = bracketed.group("rest").strip()
    level_match = LEVEL_PREFIX.match(rest)
    if level_match:
        severity, message = level_match.group("level").upper(), level_match.group("message").strip()
    else:
        severity, message = "INFO", rest
    return LogEvent(source, number, stamp, severity, message, service)


def _from_logfmt(line: str, source: str, number: int) -> Optional[LogEvent]:
    if not re.match(r"^[A-Za-z_][\w.-]*=", line):
        return None
    try:
        parts = shlex.split(line, posix=True)
    except ValueError:
        return None
    fields = {}
    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)
            fields[key.lower()] = value
    message = fields.get("msg", fields.get("message", fields.get("event", "")))
    if not message:
        return None
    timestamp = parse_timestamp(fields.get("ts", fields.get("time", fields.get("timestamp"))))
    severity = fields.get("level", fields.get("severity", "INFO")).upper()
    service = fields.get("svc", fields.get("service", "unknown"))
    event = LogEvent(source, number, timestamp, severity, message, service,
                     fields.get("trace_id", fields.get("request_id", "")))
    if fields.get("stack"):
        event.stack.extend(fields["stack"].splitlines())
    return event


def _parse_header(line: str, source: str, number: int) -> Optional[LogEvent]:
    return (_from_json(line, source, number) or _from_nginx(line, source, number)
            or _from_syslog(line, source, number) or _from_logfmt(line, source, number)
            or _from_date_text(line, source, number)
            or _from_text(line, source, number))


def _csv_payload_items(raw: str, source: str, start_line: int):
    """Split a CSV cell containing one or several mixed log records."""
    lines = raw.splitlines()
    index = 0
    decoder = json.JSONDecoder()
    while index < len(lines):
        line = lines[index]
        if line.lstrip().startswith("{"):
            tail = "\n".join(lines[index:])
            leading = len(tail) - len(tail.lstrip())
            try:
                value, end = decoder.raw_decode(tail, leading)
            except json.JSONDecodeError:
                value = None
                end = 0
            if isinstance(value, dict):
                consumed = max(1, tail[:end].count("\n") + 1)
                event = _from_json(json.dumps(value, ensure_ascii=False), source, start_line + index)
                if event is not None:
                    event.physical_lines = consumed
                    yield event, "", index
                    index += consumed
                    continue
        event = _parse_header(line, source, start_line + index)
        if event is None and EXCEPTION_START.match(line.strip()):
            event = LogEvent(source, start_line + index, None, "ERROR", line.strip())
        yield event, line, index
        index += 1


def _is_reference_error(event: LogEvent) -> bool:
    if event.severity in {"WARN", "WARNING", "ERROR", "FATAL", "CRITICAL"}:
        return True
    text = event.message + "\n" + "\n".join(event.stack)
    return bool(re.search(r"\b(error|exception|failed|failure|timeout|panic|fatal|crash|oom|deadlock|refused|segfault|out of memory)\b", text, re.I))


def iter_csv_events(path: Path) -> Iterator[LogEvent]:
    """Read row-oriented CSV datasets without loading the full dataset in memory."""
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        reader = csv.DictReader(stream)
        if not reader.fieldnames:
            return
        fields = {name.strip().lower() for name in reader.fieldnames if name}
        if not fields.intersection({"raw_log", "message", "log", "msg"}):
            raise ValueError(f"CSV needs one of these log columns: raw_log, message, log, msg ({path})")
        current: Optional[LogEvent] = None
        for row_number, row in enumerate(reader, start=1):
            if row is None:
                continue
            raw = str(row.get("raw_log") or row.get("message") or row.get("log") or row.get("msg") or "").strip("\r\n")
            if not raw:
                continue
            try:
                start_line = int(row.get("start_line") or row_number)
            except (TypeError, ValueError):
                start_line = row_number
            label = str(row.get("cluster") or "").strip()
            first_flag = str(row.get("first_of_cluster") or "").strip().lower() in {"1", "true", "yes"}
            completed = []
            row_events = []
            for event, text, _offset in _csv_payload_items(raw, str(path), start_line):
                if event is not None:
                    if current is not None:
                        completed.append(current)
                    current = event
                    row_events.append(event)
                elif text.strip():
                    if current is None:
                        current = LogEvent(str(path), start_line, None, "UNKNOWN", text)
                        row_events.append(current)
                    else:
                        current.stack.append(text)
                        current.physical_lines += 1
            if label:
                candidates = [event for event in row_events if _is_reference_error(event)]
                if not candidates and current is not None and _is_reference_error(current):
                    candidates = [current]
                if candidates:
                    candidates[0].ground_truth_cluster = label
                    candidates[0].ground_truth_first = first_flag
            for event in completed:
                yield event
        if current is not None:
            yield current


def iter_events(paths: Sequence[Path]) -> Iterator[LogEvent]:
    """Yield one complete event at a time; continuation lines stay with their event."""
    for path in paths:
        if path.suffix.lower() == ".csv":
            yield from iter_csv_events(path)
            continue
        current: Optional[LogEvent] = None
        with path.open("r", encoding="utf-8", errors="replace", newline="") as stream:
            for number, raw in enumerate(stream, start=1):
                text = raw.rstrip("\r\n")
                if not text:
                    continue
                event = _parse_header(text, str(path), number)
                if event is None and "\n" not in text and EXCEPTION_START.match(text.strip()):
                    event = LogEvent(str(path), number, None, "ERROR", text.strip())
                if event is not None:
                    if current is not None:
                        yield current
                    current = event
                elif current is not None:
                    current.stack.append(text)
                    current.physical_lines += 1
                else:
                    current = LogEvent(str(path), number, None, "UNKNOWN", text)
        if current is not None:
            yield current
