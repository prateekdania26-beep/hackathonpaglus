"""Tests for multi-format log parser and stack trace assembler."""

import os
import tempfile
import pytest
from log_detective.parser import (
    parse_json_log_line,
    parse_plaintext_log_line,
    parse_timestamp_to_epoch,
    is_stack_trace_line,
    StreamLogParser,
)
from log_detective.models import LogSeverity


def test_parse_json_log_line():
    json_str = '{"timestamp": "2026-11-21T10:00:00.123Z", "level": "ERROR", "service": "payment-svc", "trace_id": "tx-12345", "msg": "Database query timeout after 3000ms"}'
    event = parse_json_log_line(json_str, line_no=1, offset=0)
    assert event is not None
    assert event.line_number == 1
    assert event.level == LogSeverity.ERROR
    assert event.component == "payment-svc"
    assert event.trace_id == "tx-12345"
    assert event.clean_message == "Database query timeout after 3000ms"
    assert event.timestamp_epoch is not None


def test_parse_plaintext_log_line():
    line = "2026-11-21T10:15:30.000Z [auth-service] WARN - Token expired for user_98214"
    event = parse_plaintext_log_line(line, line_no=42, offset=100)
    assert event.line_number == 42
    assert event.level == LogSeverity.WARN
    assert event.component == "auth-service"
    assert "Token expired" in event.clean_message


def test_stack_trace_detection():
    assert is_stack_trace_line("Traceback (most recent call last):")
    assert is_stack_trace_line("  File 'app/server.py', line 54, in handle")
    assert is_stack_trace_line("    at com.example.MyClass.doWork(MyClass.java:99)")
    assert is_stack_trace_line("panic: runtime error: index out of range")
    assert not is_stack_trace_line("2026-11-21 10:00:00 INFO Normal application started")


def test_stream_parser_multiline_stitching():
    content = (
        '{"timestamp": "2026-11-21T10:00:01Z", "level": "INFO", "msg": "Job started"}\n'
        '2026-11-21T10:00:02Z [worker] ERROR - Unhandled job failure\n'
        'Traceback (most recent call last):\n'
        '  File "worker.py", line 10, in run\n'
        '    raise ValueError("Invalid configuration")\n'
        'ValueError: Invalid configuration\n'
        '{"timestamp": "2026-11-21T10:00:03Z", "level": "INFO", "msg": "Job ended"}\n'
    )
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".log", encoding="utf-8") as f:
        f.write(content)
        temp_path = f.name

    try:
        parser = StreamLogParser(temp_path)
        events = list(parser.iterate_events())
        assert len(events) == 3
        # First event
        assert events[0].level == LogSeverity.INFO
        assert events[0].clean_message == "Job started"
        # Second event with stitched traceback
        assert events[1].level == LogSeverity.ERROR
        assert events[1].stack_trace is not None
        assert "ValueError: Invalid configuration" in events[1].stack_trace
        assert "worker.py" in events[1].stack_trace
        # Third event
        assert events[2].level == LogSeverity.INFO
        assert events[2].clean_message == "Job ended"
    finally:
        os.remove(temp_path)
