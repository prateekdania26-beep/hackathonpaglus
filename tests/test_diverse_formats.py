"""Test parsing of diverse real-world logs without explicit error tags."""

from log_detective.parser import parse_plaintext_log_line, parse_json_log_line
from log_detective.models import LogSeverity


def test_nginx_500_error():
    line = '192.168.1.1 - - [01/Mar/2026:14:00:00 +0000] "POST /api/checkout HTTP/1.1" 500 1420'
    ev = parse_plaintext_log_line(line, 1, 0)
    assert ev.is_error
    assert ev.level in (LogSeverity.ERROR, LogSeverity.FATAL)


def test_kernel_oom_killer():
    line = "Nov 22 04:30:15 myhost kernel: Out of memory: Kill process 1234 (python)"
    ev = parse_plaintext_log_line(line, 1, 0)
    assert ev.is_error
    assert ev.is_crash


def test_nodejs_unhandled_typeerror():
    line = "TypeError: Cannot read properties of undefined (reading 'token')"
    ev = parse_plaintext_log_line(line, 1, 0)
    assert ev.is_error


def test_go_panic():
    line = "panic: runtime error: index out of range [4] with length 2"
    ev = parse_plaintext_log_line(line, 1, 0)
    assert ev.is_error
    assert ev.is_crash


def test_json_status_code_502():
    line = '{"service": "gateway", "status": 502, "msg": "Bad gateway connection reset"}'
    ev = parse_json_log_line(line, 1, 0)
    assert ev is not None
    assert ev.is_error
