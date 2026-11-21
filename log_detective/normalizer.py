"""High-performance token normalization and variable abstraction for error clustering."""

from __future__ import annotations
import re
from typing import Tuple, List

# Pre-compiled high-efficiency regexes for log normalization
RE_HEX = re.compile(r'\b0x[0-9a-fA-F]+\b')
RE_UUID = re.compile(r'\b[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\b')
RE_IPV4_PORT = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?\b')
RE_URL = re.compile(r'https?://[^\s\'"<>]+')
RE_PATH_WIN = re.compile(r'[a-zA-Z]:\\[a-zA-Z0-9_\.\-\\]+(?::\d+)?')
RE_PATH_UNIX = re.compile(r'(?:/[a-zA-Z0-9_\.\-]+){2,}(?::\d+)?')
RE_HTTP_REQ = re.compile(r'"([A-Z]+)\s+([^\s"]+)\s+(HTTP/[0-9\.]+)"', re.IGNORECASE)
RE_TIMESTAMP_ISO = re.compile(r'\b\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?\b')
RE_HASH = re.compile(r'\b[0-9a-fA-F]{24,64}\b')
RE_NUMBERS = re.compile(r'\b\d+(?:\.\d+)?(?:ms|s|m|h|ns|us|kb|mb|gb|tb|b|B|KB|MB|GB)?\b')
RE_QUOTED_STR = re.compile(r'\'[^\']*\'|"[^"]*"')
RE_WHITESPACE = re.compile(r'\s+')


def normalize_message(msg: str) -> Tuple[str, List[str]]:
    """
    Abstract out dynamic runtime variables (IDs, IPs, numbers, paths, hex, hashes)
    into standard placeholders. Returns (normalized_template, tokens_list).
    """
    if not msg:
        return "", []

    # Sequential masking pipeline
    text = RE_TIMESTAMP_ISO.sub('<TIME>', msg)
    text = RE_UUID.sub('<UUID>', text)
    text = RE_HEX.sub('<HEX>', text)
    text = RE_HASH.sub('<HASH>', text)
    text = RE_URL.sub('<URL>', text)
    text = RE_PATH_WIN.sub('<PATH>', text)
    text = RE_PATH_UNIX.sub('<PATH>', text)
    text = RE_IPV4_PORT.sub('<IP>', text)
    # Preserve HTTP verbs and protocol inside quotes before generic string masking
    text = RE_HTTP_REQ.sub(r'"\1 <PATH> \3"', text)
    text = RE_QUOTED_STR.sub('<STR>', text)
    text = RE_NUMBERS.sub('<NUM>', text)
    
    # Normalize excessive punctuation or whitespace
    text = RE_WHITESPACE.sub(' ', text).strip()
    
    # Tokenize by space and common delimiters while keeping tokens clean
    tokens = text.split()
    return text, tokens


def extract_primary_exception(clean_msg: str, stack_trace: str | None = None) -> str:
    """
    Extract the core exception class or root error phrase (e.g., 'ConnectionResetError: [Errno 104]').
    """
    if stack_trace:
        # Find the last Exception line in a Python/Java stack trace
        lines = [line.strip() for line in stack_trace.splitlines() if line.strip()]
        for line in reversed(lines):
            if any(term in line for term in ("Exception:", "Error:", "panic:", "Fatal", "Caused by:")):
                return line
    return clean_msg[:120]
