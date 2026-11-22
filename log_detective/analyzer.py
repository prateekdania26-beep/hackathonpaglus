"""Streaming analysis orchestration."""

from __future__ import annotations

import re
import time
from collections import deque
from pathlib import Path
from typing import Deque, List, Sequence

from .clustering import TemplateClusterer
from .models import AnalysisResult, CrashSequence, LogEvent
from .parser import iter_events

ERROR_WORDS = re.compile(r"\b(error|exception|failed|failure|timeout|panic|fatal|crash)\b", re.I)
CRASH_WORDS = re.compile(r"\b(fatal|panic|uncaught exception|segfault|crash|out of memory|outofmemoryerror|process exited)\b", re.I)


def is_error(event: LogEvent) -> bool:
    return event.severity in {"ERROR", "FATAL", "CRITICAL"} or bool(ERROR_WORDS.search(event.message))


def is_crash(event: LogEvent) -> bool:
    return event.severity in {"FATAL", "CRITICAL"} or bool(CRASH_WORDS.search(event.message))


def analyze(paths: Sequence[Path], context_size: int = 8, max_clusters: int = 4000) -> AnalysisResult:
    start = time.perf_counter()
    result = AnalysisResult([str(path) for path in paths])
    result.bytes_read = sum(path.stat().st_size for path in paths)
    clusterer = TemplateClusterer(max_clusters=max_clusters)
    recent: Deque[LogEvent] = deque(maxlen=max(1, context_size))

    for event in iter_events(paths):
        result.events_read += 1
        result.lines_read += event.physical_lines
        if event.severity in {"ERROR", "FATAL", "CRITICAL"}:
            result.errors_read += 1
        elif event.severity in {"WARN", "WARNING"}:
            result.warnings_read += 1

        if is_error(event):
            clusterer.add(event)
        if is_crash(event) and len(result.crashes) < 25:
            result.crashes.append(CrashSequence(event, list(recent)))
        recent.append(event)

    result.clusters = sorted(clusterer.clusters(), key=lambda item: (-item.count, item.cluster_id))
    result.untracked_patterns = clusterer.untracked_patterns
    result.elapsed_seconds = max(time.perf_counter() - start, 0.000001)
    return result
