"""Small in-house, online message-template clusterer (standard library only)."""

from __future__ import annotations

import re
from collections import defaultdict
from datetime import datetime
from typing import DefaultDict, List, Optional, Tuple

from .models import ErrorCluster, LogEvent

UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.I)
IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
HEX_RE = re.compile(r"\b0x[0-9a-f]+\b", re.I)
URL_RE = re.compile(r"https?://[^\s]+", re.I)
QUOTED_RE = re.compile(r"(['\"]).*?\1")
NUMBER_RE = re.compile(r"\d+")
TOKEN_RE = re.compile(r"<(?:uuid|ip|hex|url|text|num)>|[a-z_][a-z0-9_.:/-]*|[^\w\s]", re.I)
SIMILARITY_THRESHOLD = 0.80


def message_tokens(message: str) -> List[str]:
    value = message.lower()
    value = URL_RE.sub("<url>", value)
    value = UUID_RE.sub("<uuid>", value)
    value = IP_RE.sub("<ip>", value)
    value = HEX_RE.sub("<hex>", value)
    value = QUOTED_RE.sub("<text>", value)
    value = NUMBER_RE.sub("<num>", value)
    return TOKEN_RE.findall(value) or ["<empty>"]


class TemplateClusterer:
    def __init__(self, threshold: float = SIMILARITY_THRESHOLD, max_clusters: int = 4000) -> None:
        self.threshold = threshold
        self.max_clusters = max_clusters
        self._by_length: DefaultDict[int, List[ErrorCluster]] = defaultdict(list)
        self._next_id = 1
        self.untracked_patterns = 0

    def add(self, event: LogEvent) -> Optional[ErrorCluster]:
        tokens = message_tokens(event.message)
        candidates = self._by_length[len(tokens)]
        best: Optional[ErrorCluster] = None
        best_score = -1.0
        for cluster in candidates:
            if cluster.template and cluster.template[0] not in ("<*>", tokens[0]):
                continue
            score = sum(left == right for left, right in zip(cluster.template, tokens)) / float(len(tokens))
            if score > best_score:
                best, best_score = cluster, score

        if best is None or best_score < self.threshold:
            if self._next_id > self.max_clusters:
                self.untracked_patterns += 1
                return None
            best = ErrorCluster(self._next_id, tokens, severity=event.severity)
            self._next_id += 1
            candidates.append(best)
        else:
            best.template = [old if old == new else "<*>" for old, new in zip(best.template, tokens)]

        best.count += 1
        if best.count == 1 or self._is_earlier(event.timestamp, best.first_timestamp):
            best.first_timestamp = event.timestamp
            best.first_source = event.source
            best.first_line = event.line
        best.services[event.service] = best.services.get(event.service, 0) + 1
        if len(best.examples) < 3 and event.message not in best.examples:
            best.examples.append(event.message)
        if event.severity in {"FATAL", "CRITICAL"}:
            best.severity = event.severity
        return best

    @staticmethod
    def _is_earlier(candidate: Optional[datetime], current: Optional[datetime]) -> bool:
        if candidate is None:
            return False
        if current is None:
            return True
        try:
            return candidate < current
        except TypeError:
            return candidate.replace(tzinfo=None) < current.replace(tzinfo=None)

    def clusters(self) -> List[ErrorCluster]:
        return [item for group in self._by_length.values() for item in group]
