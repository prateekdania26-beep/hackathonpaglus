"""Drain-inspired high-speed online log clustering tree."""

from __future__ import annotations
from typing import List, Dict, Optional, Tuple, Any
from .models import LogEvent, LogCluster, LogSeverity
from .normalizer import normalize_message, extract_primary_exception


class DrainNode:
    """Internal node of the Drain parse tree."""
    __slots__ = ('children', 'clusters')

    def __init__(self):
        self.children: Dict[str, DrainNode] = {}
        self.clusters: List[LogCluster] = []


class ErrorClusterer:
    """
    High-performance Drain online clustering tree.
    Processes error messages in bounded O(1) time per event with zero external dependencies.
    """

    def __init__(self, depth: int = 4, sim_threshold: float = 0.65, max_children: int = 100):
        self.depth = depth  # max tree depth
        self.sim_threshold = sim_threshold
        self.max_children = max_children
        self.root = DrainNode()
        self.clusters: Dict[int, LogCluster] = {}
        self.next_cluster_id = 1

    def cluster_event(self, event: LogEvent, context_history: Optional[List[str]] = None) -> Tuple[LogCluster, bool]:
        """
        Cluster an error event.
        Returns (cluster, is_new_cluster).
        """
        # Determine the core text to cluster on
        target_text = event.clean_message
        if event.stack_trace:
            exc_line = extract_primary_exception(event.clean_message, event.stack_trace)
            target_text = f"{target_text} | {exc_line}"

        normalized_text, tokens = normalize_message(target_text)
        if not tokens:
            tokens = ["<EMPTY>"]

        match_cluster = self._find_or_create_cluster(
            tokens=tokens,
            event=event,
            context_history=context_history or []
        )

        is_new = (match_cluster.count == 1)
        return match_cluster, is_new

    def _calculate_similarity(self, tokens1: List[str], tokens2: List[str]) -> Tuple[float, int]:
        """Calculate token positional similarity ratio and match count."""
        if len(tokens1) != len(tokens2):
            return 0.0, 0
        matches = 0
        for t1, t2 in zip(tokens1, tokens2):
            if t1 == "<*>" or t2 == "<*>" or t1 == t2:
                matches += 1
        return matches / len(tokens1), matches

    def _find_or_create_cluster(
        self,
        tokens: List[str],
        event: LogEvent,
        context_history: List[str]
    ) -> LogCluster:
        token_count = len(tokens)
        key_len = str(token_count)

        # Level 1: Group by token count
        if key_len not in self.root.children:
            self.root.children[key_len] = DrainNode()
        curr_node = self.root.children[key_len]

        # Descend tree based on leading tokens up to depth
        curr_depth = 1
        for token in tokens:
            if curr_depth >= self.depth:
                break
            
            # If token is dynamic variable, use wildcard branch
            token_key = "<*>" if (token.startswith("<") and token.endswith(">")) else token
            
            if token_key not in curr_node.children:
                if len(curr_node.children) >= self.max_children:
                    token_key = "<*>"
                    if token_key not in curr_node.children:
                        curr_node.children[token_key] = DrainNode()
                else:
                    curr_node.children[token_key] = DrainNode()
            curr_node = curr_node.children[token_key]
            curr_depth += 1

        # Search existing candidate clusters at this leaf
        best_cluster: Optional[LogCluster] = None
        max_sim = -1.0

        for candidate in curr_node.clusters:
            sim, _ = self._calculate_similarity(candidate.tokens, tokens)
            if sim > max_sim:
                max_sim = sim
                best_cluster = candidate

        # If similarity exceeds threshold, match found!
        if best_cluster and max_sim >= self.sim_threshold:
            # Update template with wildcard <*> where tokens differ
            new_tokens = []
            for t_old, t_new in zip(best_cluster.tokens, tokens):
                if t_old == t_new:
                    new_tokens.append(t_old)
                else:
                    new_tokens.append("<*>")
            best_cluster.tokens = new_tokens
            best_cluster.template = " ".join(new_tokens)
            best_cluster.count += 1
            best_cluster.last_seen_line = event.line_number
            best_cluster.last_seen_timestamp = event.timestamp_raw
            if event.timestamp_epoch:
                setattr(best_cluster, 'last_seen_epoch', event.timestamp_epoch)
            if event.component:
                best_cluster.affected_components.add(event.component)
            if len(best_cluster.sample_messages) < 5 and event.raw_message not in best_cluster.sample_messages:
                best_cluster.sample_messages.append(event.raw_message)
            return best_cluster

        # Otherwise, create a new cluster (Patient Zero for this pattern!)
        cluster_id = self.next_cluster_id
        self.next_cluster_id += 1

        new_cluster = LogCluster(
            cluster_id=cluster_id,
            template=" ".join(tokens),
            tokens=list(tokens),
            count=1,
            first_seen_line=event.line_number,
            first_seen_timestamp=event.timestamp_raw,
            first_seen_epoch=event.timestamp_epoch,
            first_seen_raw=event.raw_message,
            first_seen_stack_trace=event.stack_trace,
            last_seen_line=event.line_number,
            last_seen_timestamp=event.timestamp_raw,
            sample_messages=[event.raw_message],
            affected_components={event.component} if event.component else set(),
            severity=event.level,
            is_crash_pattern=event.is_crash,
            context_before_first_seen=list(context_history[-4:]) if context_history else []
        )
        if event.timestamp_epoch:
            setattr(new_cluster, 'last_seen_epoch', event.timestamp_epoch)

        curr_node.clusters.append(new_cluster)
        self.clusters[cluster_id] = new_cluster
        return new_cluster

    def get_all_clusters(self) -> List[LogCluster]:
        """Return all clusters sorted by frequency descending."""
        return sorted(self.clusters.values(), key=lambda c: c.count, reverse=True)

    def get_patient_zeros(self) -> List[LogCluster]:
        """Return all failure clusters sorted chronologically by first appearance."""
        return sorted(
            self.clusters.values(),
            key=lambda c: (c.first_seen_epoch or float('inf'), c.first_seen_line)
        )
