"""Tests for Drain-inspired error clustering and token normalizer."""

from log_detective.normalizer import normalize_message
from log_detective.clustering import ErrorClusterer
from log_detective.models import LogEvent, LogSeverity


def test_normalizer_replaces_variables():
    msg = "Failed to connect to 192.168.1.50:5432 after 3000ms for user 7f8a9b1c-2d3e-4f5a-6b7c-8d9e0f1a2b3c"
    norm, tokens = normalize_message(msg)
    assert "<IP>" in tokens
    assert "<NUM>" in tokens
    assert "<UUID>" in tokens
    assert "192.168.1.50:5432" not in norm


def test_clustering_groups_similar_errors():
    clusterer = ErrorClusterer(depth=4, sim_threshold=0.65)

    ev1 = LogEvent(
        line_number=10,
        byte_offset=0,
        timestamp_raw="2026-11-21T10:00:00Z",
        level=LogSeverity.ERROR,
        clean_message="Failed to connect to 10.0.1.10:8080 timeout after 5000ms",
        raw_message="Failed to connect to 10.0.1.10:8080 timeout after 5000ms",
    )
    ev2 = LogEvent(
        line_number=15,
        byte_offset=100,
        timestamp_raw="2026-11-21T10:00:05Z",
        level=LogSeverity.ERROR,
        clean_message="Failed to connect to 10.0.2.25:8080 timeout after 3000ms",
        raw_message="Failed to connect to 10.0.2.25:8080 timeout after 3000ms",
    )
    ev3 = LogEvent(
        line_number=20,
        byte_offset=200,
        timestamp_raw="2026-11-21T10:00:10Z",
        level=LogSeverity.ERROR,
        clean_message="Database disk full on partition /var/data: 0 bytes free",
        raw_message="Database disk full on partition /var/data: 0 bytes free",
    )

    c1, is_new1 = clusterer.cluster_event(ev1)
    assert is_new1 is True
    assert c1.count == 1
    assert c1.first_seen_line == 10

    c2, is_new2 = clusterer.cluster_event(ev2)
    # Should cluster together with ev1!
    assert is_new2 is False
    assert c2.cluster_id == c1.cluster_id
    assert c2.count == 2
    assert c2.first_seen_line == 10
    assert c2.last_seen_line == 15

    # ev3 is a different pattern
    c3, is_new3 = clusterer.cluster_event(ev3)
    assert is_new3 is True
    assert c3.cluster_id != c1.cluster_id
    assert len(clusterer.clusters) == 2
