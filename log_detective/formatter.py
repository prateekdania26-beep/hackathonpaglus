"""Human-readable terminal output."""
from __future__ import annotations

from .models import AnalysisResult


def render_summary(result: AnalysisResult, limit: int = 12) -> str:
    lines = ["LOG DETECTIVE — INVESTIGATION", "=" * 34]
    lines.append(f"Files: {len(result.files)} | Events: {result.events_read:,} | Lines: {result.lines_read:,}")
    lines.append(f"Size: {result.bytes_read / (1024 * 1024):.2f} MiB | Errors: {result.errors_read:,} | Warnings: {result.warnings_read:,}")
    lines.append(f"Patterns: {len(result.clusters)} | Crash-like events: {len(result.crashes)} | Time: {result.elapsed_seconds:.2f}s")
    lines += ["", "TOP ERROR PATTERNS"]
    if not result.clusters:
        lines.append("  No error-like messages found.")
    for cluster in result.clusters[:limit]:
        first = f"{cluster.first_source}:{cluster.first_line}" if cluster.first_source else "location unknown"
        lines.append(f"  #{cluster.cluster_id:<4} {cluster.count:>6} hits | first at {first}")
        lines.append(f"       {cluster.pattern}")
    lines += ["", "CRASH CONTEXT"]
    if not result.crashes:
        lines.append("  No fatal/crash-like event detected.")
    for sequence in result.crashes[:3]:
        lines.append(f"  Crash: {sequence.crash.display()}")
        for event in sequence.context[-4:]:
            lines.append(f"    before: {event.display()}")
    return "\n".join(lines)
