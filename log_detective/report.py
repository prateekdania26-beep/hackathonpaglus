"""Dependency-free HTML, Markdown and JSON report output."""
from __future__ import annotations

import html
import json
from dataclasses import asdict
from pathlib import Path

from .models import AnalysisResult


def result_dict(result: AnalysisResult) -> dict:
    def event_dict(event):
        return {"source": event.source, "line": event.line, "timestamp": event.timestamp.isoformat() if event.timestamp else None,
                "severity": event.severity, "message": event.message, "service": event.service,
                "trace_id": event.trace_id, "stack": event.stack}
    return {
        "files": result.files, "bytes_read": result.bytes_read, "lines_read": result.lines_read,
        "events_read": result.events_read, "errors_read": result.errors_read, "warnings_read": result.warnings_read,
        "elapsed_seconds": round(result.elapsed_seconds, 4),
        "dataset_metrics": result.dataset_metrics,
        "clusters": [{"id": c.cluster_id, "pattern": c.pattern, "count": c.count,
                      "first_timestamp": c.first_timestamp.isoformat() if c.first_timestamp else None,
                      "first_source": c.first_source, "first_line": c.first_line,
                      "services": c.services, "examples": c.examples} for c in result.clusters],
        "crashes": [{"crash": event_dict(s.crash), "context": [event_dict(e) for e in s.context]} for s in result.crashes],
    }


def write_report(result: AnalysisResult, path: Path, kind: str) -> None:
    data = result_dict(result)
    if kind == "json":
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    elif kind == "markdown":
        lines = ["# Log Detective Report", "", f"- Events: {result.events_read:,}", f"- Input size: {result.bytes_read / (1024*1024):.2f} MiB",
                 f"- Error severity events: {result.errors_read:,}", f"- Scan time: {result.elapsed_seconds:.2f}s", "", "## Error patterns", ""]
        for c in result.clusters:
            lines += [f"### Pattern #{c.cluster_id} ({c.count} occurrences)", "", f"`{c.pattern}`", "", f"First seen: `{c.first_source}:{c.first_line}`", ""]
        lines += ["## Crash-like events", ""]
        for seq in result.crashes:
            lines.append(f"- `{seq.crash.source}:{seq.crash.line}` **{seq.crash.severity}** {seq.crash.message}")
            for ev in seq.context[-4:]:
                lines.append(f"  - Before: `{ev.source}:{ev.line}` {ev.message}")
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    else:
        clusters = "".join(f"<article><h3>Pattern #{c.cluster_id} · {c.count} hits</h3><code>{html.escape(c.pattern)}</code><p>First seen: {html.escape(c.first_source)}:{c.first_line}</p><ul>" + "".join(f"<li>{html.escape(e)}</li>" for e in c.examples) + "</ul></article>" for c in result.clusters)
        crashes = "".join(f"<article class='crash'><h3>{html.escape(s.crash.severity)} · {html.escape(s.crash.source)}:{s.crash.line}</h3><p>{html.escape(s.crash.message)}</p><ol>" + "".join(f"<li>{html.escape(e.display())}</li>" for e in s.context) + "</ol></article>" for s in result.crashes)
        page = f"""<!doctype html><html><meta charset='utf-8'><meta name='viewport' content='width=device-width'><title>Log Detective report</title><style>body{{margin:0;background:#0b1020;color:#e8edf7;font:15px system-ui;max-width:1050px;padding:32px;margin:auto}}h1{{color:#7dd3fc}}.stats{{display:flex;gap:12px;flex-wrap:wrap}}.stats div,article{{background:#151d31;border:1px solid #293651;border-radius:12px;padding:16px;margin:12px 0}}.stats b{{font-size:24px;display:block;color:#a5f3fc}}code{{color:#fde68a;white-space:pre-wrap}}li{{margin:8px 0;color:#cbd5e1}}.muted{{color:#9aa8c1}}.crash{{border-color:#ef4444}}</style><body><h1>🕵️ Log Detective</h1><p class='muted'>Streaming investigation report · {result.elapsed_seconds:.2f}s</p><section class='stats'><div><b>{result.events_read:,}</b>events</div><div><b>{result.errors_read:,}</b>error severity</div><div><b>{len(result.clusters)}</b>patterns</div><div><b>{len(result.crashes)}</b>crash-like events</div><div><b>{result.bytes_read/1048576:.1f} MiB</b>scanned</div></section><h2>Error patterns</h2>{clusters or '<p>No error-like messages found.</p>'}<h2>Crash timeline and preceding context</h2>{crashes or '<p>No crash-like messages found.</p>'}</body></html>"""
        path.write_text(page, encoding="utf-8")
