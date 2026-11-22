"""Command line interface for Log Detective (Python standard library only)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .analyzer import analyze
from .formatter import render_summary
from .report import write_report


def _paths(values):
    paths = [Path(value).expanduser() for value in values]
    bad = [str(p) for p in paths if not p.is_file()]
    if bad:
        raise ValueError("Input file not found: " + ", ".join(bad))
    return paths


def main() -> None:
    parser = argparse.ArgumentParser(prog="log-detective", description="Stream mixed logs, group error patterns, and show crash context.")
    sub = parser.add_subparsers(dest="command")
    for name in ("investigate", "clusters", "patient-zero", "crash", "demo"):
        cmd = sub.add_parser(name, help=f"Run {name.replace('-', ' ')} analysis")
        if name == "demo":
            cmd.add_argument("files", nargs="*", help="Log files (defaults to the bundled incident sample)")
        else:
            cmd.add_argument("files", nargs="+", help="One or more log files")
        cmd.add_argument("--limit", type=int, default=12)
        cmd.add_argument("--html", help="Write a standalone HTML report")
        cmd.add_argument("--markdown", help="Write a Markdown report")
        cmd.add_argument("--json", dest="json_path", help="Write a JSON report")
    ui = sub.add_parser("ui", help="Create and open a local HTML dashboard")
    ui.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    if not args.command:
        parser.print_help()
        return
    if args.command == "ui":
        from .webapp import serve
        try:
            serve(args.port)
        except OSError as exc:
            print(f"Could not start the web server: {exc}", file=sys.stderr)
            raise SystemExit(2)
        return
    try:
        if args.command == "demo" and not args.files:
            default = Path(__file__).resolve().parent.parent / "demo_microservice_incident.log.txt"
            paths = _paths([str(default)])
        else:
            paths = _paths(args.files)
        result = analyze(paths)
        print(render_summary(result, max(1, args.limit)))
        for key, kind in ((args.html, "html"), (args.markdown, "markdown"), (args.json_path, "json")):
            if key:
                target = Path(key)
                write_report(result, target, kind)
                print(f"Wrote {kind} report: {target.resolve()}")
    except (OSError, ValueError) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
