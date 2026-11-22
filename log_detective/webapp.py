"""Local upload UI and JSON API. Uses only Python's standard library."""
from __future__ import annotations

import json
import os
import tempfile
import threading
import traceback
import uuid
import webbrowser
import csv
from collections import Counter, OrderedDict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen
from urllib.parse import unquote

from .analyzer import analyze
from .models import AnalysisResult
from .report import result_dict

ROOT = Path(__file__).resolve().parent.parent
WEB_DIR = Path(__file__).resolve().parent / "web"
DEMO_LOG = ROOT / "demo_microservice_incident.log.txt"
DEMO_DATASET = ROOT / "sample_dataset.csv"
MAX_JSON_BYTES = 1_000_000
RECENT_RESULTS: OrderedDict[str, AnalysisResult] = OrderedDict()
RESULT_LOCK = threading.Lock()


def _remember(result: AnalysisResult) -> str:
    key = uuid.uuid4().hex
    with RESULT_LOCK:
        RECENT_RESULTS[key] = result
        while len(RECENT_RESULTS) > 4:
            RECENT_RESULTS.popitem(last=False)
    return key


def _dataset_reference(path: Path) -> dict:
    labels = Counter()
    first_markers = Counter()
    labeled_rows = 0
    with path.open("r", encoding="utf-8-sig", errors="replace", newline="") as stream:
        for row in csv.DictReader(stream):
            label = str(row.get("cluster") or "").strip()
            if not label:
                continue
            labeled_rows += 1
            labels[label] += 1
            if str(row.get("first_of_cluster") or "").strip().lower() in {"1", "true", "yes"}:
                first_markers[label] += 1
    return {
        "labeled_rows": labeled_rows,
        "reference_groups": len(labels),
        "first_occurrence_markers": sum(first_markers.values()),
        "groups": [{"label": label, "count": count, "first_markers": first_markers[label]}
                   for label, count in labels.most_common()],
    }


def _retitle_result(result: AnalysisResult, path: Path, display_name: str) -> None:
    """Replace temporary paths in the report with the user's display filename."""
    result.files = [display_name]
    old = str(path)
    for cluster in result.clusters:
        if cluster.first_source == old:
            cluster.first_source = display_name
    for sequence in result.crashes:
        events = [sequence.crash, *sequence.context]
        for event in events:
            if event.source == old:
                event.source = display_name


def _read_response_text(data: dict) -> str:
    direct = data.get("output_text")
    if isinstance(direct, str) and direct.strip():
        return direct.strip()
    pieces = []
    for item in data.get("output", []):
        if item.get("type") == "message":
            for content in item.get("content", []):
                if content.get("type") == "output_text" and isinstance(content.get("text"), str):
                    pieces.append(content["text"])
    return "\n".join(pieces).strip()


def _ai_explanation(result: AnalysisResult) -> str:
    api_key = os.environ.get("XAI_API_KEY", "").strip()
    if not api_key:
        raise RuntimeError("Grok is not configured. Set XAI_API_KEY in PowerShell, then restart this app.")

    compact = result_dict(result)
    compact = {
        "events": compact["events_read"],
        "error_events": compact["errors_read"],
        "warnings": compact["warnings_read"],
        "clusters": compact["clusters"][:12],
        "crashes": compact["crashes"][:5],
    }
    # Do not send arbitrary amounts of log content to the model.
    compact_text = json.dumps(compact, ensure_ascii=False)[:24_000]
    model = os.environ.get("XAI_MODEL", "grok-4.7")
    payload = {
        "model": model,
        "input": [
            {"role": "system", "content": (
                "You are a careful incident response assistant. Use only the supplied log findings. "
                "Separate observed facts from hypotheses. Explain the likely earliest failure, evidence, "
                "sequence, and practical next checks. Do not claim certainty or invent missing details."
            )},
            {"role": "user", "content": "Explain these locally computed log findings in plain language:\n" + compact_text},
        ],
        "max_output_tokens": 700,
        "store": False,
    }
    request = Request(
        "https://api.x.ai/v1/responses",
        data=json.dumps(payload).encode("utf-8"),
        headers={"Authorization": "Bearer " + api_key, "Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urlopen(request, timeout=45) as response:
            response_data = json.loads(response.read().decode("utf-8"))
    except HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace")
        raise RuntimeError(f"xAI API returned HTTP {exc.code}: {detail}") from exc
    except (URLError, TimeoutError) as exc:
        raise RuntimeError(f"Could not reach the xAI API: {exc}") from exc
    text = _read_response_text(response_data)
    if not text:
        raise RuntimeError("The API response did not contain text. Check the selected model and API account.")
    return text


class LogDetectiveHandler(BaseHTTPRequestHandler):
    server_version = "LogDetective/2.0"

    def log_message(self, fmt: str, *args) -> None:
        print("[log-detective] " + fmt % args)

    def _json(self, status: int, value: dict) -> None:
        encoded = json.dumps(value, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(encoded)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(encoded)

    def do_GET(self) -> None:
        if self.path in ("/", "/index.html"):
            try:
                body = (WEB_DIR / "index.html").read_bytes()
            except OSError:
                self.send_error(500, "Web page assets are missing")
                return
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
            return
        if self.path == "/api/status":
            self._json(200, {"api_configured": bool(os.environ.get("XAI_API_KEY", "").strip()),
                             "demo_available": DEMO_LOG.is_file(),
                             "dataset_available": DEMO_DATASET.is_file()})
            return
        self.send_error(404, "Not found")

    def do_POST(self) -> None:
        if self.path == "/api/analyze":
            self._analyze_upload()
        elif self.path == "/api/demo":
            self._analyze_demo()
        elif self.path == "/api/dataset":
            self._analyze_dataset()
        elif self.path == "/api/explain":
            self._explain()
        else:
            self.send_error(404, "Not found")

    def _analyze_upload(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self._json(400, {"error": "Invalid Content-Length header."})
            return
        if length <= 0:
            self._json(400, {"error": "Choose a non-empty log file first."})
            return
        filename = Path(unquote(self.headers.get("X-File-Name", "uploaded.log"))).name[:180] or "uploaded.log"
        temp_path = None
        try:
            with tempfile.NamedTemporaryFile(prefix="logdetective-", suffix=".log", delete=False) as temp:
                temp_path = Path(temp.name)
                remaining = length
                while remaining:
                    chunk = self.rfile.read(min(1024 * 1024, remaining))
                    if not chunk:
                        raise ValueError("Upload ended before all file bytes arrived.")
                    temp.write(chunk)
                    remaining -= len(chunk)
            result = analyze([temp_path])
            _retitle_result(result, temp_path, filename)
            key = _remember(result)
            payload = result_dict(result)
            payload["analysis_id"] = key
            payload["display_name"] = filename
            self._json(200, payload)
        except (OSError, ValueError, UnicodeError) as exc:
            self._json(400, {"error": str(exc)})
        finally:
            if temp_path is not None:
                try:
                    temp_path.unlink(missing_ok=True)
                except OSError:
                    pass

    def _analyze_demo(self) -> None:
        if not DEMO_LOG.is_file():
            self._json(404, {"error": "Bundled demo log is missing."})
            return
        try:
            result = analyze([DEMO_LOG])
            _retitle_result(result, DEMO_LOG, DEMO_LOG.name)
            key = _remember(result)
            payload = result_dict(result)
            payload["analysis_id"] = key
            payload["display_name"] = DEMO_LOG.name
            self._json(200, payload)
        except OSError as exc:
            self._json(500, {"error": str(exc)})

    def _analyze_dataset(self) -> None:
        if not DEMO_DATASET.is_file():
            self._json(404, {"error": "sample_dataset.csv is missing from the project folder."})
            return
        try:
            result = analyze([DEMO_DATASET])
            _retitle_result(result, DEMO_DATASET, DEMO_DATASET.name)
            key = _remember(result)
            payload = result_dict(result)
            payload["analysis_id"] = key
            payload["display_name"] = DEMO_DATASET.name
            payload["dataset_reference"] = _dataset_reference(DEMO_DATASET)
            self._json(200, payload)
        except (OSError, ValueError) as exc:
            self._json(400, {"error": str(exc)})
        except Exception as exc:
            traceback.print_exc()
            self._json(500, {"error": f"Dataset analysis failed: {type(exc).__name__}: {exc}"})

    def _explain(self) -> None:
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if not 0 < length <= MAX_JSON_BYTES:
                self._json(400, {"error": "Invalid explanation request."})
                return
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            analysis_id = str(body.get("analysis_id", ""))
            with RESULT_LOCK:
                result = RECENT_RESULTS.get(analysis_id)
            if result is None:
                self._json(404, {"error": "That analysis expired. Analyze the log again."})
                return
            explanation = _ai_explanation(result)
            self._json(200, {"explanation": explanation, "model": os.environ.get("XAI_MODEL", "grok-4.7")})
        except (ValueError, UnicodeError, RuntimeError) as exc:
            self._json(502, {"error": str(exc)})

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Allow", "GET, POST, OPTIONS")
        self.end_headers()


def serve(port: int = 8765) -> None:
    server = ThreadingHTTPServer(("127.0.0.1", port), LogDetectiveHandler)
    url = f"http://127.0.0.1:{port}/"
    print(f"Log Detective is running at {url}")
    print("Local algorithms are ready. Grok explanation: " + ("enabled" if os.environ.get("XAI_API_KEY") else "not configured"))
    print("Keep this window open; press Ctrl+C to stop.")
    try:
        webbrowser.open(url)
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopping Log Detective...")
    finally:
        server.server_close()
