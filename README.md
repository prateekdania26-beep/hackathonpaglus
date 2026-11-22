# Terminal-Native Log Detective

A local web app and CLI for investigating mixed JSON-lines and timestamped text logs. The Python backend streams log files instead of loading them all into memory, groups similar error messages, finds the first location for each pattern, and shows nearby events before crash-like messages.

## Run the web app on Windows

Double-click `run_log_detective.bat` in this folder. It starts the backend and opens the dashboard. Keep its window open while using the app; close it with Ctrl+C when finished.

Or open PowerShell in this project folder and launch the backend:

```powershell
& "C:\Users\Hp\AppData\Local\Python\bin\python.exe" -m log_detective.cli ui --port 8766
```

The app opens at `http://127.0.0.1:8766/`. The server listens only on your own computer. Do not open `log_detective\web\index.html` directly from File Explorer: the page needs the Python backend for analysis and API calls.

If your Python command works from PowerShell, you can instead run:

```powershell
python -m log_detective.cli ui --port 8766
```

## What works in the page

- Select or drag in one log file. The browser streams the file body to the local Python backend; the backend writes it to a temporary file in chunks and analyzes it line by line.
- JSON-line messages and ISO-timestamped text logs are parsed; continuation lines are attached to the previous event.
- Numbers, IP addresses, URLs, UUIDs and quoted values are normalized before a lightweight online token-template algorithm groups similar errors.
- The dashboard shows event/error/warning counts, pattern counts, first locations, examples, and rolling context before fatal or crash-like events.
- Export findings to JSON or Markdown in your browser.
- Click **Try incident demo** to analyze the bundled fixture without uploading a file.
- Click **Analyze supplied CSV** to stream `sample_dataset.csv` through the same parser and clustering engine; the page displays the CSV's reference labels separately from algorithm-detected patterns.
- The API-key-backed explanation is optional; deterministic local analysis works without a key.

CSV uploads need a `raw_log`, `message`, `log`, or `msg` column. The included CSV holds multiple log records inside some cells; the parser splits those records and handles JSON, Nginx access lines, syslog, timestamped text, logfmt, and stack traces. Its `cluster` and `first_of_cluster` fields are shown as reference data only; they do not determine the discovered groups.

This is a local deployment. A public internet website requires a hosting provider and a server deployment target; the current app deliberately binds to localhost and does not expose uploaded logs publicly.

## Configure optional Grok explanation

Create an xAI API key in the [xAI Console](https://console.x.ai/) and keep it only in the backend process environment. It is never placed in the HTML or sent to the browser. To enter it without echoing it into the PowerShell command history:

```powershell
$secure = Read-Host "xAI API key" -AsSecureString
$ptr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
try { $env:XAI_API_KEY = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($ptr) }
finally { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($ptr) }
& "C:\Users\Hp\AppData\Local\Python\bin\python.exe" -m log_detective.cli ui --port 8766
```

The AI button sends only the computed summary, up to 12 error clusters and up to 5 crash sequences to xAI's Responses API. It does not send the full source file. This API call may incur charges under your xAI account. Without `XAI_API_KEY`, the upload, parser, clustering, crash context and exports still work locally. The default model is `grok-4.7`; override it with `XAI_MODEL` if needed.

## CLI

```powershell
.\logdet.ps1 demo
.\logdet.ps1 investigate .\my-app.log --html .\report.html
.\logdet.ps1 investigate .\my-app.log --markdown .\postmortem.md --json .\report.json
```

If PowerShell script execution is disabled, use the Python command directly or enable script execution only for the current PowerShell process:

```powershell
Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass
.\logdet.ps1 demo
```

## Algorithms and limits

- **Streaming:** input is read incrementally. Memory usage depends on the number of distinct error templates, capped at 4,000 by default, plus a short context window.
- **Normalization:** regular expressions replace common variable fields before tokenizing messages.
- **Clustering:** messages with equal token counts are compared position by position. A match above the similarity threshold is merged into a template; changed positions become wildcards. It is a small heuristic, not Drain3 or a machine-learning model.
- **First occurrence:** when timestamps are comparable, the earliest timestamp is used; otherwise the first encountered event is used.
- **Crash sequence:** the backend retains the eight preceding parsed events for each fatal/crash-like event. This is temporal context, not proof of causality.
- Text log headers need an ISO-style date and time at the start of a line. Other non-empty lines attach as continuation text, or are treated as unknown events if there is no current event.

## Requirements

Python 3.9+; no third-party runtime packages required. The optional Grok connection uses Python's standard-library HTTPS client and the [xAI Responses API](https://docs.x.ai/developers/rest-api-reference/inference/responses).
