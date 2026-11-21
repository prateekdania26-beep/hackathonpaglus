# 🕵️ Terminal-Native Log Detective

> **12-Hour Hackathon Project: Problem Statement #3**  
> High-Speed Streaming Log Forensics, Error Clustering & Crash Sequence Reconstruction.

---

## 👥 Team Module Breakdown (4 Collaborators)

This repository serves as the shared hackathon workspace divided into 4 core engineering modules:

| Module | Owner | Component | Description | Status |
| :--- | :--- | :--- | :--- | :--- |
| **Module 1 (Core)** | **Prateek (Lead)** | `parser.py`, `normalizer.py`, `models.py` | Multi-format streaming parser (JSON, syslog, Apache/Nginx, multi-line stack traces) with bounded $O(1)$ memory | ✅ Implemented |
| **Module 2 (Clustering)** | **Teammate 2** | `clustering.py` | Drain prefix tree online clustering engine & dynamic `<*>` template miner | 🔄 In Progress |
| **Module 3 (Causal RCA)** | **Teammate 3** | `causal.py`, `analyzer.py` | Pre-crash circular sliding window, Patient Zero detection & Root Cause Analysis | 🔄 In Progress |
| **Module 4 (UI & Reports)** | **Teammate 4** | `formatter.py`, `web.py`, `cli.py`, `index.html` | Built-in local Web UI dashboard, Rich terminal UI & forensic reports | 🔄 In Progress |

---

## 🚀 Module 1 (Current Base): Multi-Format Streaming Engine

### Features Implemented:
- **Streaming Parser (`parser.py`):** Reads multi-gigabyte log files in $O(1)$ constant memory via buffered chunk iterations.
- **Multi-Format Ingestion:** Auto-detects structured JSON lines (via fast `orjson`), RFC syslog, bracketed ISO timestamps, Apache/Nginx access logs, and raw text.
- **Stack Trace Stitching:** Stateful lookahead assembler that glues multi-line Python tracebacks, Java exceptions, and Go panics onto their parent error event.
- **Variable Abstraction (`normalizer.py`):** Pre-compiled regex maskers for UUIDs, IPs, ports, hex addresses, hashes, numbers, URLs, and file paths.

### Running Module 1 Tests:
```bash
python -m pytest -c pytest.ini tests/
```

### Installation:
```bash
pip install -r requirements.txt
```

---

## 🛠️ Contribution Guide for Teammates

Each teammate has their dedicated package in `teammate_distribution/` containing their assigned files and automated push scripts:
1. **Teammate 2:** Pull `main`, add `log_detective/clustering.py` and `tests/test_clustering.py`, run `push_part_2.bat`.
2. **Teammate 3:** Pull `main`, add `log_detective/causal.py`, `log_detective/analyzer.py`, and `tests/test_causal.py`, run `push_part_3.bat`.
3. **Teammate 4:** Pull `main`, add CLI, web server, and dashboard files, run `push_part_4.bat`.
