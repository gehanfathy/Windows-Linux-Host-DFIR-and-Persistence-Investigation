# Windows & Linux Host DFIR and Persistence Investigation

Internal DFIR Web Application for analyzing Windows and Linux evidence,
detecting suspicious activity and persistence mechanisms,
extracting IOCs, reconstructing timelines, and generating reports.

## Project Status

Working end-to-end Windows pipeline: collector -> parser -> detection ->
API -> dashboard. Linux collector/parser are the next deliverables.

## Technologies

- Python
- Streamlit
- FastAPI
- SQLite
- Tailscale

## Platforms

- Windows
- Linux

## Repository Structure

```
collectors/            # Read-only evidence collection (per platform)
  windows/collector.ps1
parsers/               # Raw evidence -> NormalizedEvent (Data Contract)
  windows/parser.py
detection/             # NormalizedEvent -> Findings + IOCs
  windows/rules.py
sample_data/           # SANITIZED sample evidence (safe for GitHub)
  windows/
app/                   # FastAPI + SQLite + Streamlit dashboard
  api/main.py          #   /health, /events, /findings, /iocs
  database/db.py       #   tables: cases, events, findings, iocs
  dashboard/app.py
  models/schemas.py    #   pydantic models = docs/DATA_CONTRACT.md
tests/                 # pytest suite (parser, rules, samples, e2e)
docs/DATA_CONTRACT.md  # The mandatory common format for all members
output/                # REAL collected evidence - local only (gitignored)
```

**Golden rule:** real evidence stays in `output/` (never committed).
Only sanitized samples under `sample_data/` go to GitHub.

## Quick Start — Windows evidence pipeline

### 1. Install

```bash
pip install -r requirements.txt
```

### 2. Offline demo (no API needed)

```bash
python run_windows_demo.py
```

Runs parser + detection on `sample_data/windows` and writes
`output/windows/events.jsonl`, `findings.json`, `iocs.json`.

### 3. Full tool (API + Dashboard)

```bash
uvicorn app.api.main:app --reload          # terminal 1  (GET /health)
python run_windows_demo.py --push          # terminal 2  (loads data into DB)
streamlit run app/dashboard/app.py         # terminal 3  (open in browser)
```

### 4. Collect real evidence on a Windows host (read-only)

```powershell
# PowerShell "Run as Administrator"
Set-ExecutionPolicy -Scope Process Bypass
.\collectors\windows\collector.ps1 -OutputDir .\output\windows
# then parse it with the same pipeline:
python run_windows_demo.py --input output/windows --push
```

### 5. Tests

```bash
pytest tests/ -q
```

## Data flow

```
Windows/Linux Raw Data
      |
  Collector (read-only)
      |
  Parser -> NormalizedEvent   (docs/DATA_CONTRACT.md)
      |
  Detection Rules -> Finding + IOC (status: unverified)
      |
  SQLite (cases, events, findings, iocs)
      |
  FastAPI (/events, /findings, /iocs) -> Streamlit Dashboard
```

Detection results are **potential findings** that require analyst
review — never a final compromise verdict.
