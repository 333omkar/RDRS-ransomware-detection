# RDRS — Ransomware Detection and Response System

A defensive cybersecurity application that monitors file-system and process
activity in real time, scores ransomware-like behavior with a transparent
weighted rule engine, and responds with alerts, evidence quarantine, and
incident reports.

**Classification: Defensive security tool. Educational project.**
No malware, no ML training data — detection is 100% rule-based and every
point in a threat score can be explained.

## What it does

- Watches configured folders for file create/modify/delete/rename events (`watchdog`)
- Computes Shannon entropy of file contents — encrypted files look like random noise
- Snapshots running processes (CPU, memory, disk I/O) with `psutil`
- Aggregates recent activity in a sliding time window and scores it 0–100 using
  configurable weighted rules (rapid encryption, mass rename, high entropy,
  CPU spike, unknown program)
- On a **Critical** score: creates an incident, copies affected files to a
  quarantine folder (originals are never touched), and logs what a response
  action *would* do — process termination is only ever simulated, never executed
- Persists everything to SQLite, exposes it over a FastAPI REST API, and
  renders it on a live dark-themed operations dashboard
- Generates JSON, CSV, HTML, and PDF incident reports

## Project layout

```
app/
  core/        config loader, logging, entropy, shared models
  detectors/   file monitor, process monitor, sliding window, scoring, response
  database/    SQLAlchemy models + session (SQLite)
  api/         FastAPI REST endpoints
  dashboard/   static HTML/JS operations console
  reports/     JSON/CSV/HTML/PDF report generator
  main.py      entry point — wires the whole pipeline together
tests/         unit + integration tests (pytest)
scripts/       safe sandbox self-test (simulate_attack.py)
config.yaml    every threshold and weight, in one place
```

## Setup

```bash
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Run the monitor

```bash
python -m app.main --watch ./data/sandbox
```

## Run the API + dashboard

```bash
uvicorn app.api.main:app --reload
# API docs:   http://127.0.0.1:8000/docs
# Dashboard:  http://127.0.0.1:8000/dashboard/
```

Run both at once (in separate terminals) to see the dashboard update live.

## Safely test the detector

**Never use real ransomware.** Use the included sandbox self-test instead —
it creates 50 throwaway files, overwrites them with random bytes, and renames
them with a `.locked` extension, all inside `data/sandbox/`. It never touches
anything outside that folder.

```bash
# terminal 1
python -m app.main --watch ./data/sandbox

# terminal 2
python scripts/simulate_attack.py
```

You should see the threat score climb to Critical, an incident get created,
and quarantined copies appear in `data/quarantine/`.

## REST API

| Method | Path        | Description                          |
|--------|-------------|---------------------------------------|
| GET    | `/health`   | Liveness check                        |
| GET    | `/status`   | Current threat level, counts          |
| GET    | `/alerts`   | Recent alerts                         |
| GET    | `/events`   | Recent file events                    |
| GET    | `/incidents`| Recent incidents                      |
| GET    | `/reports`  | Generate a report (`?incident_id=&fmt=json\|csv\|html\|pdf`) |
| POST   | `/scan`     | On-demand process snapshot            |
| POST   | `/settings` | Update simulation mode                |

## Tests

```bash
pytest --cov=app --cov-report=term-missing
```

Covers the entropy function, the scoring engine (normal activity vs. a
ransomware-like burst, signal breakdown, score capping), and a full
integration test that feeds a burst of events through the real pipeline and
checks a Critical incident comes out the other end.

## Docker

```bash
docker compose up
```

Starts the API (port 8000) and the file monitor together, sharing the same
`data/` and `logs/` volumes.

## Configuration

Everything tunable lives in `config.yaml`: which folders to watch, window
size, signal thresholds, rule weights, score bands, simulation mode, known
processes, and file paths for the database/logs/reports/quarantine.

## Rules & responsible use

- Detection only — this project never writes, downloads, or runs real malware.
- Test only with the sandbox self-test above, never on real personal files or
  another person's computer.
- Simulation mode is on by default. Process termination is never actually
  executed by this codebase, regardless of configuration.
- Keep secrets out of the repo — none are needed for this project as shipped.
