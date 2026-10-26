"""REST API (FR-10) exposing system state over HTTP."""
from __future__ import annotations

import json
from datetime import datetime
from pathlib import Path
from typing import List, Optional

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from app.core.config import load_config, ensure_runtime_dirs
from app.database.db import AlertRecord, EventRecord, IncidentRecord, get_session, init_db
from app.reports.generator import generate_report

app = FastAPI(title="RDRS API", version="1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_cfg = load_config()
ensure_runtime_dirs(_cfg)
init_db(_cfg.database.path)

_START_TIME = datetime.utcnow()

_dashboard_dir = Path(__file__).resolve().parent.parent / "dashboard" / "static"
if _dashboard_dir.exists():
    app.mount("/dashboard", StaticFiles(directory=str(_dashboard_dir), html=True), name="dashboard")


class SettingsUpdate(BaseModel):
    simulation_mode: Optional[bool] = None


@app.get("/health")
def health():
    return {"status": "ok", "uptime_seconds": (datetime.utcnow() - _START_TIME).total_seconds()}


@app.get("/status")
def status():
    session = get_session()
    try:
        last_alert = session.query(AlertRecord).order_by(AlertRecord.id.desc()).first()
        incident_count = session.query(IncidentRecord).count()
        event_count = session.query(EventRecord).count()
        return {
            "simulation_mode": _cfg.response.simulation_mode,
            "watch_paths": _cfg.monitor.watch_paths,
            "current_level": last_alert.level if last_alert else "Normal",
            "current_score": last_alert.score if last_alert else 0,
            "total_events": event_count,
            "total_incidents": incident_count,
        }
    finally:
        session.close()


@app.get("/alerts")
def alerts(limit: int = 50):
    session = get_session()
    try:
        rows = session.query(AlertRecord).order_by(AlertRecord.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "level": r.level,
                "score": r.score,
                "message": r.message,
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
    finally:
        session.close()


@app.get("/events")
def events(limit: int = 100):
    session = get_session()
    try:
        rows = session.query(EventRecord).order_by(EventRecord.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "event_type": r.event_type,
                "path": r.path,
                "old_path": r.old_path,
                "extension": r.extension,
                "entropy": r.entropy,
                "timestamp": r.timestamp.isoformat(),
            }
            for r in rows
        ]
    finally:
        session.close()


@app.get("/incidents")
def incidents(limit: int = 50):
    session = get_session()
    try:
        rows = session.query(IncidentRecord).order_by(IncidentRecord.id.desc()).limit(limit).all()
        return [
            {
                "id": r.id,
                "score": r.score,
                "level": r.level,
                "affected_files": json.loads(r.affected_files_json),
                "suspect_process": r.suspect_process,
                "quarantined_files": json.loads(r.quarantined_files_json),
                "created_at": r.created_at.isoformat(),
            }
            for r in rows
        ]
    finally:
        session.close()


@app.get("/reports")
def reports(incident_id: int, fmt: str = "json"):
    if fmt not in ("json", "csv"):
        raise HTTPException(400, "fmt must be 'json' or 'csv'")
    path = generate_report(incident_id, fmt, _cfg.reports.dir)
    if path is None:
        raise HTTPException(404, "Incident not found")
    return {"report_path": path}


@app.post("/scan")
def trigger_scan():
    """Manual trigger placeholder — the live monitor runs via `python -m app.main`.

    Exposed so external tools can request an on-demand process snapshot.
    """
    from app.detectors.process_monitor import snapshot_processes

    snaps = snapshot_processes(top_n=10)
    return {"processes_scanned": len(snaps), "top_cpu": [s.model_dump() for s in snaps[:5]]}


@app.post("/settings")
def update_settings(update: SettingsUpdate):
    if update.simulation_mode is not None:
        _cfg.response.simulation_mode = update.simulation_mode
    return {"simulation_mode": _cfg.response.simulation_mode}
