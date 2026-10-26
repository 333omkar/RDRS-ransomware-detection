"""Incident report generation (FR-12): JSON and CSV required, HTML/PDF as extras."""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Optional

from app.database.db import IncidentRecord, get_session


def _incident_to_dict(record: IncidentRecord) -> dict:
    return {
        "incident_id": record.id,
        "created_at": record.created_at.isoformat(),
        "score": record.score,
        "level": record.level,
        "affected_files": json.loads(record.affected_files_json),
        "suspect_process": record.suspect_process,
        "quarantined_files": json.loads(record.quarantined_files_json),
        "notes": record.notes,
        "recommendations": _recommendations(record.level),
    }


def _recommendations(level: str) -> list[str]:
    if level == "Critical":
        return [
            "Isolate the affected host from the network immediately.",
            "Verify quarantined evidence and preserve it for analysis.",
            "Confirm the suspect process before taking any remediation action.",
            "Restore affected files from the most recent known-good backup.",
        ]
    if level == "Warning":
        return [
            "Monitor the source process closely for continued suspicious activity.",
            "Review recently modified files for unexpected changes.",
        ]
    return ["No action required; continue routine monitoring."]


def generate_report(incident_id: int, fmt: str, out_dir: str) -> Optional[str]:
    """Write a report file for an incident and return its path, or None if not found."""
    session = get_session()
    try:
        record = session.get(IncidentRecord, incident_id)
        if record is None:
            return None
        data = _incident_to_dict(record)
    finally:
        session.close()

    out_path = Path(out_dir)
    out_path.mkdir(parents=True, exist_ok=True)

    if fmt == "json":
        file_path = out_path / f"incident_{incident_id}.json"
        file_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return str(file_path)

    if fmt == "csv":
        file_path = out_path / f"incident_{incident_id}.csv"
        with file_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["field", "value"])
            for key, value in data.items():
                if isinstance(value, list):
                    value = "; ".join(str(v) for v in value)
                writer.writerow([key, value])
        return str(file_path)

    if fmt == "html":
        file_path = out_path / f"incident_{incident_id}.html"
        rows = "".join(f"<tr><th>{k}</th><td>{v}</td></tr>" for k, v in data.items())
        file_path.write_text(
            f"<html><body><h1>Incident #{incident_id}</h1><table border='1'>{rows}</table></body></html>",
            encoding="utf-8",
        )
        return str(file_path)

    if fmt == "pdf":
        return _generate_pdf(data, out_path, incident_id)

    raise ValueError(f"Unsupported report format: {fmt}")


def _generate_pdf(data: dict, out_path: Path, incident_id: int) -> str:
    from reportlab.lib.pagesizes import letter
    from reportlab.pdfgen import canvas

    file_path = out_path / f"incident_{incident_id}.pdf"
    c = canvas.Canvas(str(file_path), pagesize=letter)
    width, height = letter
    y = height - 50
    c.setFont("Helvetica-Bold", 16)
    c.drawString(50, y, f"RDRS Incident Report #{incident_id}")
    y -= 30
    c.setFont("Helvetica", 10)
    for key, value in data.items():
        text = f"{key}: {value}"
        for line in _wrap(text, 100):
            if y < 50:
                c.showPage()
                y = height - 50
                c.setFont("Helvetica", 10)
            c.drawString(50, y, line)
            y -= 14
    c.save()
    return str(file_path)


def _wrap(text: str, width: int) -> list[str]:
    words = text.split(" ")
    lines, current = [], ""
    for word in words:
        if len(current) + len(word) + 1 > width:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}".strip()
    if current:
        lines.append(current)
    return lines
