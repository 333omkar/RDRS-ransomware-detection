import os
from datetime import datetime, timedelta

import pytest

from app.core.config import DetectionConfig, ResponseConfig
from app.core.models import EventType, FileEvent
from app.database.db import IncidentRecord, get_session, init_db
from app.detectors.detection_engine import SlidingWindow
from app.detectors.response import handle_score
from app.detectors.scoring import score_window


@pytest.fixture()
def temp_db(tmp_path):
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    return db_path


def test_burst_of_events_produces_critical_incident(temp_db, tmp_path):
    window = SlidingWindow(window_seconds=60, high_entropy_threshold=7.5)
    cfg = DetectionConfig()
    response_cfg = ResponseConfig(
        simulation_mode=True,
        quarantine_dir=str(tmp_path / "quarantine"),
        known_processes=["python"],
    )

    # Create real files so quarantine copy has something to act on.
    sandbox = tmp_path / "sandbox"
    sandbox.mkdir()
    files = []
    for i in range(30):
        f = sandbox / f"file_{i}.locked"
        f.write_bytes(os.urandom(2000))  # high entropy, like encrypted content
        files.append(f)

    # Real ransomware-like activity is a write (modify) followed by a
    # rename, mirroring the sandbox self-test script in scripts/simulate_attack.py.
    base_time = datetime(2026, 1, 1, 12, 0, 0)
    stats = None
    for i, f in enumerate(files):
        modify_event = FileEvent(
            event_type=EventType.MODIFIED,
            path=str(f),
            extension=".txt",
            entropy=7.9,
            timestamp=base_time + timedelta(seconds=i, milliseconds=0),
        )
        stats = window.add_event(modify_event)

        rename_event = FileEvent(
            event_type=EventType.RENAMED,
            path=str(f).replace(".txt", ".locked"),
            old_path=str(f),
            old_extension=".txt",
            extension=".locked",
            entropy=7.9,
            timestamp=base_time + timedelta(seconds=i, milliseconds=500),
        )
        stats = window.add_event(rename_event)

    score = score_window(stats, cfg, processes=[], known_processes=response_cfg.known_processes)
    incident_id = handle_score(score, response_cfg.quarantine_dir, response_cfg.simulation_mode)

    assert score.level.value == "Critical"
    assert incident_id is not None

    session = get_session()
    try:
        incident = session.get(IncidentRecord, incident_id)
        assert incident is not None
        assert incident.level == "Critical"
    finally:
        session.close()

    quarantined = list((tmp_path / "quarantine").glob("*"))
    assert len(quarantined) > 0


def test_normal_activity_creates_no_incident(temp_db, tmp_path):
    window = SlidingWindow(window_seconds=60, high_entropy_threshold=7.5)
    cfg = DetectionConfig()

    event = FileEvent(
        event_type=EventType.MODIFIED,
        path=str(tmp_path / "notes.txt"),
        extension=".txt",
        entropy=3.2,
        timestamp=datetime(2026, 1, 1, 12, 0, 0),
    )
    stats = window.add_event(event)
    score = score_window(stats, cfg, processes=[], known_processes=["python"])
    incident_id = handle_score(score, str(tmp_path / "quarantine"), True)

    assert score.level.value == "Normal"
    assert incident_id is None
