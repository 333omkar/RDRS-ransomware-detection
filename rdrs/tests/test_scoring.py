from datetime import datetime

from app.core.config import DetectionConfig
from app.core.models import ProcessSnapshot
from app.detectors.detection_engine import WindowStats
from app.detectors.scoring import score_window


def make_stats(**overrides) -> WindowStats:
    base = dict(
        window_start=datetime(2026, 1, 1, 0, 0, 0),
        window_end=datetime(2026, 1, 1, 0, 1, 0),
        files_modified_per_minute=0,
        renames_per_minute=0,
        extension_changes_per_minute=0,
        avg_new_file_entropy=0.0,
        high_entropy_ratio=0.0,
        affected_files=[],
    )
    base.update(overrides)
    return WindowStats(**base)


def test_normal_activity_scores_low():
    cfg = DetectionConfig()
    stats = make_stats(files_modified_per_minute=2, renames_per_minute=0)
    score = score_window(stats, cfg)
    assert score.level.value == "Normal"
    assert score.score <= cfg.bands.normal_max


def test_ransomware_like_burst_scores_critical():
    cfg = DetectionConfig()
    stats = make_stats(
        files_modified_per_minute=50,
        renames_per_minute=40,
        extension_changes_per_minute=40,
        high_entropy_ratio=0.9,
        affected_files=["a.txt", "b.txt"],
    )
    processes = [
        ProcessSnapshot(
            pid=1234,
            name="suspicious.exe",
            cpu_percent=95.0,
            memory_mb=50,
            timestamp=datetime(2026, 1, 1),
        )
    ]
    score = score_window(stats, cfg, processes=processes, known_processes=["python"])
    assert score.level.value == "Critical"
    assert score.score > cfg.bands.warning_max
    assert score.signals.rapid_encryption
    assert score.signals.mass_rename
    assert score.signals.high_entropy
    assert score.signals.cpu_spike
    assert score.signals.unknown_program


def test_known_process_does_not_add_unknown_signal():
    cfg = DetectionConfig()
    stats = make_stats()
    processes = [
        ProcessSnapshot(
            pid=1, name="python3", cpu_percent=10.0, memory_mb=10,
            timestamp=datetime(2026, 1, 1),
        )
    ]
    score = score_window(stats, cfg, processes=processes, known_processes=["python"])
    assert not score.signals.unknown_program


def test_score_never_exceeds_100():
    cfg = DetectionConfig()
    stats = make_stats(
        files_modified_per_minute=999,
        renames_per_minute=999,
        extension_changes_per_minute=999,
        high_entropy_ratio=1.0,
    )
    processes = [
        ProcessSnapshot(
            pid=1, name="evil.exe", cpu_percent=100.0, memory_mb=10,
            timestamp=datetime(2026, 1, 1),
        )
    ]
    score = score_window(stats, cfg, processes=processes, known_processes=[])
    assert score.score <= 100
