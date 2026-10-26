"""Weighted threat scoring (FR-7): a transparent rule engine, no ML.

Each signal that fires contributes its configured weight; the total is
capped at 100 and mapped to a Normal / Warning / Critical band.
"""
from __future__ import annotations

from typing import List, Optional

from app.core.config import DetectionConfig
from app.core.models import ProcessSnapshot, SignalBreakdown, ThreatLevel, ThreatScore
from app.detectors.detection_engine import WindowStats


def score_window(
    stats: WindowStats,
    detection_cfg: DetectionConfig,
    processes: Optional[List[ProcessSnapshot]] = None,
    known_processes: Optional[List[str]] = None,
) -> ThreatScore:
    """Combine window stats + process info into a single 0-100 threat score."""
    thresholds = detection_cfg.thresholds
    weights = detection_cfg.weights
    known_processes = known_processes or []
    processes = processes or []

    signals = SignalBreakdown()
    total = 0
    suspect_process = None

    if stats.files_modified_per_minute >= thresholds.files_modified_per_minute:
        signals.rapid_encryption = True
        total += weights.rapid_encryption

    if stats.renames_per_minute >= thresholds.renames_per_minute or (
        stats.extension_changes_per_minute >= thresholds.extension_changes_per_minute
    ):
        signals.mass_rename = True
        total += weights.mass_rename

    if stats.high_entropy_ratio >= thresholds.high_entropy_file_ratio:
        signals.high_entropy = True
        total += weights.high_entropy

    top_process = max(processes, key=lambda p: p.cpu_percent, default=None)
    if top_process and top_process.cpu_percent >= thresholds.cpu_spike_percent:
        signals.cpu_spike = True
        total += weights.cpu_spike
        suspect_process = top_process.name

    if top_process:
        name = (top_process.name or "").lower()
        is_known = any(k.lower() in name for k in known_processes)
        if not is_known:
            signals.unknown_program = True
            total += weights.unknown_program
            suspect_process = suspect_process or top_process.name

    total = min(total, 100)

    if total <= detection_cfg.bands.normal_max:
        level = ThreatLevel.NORMAL
    elif total <= detection_cfg.bands.warning_max:
        level = ThreatLevel.WARNING
    else:
        level = ThreatLevel.CRITICAL

    return ThreatScore(
        score=total,
        level=level,
        signals=signals,
        window_start=stats.window_start,
        window_end=stats.window_end,
        affected_files=stats.affected_files,
        suspect_process=suspect_process,
    )
