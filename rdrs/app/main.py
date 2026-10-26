"""RDRS entry point.

Wires together: config -> logging -> file monitor -> sliding window ->
scoring -> response -> database persistence.

Usage:
    python -m app.main --watch ./data/sandbox
    python -m app.main            # uses watch_paths from config.yaml
"""
from __future__ import annotations

import argparse
import json
import time

from app.core.config import ensure_runtime_dirs, load_config
from app.core.logging_setup import get_logger, setup_logging
from app.core.models import FileEvent
from app.database.db import EventRecord, get_session, init_db
from app.detectors.detection_engine import SlidingWindow
from app.detectors.file_monitor import FileMonitor
from app.detectors.process_monitor import snapshot_processes
from app.detectors.response import handle_score
from app.detectors.scoring import score_window

system_log = get_logger("system")
event_log = get_logger("events")


def persist_event(event: FileEvent) -> None:
    session = get_session()
    try:
        session.add(
            EventRecord(
                event_type=event.event_type.value,
                path=event.path,
                old_path=event.old_path,
                extension=event.extension,
                entropy=event.entropy,
                timestamp=event.timestamp,
            )
        )
        session.commit()
    finally:
        session.close()


def build_pipeline(cfg):
    window = SlidingWindow(
        window_seconds=cfg.detection.window_seconds,
        high_entropy_threshold=cfg.detection.thresholds.high_entropy_value,
    )

    def on_event(event: FileEvent) -> None:
        event_log.info(f"{event.event_type.value} {event.path} entropy={event.entropy}")
        persist_event(event)

        stats = window.add_event(event)
        processes = snapshot_processes(top_n=20)
        score = score_window(
            stats,
            cfg.detection,
            processes=processes,
            known_processes=cfg.response.known_processes,
        )

        if score.level.value != "Normal":
            system_log.info(
                f"Threat score {score.score} ({score.level.value}) — "
                f"signals={score.signals.model_dump()}"
            )
        incident_id = handle_score(score, cfg.response.quarantine_dir, cfg.response.simulation_mode)
        if incident_id:
            system_log.warning(f"CRITICAL — incident #{incident_id} created")

    return on_event


def main() -> None:
    parser = argparse.ArgumentParser(description="RDRS — Ransomware Detection and Response System")
    parser.add_argument("--watch", action="append", help="Folder to watch (repeatable). Overrides config.")
    parser.add_argument("--config", default="config.yaml", help="Path to config.yaml")
    args = parser.parse_args()

    cfg = load_config(args.config)
    if args.watch:
        cfg.monitor.watch_paths = args.watch

    ensure_runtime_dirs(cfg)
    setup_logging(cfg)
    init_db(cfg.database.path)

    system_log.info(f"RDRS starting — watching {cfg.monitor.watch_paths}")
    system_log.info(f"Simulation mode: {cfg.response.simulation_mode}")

    on_event = build_pipeline(cfg)
    monitor = FileMonitor(cfg.monitor.watch_paths, cfg.monitor.recursive, on_event)
    monitor.start()

    try:
        while True:
            time.sleep(2)
            print(f"\rEvents observed: {monitor.event_count}", end="", flush=True)
    except KeyboardInterrupt:
        print()
        system_log.info("RDRS shutting down")
    finally:
        monitor.stop()


if __name__ == "__main__":
    main()
