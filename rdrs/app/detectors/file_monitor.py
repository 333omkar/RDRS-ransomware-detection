"""Real-time file-system monitoring (FR-2) using watchdog.

Converts raw watchdog events into our own FileEvent objects and hands
them to a callback (typically the DetectionEngine).
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Callable, List

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer

from app.core.entropy import file_entropy
from app.core.models import EventType, FileEvent


def _ext(path: str) -> str:
    return Path(path).suffix.lower()


class _Handler(FileSystemEventHandler):
    def __init__(self, on_event: Callable[[FileEvent], None]):
        self._on_event = on_event

    def on_created(self, event: FileSystemEvent):
        if event.is_directory:
            return
        entropy = file_entropy(event.src_path)
        self._on_event(
            FileEvent(
                event_type=EventType.CREATED,
                path=event.src_path,
                timestamp=datetime.utcnow(),
                extension=_ext(event.src_path),
                entropy=entropy,
            )
        )

    def on_modified(self, event: FileSystemEvent):
        if event.is_directory:
            return
        entropy = file_entropy(event.src_path)
        self._on_event(
            FileEvent(
                event_type=EventType.MODIFIED,
                path=event.src_path,
                timestamp=datetime.utcnow(),
                extension=_ext(event.src_path),
                entropy=entropy,
            )
        )

    def on_deleted(self, event: FileSystemEvent):
        if event.is_directory:
            return
        self._on_event(
            FileEvent(
                event_type=EventType.DELETED,
                path=event.src_path,
                timestamp=datetime.utcnow(),
                extension=_ext(event.src_path),
            )
        )

    def on_moved(self, event: FileSystemEvent):
        if event.is_directory:
            return
        entropy = file_entropy(event.dest_path)
        self._on_event(
            FileEvent(
                event_type=EventType.RENAMED,
                path=event.dest_path,
                old_path=event.src_path,
                old_extension=_ext(event.src_path),
                timestamp=datetime.utcnow(),
                extension=_ext(event.dest_path),
                entropy=entropy,
            )
        )


class FileMonitor:
    """Watches one or more folders and streams FileEvents to a callback."""

    def __init__(self, watch_paths: List[str], recursive: bool, on_event: Callable[[FileEvent], None]):
        self.watch_paths = watch_paths
        self.recursive = recursive
        self._observer = Observer()
        self._handler = _Handler(on_event)
        self.event_count = 0

        wrapped = on_event

        def counting_callback(evt: FileEvent):
            self.event_count += 1
            wrapped(evt)

        self._handler._on_event = counting_callback

    def start(self):
        for path in self.watch_paths:
            Path(path).mkdir(parents=True, exist_ok=True)
            self._observer.schedule(self._handler, path, recursive=self.recursive)
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join()
