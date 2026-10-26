"""Sliding-window detection engine (FR-6).

Keeps recent events in memory and, on each new event, recomputes the
window statistics that the scoring engine consumes: modification rate,
rename rate, extension-change rate, and average entropy of new writes.
"""
from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Deque, List

from app.core.models import EventType, FileEvent


@dataclass
class WindowStats:
    window_start: datetime
    window_end: datetime
    files_modified_per_minute: float
    renames_per_minute: float
    extension_changes_per_minute: float
    avg_new_file_entropy: float
    high_entropy_ratio: float
    affected_files: List[str] = field(default_factory=list)


class SlidingWindow:
    """Maintains a rolling window of FileEvents and computes stats on demand."""

    def __init__(self, window_seconds: int = 60, high_entropy_threshold: float = 7.5):
        self.window_seconds = window_seconds
        self.high_entropy_threshold = high_entropy_threshold
        self._events: Deque[FileEvent] = deque()

    def add_event(self, event: FileEvent) -> WindowStats:
        self._events.append(event)
        self._evict_old(event.timestamp)
        return self.stats(now=event.timestamp)

    def _evict_old(self, now: datetime) -> None:
        cutoff = now - timedelta(seconds=self.window_seconds)
        while self._events and self._events[0].timestamp < cutoff:
            self._events.popleft()

    def stats(self, now: datetime | None = None) -> WindowStats:
        now = now or datetime.utcnow()
        cutoff = now - timedelta(seconds=self.window_seconds)
        window_events = [e for e in self._events if e.timestamp >= cutoff]

        minutes = max(self.window_seconds / 60.0, 1e-6)

        modified = [e for e in window_events if e.event_type in (EventType.MODIFIED, EventType.CREATED)]
        renamed = [e for e in window_events if e.event_type == EventType.RENAMED]
        ext_changes = [
            e for e in renamed
            if e.old_extension is not None and e.old_extension != e.extension
        ]

        # Track each file's *latest known* entropy rather than counting every
        # event: a rename should replace a file's stale creation-time entropy
        # with its post-write value, not just add another data point next to
        # it. Otherwise a burst that renames files already present in the
        # window (a very common ransomware pattern) gets its high-entropy
        # ratio diluted by those files' original, low-entropy baseline.
        entropy_by_identity: dict[str, float] = {}
        for e in window_events:
            if e.event_type == EventType.RENAMED:
                if e.old_path is not None:
                    entropy_by_identity.pop(e.old_path, None)
                if e.entropy is not None:
                    entropy_by_identity[e.path] = e.entropy
            elif e.event_type == EventType.DELETED:
                entropy_by_identity.pop(e.path, None)
            else:
                if e.entropy is not None:
                    entropy_by_identity[e.path] = e.entropy

        entropies = list(entropy_by_identity.values())
        avg_entropy = sum(entropies) / len(entropies) if entropies else 0.0
        high_entropy_count = sum(1 for v in entropies if v >= self.high_entropy_threshold)
        high_entropy_ratio = (high_entropy_count / len(entropies)) if entropies else 0.0

        affected = list({e.path for e in window_events})

        return WindowStats(
            window_start=cutoff,
            window_end=now,
            files_modified_per_minute=len(modified) / minutes,
            renames_per_minute=len(renamed) / minutes,
            extension_changes_per_minute=len(ext_changes) / minutes,
            avg_new_file_entropy=avg_entropy,
            high_entropy_ratio=high_entropy_ratio,
            affected_files=affected,
        )
