"""Process metadata collection (FR-4) using psutil."""
from __future__ import annotations

from datetime import datetime
from typing import List

import psutil

from app.core.models import ProcessSnapshot


def snapshot_processes(top_n: int = 50) -> List[ProcessSnapshot]:
    """Take a snapshot of running processes, sorted by CPU usage.

    Access-denied / zombie processes are skipped gracefully rather than
    raising, since some system processes are protected.
    """
    snapshots: List[ProcessSnapshot] = []
    now = datetime.utcnow()

    for proc in psutil.process_iter(
        ["pid", "name", "exe", "cpu_percent", "memory_info", "ppid", "io_counters"]
    ):
        try:
            info = proc.info
            mem = info.get("memory_info")
            io = info.get("io_counters")
            snapshots.append(
                ProcessSnapshot(
                    pid=info["pid"],
                    name=info.get("name") or "unknown",
                    exe=info.get("exe"),
                    cpu_percent=proc.cpu_percent(interval=None) or 0.0,
                    memory_mb=(mem.rss / (1024 * 1024)) if mem else 0.0,
                    disk_write_bytes=getattr(io, "write_bytes", 0) if io else 0,
                    parent_pid=info.get("ppid"),
                    timestamp=now,
                )
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    snapshots.sort(key=lambda s: s.cpu_percent, reverse=True)
    return snapshots[:top_n]
