"""Shared in-memory data models used across the detection pipeline."""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import List, Optional

from pydantic import BaseModel


class EventType(str, Enum):
    CREATED = "created"
    MODIFIED = "modified"
    DELETED = "deleted"
    RENAMED = "renamed"


class FileEvent(BaseModel):
    event_type: EventType
    path: str
    timestamp: datetime
    extension: str = ""
    old_path: Optional[str] = None       # populated for renames
    old_extension: Optional[str] = None  # populated for renames
    entropy: Optional[float] = None


class ProcessSnapshot(BaseModel):
    pid: int
    name: str
    exe: Optional[str] = None
    cpu_percent: float = 0.0
    memory_mb: float = 0.0
    disk_write_bytes: int = 0
    parent_pid: Optional[int] = None
    timestamp: datetime


class ThreatLevel(str, Enum):
    NORMAL = "Normal"
    WARNING = "Warning"
    CRITICAL = "Critical"


class SignalBreakdown(BaseModel):
    rapid_encryption: bool = False
    mass_rename: bool = False
    high_entropy: bool = False
    cpu_spike: bool = False
    unknown_program: bool = False


class ThreatScore(BaseModel):
    score: int
    level: ThreatLevel
    signals: SignalBreakdown
    window_start: datetime
    window_end: datetime
    affected_files: List[str] = []
    suspect_process: Optional[str] = None


class Incident(BaseModel):
    id: Optional[int] = None
    created_at: datetime
    score: int
    level: ThreatLevel
    affected_files: List[str]
    suspect_process: Optional[str] = None
    quarantined_files: List[str] = []
    notes: str = ""
