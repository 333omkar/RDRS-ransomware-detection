"""SQLite database via SQLAlchemy (FR-5).

Tables: events, processes, scores, alerts, incidents.
"""
from __future__ import annotations

from datetime import datetime
from pathlib import Path
from typing import Optional

from sqlalchemy import (
    Column,
    DateTime,
    Float,
    Integer,
    String,
    Text,
    create_engine,
)
from sqlalchemy.orm import DeclarativeBase, sessionmaker


class Base(DeclarativeBase):
    pass


class EventRecord(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    event_type = Column(String(20), nullable=False)
    path = Column(Text, nullable=False)
    old_path = Column(Text, nullable=True)
    extension = Column(String(20), nullable=True)
    entropy = Column(Float, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


class ProcessRecord(Base):
    __tablename__ = "processes"

    id = Column(Integer, primary_key=True, autoincrement=True)
    pid = Column(Integer, nullable=False)
    name = Column(String(255), nullable=False)
    exe = Column(Text, nullable=True)
    cpu_percent = Column(Float, default=0.0)
    memory_mb = Column(Float, default=0.0)
    disk_write_bytes = Column(Integer, default=0)
    parent_pid = Column(Integer, nullable=True)
    timestamp = Column(DateTime, nullable=False, default=datetime.utcnow)


class ScoreRecord(Base):
    __tablename__ = "scores"

    id = Column(Integer, primary_key=True, autoincrement=True)
    score = Column(Integer, nullable=False)
    level = Column(String(20), nullable=False)
    signals_json = Column(Text, nullable=False)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class AlertRecord(Base):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    level = Column(String(20), nullable=False)
    score = Column(Integer, nullable=False)
    message = Column(Text, nullable=False)
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


class IncidentRecord(Base):
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    score = Column(Integer, nullable=False)
    level = Column(String(20), nullable=False)
    affected_files_json = Column(Text, nullable=False)
    suspect_process = Column(String(255), nullable=True)
    quarantined_files_json = Column(Text, nullable=False, default="[]")
    notes = Column(Text, default="")
    created_at = Column(DateTime, nullable=False, default=datetime.utcnow)


_engine = None
_SessionLocal: Optional[sessionmaker] = None


def init_db(db_path: str = "./data/rdrs.db"):
    """Create the engine, tables, and session factory. Idempotent."""
    global _engine, _SessionLocal
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    _engine = create_engine(f"sqlite:///{db_path}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(_engine)
    _SessionLocal = sessionmaker(bind=_engine, expire_on_commit=False)
    return _engine


def get_session():
    if _SessionLocal is None:
        raise RuntimeError("Database not initialized — call init_db() first")
    return _SessionLocal()
