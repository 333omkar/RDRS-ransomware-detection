"""Configuration loading for RDRS.

Reads config.yaml and validates it with pydantic models so the rest of
the application can rely on typed, validated settings (FR-1).
"""
from __future__ import annotations

from pathlib import Path
from typing import List

import yaml
from pydantic import BaseModel, Field


class MonitorConfig(BaseModel):
    watch_paths: List[str] = Field(default_factory=lambda: ["./data/sandbox"])
    recursive: bool = True


class ThresholdsConfig(BaseModel):
    files_modified_per_minute: int = 20
    renames_per_minute: int = 10
    extension_changes_per_minute: int = 5
    high_entropy_value: float = 7.5
    high_entropy_file_ratio: float = 0.5
    cpu_spike_percent: float = 70.0


class WeightsConfig(BaseModel):
    rapid_encryption: int = 40
    mass_rename: int = 30
    high_entropy: int = 25
    cpu_spike: int = 15
    unknown_program: int = 10


class BandsConfig(BaseModel):
    normal_max: int = 40
    warning_max: int = 70


class DetectionConfig(BaseModel):
    window_seconds: int = 60
    thresholds: ThresholdsConfig = Field(default_factory=ThresholdsConfig)
    weights: WeightsConfig = Field(default_factory=WeightsConfig)
    bands: BandsConfig = Field(default_factory=BandsConfig)


class ResponseConfig(BaseModel):
    simulation_mode: bool = True
    quarantine_dir: str = "./data/quarantine"
    known_processes: List[str] = Field(default_factory=list)


class DatabaseConfig(BaseModel):
    path: str = "./data/rdrs.db"


class LoggingConfig(BaseModel):
    dir: str = "./logs"
    level: str = "INFO"
    rotation: str = "10 MB"
    retention: str = "14 days"


class ApiConfig(BaseModel):
    host: str = "0.0.0.0"
    port: int = 8000


class ReportsConfig(BaseModel):
    dir: str = "./data/reports"


class AppConfig(BaseModel):
    monitor: MonitorConfig = Field(default_factory=MonitorConfig)
    detection: DetectionConfig = Field(default_factory=DetectionConfig)
    response: ResponseConfig = Field(default_factory=ResponseConfig)
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    logging: LoggingConfig = Field(default_factory=LoggingConfig)
    api: ApiConfig = Field(default_factory=ApiConfig)
    reports: ReportsConfig = Field(default_factory=ReportsConfig)


_CACHED_CONFIG: AppConfig | None = None


def load_config(path: str | Path = "config.yaml", force_reload: bool = False) -> AppConfig:
    """Load and validate config.yaml, caching the result.

    Falls back to schema defaults if a key is missing, but the file itself
    must exist and be valid YAML.
    """
    global _CACHED_CONFIG
    if _CACHED_CONFIG is not None and not force_reload:
        return _CACHED_CONFIG

    config_path = Path(path)
    if not config_path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with config_path.open("r", encoding="utf-8") as f:
        raw = yaml.safe_load(f) or {}

    _CACHED_CONFIG = AppConfig(**raw)
    return _CACHED_CONFIG


def ensure_runtime_dirs(cfg: AppConfig) -> None:
    """Create directories the app writes to at runtime, if missing."""
    for path in cfg.monitor.watch_paths:
        Path(path).mkdir(parents=True, exist_ok=True)
    Path(cfg.response.quarantine_dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.logging.dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.reports.dir).mkdir(parents=True, exist_ok=True)
    Path(cfg.database.path).parent.mkdir(parents=True, exist_ok=True)
