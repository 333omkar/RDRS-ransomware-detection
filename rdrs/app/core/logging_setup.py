"""Rotating, categorized logging for RDRS using loguru.

Five log streams: system, events, alerts, errors, audit. Each is a
separate rotating file so an operator can tail exactly the stream they
care about.
"""
from __future__ import annotations

from pathlib import Path

from loguru import logger

from app.core.config import AppConfig

_CONFIGURED = False


def setup_logging(cfg: AppConfig) -> None:
    """Configure loguru sinks. Safe to call more than once (no duplicate sinks)."""
    global _CONFIGURED
    if _CONFIGURED:
        return

    log_dir = Path(cfg.logging.dir)
    log_dir.mkdir(parents=True, exist_ok=True)

    logger.remove()  # drop default stderr handler, we re-add a clean one below

    logger.add(
        lambda msg: print(msg, end=""),
        level=cfg.logging.level,
        filter=lambda record: record["extra"].get("stream") != "audit",
    )

    common = dict(
        rotation=cfg.logging.rotation,
        retention=cfg.logging.retention,
        level=cfg.logging.level,
        enqueue=True,
        backtrace=False,
    )

    logger.add(log_dir / "system.log", filter=lambda r: r["extra"].get("stream") == "system", **common)
    logger.add(log_dir / "events.log", filter=lambda r: r["extra"].get("stream") == "events", **common)
    logger.add(log_dir / "alerts.log", filter=lambda r: r["extra"].get("stream") == "alerts", **common)
    logger.add(log_dir / "errors.log", filter=lambda r: r["level"].name == "ERROR", **common)
    logger.add(log_dir / "audit.log", filter=lambda r: r["extra"].get("stream") == "audit", **common)

    _CONFIGURED = True


def get_logger(stream: str):
    """Return a logger bound to a named stream (system/events/alerts/audit)."""
    return logger.bind(stream=stream)
