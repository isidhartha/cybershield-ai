"""Structured logging configuration for CyberShield AI."""

from __future__ import annotations

import logging
import sys
from typing import Any

from .config import get_settings


def setup_logging() -> logging.Logger:
    """Configure and return the root logger."""
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    formatter = logging.Formatter(
        fmt="%(asctime)s | %(levelname)-8s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)

    root = logging.getLogger("cybershield")
    root.setLevel(level)
    root.addHandler(handler)
    root.propagate = False

    return root


def get_logger(name: str) -> logging.Logger:
    """Return a child logger under the cybershield namespace."""
    return logging.getLogger(f"cybershield.{name}")


def log_scan_event(logger: logging.Logger, event: str, **kwargs: Any) -> None:
    """Log a structured scan event."""
    extra = " ".join(f"{k}={v}" for k, v in kwargs.items())
    logger.info("SCAN_EVENT event=%s %s", event, extra)
