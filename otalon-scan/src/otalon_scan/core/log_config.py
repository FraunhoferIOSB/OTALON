"""Logging configuration for CyberScan-ICS.

Provides a single setup function to initialize loguru logging with
- console sink (human friendly format)
- rotating file sink (configurable rotation/retention/compression) with safe fallbacks

Configuration is sourced from the central Settings (config/config.json),
so core/settings.py is no longer required.

References:
- [setup_logging()](otalon-scan/src/otalon_scan/core/log_config.py:48)
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import TYPE_CHECKING, Optional

from loguru import logger
from otalon_common.logging import configure_logging

from otalon_scan.settings import get_default_settings

if TYPE_CHECKING:
    from loguru import Record

_LOGGING_INITIALIZED: bool = False

_CTX_RESERVED: frozenset[str] = frozenset({"run_id", "module", "ctx"})

_CONTEXT_FORMAT: str = (
    "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
    "<level>{level: <8}</level> | "
    "run_id={extra[run_id]:<36} module={extra[module]:<16} | "
    "<white>{file}:{line}</white> | "
    "<level>{message}</level> | ctx={extra[ctx]}"
)

_FILE_FORMAT: str = (
    "{time:YYYY-MM-DD HH:mm:ss} | {file}:{line} | {level} | "
    "run_id={extra[run_id]} module={extra[module]} | {message} | ctx={extra[ctx]}"
)


def _render_context(record: "Record") -> None:
    """Fold ad-hoc ``logger.bind(...)`` fields into a printable ``ctx`` column.

    SCAN-034: the API layer used to carry structured fields as stdlib
    ``extra={...}`` dicts. Their loguru replacement is ``logger.bind(**fields)``,
    which lands the fields in ``record["extra"]`` under arbitrary keys. Neither
    the console format nor ``otalon_common.logging.DEFAULT_FORMAT`` references
    arbitrary keys, so without this patcher every bound field would be silently
    dropped from the rendered line.

    Args:
        record: The loguru record dict being emitted.
    """
    extra = record["extra"]
    fields = {key: value for key, value in extra.items() if key not in _CTX_RESERVED}
    extra.setdefault("run_id", "-")
    extra.setdefault("module", "-")
    extra["ctx"] = (
        " ".join(f"{key}={value}" for key, value in sorted(fields.items()))
        if fields
        else "-"
    )


def _ensure_parent_dir(file_path: str) -> None:
    """Ensure the directory for the log file exists."""
    try:
        p = Path(file_path).expanduser().resolve()
        p.parent.mkdir(parents=True, exist_ok=True)
    except Exception:
        # Do not fail if we cannot create; loguru will error on add if needed
        pass


def _add_file_sink_safe(
    file_path: str,
    level: str,
    rotation: str,
    retention: str,
    compression: str,
) -> bool:
    """
    Attempt to add a file sink. On PermissionError or other failures, return False.
    """
    try:
        _ensure_parent_dir(file_path)
        logger.add(
            file_path,
            level=level,
            format=_FILE_FORMAT,
            rotation=rotation,
            retention=retention,
            compression=compression,
        )
        return True
    except PermissionError:
        logger.warning(
            "Permission denied for log file path: {file_path}; falling back to /tmp",
            file_path=file_path,
        )
        return False
    except Exception as exc:
        logger.warning(
            "Failed to configure file logging at {file_path}: {exc}",
            file_path=file_path,
            exc=exc,
        )
        return False


def setup_logging(
    level_console: Optional[str] = None, level_file: Optional[str] = None
) -> None:
    """Initialize loguru logging (idempotent).

    Parameters
    ----------
    level_console:
        Override for console log level. If None, uses settings.logging.level_console.
    level_file:
        Override for file log level. If None, uses settings.logging.level_file.
    """
    global _LOGGING_INITIALIZED
    if _LOGGING_INITIALIZED:
        return

    s = get_default_settings()

    # F-02 / scan--structured-logging Requirement "Loguru Format String
    # Includes run_id and Module": render the bound ``run_id`` and
    # ``module`` fields visibly in human-readable log output. Lines
    # emitted in a context where ``run_id`` is not bound (startup,
    # lifespan) render ``run_id=-`` and ``module=-`` so the column
    # alignment is preserved and the absence is visible.
    # SCAN-034: ``patcher`` folds ad-hoc ``logger.bind(**fields)`` keys into a
    # rendered ``ctx`` column so the structured context that the API layer used
    # to pass as stdlib ``extra={...}`` survives the loguru migration.
    logger.configure(
        extra={"run_id": "-", "module": "-", "ctx": "-"}, patcher=_render_context
    )

    # SUITE-043: the console sink comes from the shared helper (which owns the
    # ``logger.remove()`` reset). The file sinks stay on ``_add_file_sink_safe``
    # below because they need the PermissionError fallback to /tmp and a
    # ``compression`` setting; ``configure_logging`` raises instead of falling
    # back, and its internal reset would already have dropped the console sink.
    console_level = (level_console or s.logging.level_console).upper()
    configure_logging(
        console_level=console_level,
        stream=sys.stdout,
        console_format=_CONTEXT_FORMAT,
        colorize=True,
    )

    file_level = (level_file or s.logging.level_file).upper()

    # Primary file sink attempt (as configured)
    primary_ok = _add_file_sink_safe(
        s.logging.file_path,
        level=file_level,
        rotation=s.logging.file_rotation,
        retention=s.logging.file_retention,
        compression=s.logging.file_compression,
    )

    if not primary_ok:
        # Fallback to /tmp where write permissions should be available during tests/containers
        tmp_path = "/tmp/otalon-scan/logs/application.log"
        fallback_ok = _add_file_sink_safe(
            tmp_path,
            level=file_level,
            rotation=s.logging.file_rotation,
            retention=s.logging.file_retention,
            compression=s.logging.file_compression,
        )
        if not fallback_ok:
            logger.warning("File sink disabled; continuing with console logging only.")

    _LOGGING_INITIALIZED = True
