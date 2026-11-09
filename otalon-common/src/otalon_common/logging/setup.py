"""Unified loguru logging configuration with console and optional file handler."""

import sys
from pathlib import Path
from typing import TextIO

from loguru import logger

DEFAULT_FORMAT: str = "{time:YYYY-MM-DD HH:mm:ss} | {file}:{line} | {level} | {message}"
"""Default loguru format string for consistent log output across subprojects."""


def configure_logging(
    log_file: str | Path | None = None,
    console_level: str = "INFO",
    file_level: str = "INFO",
    format_string: str | None = None,
    rotation: str = "10 MB",
    retention: str | int | None = "14 days",
    stream: TextIO | None = None,
    console_format: str | None = None,
    colorize: bool = False,
    enqueue: bool = False,
) -> None:
    """Configure loguru with console and optional file handler.

    Removes all existing handlers first to ensure idempotency. Safe to call
    multiple times without accumulating duplicate handlers.

    Args:
        log_file: Path for file logging. If None, only console logging is configured.
        console_level: Log level for the console handler.
        file_level: Log level for the file handler (only used if log_file is set).
        format_string: Custom format string applied to both handlers. Defaults
            to DEFAULT_FORMAT.
        rotation: File rotation size or interval. Defaults to ``"10 MB"``.
        retention: Retention policy for rotated files, either a duration string
            or a maximum number of retained files. Defaults to ``"14 days"``.
        stream: Output stream for console logging. Defaults to ``sys.stdout``.
        console_format: Console-only format override. Takes precedence over
            ``format_string`` for the console handler, leaving the file handler
            on ``format_string``/DEFAULT_FORMAT. Use for human-readable console
            output (markup tags) while keeping the file sink machine-uniform.
        colorize: Whether to render loguru colour markup on the console handler.
            File handlers are never colourized.
        enqueue: Whether the file handler routes records through a queue, making
            writes process-safe at the cost of a background thread.
    """
    logger.remove()

    fmt = format_string or DEFAULT_FORMAT
    out_stream = stream or sys.stdout

    logger.add(
        out_stream,
        level=console_level,
        format=console_format or fmt,
        colorize=colorize,
    )

    if log_file is not None:
        logger.add(
            str(log_file),
            level=file_level,
            format=fmt,
            rotation=rotation,
            retention=retention,
            enqueue=enqueue,
        )
