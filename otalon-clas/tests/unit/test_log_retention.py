"""Tests that the otalon-clas sink configures log retention explicitly (SUITE-066)."""

from __future__ import annotations

from pathlib import Path
from typing import Any, cast

from loguru import logger

from otalon_clas.common.settings import (
    AppConfig,
    InfluxConfig,
    LoggingConfig,
    ModelsConfig,
    PostgresConfig,
)
from otalon_clas.main import _setup_logging


def _app_config(logging: LoggingConfig) -> AppConfig:
    return AppConfig(
        influx=InfluxConfig(url="http://localhost:8181", token="test"),
        postgres=PostgresConfig(dsn="postgresql://postgres:test@localhost:5432/test"),
        models=ModelsConfig(dir="models"),
        logging=logging,
    )


def _file_handlers() -> list[Any]:
    """Return the active loguru file-handler sinks."""
    handlers = cast(Any, logger)._core.handlers.values()
    return [handler for handler in handlers if hasattr(handler._sink, "_retention_function")]


class TestSetupLoggingRetention:
    """_setup_logging must pass an explicit retention policy for the file sink."""

    def test_file_sink_has_explicit_retention(self, tmp_path: Path) -> None:
        log_file = tmp_path / "rotating.log"
        config = LoggingConfig(level="INFO", file=str(log_file))
        _setup_logging(_app_config(config))

        file_handlers = _file_handlers()
        assert len(file_handlers) == 1
        assert file_handlers[0]._sink._retention_function is not None

    def test_explicit_retention_writes_and_rotates_setup(self, tmp_path: Path) -> None:
        """Sink stays writable under the explicit retention policy."""
        log_file = tmp_path / "explicit.log"
        config = LoggingConfig(level="INFO", file=str(log_file))
        _setup_logging(_app_config(config))

        logger.info("retention sink active")
        assert log_file.read_text().strip() != ""

    def test_console_only_setup_keeps_sinks_clean(self) -> None:
        config = LoggingConfig(level="WARNING", file="")
        _setup_logging(_app_config(config))

        assert _file_handlers() == []
