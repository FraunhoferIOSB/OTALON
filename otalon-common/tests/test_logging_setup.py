"""Tests for unified loguru logging configuration."""

import io
from pathlib import Path
from typing import Any, cast

from loguru import logger

from otalon_common.logging.setup import DEFAULT_FORMAT, configure_logging


class TestDefaultFormat:
    """Tests for DEFAULT_FORMAT constant."""

    def test_format_contains_time(self) -> None:
        assert "{time:" in DEFAULT_FORMAT

    def test_format_contains_level(self) -> None:
        assert "{level}" in DEFAULT_FORMAT

    def test_format_contains_message(self) -> None:
        assert "{message}" in DEFAULT_FORMAT


class TestConfigureLogging:
    """Tests for configure_logging()."""

    def test_console_only(self) -> None:
        stream = io.StringIO()
        configure_logging(console_level="INFO", stream=stream)
        logger.info("test console message")
        output = stream.getvalue()
        assert "test console message" in output

    def test_console_and_file(self, tmp_path: Path) -> None:
        log_file = tmp_path / "test.log"
        stream = io.StringIO()
        configure_logging(
            log_file=log_file,
            console_level="INFO",
            file_level="DEBUG",
            stream=stream,
        )
        logger.debug("debug message")
        logger.info("info message")

        log_content = log_file.read_text()
        assert "debug message" in log_content
        assert "info message" in log_content

        console_output = stream.getvalue()
        assert "info message" in console_output

    def test_file_sink_default_level_is_info(self, tmp_path: Path) -> None:
        """SUITE-060: the default file level must not write DEBUG lines (GB log volume)."""
        log_file = tmp_path / "default_level.log"
        configure_logging(log_file=log_file, stream=io.StringIO())
        logger.debug("debug should be filtered")
        logger.info("info should be kept")

        log_content = log_file.read_text()
        assert "debug should be filtered" not in log_content
        assert "info should be kept" in log_content

    def test_file_sink_has_default_retention(self, tmp_path: Path) -> None:
        log_file = tmp_path / "retention.log"
        configure_logging(log_file=log_file, stream=io.StringIO())

        handlers = cast(Any, logger)._core.handlers.values()
        file_handler = next(
            handler
            for handler in handlers
            if hasattr(handler._sink, "_retention_function")
        )

        assert file_handler._sink._retention_function is not None

    def test_idempotency(self) -> None:
        stream1 = io.StringIO()
        stream2 = io.StringIO()
        configure_logging(console_level="INFO", stream=stream1)
        configure_logging(console_level="INFO", stream=stream2)
        logger.info("after second configure")

        output1 = stream1.getvalue()
        output2 = stream2.getvalue()
        assert "after second configure" not in output1
        assert "after second configure" in output2

    def test_custom_stream_stderr(self) -> None:
        stream = io.StringIO()
        configure_logging(console_level="INFO", stream=stream)
        logger.info("stderr test")
        assert "stderr test" in stream.getvalue()

    def test_custom_format(self) -> None:
        stream = io.StringIO()
        custom_fmt = "{level} - {message}"
        configure_logging(console_level="INFO", format_string=custom_fmt, stream=stream)
        logger.info("custom format test")
        output = stream.getvalue()
        assert "INFO - custom format test" in output
