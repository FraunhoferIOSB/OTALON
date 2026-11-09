"""Unit tests for F-02 ``scan--structured-logging`` capability.

Verifies:

- The loguru format string in :mod:`otalon_scan.core.log_config` renders the
  bound ``run_id`` and ``module`` fields.
- The fallback (``run_id=-``, ``module=-``) is emitted when nothing is
  bound on the call site.
- :meth:`logger.bind(run_id=..., module=...)` correctly threads the
  fields into the emitted record's ``extra`` mapping.
- F-string interpolation in log calls is forbidden (CI gate):
  ``rg -n 'logger\\.(info|warning|error|critical|debug)\\(f"'
  otalon-scan/src/`` returns zero hits.
"""

from __future__ import annotations

import asyncio
import io
import re
import subprocess
import threading
from pathlib import Path
from types import SimpleNamespace
from typing import TYPE_CHECKING

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from otalon_scan.api.scan_sink import ScanSink
from otalon_scan.api.state import ApiState
from otalon_scan.core.log_config import _FILE_FORMAT, _render_context

if TYPE_CHECKING:
    pass

_OTALON_SCAN_SRC = Path(__file__).resolve().parents[2] / "src" / "otalon_scan"


def test_logger_bind_threads_run_id_and_module() -> None:
    """``logger.bind(run_id=..., module=...)`` SHALL surface in ``record.extra``."""
    captured: list[dict[str, object]] = []

    def _sink(message: object) -> None:
        # loguru ``Message`` objects carry the record on ``.record``
        captured.append(dict(getattr(message, "record", {}).get("extra", {})))

    handler_id = logger.add(_sink, level="DEBUG")
    try:
        bound = logger.bind(run_id="abc-123", module="arp_scan")
        bound.info("test line")
        assert any(
            entry.get("run_id") == "abc-123" and entry.get("module") == "arp_scan"
            for entry in captured
        )
    finally:
        logger.remove(handler_id)


def test_logger_default_extra_is_present() -> None:
    """Default ``extra`` SHALL include ``run_id`` and ``module`` keys.

    The loguru ``logger.configure(extra=...)`` call in
    :func:`otalon_scan.core.log_config.setup_logging` is responsible for the
    default — but the test verifies the contract is reachable from an
    isolated logger instance bound with the same defaults.
    """
    # Configure a fresh extra map; this is what setup_logging does at
    # service startup. We do not call setup_logging here because that
    # also touches the global console + file sinks; we only want to
    # exercise the ``extra`` contract.
    logger.configure(extra={"run_id": "-", "module": "-"})
    captured: list[dict[str, object]] = []

    def _sink(message: object) -> None:
        captured.append(dict(getattr(message, "record", {}).get("extra", {})))

    handler_id = logger.add(_sink, level="DEBUG")
    try:
        logger.info("untagged line")
        # The unbound call's extra MUST include the defaults.
        assert any(
            entry.get("run_id") == "-" and entry.get("module") == "-"
            for entry in captured
        )
    finally:
        logger.remove(handler_id)


def test_log_format_string_renders_run_id_column() -> None:
    """The format string SHALL render ``run_id`` and ``module`` columns visibly."""
    logger.configure(extra={"run_id": "-", "module": "-"})

    sink = io.StringIO()
    handler_id = logger.add(
        sink,
        level="DEBUG",
        format=(
            "{level: <8} | run_id={extra[run_id]:<36} module={extra[module]:<16} | "
            "{message}"
        ),
    )
    try:
        bound = logger.bind(run_id="ZZZZ-RUN-1234", module="port_scan")
        bound.info("hello")
        # Unbound call must still render (default fallback).
        logger.info("world")
    finally:
        logger.remove(handler_id)

    output = sink.getvalue()
    assert "run_id=ZZZZ-RUN-1234" in output
    assert "module=port_scan" in output
    assert "run_id=-" in output  # unbound line
    assert "module=-" in output


def test_scan034_render_context_folds_bound_fields_into_ctx() -> None:
    """SCAN-034: ad-hoc ``logger.bind(...)`` fields SHALL render in ``ctx``.

    The API layer's former stdlib ``extra={...}`` dicts became
    ``logger.bind(**fields)``. Neither the console format nor
    ``otalon_common.logging.DEFAULT_FORMAT`` names those arbitrary keys, so
    without the ``_render_context`` patcher the structured context would be
    silently dropped from every rendered line.
    """
    logger.configure(
        extra={"run_id": "-", "module": "-", "ctx": "-"}, patcher=_render_context
    )
    sink = io.StringIO()
    handler_id = logger.add(sink, level="DEBUG", format=_FILE_FORMAT)
    try:
        logger.bind(scan_id="S-42", module_name="port_scan", batch_size=7).error(
            "persist failed"
        )
        logger.info("unbound line")
    finally:
        logger.remove(handler_id)
        logger.configure(extra={"run_id": "-", "module": "-"}, patcher=None)

    output = sink.getvalue()
    assert "scan_id=S-42" in output
    assert "module_name=port_scan" in output
    assert "batch_size=7" in output
    assert "ctx=-" in output


class _FailingRepo:
    """Repo stand-in whose findings write always fails with a DB error."""

    async def get_scan(self, scan_id: str) -> object:
        """Return a stub scan row carrying only the attributes the sink reads."""
        return SimpleNamespace(status="completed", started_at=None, finished_at=None)

    async def finish_scan(self, scan_id: str, **kwargs: object) -> None:
        """Fail the way a real repository failure surfaces."""
        raise SQLAlchemyError("boom")


def test_scan034_scan_sink_failure_path_emits_bound_fields() -> None:
    """SCAN-034: the ``ScanSink`` DB-failure path SHALL bind its context fields.

    Captures loguru records directly (a callable sink) rather than ``caplog``:
    ``caplog`` hooks stdlib ``logging`` and would silently see nothing after the
    migration. Pins both the bound fields and the attached traceback, i.e. that
    ``bound.exception(...)`` inside ``except`` still carries ``exc_info``.
    """
    records: list[dict[str, object]] = []

    def _sink(message: object) -> None:
        record = getattr(message, "record", {})
        records.append(
            {
                "message": record["message"],
                "extra": dict(record["extra"]),
                "exception": record["exception"],
            }
        )

    loop = asyncio.new_event_loop()
    thread = threading.Thread(
        target=loop.run_forever, name="scan034-sink-loop", daemon=True
    )
    thread.start()
    handler_id = logger.add(_sink, level="DEBUG")
    try:
        state = ApiState(repo=_FailingRepo(), main_loop=loop)  # type: ignore[arg-type]
        ScanSink(state).persist_scan_findings("S-7", [{"ip": "10.0.0.1"}])
    finally:
        logger.remove(handler_id)
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5.0)
        loop.close()

    failures = [
        entry
        for entry in records
        if "_persist_scan_findings: repo write failed" in str(entry["message"])
    ]
    assert failures, f"no failure record captured: {records}"
    extra = failures[0]["extra"]
    assert isinstance(extra, dict)
    assert extra.get("scan_id") == "S-7"
    assert extra.get("findings") == 1
    assert failures[0]["exception"] is not None


def test_scan034_no_stdlib_logging_in_api_layer() -> None:
    """SCAN-034: the ``otalon-scan`` API layer SHALL NOT import stdlib logging."""
    offenders = [
        str(path)
        for path in (_OTALON_SCAN_SRC / "api").rglob("*.py")
        if "__pycache__" not in path.parts
        and re.search(r"^import logging$", path.read_text(encoding="utf-8"), re.M)
    ]
    assert offenders == [], f"stdlib logging still present in api layer: {offenders}"


def test_no_fstring_interpolation_in_log_calls_in_production_code() -> None:
    """``logger.<lvl>(f"..."`` SHALL NOT appear in otalon-scan/src/.

    Enforces F-02 / scan--structured-logging Requirement
    "logger.bind Replaces F-String Interpolation" via a grep check
    over the production source tree. Test-only and documentation
    files are excluded by virtue of restricting the scope to ``src/``.
    """
    result = subprocess.run(
        [
            "grep",
            "-rnE",
            r'logger\.(info|warning|error|critical|debug|success)\(f"',
            str(_OTALON_SCAN_SRC),
        ],
        check=False,
        capture_output=True,
        text=True,
    )
    assert (
        result.returncode == 1
    ), f"f-string log calls forbidden in production code, found:\n{result.stdout}"
