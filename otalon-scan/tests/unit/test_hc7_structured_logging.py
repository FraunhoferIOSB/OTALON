"""HC7 + D-O1 — explicit exception handling + structured logging fields.

Covers ``.dev/TODO_otalon-scan.md`` HC7 + D-O1 acceptance criteria for
the otalon-scan API layer:

- Every former ``except Exception: pass`` either uses a narrow
  exception type or logs with structured ``extra`` fields and a
  documented ``# noqa`` rationale.
- DB failures inside the persistence sinks no longer disappear: they
  are emitted via ``logger.exception(...)`` so callers see them with
  ``scan_id`` / ``run_id`` / ``module_name`` as structured fields.
  SCAN-033 moved those sinks into
  :class:`otalon_scan.api.scan_sink.ScanSink`; SCAN-034 converted the
  calls from stdlib ``logging`` to loguru ``logger.bind(...)``.
- No f-string interpolation remains in loguru ``logger`` calls across ``src/``.
"""

from __future__ import annotations

import ast
import asyncio
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from otalon_scan.api.scan_sink import ScanSink
from otalon_scan.api.state import ApiState
from otalon_scan.core.models import ScanResult

_PROJECT_SRC = Path(__file__).resolve().parents[2] / "src" / "otalon_scan"

_LOGGER_NAMES = {"logger", "_log"}
_LEVEL_METHODS = {
    "debug",
    "info",
    "warning",
    "error",
    "success",
    "exception",
    "critical",
}


# ---- D-O1: no f-string logger calls anywhere under src/ ----


def _collect_fstring_logger_calls() -> list[tuple[Path, int]]:
    """Walk every Python file under ``src/`` and AST-check for f-string
    arguments passed to logger/log calls.

    AST-level scan catches multi-line implicit-concatenation cases that
    the original ``grep -rn 'logger\\.\\w*(f"'`` shell check misses
    (e.g. ``logger.info(\\n    f"foo "\\n    f"bar"\\n)``).
    """
    hits: list[tuple[Path, int]] = []
    for f in sorted(_PROJECT_SRC.rglob("*.py")):
        try:
            tree = ast.parse(f.read_text())
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in _LEVEL_METHODS:
                continue
            if not isinstance(node.func.value, ast.Name):
                continue
            if node.func.value.id not in _LOGGER_NAMES:
                continue
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    hits.append((f, arg.lineno))
                    break
    return hits


def test_no_fstring_logger_calls_under_src() -> None:
    """No ``logger.*(f"...")`` / ``_log.*(f"...")`` calls anywhere in ``src/``.

    Spec: ``.dev/TODO_otalon-scan.md`` D-O1 acceptance criterion #1.
    Implemented as an AST walk so multi-line implicit-concat f-strings
    (which the spec's literal ``grep -rn 'logger\\.\\w*(f"' src/`` cannot
    see) are caught too.
    """
    hits = _collect_fstring_logger_calls()
    formatted = "\n".join(f"  {f}:{ln}" for f, ln in hits)
    assert not hits, "Found f-string logger/log calls (D-O1 violation):\n" + formatted


# ---- HC7: persistence sink failures are logged with structured fields ----


class _RaisingRepo:
    """Async repo stub whose ``save_findings_batch`` raises a DB error.

    Mirrors only the surface ``ScanSink.persist_findings`` touches so the
    test can drive the sink without spinning up Postgres.
    """

    async def save_findings_batch(self, *args: Any, **kwargs: Any) -> int:
        raise SQLAlchemyError("simulated DB outage during batch insert")

    async def save_port_scan_results(self, *args: Any, **kwargs: Any) -> list[int]:
        raise SQLAlchemyError("simulated DB outage during port-scan save")


def test_persist_findings_logs_db_failure_with_structured_extra() -> None:
    """``ScanSink.persist_findings`` SHALL emit ``logger.exception`` with bound fields.

    HC7 acceptance: a module persistence failure must be visible in the log
    stream with ``scan_id`` / ``batch_size`` / ``module_name`` as structured
    fields (not buried inside an interpolated string).

    SCAN-034 migrated the sink from stdlib ``logging`` to loguru, so the capture
    moved from ``caplog`` (which hooks stdlib ``logging`` and now sees nothing)
    to a loguru callable sink reading ``message.record``.
    """
    records: list[dict[str, Any]] = []

    def _capture(message: Any) -> None:
        record = message.record
        records.append(
            {
                "message": record["message"],
                "extra": dict(record["extra"]),
                "exception": record["exception"],
            }
        )

    loop = asyncio.new_event_loop()
    handler_id = logger.add(_capture, level="ERROR")
    try:
        # SCAN-033: the sink is bound to an ApiState instead of reading
        # module globals.
        state = ApiState(repo=_RaisingRepo(), main_loop=loop)  # type: ignore[arg-type]
        sink = ScanSink(state)

        # Run the loop in a background thread so
        # ``asyncio.run_coroutine_threadsafe`` can dispatch onto it.
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        try:
            scan_result = ScanResult(
                module_name="T1046/port_scan",
                started_at=datetime(2026, 5, 18, 16, 0, 0, tzinfo=timezone.utc),
                finished_at=datetime(2026, 5, 18, 16, 0, 5, tzinfo=timezone.utc),
                protocol="tcp",
                findings=[],
                raw_results=[],
            )
            sink.persist_findings(
                scan_id="11111111-1111-1111-1111-111111111111",
                batch=[],
                result=scan_result,
            )

            failure_records = [
                r for r in records if "save_findings_batch failed" in str(r["message"])
            ]
            assert failure_records, (
                "Expected a logger.exception() record for save_findings_batch failure; got: "
                + repr([r["message"] for r in records])
            )
            rec = failure_records[0]
            assert rec["exception"] is not None, "exception() must attach the traceback"
            # Structured fields land in ``record["extra"]`` (loguru ``bind()``).
            assert rec["extra"].get("scan_id") == "11111111-1111-1111-1111-111111111111"
            assert rec["extra"].get("batch_size") == 0
            # ``module_name`` not ``module`` — ``module`` is reserved as the
            # orchestrator-bound correlation field in log_config.
            assert rec["extra"].get("module_name") == "T1046/port_scan"
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=2.0)
    finally:
        logger.remove(handler_id)
        loop.close()


# ---- HC7: serialize fallback documentation ----


def test_serialize_module_results_catch_alls_carry_noqa_rationale() -> None:
    """The ``serialize_module_results`` duck-typing fallbacks SHALL be
    annotated blanket-except rationale blocks per HC7 acceptance
    criterion (c) — each ``except Exception`` carries a documented
    suppression marker explaining why the broad catch is intentional.

    SCAN-033 moved the function to ``src/otalon_scan/api/serializers.py`` and dropped
    the leading underscore; the fallback contract is unchanged.
    """
    src = (_PROJECT_SRC / "api" / "serializers.py").read_text()
    # Locate the function body and assert every ``except Exception``
    # inside it carries the documented suppression marker.
    match = re.search(
        r"def serialize_module_results\(.*?\n(?=\n\ndef |\Z)",
        src,
        re.DOTALL,
    )
    assert match, "serialize_module_results function not found"
    body = match.group(0)
    bare_catches = re.findall(r"except Exception:\s*\n", body)
    documented_catches = re.findall(r"except Exception:\s*# noqa: BLE001", body)
    assert not bare_catches, (
        "serialize_module_results contains undocumented "
        f"`except Exception` blocks ({len(bare_catches)}); "
        "HC7 requires `# noqa: BLE001 -- <reason>` on each."
    )
    assert documented_catches, (
        "serialize_module_results SHOULD contain documented "
        "`# noqa: BLE001` fallback blocks per HC7."
    )
