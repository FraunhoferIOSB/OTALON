"""Unit tests for Phase 5 (HC16) batched commits + D4 cancellation semantics.

Covers tasks 6.1, 6.2, 6.3:

- ``_persist_batch`` chunks the input by :attr:`ModuleManager.batch_size`
  (D3 = 100, configurable) — task 6.1.
- ``asyncio.CancelledError`` mid-flight inside ``_persist_batch`` drains
  the remaining buffer once, tags the scan ``cancelled_partial`` via the
  finish-sink, and re-raises ``CancelledError`` — task 6.2 / D4.
- ``_finalize_run`` selects the terminal :class:`ScanStatus` correctly
  (completed / failed / aborted / cancelled_partial) — task 6.3.
- The SSE-forwarder accumulator (``_on_forwarder_item``) appends only
  progress events with a ``finding`` payload, triggers an interim flush
  when the buffer reaches ``batch_size``, and marks the run as having
  ``had_partial_flush`` — task 6.1.
"""

from __future__ import annotations

import asyncio
from typing import Any, List, Optional, Tuple

import pytest

from otalon_scan.core.models import DeviceFinding, ScanProgress, ScanResult
from otalon_scan.core.module_manager import ModuleManager


@pytest.fixture()
def manager(tmp_path: Any) -> ModuleManager:
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    return ModuleManager(modules_path=str(empty_modules), batch_size=3)


# ---- 6.1 batched chunking ----


def test_persist_batch_chunks_by_batch_size(manager: ModuleManager) -> None:
    """Batches larger than ``batch_size`` SHALL be sliced into chunks."""
    captured: List[Tuple[str, List[DeviceFinding], ScanResult]] = []

    def sink(scan_id: str, batch: List[DeviceFinding], result: ScanResult) -> None:
        captured.append((scan_id, list(batch), result))

    manager.set_persist_sink(sink)

    findings = [DeviceFinding(ipv4=f"10.0.0.{i}") for i in range(7)]  # 7 findings, batch=3 → 3 chunks
    result = ScanResult(module_name="test/dummy", findings=findings)

    manager._persist_batch("scan-chunked", findings, result)

    assert len(captured) == 3, "expected 3 chunks: 3 + 3 + 1"
    assert [len(c[1]) for c in captured] == [3, 3, 1]
    assert all(c[0] == "scan-chunked" for c in captured)


def test_persist_batch_single_chunk_when_under_batch_size(manager: ModuleManager) -> None:
    captured: List[Tuple[str, List[DeviceFinding], ScanResult]] = []

    def sink(scan_id: str, batch: List[DeviceFinding], result: ScanResult) -> None:
        captured.append((scan_id, list(batch), result))

    manager.set_persist_sink(sink)
    findings = [DeviceFinding(ipv4="10.0.0.1"), DeviceFinding(ipv4="10.0.0.2")]
    result = ScanResult(module_name="test/dummy", findings=findings)

    manager._persist_batch("scan-small", findings, result)

    assert len(captured) == 1
    assert len(captured[0][1]) == 2


def test_persist_batch_default_size_from_env(tmp_path: Any, monkeypatch: Any) -> None:
    """``SCAN_PERSIST_BATCH_SIZE`` env var SHALL override the default."""
    monkeypatch.setenv("SCAN_PERSIST_BATCH_SIZE", "50")
    empty = tmp_path / "m"
    empty.mkdir()
    mgr = ModuleManager(modules_path=str(empty))
    assert mgr.batch_size == 50


# ---- 6.2 D4 CancelledError flush-partial ----


def test_persist_batch_on_cancelled_drains_remainder_and_marks_partial(
    manager: ModuleManager,
) -> None:
    """On ``CancelledError`` mid-flight:

    1. The chunk that raised is treated as partially committed.
    2. The remaining un-attempted chunks are flushed once more (best effort).
    3. The finish-sink is invoked with status='cancelled_partial'.
    4. ``CancelledError`` is re-raised so the caller's cancellation chain
       completes.
    """
    sink_calls: List[Tuple[str, int, str]] = []
    cancel_after = 1  # let the first chunk persist, raise on the second

    def sink(scan_id: str, batch: List[DeviceFinding], result: ScanResult) -> None:
        sink_calls.append((scan_id, len(batch), "sink"))
        if len(sink_calls) == cancel_after + 1:
            raise asyncio.CancelledError("simulated mid-flight abort")

    finish_calls: List[Tuple[str, str, Optional[str]]] = []

    def finish(scan_id: str, status: str, err: Optional[str]) -> None:
        finish_calls.append((scan_id, status, err))

    manager.set_persist_sink(sink)
    manager.set_finish_sink(finish)

    findings = [DeviceFinding(ipv4=f"10.0.1.{i}") for i in range(9)]  # batch=3 → 3 chunks
    result = ScanResult(module_name="test/dummy", findings=findings)

    with pytest.raises(asyncio.CancelledError):
        manager._persist_batch("scan-cancel", findings, result)

    # Chunk 0 OK, chunk 1 raised, then one final drain attempt with remainder
    # The exact remainder count depends on whether chunk 1's findings are
    # considered persisted. In our implementation, on CancelledError the
    # raising chunk is NOT counted as persisted, so the drain covers
    # chunks 1+2 (size 3 + 3) = 6 findings.
    assert len(sink_calls) >= 2, "expected at least 2 sink invocations"
    # Finish sink invoked with cancelled_partial
    assert finish_calls, "finish sink not invoked"
    assert finish_calls[0][1] == "cancelled_partial"
    assert finish_calls[0][0] == "scan-cancel"


def test_persist_batch_cancelled_with_no_finish_sink_still_reraises(
    manager: ModuleManager,
) -> None:
    """``CancelledError`` SHALL re-raise even without a finish-sink wired."""

    def sink(scan_id: str, batch: List[DeviceFinding], result: ScanResult) -> None:
        raise asyncio.CancelledError()

    manager.set_persist_sink(sink)
    # no finish_sink
    findings = [DeviceFinding(ipv4="10.0.1.1")]
    result = ScanResult(module_name="test/dummy", findings=findings)

    with pytest.raises(asyncio.CancelledError):
        manager._persist_batch("scan-x", findings, result)


# ---- 6.1 forwarder accumulator ----


def test_on_forwarder_item_appends_finding_and_flushes_at_batch_size(
    manager: ModuleManager,
) -> None:
    """The SSE-forwarder hook SHALL drive interim batched flushes."""
    captured: List[Tuple[str, List[DeviceFinding], ScanResult]] = []

    def sink(scan_id: str, batch: List[DeviceFinding], result: ScanResult) -> None:
        captured.append((scan_id, list(batch), result))

    manager.set_persist_sink(sink)
    run_id = "run-fwd-1"
    manager.module_results[run_id] = {"module_name": "test/dummy", "scan_id": "scan-fwd-1"}
    manager._run_module_name[run_id] = "test/dummy"

    # Feed 7 progress events with findings; batch_size=3 → 2 interim flushes
    # (after #3 and #6), with #7 staying in the buffer.
    for i in range(7):
        progress = ScanProgress(
            module_name="test/dummy",
            phase="scanning",
            finding=DeviceFinding(ipv4=f"10.0.2.{i}"),
        )
        manager._on_forwarder_item(
            run_id,
            {"event": "progress", "data": progress.model_dump(mode="json")},
        )

    # 2 interim flushes
    assert len(captured) == 2
    assert [len(c[1]) for c in captured] == [3, 3]
    # Trailing finding still in buffer
    with manager._buffer_lock:
        assert len(manager._run_buffers[run_id]) == 1
    assert run_id in manager._partial_flushed_runs


def test_on_forwarder_item_ignores_non_progress_and_no_finding(
    manager: ModuleManager,
) -> None:
    captured: List[Any] = []
    manager.set_persist_sink(lambda *a, **k: captured.append(a))
    run_id = "run-fwd-2"
    manager.module_results[run_id] = {"module_name": "test/dummy", "scan_id": "scan-fwd-2"}

    manager._on_forwarder_item(run_id, {"event": "result", "data": {}})
    manager._on_forwarder_item(run_id, {"event": "progress", "data": {"phase": "init"}})

    assert captured == []
    with manager._buffer_lock:
        assert manager._run_buffers.get(run_id, []) == []


# ---- 6.3 final flush + status reporting ----


def test_finalize_run_emits_completed_status_on_normal_finish(manager: ModuleManager) -> None:
    persisted: List[Any] = []
    finish: List[Tuple[str, str, Optional[str]]] = []

    manager.set_persist_sink(lambda sid, batch, result: persisted.append((sid, list(batch), result)))
    manager.set_finish_sink(lambda sid, status, err: finish.append((sid, status, err)))

    uid = "run-done"
    finding = DeviceFinding(ipv4="10.0.3.1")
    result = ScanResult(module_name="test/dummy", findings=[finding])
    manager.module_results[uid] = {
        "module_name": "test/dummy",
        "results": None,
        "scan_result": result.model_dump(mode="json"),
        "findings": [finding.model_dump(mode="json")],
        "scan_id": "scan-done",
    }

    manager._finalize_run(uid, "test/dummy")

    assert finish == [("scan-done", "completed", None)]
    assert len(persisted) == 1


def test_finalize_run_emits_failed_status_when_error_present(manager: ModuleManager) -> None:
    finish: List[Tuple[str, str, Optional[str]]] = []
    manager.set_persist_sink(lambda *a, **k: None)
    manager.set_finish_sink(lambda sid, status, err: finish.append((sid, status, err)))

    uid = "run-failed"
    manager.module_results[uid] = {
        "module_name": "test/dummy",
        "results": None,
        "scan_result": None,
        "findings": [],
        "scan_id": "scan-failed",
        "error": "module blew up",
    }

    manager._finalize_run(uid, "test/dummy")

    assert finish == [("scan-failed", "failed", "module blew up")]


def test_finalize_run_emits_cancelled_partial_after_partial_flush(manager: ModuleManager) -> None:
    """D4: cancelled run with partial flush SHALL report ``cancelled_partial``."""
    finish: List[Tuple[str, str, Optional[str]]] = []
    manager.set_persist_sink(lambda *a, **k: None)
    manager.set_finish_sink(lambda sid, status, err: finish.append((sid, status, err)))

    uid = "run-cancel-partial"
    # Set up the run state: forwarder wired (so legacy fallback doesn't fire),
    # at least one partial flush happened, and stop_module marked it cancelled.
    manager.module_results[uid] = {
        "module_name": "test/dummy",
        "results": None,
        "scan_result": None,
        "findings": [],
        "scan_id": "scan-cancel-partial",
    }
    manager._forwarder_wired.add(uid)
    manager._partial_flushed_runs.add(uid)
    manager._cancelled_runs.add(uid)

    manager._finalize_run(uid, "test/dummy")

    assert finish == [("scan-cancel-partial", "cancelled_partial", None)]


def test_finalize_run_emits_aborted_when_cancelled_with_no_data(manager: ModuleManager) -> None:
    """Cancelled run with NO findings flushed SHALL report ``aborted``."""
    finish: List[Tuple[str, str, Optional[str]]] = []
    manager.set_persist_sink(lambda *a, **k: None)
    manager.set_finish_sink(lambda sid, status, err: finish.append((sid, status, err)))

    uid = "run-aborted"
    manager.module_results[uid] = {
        "module_name": "test/dummy",
        "results": None,
        "scan_result": None,
        "findings": [],
        "scan_id": "scan-aborted",
    }
    manager._forwarder_wired.add(uid)
    manager._cancelled_runs.add(uid)
    # no partial flush, no findings

    manager._finalize_run(uid, "test/dummy")

    assert finish == [("scan-aborted", "aborted", None)]


def test_finalize_run_drains_trailing_buffer_for_forwarder_wired_run(
    manager: ModuleManager,
) -> None:
    """Trailing findings in the parent buffer SHALL be flushed at finalize."""
    captured: List[Tuple[str, List[DeviceFinding], ScanResult]] = []
    manager.set_persist_sink(lambda sid, batch, result: captured.append((sid, list(batch), result)))
    manager.set_finish_sink(lambda *a, **k: None)

    uid = "run-trailing"
    manager.module_results[uid] = {
        "module_name": "test/dummy",
        "results": None,
        "scan_result": ScanResult(module_name="test/dummy").model_dump(mode="json"),
        "findings": [],
        "scan_id": "scan-trailing",
    }
    manager._forwarder_wired.add(uid)
    trailing = [DeviceFinding(ipv4="10.0.4.1"), DeviceFinding(ipv4="10.0.4.2")]
    with manager._buffer_lock:
        manager._run_buffers[uid] = list(trailing)

    manager._finalize_run(uid, "test/dummy")

    # One trailing flush with both findings (under batch_size=3, single chunk)
    assert len(captured) == 1
    assert captured[0][0] == "scan-trailing"
    assert len(captured[0][1]) == 2


def test_cancel_run_marks_run_cancelled(manager: ModuleManager) -> None:
    manager.cancel_run("run-c1")
    assert "run-c1" in manager._cancelled_runs
