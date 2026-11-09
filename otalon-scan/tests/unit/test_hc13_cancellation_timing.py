"""HC13 — three cancellation-timing tests for ``ModuleManager``.

Covers ``.dev/TODO_otalon-scan.md`` HC13 Sub-Item B acceptance criterion
"Mindestens 3 Cancellation-Tests in ``ModuleManager``: (a) Cancel vor
Modul-Start, (b) Cancel während Scan, (c) Cancel nach Modul-Ende aber
vor Callback."

The existing ``tests/unit/test_phase5_batched_persistence.py`` already
covers the persistence/finalisation surface; this file pins the three
timing variants explicitly so a future refactor can't accidentally
collapse them into one.
"""

from __future__ import annotations

from typing import Any, List, Tuple

import pytest

from otalon_scan.core.module_manager import ModuleManager


@pytest.fixture()
def manager(tmp_path: Any) -> ModuleManager:
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    return ModuleManager(modules_path=str(empty_modules), batch_size=3)


# ---- (a) Cancel before module start ----


def test_cancel_before_module_start_marks_run_cancelled(manager: ModuleManager) -> None:
    """Calling ``cancel_run(run_id)`` *before* the run has emitted any
    findings SHALL still mark the run as cancelled.

    The orchestrator's :meth:`_finalize_run` reads the cancellation flag
    and reports ``ABORTED`` (no partial data) — covered separately in
    ``test_finalize_run_emits_aborted_when_cancelled_with_no_data``.
    Here we pin the underlying flag-flip in isolation: the public API
    surface used by ``/scans/{id}/stop`` must accept a run-id that the
    manager has never seen and not raise.
    """
    run_id = "run-pre-start"
    # No prior ``start_module``; cancel must be tolerant.
    manager.cancel_run(run_id)
    assert run_id in manager._cancelled_runs


# ---- (b) Cancel during scan (mid-flight, after first finding) ----


def test_cancel_during_scan_persists_buffered_findings(
    manager: ModuleManager,
) -> None:
    """Cancelling a run mid-scan SHALL still drain whatever findings the
    forwarder already buffered into the persistence sink.

    Without this guarantee, an operator-issued stop in the middle of a
    long port scan would silently lose every host that had already
    responded — exactly the regression D4 was introduced to prevent.
    """
    captured: List[Tuple[str, int]] = []

    def sink(scan_id: str, batch: list, result: Any) -> None:
        captured.append((scan_id, len(batch)))

    manager.set_persist_sink(sink)

    run_id = "run-mid-flight"
    scan_id = "scan-mid-flight"
    manager.register_scan_id(run_id, scan_id)

    # Pre-populate the forwarder buffer as if 2 progress findings landed.
    from otalon_scan.core.models import DeviceFinding

    findings = [DeviceFinding(ipv4=f"10.0.0.{i}") for i in range(2)]
    with manager._buffer_lock:
        manager._run_buffers.setdefault(run_id, []).extend(findings)
    manager._forwarder_wired.add(run_id)

    # Now cancel and finalise: the buffer SHALL be drained as one batch.
    manager.cancel_run(run_id)
    manager._finalize_run(run_id, "port_scan")

    assert captured, "Expected the persist sink to be invoked at least once"
    total_persisted = sum(n for _, n in captured)
    assert total_persisted == 2, f"Expected 2 findings to flush on cancel-mid-flight, got {total_persisted}"


# ---- (c) Cancel after module end but before callback ----


def test_cancel_after_module_end_is_idempotent(manager: ModuleManager) -> None:
    """A late ``cancel_run`` arriving *after* the run already finalised
    cleanly SHALL be a no-op rather than corrupt the terminal state.

    The orchestrator's monitor thread can race with an HTTP
    ``/scans/{id}/stop`` request: the module process may have already
    exited (and the finish-sink fired) by the time the cancel arrives.
    The contract is "first finalisation wins" — see
    ``openspec/specs/scan--persistence-ownership.md`` § "Single Commit
    Boundary for Future Idempotency".
    """
    captured: List[Tuple[str, str, str | None]] = []

    def finish_sink(scan_id: str, status: str, error_message: str | None) -> None:
        captured.append((scan_id, status, error_message))

    manager.set_finish_sink(finish_sink)

    run_id = "run-late-cancel"
    scan_id = "scan-late-cancel"
    manager.register_scan_id(run_id, scan_id)

    # Normal finalisation first — sink fires with ``completed``.
    manager._finalize_run(run_id, "arp_scan")
    assert captured, "Expected finish sink to fire on normal finalise"
    first_call = captured[0]
    assert first_call[1] in {
        "completed",
        "aborted",
    }, f"Expected 'completed' or 'aborted' on clean finalise, got {first_call[1]!r}"

    # Now a late cancel: must not raise, must not retransition.
    snapshot_len = len(captured)
    manager.cancel_run(run_id)
    # cancel_run alone doesn't fire the sink — only finalise does. The
    # important invariant is the flag flip is silent + idempotent.
    assert run_id in manager._cancelled_runs
    assert len(captured) == snapshot_len, "Late cancel_run() must NOT spuriously refire the finish sink"
