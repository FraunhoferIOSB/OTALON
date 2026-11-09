"""Regression tests for B-E3 / B-E4 (otalon-scan stuck-RUNNING scans).

Bug B-E3 (``.dev/TODO_otalon-scan.md`` § Hoch, confirmed open 2026-06-04):
roughly 46 % of finished scans never flipped ``status`` from ``RUNNING`` to a
terminal value even though ``finished_at`` had been stamped, producing the
inconsistent end-state ``finished_at != NULL AND status = RUNNING``.

Two cooperating root causes were fixed:

1. The persistence result-normalizers
   :meth:`ScannerPostgresRepo.save_arp_scan_results` and
   :meth:`ScannerPostgresRepo.save_port_scan_results` used to stamp
   ``finished_at`` without setting ``status``. The terminal lifecycle is now
   owned exclusively by :meth:`ScannerPostgresRepo.finish_scan`, which sets
   both columns atomically.
2. A fast scan could complete — and the monitor thread fire
   :meth:`ModuleManager._finalize_run` — before the API layer had called
   :meth:`ModuleManager.register_scan_id` to write the persistence
   ``scan_id``. Finalising against the run UUID made ``finish_scan`` no-op on
   a missing row. ``_finalize_run`` now defers when the scan_id is unknown and
   :meth:`register_scan_id` re-drives the terminal transition against the real
   DB UUID.

Bug B-E4 is a direct consequence: the ``cyberscan_scan_duration_seconds``
histogram is observed inside the same finish-sink path, so an unreliable
finish-sink meant the histogram never recorded a sample. Once the finish-sink
runs reliably the histogram observes ``_count > 0``.

These tests are pure unit tests — no PostgreSQL, no event loop owned by the
test framework beyond the explicit one in the B-E4 case. The ``ModuleManager``
is pointed at an empty modules directory (no discovery) and driven through its
public-ish lifecycle methods, mirroring ``test_hc12_idempotency_guard.py``.
"""

from __future__ import annotations

import threading
from typing import Any, List, Optional, Tuple

import pytest

from otalon_scan.core.module_manager import ModuleManager


@pytest.fixture()
def manager(tmp_path: Any) -> ModuleManager:
    """A ModuleManager over an empty modules dir (no discovery required)."""
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    return ModuleManager(modules_path=str(empty_modules), batch_size=3)


def _seed_completed_child_payload(
    manager: ModuleManager,
    uid: str,
    *,
    module: str = "arp_scan",
    error: Optional[str] = None,
    findings: Optional[List[dict]] = None,
) -> None:
    """Emulate the child process having written its terminal payload.

    Mirrors the shape written by ``_run_module_proc`` into
    ``module_results[uid]`` *before* ``register_scan_id`` has run, so no
    ``scan_id`` key is present yet.
    """
    payload: dict = {
        "module_name": module,
        "results": None,
        "scan_result": None,
        "findings": findings or [],
    }
    if error is not None:
        payload["error"] = error
    manager.module_results[uid] = payload


# ---- 1. Deferred finalisation is re-driven on registration (the core race) ----


def test_finalize_before_register_defers_then_completes_on_register(
    manager: ModuleManager,
) -> None:
    """A run that finishes before ``register_scan_id`` must still reach a
    terminal status — addressed to the DB scan_id, never the run UUID.

    This is the exact B-E3 race: monitor fires ``_finalize_run`` first,
    ``register_scan_id`` arrives second.
    """
    finish_calls: List[Tuple[str, str, Optional[str]]] = []

    def finish_sink(scan_id: str, status: str, error_message: Optional[str]) -> None:
        finish_calls.append((scan_id, status, error_message))

    manager.set_finish_sink(finish_sink)

    uid = "run-fast"
    db_scan_id = "11111111-1111-1111-1111-111111111111"
    _seed_completed_child_payload(manager, uid, module="arp_scan")

    # Monitor thread fires first — scan_id not registered yet.
    manager._finalize_run(uid, "arp_scan")
    # No terminal transition yet: it was deferred, not lost.
    assert finish_calls == []
    assert uid in manager._pending_finalize

    # API layer registers the DB scan_id second — this must re-drive the
    # finalisation against the real row.
    manager.register_scan_id(uid, db_scan_id)

    assert len(finish_calls) == 1
    addressed_scan_id, status, error_message = finish_calls[0]
    # The finish-sink MUST address the DB scan_id, not the run UUID.
    assert addressed_scan_id == db_scan_id
    assert addressed_scan_id != uid
    assert status == "completed"
    assert error_message is None
    # Pending entry was consumed.
    assert uid not in manager._pending_finalize


# ---- 2. Normal ordering still fires exactly once (no double-finalise) ----


def test_register_then_finalize_completes_once(manager: ModuleManager) -> None:
    """When ``register_scan_id`` runs before ``_finalize_run`` (the common
    slow-scan ordering) the scan still transitions exactly once."""
    finish_calls: List[Tuple[str, str, Optional[str]]] = []
    manager.set_finish_sink(lambda s, st, e: finish_calls.append((s, st, e)))

    uid = "run-normal"
    db_scan_id = "22222222-2222-2222-2222-222222222222"
    _seed_completed_child_payload(manager, uid, module="port_scan")

    manager.register_scan_id(uid, db_scan_id)
    # No deferral happened (scan_id was already present at registration time).
    assert uid not in manager._pending_finalize

    manager._finalize_run(uid, "port_scan")
    # A second finalise (monitor + cleanup race) must be a HC12 no-op.
    manager._finalize_run(uid, "port_scan")

    assert len(finish_calls) == 1
    assert finish_calls[0][0] == db_scan_id
    assert finish_calls[0][1] == "completed"


# ---- 3. Error path yields a terminal FAILED status, never stuck RUNNING ----


def test_deferred_error_run_transitions_to_failed(manager: ModuleManager) -> None:
    """A run that errored before registration must finalise as ``failed``."""
    finish_calls: List[Tuple[str, str, Optional[str]]] = []
    manager.set_finish_sink(lambda s, st, e: finish_calls.append((s, st, e)))

    uid = "run-error"
    db_scan_id = "33333333-3333-3333-3333-333333333333"
    _seed_completed_child_payload(manager, uid, module="port_scan", error="module crashed mid-scan")

    manager._finalize_run(uid, "port_scan")
    assert finish_calls == []  # deferred

    manager.register_scan_id(uid, db_scan_id)

    assert len(finish_calls) == 1
    scan_id, status, error_message = finish_calls[0]
    assert scan_id == db_scan_id
    assert status == "failed"
    assert error_message == "module crashed mid-scan"


# ---- 4. Cancel/abort path on the deferred race ----


def test_deferred_cancelled_run_transitions_to_terminal(manager: ModuleManager) -> None:
    """A cancelled run that finished before registration must finalise on a
    terminal status (``aborted`` with no findings flushed), not ``RUNNING``."""
    finish_calls: List[Tuple[str, str, Optional[str]]] = []
    manager.set_finish_sink(lambda s, st, e: finish_calls.append((s, st, e)))

    uid = "run-cancelled"
    db_scan_id = "44444444-4444-4444-4444-444444444444"
    _seed_completed_child_payload(manager, uid, module="arp_scan")
    manager.cancel_run(uid)  # operator stop arrived before the child exited

    manager._finalize_run(uid, "arp_scan")
    assert finish_calls == []  # deferred

    manager.register_scan_id(uid, db_scan_id)

    assert len(finish_calls) == 1
    scan_id, status, _ = finish_calls[0]
    assert scan_id == db_scan_id
    # Terminal status — the invariant is "not RUNNING"; no findings were
    # flushed so D4 picks ABORTED over CANCELLED_PARTIAL.
    assert status in {"aborted", "cancelled_partial"}
    assert status != "running"


# ---- 5. A run whose child wrote nothing still gets a terminal status ----


def test_missing_child_payload_deferred_then_failed(manager: ModuleManager) -> None:
    """If the child wrote no ``module_results`` entry (e.g. fatal import error)
    the run is still deferred and then transitioned away from RUNNING once the
    scan_id is registered."""
    finish_calls: List[Tuple[str, str, Optional[str]]] = []
    manager.set_finish_sink(lambda s, st, e: finish_calls.append((s, st, e)))

    uid = "run-no-payload"
    db_scan_id = "55555555-5555-5555-5555-555555555555"
    # Intentionally do NOT seed module_results[uid].

    manager._finalize_run(uid, "snmp_scan")
    assert uid in manager._pending_finalize
    assert finish_calls == []

    # Now the API registers the scan_id and seeds the (empty) payload, as the
    # real register path does via module_results write.
    manager.register_scan_id(uid, db_scan_id)

    # register_scan_id wrote a module_results entry with the scan_id, so the
    # re-driven finalise resolves the row and transitions it.
    assert len(finish_calls) == 1
    scan_id, status, _ = finish_calls[0]
    assert scan_id == db_scan_id
    assert status != "running"


# ---- 6. B-E4: the duration histogram is observed by the finish-sink ----


def test_finish_sink_observes_duration_histogram() -> None:
    """B-E4: ``cyberscan_scan_duration_seconds`` records a sample once the
    orchestrator finish-sink runs against a reachable repo.

    Exercises the real ``otalon_scan.api.scan_sink.ScanSink.finish_scan`` against a fake async
    repo and a dedicated event loop running in a background thread (the same
    ``run_coroutine_threadsafe`` dispatch shape production uses). With the
    B-E3 fix the finish-sink now runs reliably, so the histogram observes a
    sample and exposes ``_count > 0``.
    """
    import asyncio
    from datetime import datetime, timedelta, timezone

    from prometheus_client import generate_latest

    from otalon_scan.api.metrics import SCAN_DURATION_SECONDS
    from otalon_scan.api.scan_sink import ScanSink
    from otalon_scan.api.state import ApiState
    from otalon_scan.repositories.models import ScanStatus

    started = datetime(2026, 6, 4, 12, 0, 0, tzinfo=timezone.utc)
    finished = started + timedelta(seconds=2.5)

    class _FakeScanRow:
        def __init__(self) -> None:
            self.module_name = "arp_scan"
            self.started_at = started
            self.finished_at = finished
            self.status = ScanStatus.COMPLETED

    class _FakeRepo:
        def __init__(self) -> None:
            self.finished: List[Tuple[str, ScanStatus, Optional[str]]] = []

        async def finish_scan(
            self,
            scan_id: str,
            status: ScanStatus,
            error_message: Optional[str] = None,
        ) -> None:
            self.finished.append((scan_id, status, error_message))

        async def get_scan(self, scan_id: str) -> _FakeScanRow:
            return _FakeScanRow()

    # Snapshot the histogram sample count before the observation. The metric
    # is a process-global singleton, so we assert a strict increase rather
    # than an absolute value to stay robust against other tests.
    label = SCAN_DURATION_SECONDS.labels(module="arp_scan", status="completed")
    before = label._sum.get()

    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, name="be4-test-loop", daemon=True)
    t.start()

    fake_repo = _FakeRepo()
    # SCAN-033: the sink is bound to an ApiState instead of reading module
    # globals, so the test builds its own state rather than patching.
    state = ApiState(repo=fake_repo, main_loop=loop)  # type: ignore[arg-type]
    try:
        ScanSink(state).finish_scan(
            "66666666-6666-6666-6666-666666666666",
            "completed",
            None,
        )
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5.0)
        loop.close()

    # finish_scan was invoked with the COMPLETED enum.
    assert fake_repo.finished, "finish_scan was not called"
    assert fake_repo.finished[0][1] is ScanStatus.COMPLETED

    # The histogram observed the 2.5 s duration → _sum advanced and the
    # exposition now carries a _count series (the B-E4 acceptance).
    after = label._sum.get()
    assert after > before
    assert after - before == pytest.approx(2.5, abs=1e-6)

    body = generate_latest().decode("utf-8")
    assert "cyberscan_scan_duration_seconds_count" in body
