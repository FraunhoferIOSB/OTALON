"""HC12 — idempotency guard for ``ModuleManager._finalize_run``.

Covers ``.dev/TODO_otalon-scan.md`` HC12 acceptance criteria:

- ``ModuleManager`` keeps a ``Set[str]`` of finalised run-ids plus a
  ``threading.Lock`` (or ``asyncio.Lock``).
- A second ``_finalize_run`` call for the same uid logs a warning and
  early-returns without invoking the persist sink or finish sink again.
- Rapid back-to-back finalisation produces exactly one persist-sink
  invocation.
- Cancel + normal termination racing produce exactly one terminal
  status, deterministically the first to complete.
"""

from __future__ import annotations

import threading
from typing import Any, List, Tuple

import pytest

from otalon_scan.core.models import DeviceFinding
from otalon_scan.core.module_manager import ModuleManager


@pytest.fixture()
def manager(tmp_path: Any) -> ModuleManager:
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    return ModuleManager(modules_path=str(empty_modules), batch_size=3)


# ---- 1. Single persist-sink invocation on rapid double-call ----


def test_finalize_run_invoked_twice_produces_single_persist(
    manager: ModuleManager,
) -> None:
    """``_finalize_run(uid)`` SHALL only run its body once per uid.

    Spec: ``.dev/TODO_otalon-scan.md`` HC12 acceptance:
    "Zweimal ``_on_module_finished(run_id)`` rapide hintereinander →
    exakt ein DB-Insert."
    """
    persist_calls: List[Tuple[str, int]] = []

    def persist_sink(scan_id: str, batch: list, result: Any) -> None:
        persist_calls.append((scan_id, len(batch)))

    finish_calls: List[Tuple[str, str, str | None]] = []

    def finish_sink(scan_id: str, status: str, error_message: str | None) -> None:
        finish_calls.append((scan_id, status, error_message))

    manager.set_persist_sink(persist_sink)
    manager.set_finish_sink(finish_sink)

    uid = "run-double-finalise"
    scan_id = "scan-double-finalise"
    manager.register_scan_id(uid, scan_id)

    # Seed a buffered finding via the public state surface so the first
    # finalise has something to persist.
    with manager._buffer_lock:
        manager._run_buffers.setdefault(uid, []).append(DeviceFinding(ipv4="10.0.0.42"))
    manager._forwarder_wired.add(uid)

    manager._finalize_run(uid, "port_scan")
    # Second call — must be a no-op.
    manager._finalize_run(uid, "port_scan")

    assert len(persist_calls) == 1, (
        f"Expected one persist-sink invocation, got {len(persist_calls)}: " f"{persist_calls!r}"
    )
    assert len(finish_calls) == 1, f"Expected one finish-sink invocation, got {len(finish_calls)}: " f"{finish_calls!r}"
    assert finish_calls[0][1] == "completed"


# ---- 2. Cancel + normal-termination race ----


def test_finalize_run_concurrent_cancel_and_normal_yields_one_status(
    manager: ModuleManager,
) -> None:
    """When cancellation arrives concurrently with normal termination,
    exactly one finish-sink call SHALL be emitted. Which one wins is
    deterministic for the same input ordering — the first thread to
    enter the critical section.

    Spec: HC12 acceptance #2 — "Cancel + Normal-Termination gleichzeitig
    → exakt ein Endstatus, deterministisch der erste."
    """
    finish_calls: List[Tuple[str, str, str | None]] = []
    lock = threading.Lock()

    def finish_sink(scan_id: str, status: str, error_message: str | None) -> None:
        with lock:
            finish_calls.append((scan_id, status, error_message))

    manager.set_finish_sink(finish_sink)

    uid = "run-cancel-race"
    scan_id = "scan-cancel-race"
    manager.register_scan_id(uid, scan_id)

    # First thread: normal finalise.
    # Second thread: cancel + finalise from stop-handler.
    barrier = threading.Barrier(2)

    def normal_path() -> None:
        barrier.wait()
        manager._finalize_run(uid, "arp_scan")

    def cancel_path() -> None:
        manager.cancel_run(uid)
        barrier.wait()
        manager._finalize_run(uid, "arp_scan")

    t1 = threading.Thread(target=normal_path)
    t2 = threading.Thread(target=cancel_path)
    t1.start()
    t2.start()
    t1.join(timeout=5.0)
    t2.join(timeout=5.0)

    assert len(finish_calls) == 1, (
        f"HC12: exactly one finish_sink call expected on cancel/normal "
        f"race; got {len(finish_calls)}: {finish_calls!r}"
    )


# ---- 3. State is recorded under the lock ----


def test_finalised_runs_set_records_uid(manager: ModuleManager) -> None:
    """After finalisation, the uid SHALL persist in ``_finalised_runs``.

    Ensures the state used by the guard remains observable for any
    cross-cutting tooling (e.g. log correlation, stop-handler short-
    circuits) and is not silently discarded.

    B-E3 (2026-06-04): a run is only *finalised* (and thus added to
    ``_finalised_runs``) once its persistence ``scan_id`` is known —
    otherwise finalisation is deferred so the terminal-status sink never
    addresses the wrong row. The run is therefore seeded with a scan_id
    so this exercises the genuine finalisation path, not the deferral.
    """
    uid = "run-state-recorded"
    manager.module_results[uid] = {
        "module_name": "snmp_scan",
        "results": None,
        "scan_result": None,
        "findings": [],
        "scan_id": "scan-state-recorded",
    }
    manager._finalize_run(uid, "snmp_scan")
    assert uid in manager._finalised_runs


# ---- 4. Guard does not interfere with first call ----


def test_first_finalize_run_still_produces_terminal_status(
    manager: ModuleManager,
) -> None:
    """The HC12 guard SHALL be invisible to the first caller — the
    completed/aborted/cancelled_partial decision tree continues to
    function. Regression-test for accidental short-circuit.
    """
    finish_calls: List[Tuple[str, str, str | None]] = []
    manager.set_finish_sink(lambda scan_id, status, err: finish_calls.append((scan_id, status, err)))

    uid = "run-first-finalise"
    scan_id = "scan-first-finalise"
    manager.register_scan_id(uid, scan_id)
    manager._finalize_run(uid, "arp_scan")

    assert finish_calls, "Expected the first finalise to still fire finish_sink"
    assert finish_calls[0][1] == "completed"
