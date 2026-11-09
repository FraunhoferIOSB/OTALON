"""Regression tests for SC-05 (SUITE-031 audit): double-write window between
``register_scan_id`` forwarder wiring and ``_finalize_run`` source selection.

Root cause: ``_finalize_run`` can complete via the legacy terminal-payload
path (when the ``scan_id`` was seeded into ``module_results`` directly, or
whenever its deferral check passed before registration). Afterwards
``register_scan_id`` would still wire the SSE forwarder for the finished run:
the forwarder then drains the child's mp queue and feeds the same findings
through ``_on_forwarder_item`` → ``_persist_batch`` a SECOND time.

Fix: ``register_scan_id`` decides the wiring inside the
``_pending_finalize_lock`` critical section (atomically with the
``_finalize_run`` deferral check) and skips the wiring entirely for a run
that is already finalised (HC12 set), so a finished run's findings are
written exactly once.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import threading
import time
from typing import Any, List, Tuple

import pytest

from otalon_scan.core.module_manager import _PROGRESS_DONE, ModuleManager

_FINDING: dict = {"ipv4": "192.0.2.44", "mac": "02:00:00:00:00:2c", "vendor": "ACME"}


@pytest.fixture()
def manager(tmp_path: Any) -> Any:
    """ModuleManager with batch_size=1 so one buffered finding flushes."""
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    mgr = ModuleManager(modules_path=str(empty_modules), batch_size=1)
    yield mgr
    mgr.manager.shutdown()


@pytest.fixture()
def bus_loop() -> Any:
    """A real event loop running in a daemon thread for the progress bus."""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, name="sc05-bus-loop", daemon=True)
    t.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    t.join(timeout=5.0)
    loop.close()


def test_register_finalize_boundary_writes_findings_exactly_once(
    manager: ModuleManager, bus_loop: Any, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The SC-05 window: ``register_scan_id`` has already made the scan_id
    visible and fetched the mp queue, but the monitor thread's
    ``_finalize_run`` runs BEFORE the forwarder wiring lands in
    ``_forwarder_wired`` — so finalise picks the legacy terminal-payload
    source while the forwarder still drains the same findings off the mp
    queue. The finding must be persisted exactly once.

    The interleaving is made deterministic by interposing the monitor
    finalise inside ``start_forwarder``.
    """
    persisted: List[Tuple[str, int]] = []

    def persist_sink(scan_id: str, batch: List[Any], result: Any) -> None:
        if batch:
            persisted.append((scan_id, len(batch)))

    manager.set_persist_sink(persist_sink)
    manager.progress_bus.attach_loop(bus_loop)

    uid = "run-sc05"
    scan_id = "scan-sc05"
    manager.module_results[uid] = {
        "module_name": "arp_scan",
        "results": None,
        "scan_result": None,
        "findings": [dict(_FINDING)],
        "scan_id": scan_id,
    }
    mp_q: "multiprocessing.Queue[Any]" = multiprocessing.Queue(maxsize=100)
    mp_q.put({"event": "progress", "data": {"module_name": "arp_scan", "message": "found", "finding": dict(_FINDING)}})
    mp_q.put(dict(_PROGRESS_DONE))
    manager._progress_mp_queues[uid] = mp_q

    real_start_forwarder = manager.progress_bus.start_forwarder

    def _racing_start_forwarder(sid: str, q: Any, on_item: Any = None) -> None:
        # The monitor thread wins the boundary race: finalise runs after the
        # scan_id became visible but (pre-fix) before ``_forwarder_wired``
        # reflects the wiring, so it takes the legacy terminal-payload path.
        manager._finalize_run(uid, "arp_scan")
        real_start_forwarder(sid, q, on_item=on_item)

    monkeypatch.setattr(manager.progress_bus, "start_forwarder", _racing_start_forwarder)

    manager.register_scan_id(uid, scan_id)

    # Give the forwarder thread time to drain the mp queue and flush.
    deadline = time.monotonic() + 3.0
    while time.monotonic() < deadline:
        if sum(count for _, count in persisted) >= 2:
            break
        time.sleep(0.02)

    total_findings = sum(count for _, count in persisted)
    assert total_findings == 1, (
        f"finding persisted {total_findings} times ({persisted}) — double-write "
        "across the register/finalize boundary (SC-05)"
    )


def test_register_after_finalize_does_not_wire_forwarder(manager: ModuleManager, bus_loop: Any) -> None:
    """A run that completed finalisation BEFORE registration must never get
    a forwarder wired afterwards (its queue events would re-enter the
    persistence buffer)."""
    persisted: List[Tuple[str, int]] = []

    def persist_sink(scan_id: str, batch: List[Any], result: Any) -> None:
        if batch:
            persisted.append((scan_id, len(batch)))

    manager.set_persist_sink(persist_sink)
    manager.progress_bus.attach_loop(bus_loop)

    uid = "run-sc05-post"
    scan_id = "scan-sc05-post"
    manager.module_results[uid] = {
        "module_name": "arp_scan",
        "results": None,
        "scan_result": None,
        "findings": [dict(_FINDING)],
        "scan_id": scan_id,
    }
    mp_q: "multiprocessing.Queue[Any]" = multiprocessing.Queue(maxsize=100)
    mp_q.put({"event": "progress", "data": {"module_name": "arp_scan", "message": "found", "finding": dict(_FINDING)}})
    mp_q.put(dict(_PROGRESS_DONE))
    manager._progress_mp_queues[uid] = mp_q

    manager._finalize_run(uid, "arp_scan")
    assert persisted == [(scan_id, 1)]

    manager.register_scan_id(uid, scan_id)

    deadline = time.monotonic() + 2.0
    while time.monotonic() < deadline and sum(count for _, count in persisted) < 2:
        time.sleep(0.02)

    assert uid not in manager._forwarder_wired
    assert persisted == [(scan_id, 1)]


def test_register_before_finalize_still_wires_forwarder(manager: ModuleManager, bus_loop: Any) -> None:
    """Normal ordering guard: a live run registered BEFORE finalisation keeps
    its forwarder wiring (the SSE stream must not regress)."""
    manager.progress_bus.attach_loop(bus_loop)

    uid = "run-sc05-live"
    scan_id = "scan-sc05-live"
    manager.module_results[uid] = None  # child has not written a terminal payload yet
    mp_q: "multiprocessing.Queue[Any]" = multiprocessing.Queue(maxsize=100)
    manager._progress_mp_queues[uid] = mp_q

    manager.register_scan_id(uid, scan_id)

    assert uid in manager._forwarder_wired
