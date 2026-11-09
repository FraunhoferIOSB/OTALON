"""Regression tests for UI-173: the terminal ``result`` SSE event SHALL be
emitted AFTER ``persist_findings`` commits ``last_scan_at`` (the persist
sink) and ``finish_scan`` sets the row status, so the UI's finish signal
cannot fire while the just-scanned devices still carry a stale
``last_scan_at``.

Root cause: the child process pushed the terminal ``result`` event onto
the progress mp queue at yield time (``_run_module_proc``) and the
parent-side forwarder fanned it straight out to SSE subscribers — BEFORE
the monitor thread's ``_finalize_run`` ran the trailing ``_persist_batch``
that commits the trailing findings' ``last_scan_at``. The UI has two
finish-signal paths that both fire on the ``result`` SSE event:

- ``ScanRunModal.onStreamEvent`` -> ``emit('finished', ...)``.
- ``JobNotificationListener`` -> ``recordScanTerminal`` ->
  ``jobNotificationsStore.addNotification({status: 'completed'})`` ->
  ``devices.vue`` watcher -> ``refreshDevices()`` (immediate, no delay).

The second path bypasses the UI-170 mitigation's 1.5s delay and refreshes
immediately, reading pre-commit rows — the device badge flaps
grey ("Not in window") -> green once the commit lands.

Fix (backend, three seams):

1. The child (``_run_module_proc``) no longer pushes the terminal
   ``result`` event onto the mp queue; it still publishes live
   ``progress`` events and the ``_PROGRESS_DONE`` sentinel.
2. The forwarder (``_ProgressBus._drain``) no longer fans out the
   terminal ``None`` sentinel on ``_PROGRESS_DONE`` — that would close
   the SSE stream before the deferred ``result`` is emitted. The parent
   owns the authoritative stream close via ``progress_bus.close()`` in
   ``_finalize_run``'s ``finally`` block (after persistence).
3. ``_finalize_run`` emits the deferred ``result`` SSE event onto the
   bus AFTER ``persist_findings`` + ``finish_scan`` complete.
"""

from __future__ import annotations

import asyncio
import multiprocessing
import os
import queue
import signal
import threading
import time
from typing import Any, List

import pytest

from otalon_scan.core.models import DeviceFinding, ScanProgress, ScanResult
from otalon_scan.core.module_manager import _PROGRESS_DONE, ModuleManager

_FINDING: dict = {"ipv4": "192.0.2.44", "mac": "02:00:00:00:00:2c", "vendor": "ACME"}


@pytest.fixture()
def manager(tmp_path: Any) -> Any:
    """ModuleManager with a large batch so the single finding stays buffered
    (no interim forwarder flush) — the trailing ``_persist_batch`` in
    ``_finalize_run`` is the only persist, which must precede the result.
    """
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    mgr = ModuleManager(modules_path=str(empty_modules), batch_size=100)
    yield mgr
    mgr.manager.shutdown()


@pytest.fixture()
def bus_loop() -> Any:
    """A real event loop running in a daemon thread for the progress bus."""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, name="ui173-bus-loop", daemon=True)
    t.start()
    yield loop
    loop.call_soon_threadsafe(loop.stop)
    t.join(timeout=5.0)
    loop.close()


# ---- child: no terminal result on the mp queue ----


class _StubScanModule:
    """In-process stub conforming to the ScanModule protocol — yields one
    progress event (with a finding) then one terminal ScanResult."""

    name = "stub_ui173"

    async def scan(self, config: Any) -> Any:
        finding = DeviceFinding(ipv4="192.0.2.44")
        yield ScanProgress(module_name="stub_ui173", message="found", finding=finding)
        yield ScanResult(module_name="stub_ui173", findings=[finding])


def test_run_module_proc_does_not_push_terminal_result(manager: ModuleManager, monkeypatch: pytest.MonkeyPatch) -> None:
    """UI-173 seam 1: the child SHALL NOT push the terminal ``result`` event
    onto the progress mp queue. Forwarding it here would let the SSE
    forwarder fan it out before ``_finalize_run`` commits ``last_scan_at``.

    Runs ``_run_module_proc`` in-process against a stub module (no real
    subprocess) and drains the queue: progress + ``_PROGRESS_DONE`` only,
    never ``result``.
    """
    monkeypatch.setattr(manager, "_import_module_class", lambda start_path: _StubScanModule)
    monkeypatch.setattr(signal, "signal", lambda *a: None)
    saved_run_id = os.environ.get("OTALON_SCAN_RUN_ID")
    progress_q: "multiprocessing.Queue[Any]" = multiprocessing.Queue(maxsize=100)

    try:
        manager._run_module_proc(
            start_path="<stub>",
            config={},
            shared_results=manager.module_results,
            uid="run-stub-ui173",
            module_name="stub_ui173",
            progress_q=progress_q,
        )
    finally:
        if saved_run_id is None:
            os.environ.pop("OTALON_SCAN_RUN_ID", None)
        else:
            os.environ["OTALON_SCAN_RUN_ID"] = saved_run_id

    drained: List[Any] = []
    while True:
        try:
            drained.append(progress_q.get(timeout=1.0))
        except queue.Empty:
            break

    events = [it for it in drained if isinstance(it, dict) and it.get("__type__") != "__done__"]
    result_events = [it for it in events if it.get("event") == "result"]
    assert result_events == [], (
        f"child pushed terminal result event(s) onto the mp queue: {result_events} — "
        "the terminal result must be deferred to _finalize_run so the UI finish "
        "signal cannot precede the last_scan_at commit (UI-173)"
    )
    assert any(it.get("event") == "progress" for it in events), f"no progress event pushed: {events}"
    assert any(
        isinstance(it, dict) and it.get("__type__") == "__done__" for it in drained
    ), f"no _PROGRESS_DONE sentinel pushed: {drained}"


# ---- parent: deferred result after persistence; stream stays open ----


def test_finalize_run_emits_result_after_persist(manager: ModuleManager, bus_loop: Any) -> None:
    """UI-173 seams 2 + 3: the forwarder SHALL NOT close the SSE stream on
    ``_PROGRESS_DONE`` (the deferred ``result`` would be dropped), and
    ``_finalize_run`` SHALL emit the terminal ``result`` AFTER the persist
    sink commits ``last_scan_at``.

    Setup mirrors a live run: the child pushed a progress event (with a
    finding) and the ``_PROGRESS_DONE`` sentinel, but NO ``result`` event
    (seam 1). The forwarder is wired; the monitor's ``_finalize_run`` is
    driven explicitly. The subscriber must receive the ``result`` event and
    the persist sink must have fired first.
    """
    order: List[str] = []
    manager.set_persist_sink(lambda sid, batch, result: order.append("persist"))
    manager.set_finish_sink(lambda sid, status, err: order.append("finish"))
    manager.progress_bus.attach_loop(bus_loop)

    uid = "run-ui173"
    scan_id = "scan-ui173"
    finding = DeviceFinding.model_validate(_FINDING)
    result = ScanResult(module_name="arp_scan", findings=[finding])
    manager.module_results[uid] = {
        "module_name": "arp_scan",
        "results": None,
        "scan_result": result.model_dump(mode="json"),
        "findings": [dict(_FINDING)],
        "scan_id": scan_id,
    }
    mp_q: "multiprocessing.Queue[Any]" = multiprocessing.Queue(maxsize=100)
    mp_q.put({"event": "progress", "data": {"module_name": "arp_scan", "message": "found", "finding": dict(_FINDING)}})
    mp_q.put(dict(_PROGRESS_DONE))
    manager._progress_mp_queues[uid] = mp_q

    result_seen = threading.Event()

    async def _collect() -> None:
        async for item in manager.progress_bus.subscribe(scan_id):
            if item is not None and item.get("event") == "result":
                order.append("result")
                result_seen.set()
                return

    future = asyncio.run_coroutine_threadsafe(_collect(), bus_loop)

    manager.register_scan_id(uid, scan_id)
    # Let the forwarder drain the mp queue (progress + _PROGRESS_DONE).
    time.sleep(0.3)
    # Drive the monitor's finalise (after the child sentinel arrived).
    manager._finalize_run(uid, "arp_scan")

    assert result_seen.wait(3.0), f"no result event observed; order={order}"
    future.result(timeout=3.0)

    assert "persist" in order, f"persist sink never fired; order={order}"
    assert order.index("persist") < order.index("result"), (
        f"result event fired before persist (order={order}) — the UI finish signal "
        "precedes the last_scan_at commit (UI-173 badge flap)"
    )
