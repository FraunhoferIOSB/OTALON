"""Regression tests for SC-04 (SUITE-031 audit): SSE
``GET /scans/{scan_id}/events`` hangs forever for a scan with no wired
forwarder.

Root cause: the endpoint blindly subscribed to the progress bus; the terminal
sentinel is only ever published by the forwarder drain thread, which exists
only when ``register_scan_id`` wired one (``module_manager.py``). For a scan
without a forwarder — or a scan_id that never existed — the subscription
blocked in ``await q.get()`` until the client gave up.

Fix (two layers):

1. ``ModuleManager._finalize_run`` publishes the terminal sentinel onto the
   bus for the scan once the run is finalised, so subscribers of a run whose
   forwarder was never wired still terminate.
2. The endpoint watches for an idle subscription: after a bounded wait with
   no events it consults the scan row and closes the stream when the scan is
   in a terminal state (or absent/invalid).

Pure unit tests; the progress bus runs on the test's own event loop.
"""

from __future__ import annotations

import asyncio
import threading
from types import SimpleNamespace
from typing import Any, Dict, List

import pytest

from otalon_scan.api.routers import scan_events as scan_events_router
from otalon_scan.api.state import ApiState
from otalon_scan.core.module_manager import ModuleManager
from otalon_scan.repositories.models import ScanStatus


class _FakeRepo:
    """Repo stand-in returning a canned scan row (or None)."""

    def __init__(self, row: Any) -> None:
        self._row = row

    async def get_scan(self, scan_id: str) -> Any:
        return self._row


@pytest.fixture()
def manager(tmp_path: Any) -> Any:
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    mgr = ModuleManager(modules_path=str(empty_modules), batch_size=3)
    yield mgr
    mgr.manager.shutdown()


@pytest.fixture()
async def wired_state(manager: ModuleManager, monkeypatch: pytest.MonkeyPatch) -> Any:
    """Build the app state the SSE handler reads, plus a fast poll interval.

    Attaches the test's running loop to the progress bus, mirroring the
    production lifespan (``manager.progress_bus.attach_loop(main_loop)``).

    SCAN-033: the handler receives the manager and the state as injected
    parameters, so only the module-level poll interval still needs a
    monkeypatch.
    """
    manager.progress_bus.attach_loop(asyncio.get_running_loop())
    monkeypatch.setattr(scan_events_router, "SSE_TERMINAL_CHECK_INTERVAL_S", 0.05)
    return ApiState(manager=manager)


async def _next_chunk(response: Any, timeout: float = 3.0) -> Any:
    """anext() the SSE body iterator with a bound so a hang fails fast."""
    return await asyncio.wait_for(anext(response.body_iterator), timeout=timeout)


async def test_events_stream_closes_for_terminal_scan(wired_state: ApiState) -> None:
    """A scan already in a terminal state (no forwarder wired) must terminate
    the stream instead of hanging."""
    wired_state.repo = _FakeRepo(SimpleNamespace(status=ScanStatus.COMPLETED))  # type: ignore[assignment]

    response = await scan_events_router.scan_events(
        "11111111-1111-1111-1111-111111111111",
        manager=wired_state.manager,
        state=wired_state,
    )
    with pytest.raises(StopAsyncIteration):
        await _next_chunk(response)


async def test_events_stream_closes_for_unknown_scan(wired_state: ApiState) -> None:
    """A scan_id with no row at all must terminate the stream (no forwarder
    will ever exist for it)."""
    wired_state.repo = _FakeRepo(None)  # type: ignore[assignment]

    response = await scan_events_router.scan_events(
        "22222222-2222-2222-2222-222222222222",
        manager=wired_state.manager,
        state=wired_state,
    )
    with pytest.raises(StopAsyncIteration):
        await _next_chunk(response)


async def test_events_stream_stays_open_for_running_scan(wired_state: ApiState) -> None:
    """Guard: a RUNNING scan with a temporarily quiet bus must NOT be closed
    by the idle-timeout path."""
    wired_state.repo = _FakeRepo(SimpleNamespace(status=ScanStatus.RUNNING))  # type: ignore[assignment]

    response = await scan_events_router.scan_events(
        "33333333-3333-3333-3333-333333333333",
        manager=wired_state.manager,
        state=wired_state,
    )
    with pytest.raises(asyncio.TimeoutError):
        # Several poll intervals pass with no events; the stream stays open.
        await _next_chunk(response, timeout=0.4)


async def test_events_stream_delivers_events_before_closing(
    wired_state: ApiState,
) -> None:
    """Guard: events published on the bus still flow through unchanged."""
    wired_state.repo = _FakeRepo(SimpleNamespace(status=ScanStatus.RUNNING))  # type: ignore[assignment]
    scan_id = "44444444-4444-4444-4444-444444444444"

    response = await scan_events_router.scan_events(
        scan_id,
        manager=wired_state.manager,
        state=wired_state,
    )
    assert wired_state.manager is not None
    wired_state.manager.progress_bus.emit(scan_id, {"event": "progress", "data": {"message": "hello"}})
    chunk = await _next_chunk(response)
    assert chunk["event"] == "progress"
    assert "hello" in chunk["data"]


def test_finalize_closes_bus_for_unwired_run(manager: ModuleManager) -> None:
    """Finalising a run whose forwarder was never wired SHALL publish the
    terminal sentinel so present and future subscribers terminate."""
    loop = asyncio.new_event_loop()
    t = threading.Thread(target=loop.run_forever, name="sc04-bus-loop", daemon=True)
    t.start()
    manager.progress_bus.attach_loop(loop)

    uid = "run-sc04"
    scan_id = "55555555-5555-5555-5555-555555555555"
    manager.module_results[uid] = {
        "module_name": "arp_scan",
        "results": None,
        "scan_result": None,
        "findings": [],
        "scan_id": scan_id,
    }
    try:
        manager._finalize_run(uid, "arp_scan")

        async def _collect() -> List[Dict[str, Any]]:
            items: List[Dict[str, Any]] = []
            async for item in manager.progress_bus.subscribe(scan_id):
                items.append(item)
            return items

        future = asyncio.run_coroutine_threadsafe(_collect(), loop)
        items = future.result(timeout=3.0)
        assert items == [], "expected immediate termination, got events: %r" % (items,)
    finally:
        loop.call_soon_threadsafe(loop.stop)
        t.join(timeout=5.0)
        loop.close()
