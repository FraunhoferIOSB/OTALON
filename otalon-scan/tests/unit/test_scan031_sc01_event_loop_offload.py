"""Regression tests for SC-01 (SUITE-031 audit): event-loop deadlock in the
finalize path.

Root cause: several FastAPI handlers invoked synchronous
:class:`~otalon_scan.core.module_manager.ModuleManager` methods directly on the event
loop. Those methods run ``_clean_up_finished_modules`` → ``_finalize_run`` →
the persistence sink, which dispatches a coroutine back onto the SAME loop via
:func:`asyncio.run_coroutine_threadsafe` and then blocks in
``future.result(timeout=...)``. With the loop blocked, the dispatched coroutine
can never run — a self-deadlock that burns the full 60 s timeout per finished
module on every affected request.

Fix: the handlers offload the blocking manager calls with
:func:`asyncio.to_thread`, consistent with how the rest of the manager already
offloads blocking I/O (monitor thread, SSE forwarder thread).

These tests are pure unit tests: no PostgreSQL, no real module processes.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Dict, List, Optional

import pytest
from fastapi import HTTPException

from otalon_scan.api.routers import health as health_router
from otalon_scan.api.routers import scans as scans_router
from otalon_scan.api.schemas.scans import StartScanRequest
from otalon_scan.api.state import ApiState


class _ThreadRecordingManager:
    """ModuleManager stand-in that records which thread each method ran on."""

    def __init__(self) -> None:
        self.calls: Dict[str, int] = {}

    def _record(self, name: str) -> None:
        self.calls[name] = threading.get_ident()

    # Manager surface used by the handlers under test.
    def get_module_names(self) -> List[str]:
        self._record("get_module_names")
        return []

    def get_all_running_modules_status(self) -> Dict[str, str]:
        self._record("get_all_running_modules_status")
        return {}

    def get_module_results(self, uid: str) -> Dict[str, Any]:
        self._record("get_module_results")
        return {}

    def get_all_finished_modules(self) -> Dict[str, str]:
        self._record("get_all_finished_modules")
        return {}

    def start_module(self, module_name: str, overrides: Optional[Dict[str, Any]] = None) -> Optional[str]:
        self._record("start_module")
        return None

    def stop_module(self, uid: str) -> bool:
        self._record("stop_module")
        return True


@pytest.fixture()
def recording_manager() -> Any:
    """Return the recording stub the tests inject as the module manager.

    SCAN-033: handlers take the manager as an injected parameter, so the
    tests pass the stub directly instead of patching a module global.
    """
    return _ThreadRecordingManager()


def _loop_thread_ident() -> int:
    return threading.get_ident()


async def test_list_running_scans_offloads_manager_call(recording_manager: Any) -> None:
    """``GET /scans/running`` SHALL NOT run the manager call on the loop thread."""
    loop_ident = _loop_thread_ident()
    await scans_router.list_running_scans(manager=recording_manager)
    assert "get_all_running_modules_status" in recording_manager.calls
    assert recording_manager.calls["get_all_running_modules_status"] != loop_ident


async def test_get_scan_results_offloads_manager_call(recording_manager: Any) -> None:
    """``GET /scans/{run_id}/results`` SHALL NOT run the manager call on the loop thread."""
    loop_ident = _loop_thread_ident()
    await scans_router.get_scan_results("run-x", manager=recording_manager)
    assert recording_manager.calls["get_module_results"] != loop_ident


async def test_list_finished_scans_offloads_manager_call(
    recording_manager: Any,
) -> None:
    """``GET /scans/finished`` SHALL NOT run the manager call on the loop thread."""
    loop_ident = _loop_thread_ident()
    await scans_router.list_finished_scans(manager=recording_manager, state=ApiState())
    assert recording_manager.calls["get_all_finished_modules"] != loop_ident


async def test_health_deep_offloads_manager_call(recording_manager: Any) -> None:
    """``GET /health?deep=true`` SHALL NOT run the manager call on the loop thread."""

    class _ProbeRepo:
        async def probe(self) -> Any:
            return True, None

    loop_ident = _loop_thread_ident()
    # The port label is irrelevant to this assertion, so settings stay None.
    await health_router.health(
        deep=True,
        manager=recording_manager,
        repo=_ProbeRepo(),  # type: ignore[arg-type]
        settings=None,
    )
    assert recording_manager.calls["get_all_running_modules_status"] != loop_ident


async def test_start_scan_offloads_start_module(recording_manager: Any) -> None:
    """``POST /scans/start`` SHALL NOT run ``start_module`` on the loop thread."""

    recording_manager.start_module = lambda *a, **k: None

    def _recording_start(module_name: str, overrides: Optional[Dict[str, Any]] = None) -> Optional[str]:
        recording_manager.calls["start_module"] = threading.get_ident()
        return None  # returning None keeps the handler on its HTTP-400 path

    recording_manager.start_module = _recording_start

    req = StartScanRequest(module_name="modules/arp_scan")
    loop_ident = _loop_thread_ident()
    # ``repo`` only has to be truthy — the handler's guard is its sole reader
    # before ``start_module`` runs.
    repo: Any = object()
    with pytest.raises(HTTPException):
        await scans_router.start_scan(req, manager=recording_manager, repo=repo, state=ApiState())
    assert recording_manager.calls["start_module"] != loop_ident


async def test_stop_scan_offloads_stop_module(recording_manager: Any) -> None:
    """``POST /scans/{run_id}/stop`` SHALL NOT run ``stop_module`` on the loop thread."""
    loop_ident = _loop_thread_ident()
    repo: Any = object()  # only the guard reads it
    await scans_router.stop_scan("run-x", manager=recording_manager, repo=repo)
    assert recording_manager.calls["stop_module"] != loop_ident


async def test_finalize_sink_no_longer_self_deadlocks() -> None:
    """Functional probe of the SC-01 deadlock shape.

    A finished module on the registry makes ``_clean_up_finished_modules``
    drive ``_finalize_run``; the wired persist sink dispatches a coroutine
    onto the running loop and waits for it. When the handler runs the manager
    call on the loop thread, the dispatched coroutine can never execute (the
    loop is blocked in ``future.result``) and the probe times out. Offloaded,
    the coroutine runs to completion.
    """
    from otalon_scan.core.module_manager import ModuleManager

    loop = asyncio.get_running_loop()
    coroutine_ran: List[bool] = []

    class _DeadProcess:
        pid = 2**22  # guaranteed-absent PID: psutil raises NoSuchProcess (swallowed)

        def is_alive(self) -> bool:
            return False

        def join(self, timeout: Optional[float] = None) -> None:
            return None

    def persist_sink(scan_id: str, batch: List[Any], result: Any) -> None:
        async def _impl() -> None:
            coroutine_ran.append(True)

        future = asyncio.run_coroutine_threadsafe(_impl(), loop)
        try:
            future.result(timeout=2.0)
        except Exception:
            pass

    mgr = ModuleManager(modules_path="/nonexistent-scan031", batch_size=1)
    try:
        uid = "run-sc01"
        mgr.module_results[uid] = {
            "module_name": "arp_scan",
            "results": None,
            "scan_result": None,
            # One finding so the legacy (no-forwarder) path invokes the
            # persist sink — that is where the blocking dispatch lives.
            "findings": [{"ipv4": "192.0.2.1", "mac": "02:00:00:00:00:01"}],
            "scan_id": "scan-sc01",
        }
        mgr.set_persist_sink(persist_sink)
        mgr.running_modules.add((uid, "arp_scan", _DeadProcess()))  # type: ignore[arg-type]

        # Offloaded (post-fix contract): the sink's coroutine completes.
        await asyncio.to_thread(mgr.get_all_running_modules_status)
        assert coroutine_ran, (
            "persist-sink coroutine never ran — the manager call blocked the " "event loop (SC-01 self-deadlock shape)"
        )
    finally:
        mgr.manager.shutdown()
