"""SCAN-033 — ``ScanSink`` state-binding regression guards.

The four orchestrator callbacks run on the ``ModuleManager`` monitor
thread and have no request scope, so they cannot resolve a FastAPI
dependency. They are bound to the shared :class:`ApiState` instead. Two
properties of that binding are load-bearing and easy to break silently:

1. **Late binding.** The sink is constructed in the lifespan *before*
   ``state.repo`` is assigned. Capturing the repository into an
   instance attribute at construction time would leave every sink
   permanently disabled — the exact failure mode the pre-split
   ``global _repo`` rebinding avoided.
2. **No-op on unpopulated state.** A sink firing before startup finished
   must return quietly rather than raise into the monitor thread.

The bookkeeping written by ``on_module_finished`` must also land on the
same state the ``GET /scans/finished`` handler reads.
"""

from __future__ import annotations

import asyncio
import threading
from typing import Any, Iterator, List, Tuple

import pytest

from otalon_scan.api.scan_sink import ScanSink
from otalon_scan.api.state import ApiState


class _RecordingRepo:
    """Repo stand-in recording the ARP/port persistence calls it receives."""

    def __init__(self) -> None:
        self.arp_calls: List[Tuple[str, List[str]]] = []
        self.port_calls: List[Tuple[str, Any]] = []

    async def save_arp_scan_results(self, scan_id: str, ips: List[str]) -> None:
        self.arp_calls.append((scan_id, list(ips)))

    async def save_port_scan_results(self, scan_id: str, rows: Any) -> None:
        self.port_calls.append((scan_id, rows))


@pytest.fixture()
def background_loop() -> Iterator[asyncio.AbstractEventLoop]:
    """A loop running in a background thread, as production dispatch expects."""
    loop = asyncio.new_event_loop()
    thread = threading.Thread(target=loop.run_forever, name="scan033-sink-loop", daemon=True)
    thread.start()
    try:
        yield loop
    finally:
        loop.call_soon_threadsafe(loop.stop)
        thread.join(timeout=5.0)
        loop.close()


def test_sink_observes_repo_assigned_after_construction(
    background_loop: asyncio.AbstractEventLoop,
) -> None:
    """A repo wired AFTER the sink was built SHALL still be used.

    This is the lifespan's real ordering: ``ScanSink(state)`` is
    constructed before the Postgres probe assigns ``state.repo``.
    """
    state = ApiState()
    sink = ScanSink(state)  # constructed while repo/main_loop are still None

    repo = _RecordingRepo()
    state.repo = repo  # type: ignore[assignment]
    state.main_loop = background_loop
    state.run_to_scan_map["run-late"] = "scan-late"

    sink.on_module_finished("run-late", "modules/arp_scan", ["10.0.0.1", "10.0.0.2"])

    assert repo.arp_calls == [("scan-late", ["10.0.0.1", "10.0.0.2"])]


def test_sink_records_finished_run_on_shared_state(
    background_loop: asyncio.AbstractEventLoop,
) -> None:
    """The finished-run bookkeeping SHALL land on the shared state.

    ``GET /scans/finished`` reads ``state.finished_runs``; the monitor
    thread writes it. Both must be the same mapping.
    """
    state = ApiState(repo=_RecordingRepo(), main_loop=background_loop)  # type: ignore[arg-type]
    state.run_to_scan_map["run-b"] = "scan-b"

    ScanSink(state).on_module_finished("run-b", "modules/port_scan", [])

    assert state.finished_runs == {"run-b": "modules/port_scan"}


@pytest.mark.parametrize(
    "state",
    [
        ApiState(),
        ApiState(repo=_RecordingRepo()),  # type: ignore[arg-type]
        ApiState(main_loop=None),
    ],
)
def test_sinks_noop_when_state_incomplete(state: ApiState) -> None:
    """Every sink SHALL return quietly when repo or loop is missing.

    A raise here would surface on the orchestrator monitor thread, where
    nothing catches it.
    """
    sink = ScanSink(state)
    sink.on_module_finished("run-x", "modules/arp_scan", [])
    sink.finish_scan("scan-x", "completed", None)
    sink.persist_scan_findings("scan-x", [])
    # No exception, and no bookkeeping written for a dispatch that never ran.
    assert state.finished_runs == {}
