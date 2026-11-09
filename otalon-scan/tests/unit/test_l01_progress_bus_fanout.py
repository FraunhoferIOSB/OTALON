"""Regression tests for L-01 (scan modal stuck in "Running").

Root cause (``.dev/runtime/ux-review-scan/LIFECYCLE-FINDINGS.md``): the UI
opens **two** concurrent SSE subscriptions for the same running scan — the
run-modal's ``useJobStream`` and the global ``JobNotificationListener``. The
former single-subscriber :class:`~otalon_scan.core.module_manager._ProgressBus` backed
each ``scan_id`` with ONE shared ``asyncio.Queue``, so every event was consumed
by exactly one of the two streams. For a slow ``arp_scan`` (events flushed in a
single burst at ~18 s) the global listener typically won the terminal
``result`` frame — firing the "Scan completed" toast — while the modal stream
never saw ``result`` and stayed "Running" forever.

The fix makes the bus **multi-subscriber** (fan-out): each :meth:`subscribe`
registers an independent queue and every published event — including the
terminal sentinel — is delivered to all live subscribers. A bounded replay
buffer additionally brings a late-joining subscriber up to date.

These tests drive the bus directly against a real event loop; no PostgreSQL
and no child processes are required.
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List

import pytest

from otalon_scan.core.module_manager import _ProgressBus


def _make_bus(loop: asyncio.AbstractEventLoop) -> _ProgressBus:
    bus = _ProgressBus()
    bus.attach_loop(loop)
    return bus


@pytest.mark.asyncio
async def test_two_concurrent_subscribers_each_receive_terminal_result() -> None:
    """Both concurrent subscribers must see every event incl. the result."""
    loop = asyncio.get_running_loop()
    bus = _make_bus(loop)
    scan_id = "scan-1"

    async def collect() -> List[Dict[str, Any]]:
        events: List[Dict[str, Any]] = []
        async for evt in bus.subscribe(scan_id):
            events.append(evt)
        return events

    task_a = asyncio.create_task(collect())
    task_b = asyncio.create_task(collect())
    await asyncio.sleep(0)  # let both register before any event is published

    bus._fanout(scan_id, {"event": "progress", "data": {"i": 0}})
    bus._fanout(scan_id, {"event": "result", "data": {"status": None}})
    bus._fanout(scan_id, None)  # terminal sentinel

    got_a, got_b = await asyncio.gather(task_a, task_b)

    for got in (got_a, got_b):
        kinds = [e["event"] for e in got]
        assert "progress" in kinds
        assert "result" in kinds, "subscriber missed the terminal result frame"


@pytest.mark.asyncio
async def test_late_subscriber_replays_buffered_events() -> None:
    """A subscriber connecting after events were emitted catches up via replay."""
    loop = asyncio.get_running_loop()
    bus = _make_bus(loop)
    scan_id = "scan-2"

    bus._fanout(scan_id, {"event": "progress", "data": {"i": 0}})
    bus._fanout(scan_id, {"event": "result", "data": {"status": None}})
    bus._fanout(scan_id, None)

    events: List[Dict[str, Any]] = []
    async for evt in bus.subscribe(scan_id):
        events.append(evt)

    kinds = [e["event"] for e in events]
    assert kinds == ["progress", "result"], "late subscriber did not replay history"


@pytest.mark.asyncio
async def test_subscriber_unregistered_after_stream_ends() -> None:
    """Replay buffer is dropped once the last subscriber drains a terminated scan."""
    loop = asyncio.get_running_loop()
    bus = _make_bus(loop)
    scan_id = "scan-3"

    bus._fanout(scan_id, {"event": "result", "data": {}})
    bus._fanout(scan_id, None)

    async for _ in bus.subscribe(scan_id):
        pass

    assert scan_id not in bus._subscribers
    assert scan_id not in bus._replay
