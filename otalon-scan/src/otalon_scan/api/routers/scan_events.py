"""Scan SSE router — ``GET /scans/{scan_id}/events`` (SCAN-033 extraction).

Owns the live progress stream and its close predicate. Kept apart from
:mod:`otalon_scan.api.routers.scans` because the streaming lifecycle (subscriber
queue, idle-poll terminal check, unsubscribe on teardown) is a different
concern from the request/response CRUD surface, and because the SC-04
regression tests monkeypatch this module's poll interval.

The close predicate reads ``state.repo`` on every poll rather than
capturing the repository once at request entry, preserving the
late-binding semantics of the module global it replaces.
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import APIRouter, Depends
from sqlalchemy.exc import SQLAlchemyError
from sse_starlette.sse import EventSourceResponse

from ...core.auth import verify_api_key
from ...core.module_manager import ModuleManager
from ..dependencies import get_api_state, get_optional_manager, require_manager
from ..state import ApiState

__all__ = ["router", "scan_stream_should_close"]

router = APIRouter()

# SC-04: idle-wait bound after which the SSE endpoint re-checks whether the
# scan reached a terminal state. Only a genuine terminal/unknown scan closes
# the stream — a quiet RUNNING scan keeps streaming.
SSE_TERMINAL_CHECK_INTERVAL_S = 5.0

TERMINAL_SCAN_STATUS_VALUES = frozenset({"completed", "failed", "aborted", "cancelled_partial"})


async def scan_stream_should_close(scan_id: str, state: ApiState) -> bool:
    """Return True when the SSE stream for ``scan_id`` should terminate.

    SC-04: the progress bus only delivers a terminal sentinel when a
    forwarder was wired for the scan (or once finalisation publishes it).
    For a scan without one — or a ``scan_id`` that never existed — a blind
    subscription would hang forever, so the endpoint polls this predicate
    on idle timeouts and closes the stream for terminal or absent scans.
    A transient DB error keeps the stream open (events may still arrive).

    Args:
        scan_id: The scan whose stream is being evaluated.
        state: The shared runtime state; its ``repo`` is read on every
            call so a repository wired after the stream opened is picked
            up (and a missing one keeps the stream open, as before).

    Returns:
        ``True`` when the stream should be closed.
    """
    repo = state.repo
    if repo is None:
        return False
    try:
        row = await repo.get_scan(scan_id)
    except ValueError:
        return True  # unparseable id — no scan will ever produce events
    except SQLAlchemyError:
        return False
    if row is None:
        return True
    status = getattr(row, "status", None)
    value = getattr(status, "value", status)
    return str(value) in TERMINAL_SCAN_STATUS_VALUES


@router.get(
    "/scans/{scan_id}/events",
    dependencies=[Depends(verify_api_key("viewer"))],
)
async def scan_events(
    scan_id: str,
    manager: Optional[ModuleManager] = Depends(get_optional_manager),
    state: ApiState = Depends(get_api_state),
) -> EventSourceResponse:
    """Stream live ``ScanProgress`` / ``ScanResult`` events via SSE.

    Mission Q9 prerequisite. The endpoint subscribes to the
    :class:`~otalon_scan.core.module_manager._ProgressBus` for the given
    ``scan_id`` and emits one ``text/event-stream`` chunk per yielded
    module event. The stream terminates when the orchestrator publishes
    its terminal sentinel (module iteration ended or finalised — SC-04),
    when the scan row reports a terminal state after an idle interval, or
    when the client disconnects.

    Event format (per `EventSourceResponse` convention):

    - ``event``: ``progress`` for intermediate :class:`ScanProgress`,
      ``result`` for the terminal :class:`ScanResult`.
    - ``data``: the model-dumped JSON payload.
    """

    module_manager = require_manager(manager)

    async def _event_stream() -> AsyncIterator[Dict[str, Any]]:
        bus = module_manager.progress_bus
        # Drive the subscriber queue directly (rather than ``subscribe()``)
        # so the idle-timeout check does not re-register on every cycle —
        # re-registering would re-prime the replay buffer and duplicate
        # already-delivered events onto the stream.
        queue = bus.register(scan_id)
        try:
            while True:
                try:
                    evt = await asyncio.wait_for(queue.get(), timeout=SSE_TERMINAL_CHECK_INTERVAL_S)
                except asyncio.TimeoutError:
                    if await scan_stream_should_close(scan_id, state):
                        return
                    continue
                if evt is None:
                    return
                yield {
                    "event": str(evt.get("event") or "message"),
                    "data": json.dumps(evt.get("data") or {}),
                }
        finally:
            bus.unsubscribe(scan_id, queue)

    return EventSourceResponse(_event_stream())
