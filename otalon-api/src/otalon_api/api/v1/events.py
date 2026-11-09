"""Server-Sent Events router for real-time data streaming.

Provides an SSE endpoint that clients can subscribe to for receiving
live updates on health, topology, anomaly, and admin events.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncGenerator

from fastapi import APIRouter, HTTPException, Query, Request
from sse_starlette.sse import EventSourceResponse

from otalon_api.services.event_bus import get_event_bus, serialize_event_data

router = APIRouter(prefix="/api/v1/events", tags=["events"])

# How often the stream polls the client-connection state while idle so a
# disconnect is observed (and the connection slot released) well before the
# 45 s heartbeat, without busy-waiting.
_DISCONNECT_POLL_S: float = 1.0


@router.get("/stream")
async def event_stream(
    request: Request,
    topics: str = Query(default="*", description="Comma-separated list of topics to subscribe to"),
) -> EventSourceResponse:
    """Subscribe to a Server-Sent Events stream.

    Topics: ``topology``, ``health``, ``anomaly``, ``admin``, or ``*`` for all.
    A heartbeat event is sent every 45 seconds to keep the connection alive.

    The streaming generator polls ``request.is_disconnected()`` so it exits its
    own loop — and runs its ``finally`` to release the connection slot — as soon
    as the client goes away. This does not rely on ``sse-starlette`` calling
    ``aclose()`` on the generator (which it does NOT do when it cancels the
    streaming task on disconnect), and is therefore version-independent. Without
    this the connection count leaked monotonically to ``max_connections`` and
    every subsequent stream returned HTTP 429, breaking the live SSE indicator
    and live health/jobs updates on all pages.

    Args:
        request: The incoming request, used to detect client disconnect.
        topics: Comma-separated topic names. Defaults to ``*`` (all topics).

    Returns:
        An SSE stream response.

    Raises:
        HTTPException: 429 if the maximum number of SSE connections is reached.
    """
    topic_list = [t.strip() for t in topics.split(",") if t.strip()]
    bus = get_event_bus()

    if bus.connection_count >= bus.max_connections:
        raise HTTPException(status_code=429, detail="Too many SSE connections")

    try:
        queue, resolved_topics = bus.register(topic_list)
    except RuntimeError as exc:
        raise HTTPException(status_code=429, detail="Too many SSE connections") from exc

    async def _generator() -> AsyncGenerator[dict[str, str], None]:
        idle_since_heartbeat = 0.0
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=_DISCONNECT_POLL_S)
                    idle_since_heartbeat = 0.0
                    yield {
                        "event": event.get("topic", "message"),
                        "data": serialize_event_data(event.get("data", {})),
                    }
                except asyncio.TimeoutError:
                    # Idle poll tick: re-check the disconnect state on the next
                    # loop, and only emit a heartbeat once the full heartbeat
                    # interval has elapsed (preserves the 45 s heartbeat cadence
                    # while still releasing promptly on disconnect).
                    idle_since_heartbeat += _DISCONNECT_POLL_S
                    if idle_since_heartbeat >= bus.HEARTBEAT_INTERVAL:
                        idle_since_heartbeat = 0.0
                        yield {"event": "heartbeat", "data": "{}"}
        finally:
            bus.release(queue, resolved_topics)

    return EventSourceResponse(_generator())
