"""In-memory event bus for Server-Sent Events (SSE).

Provides a publish/subscribe mechanism where services publish events
to named topics and SSE clients subscribe to receive them in real time.
Includes heartbeat support and connection limiting.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncGenerator
from typing import Any

from fastapi.encoders import jsonable_encoder
from loguru import logger

ALL_TOPICS = "*"

KNOWN_TOPICS: frozenset[str] = frozenset(
    {
        "topology",
        "health",
        "anomaly",
        "admin",
        "kpi",
        "jobs",
    }
)


def serialize_event_data(data: Any) -> str:
    """Serialize SSE payload data using FastAPI's JSON-compatible encoding."""
    return json.dumps(jsonable_encoder(data))


class EventBus:
    """In-memory event bus for SSE with topic-based pub/sub."""

    MAX_CONNECTIONS: int = 50
    HEARTBEAT_INTERVAL: float = 45.0

    def __init__(self, max_connections: int = 50) -> None:
        """Initialize the event bus.

        Args:
            max_connections: Maximum number of simultaneous SSE connections.
        """
        self._subscribers: dict[str, set[asyncio.Queue[dict[str, Any]]]] = {}
        self._max_connections = max_connections
        self._connection_count = 0

    @property
    def connection_count(self) -> int:
        """Return the current number of active SSE connections."""
        return self._connection_count

    @property
    def max_connections(self) -> int:
        """Return the maximum allowed SSE connections."""
        return self._max_connections

    def register(self, topics: list[str] | None = None) -> tuple[asyncio.Queue[dict[str, Any]], list[str]]:
        """Register a new subscriber queue and count the connection.

        Split out of :meth:`subscribe` so the connection can be released
        deterministically by :meth:`release` from the response's client-close
        hook, rather than relying solely on the generator ``finally`` — which
        ``sse-starlette`` does not always run when it cancels the streaming
        task on client disconnect (the generator is abandoned without
        ``aclose()``), leaking the count until the ``max_connections`` cap is
        hit and every new stream returns HTTP 429.

        Args:
            topics: List of topic names to subscribe to. Use ``["*"]`` for all.

        Returns:
            The subscriber queue and the resolved topic list (pass both back to
            :meth:`release`).

        Raises:
            RuntimeError: If the maximum connection limit is reached.
        """
        if self._connection_count >= self._max_connections:
            raise RuntimeError("Maximum SSE connections reached")

        resolved_topics = self._resolve_topics(topics)
        queue: asyncio.Queue[dict[str, Any]] = asyncio.Queue(maxsize=256)

        for topic in resolved_topics:
            if topic not in self._subscribers:
                self._subscribers[topic] = set()
            self._subscribers[topic].add(queue)

        self._connection_count += 1
        logger.info(
            "SSE client connected (topics={}, total={})",
            resolved_topics,
            self._connection_count,
        )
        return queue, resolved_topics

    def release(self, queue: asyncio.Queue[dict[str, Any]], resolved_topics: list[str]) -> None:
        """Release a registered subscriber and decrement the connection count.

        Idempotent: only decrements when the given queue is still registered on
        at least one topic, so it is safe to call from BOTH the client-close
        hook and the generator ``finally`` without double-counting.

        Args:
            queue: The queue returned by :meth:`register`.
            resolved_topics: The resolved topics returned by :meth:`register`.
        """
        was_registered = False
        for topic in resolved_topics:
            subscribers = self._subscribers.get(topic)
            if subscribers and queue in subscribers:
                was_registered = True
                subscribers.discard(queue)
                if not subscribers:
                    del self._subscribers[topic]
        if not was_registered:
            return
        self._connection_count = max(0, self._connection_count - 1)
        logger.info("SSE client disconnected (total={})", self._connection_count)

    async def subscribe(self, topics: list[str] | None = None) -> AsyncGenerator[dict[str, str], None]:
        """Subscribe to events and yield SSE-formatted dicts with heartbeat.

        Each yielded dict has ``event`` and ``data`` keys suitable for
        ``sse-starlette``'s ``EventSourceResponse``. The connection is counted
        via :meth:`register` and released via :meth:`release`; the ``finally``
        here is an idempotent safety net for the case where the generator IS
        closed normally (e.g. direct consumer cancellation in tests).

        Args:
            topics: List of topic names to subscribe to. Use ``["*"]`` for all.

        Yields:
            Dicts with ``event`` (topic name or ``heartbeat``) and ``data`` (JSON string).

        Raises:
            RuntimeError: If the maximum connection limit is reached.
        """
        queue, resolved_topics = self.register(topics)
        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=self.HEARTBEAT_INTERVAL)
                    yield {
                        "event": event.get("topic", "message"),
                        "data": serialize_event_data(event.get("data", {})),
                    }
                except asyncio.TimeoutError:
                    yield {"event": "heartbeat", "data": "{}"}
        except asyncio.CancelledError:
            pass
        finally:
            self.release(queue, resolved_topics)

    async def publish(self, topic: str, data: dict[str, Any]) -> None:
        """Publish an event to all subscribers of a topic.

        Delivers to subscribers of the specific topic and also to
        subscribers of the wildcard topic ``*``.

        Args:
            topic: The event topic name.
            data: The event payload to send as JSON.
        """
        event = {"topic": topic, "data": data}
        target_queues: set[asyncio.Queue[dict[str, Any]]] = set()

        specific_subs = self._subscribers.get(topic, set())
        target_queues.update(specific_subs)

        wildcard_subs = self._subscribers.get(ALL_TOPICS, set())
        target_queues.update(wildcard_subs)

        for queue in target_queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("SSE subscriber queue full, dropping event for topic={}", topic)

    def _resolve_topics(self, topics: list[str] | None) -> list[str]:
        """Normalize the topic list, expanding None or empty to wildcard.

        Args:
            topics: Raw topic list from the client.

        Returns:
            A normalized list of topic strings.
        """
        if not topics:
            return [ALL_TOPICS]
        cleaned = [t.strip() for t in topics if t.strip()]
        if not cleaned or ALL_TOPICS in cleaned:
            return [ALL_TOPICS]
        return cleaned


_event_bus_instance: EventBus | None = None


def get_event_bus() -> EventBus:
    """Return the singleton EventBus instance.

    Returns:
        The global EventBus.
    """
    global _event_bus_instance
    if _event_bus_instance is None:
        _event_bus_instance = EventBus()
    return _event_bus_instance
