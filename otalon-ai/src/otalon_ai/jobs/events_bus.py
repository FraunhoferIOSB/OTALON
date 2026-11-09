"""In-memory pub/sub for live SSE followers of running subagent jobs.

The persisted ``tool_trace`` in PostgreSQL is the source of truth for
historical replay. This bus only buffers events that have not yet been
seen by all current subscribers and is purely best-effort for live UX.
"""

from __future__ import annotations

import asyncio
from collections import defaultdict
from typing import Dict, Optional, Set
from uuid import UUID

from loguru import logger

from otalon_ai.jobs.domain.events import SubagentEvent

# Queues carry SubagentEvent values plus a ``None`` sentinel posted by
# ``mark_closed`` so subscribers can tell "stream finished" apart from
# "no event yet". The alias keeps the call-site signatures readable.
EventQueue = asyncio.Queue[Optional[SubagentEvent]]


class EventsBus:
    """Multi-subscriber per-job event queue."""

    def __init__(self) -> None:
        self._queues: Dict[UUID, Set[EventQueue]] = defaultdict(set)
        self._closed: Set[UUID] = set()
        self._lock = asyncio.Lock()

    async def publish(self, job_id: UUID, event: SubagentEvent) -> None:
        async with self._lock:
            queues = list(self._queues.get(job_id, set()))
        for queue in queues:
            try:
                queue.put_nowait(event)
            except asyncio.QueueFull:
                logger.warning("EventsBus queue full for job {}", job_id)

    async def subscribe(self, job_id: UUID) -> EventQueue:
        queue: EventQueue = asyncio.Queue(maxsize=2048)
        async with self._lock:
            self._queues[job_id].add(queue)
        return queue

    async def unsubscribe(self, job_id: UUID, queue: EventQueue) -> None:
        async with self._lock:
            if job_id in self._queues:
                self._queues[job_id].discard(queue)
                if not self._queues[job_id]:
                    del self._queues[job_id]

    async def mark_closed(self, job_id: UUID) -> None:
        """Signal that no more events will arrive for ``job_id``."""
        async with self._lock:
            self._closed.add(job_id)
            for queue in list(self._queues.get(job_id, set())):
                try:
                    queue.put_nowait(None)  # sentinel
                except asyncio.QueueFull:
                    pass

    def is_closed(self, job_id: UUID) -> bool:
        return job_id in self._closed
