"""Unit tests for :class:`src.jobs.events_bus.EventsBus`.

The bus is in-memory pub/sub for SSE followers. We validate:

- publish/subscribe with multiple subscribers
- a slow consumer does not block publishers (queue maxsize=2048 + nowait drops on full)
- unsubscribe cleans up the per-job set
- ``mark_closed`` delivers a ``None`` sentinel to all current subscribers
"""

from __future__ import annotations

import asyncio
from uuid import uuid4

import pytest

from otalon_ai.jobs.domain.events import ProgressEvent
from otalon_ai.jobs.events_bus import EventsBus


def _evt(job_id: str, rnd: int = 1, chars: int = 100) -> ProgressEvent:
    return ProgressEvent(job_id=job_id, round=rnd, context_chars=chars)


@pytest.mark.unit
async def test_subscribe_and_publish_delivers_to_single_subscriber() -> None:
    bus = EventsBus()
    job_id = uuid4()
    q = await bus.subscribe(job_id)
    await bus.publish(job_id, _evt(str(job_id)))
    out = await asyncio.wait_for(q.get(), timeout=1.0)
    assert out is not None
    assert out.round == 1


@pytest.mark.unit
async def test_multiple_subscribers_each_receive_published_event() -> None:
    bus = EventsBus()
    job_id = uuid4()
    q1 = await bus.subscribe(job_id)
    q2 = await bus.subscribe(job_id)
    q3 = await bus.subscribe(job_id)

    await bus.publish(job_id, _evt(str(job_id), rnd=7))

    for q in (q1, q2, q3):
        evt = await asyncio.wait_for(q.get(), timeout=1.0)
        assert evt is not None
        assert evt.round == 7


@pytest.mark.unit
async def test_publish_to_no_subscribers_is_a_noop() -> None:
    bus = EventsBus()
    job_id = uuid4()
    # Should not raise.
    await bus.publish(job_id, _evt(str(job_id)))


@pytest.mark.unit
async def test_unsubscribe_removes_queue() -> None:
    bus = EventsBus()
    job_id = uuid4()
    q1 = await bus.subscribe(job_id)
    q2 = await bus.subscribe(job_id)

    await bus.unsubscribe(job_id, q1)

    await bus.publish(job_id, _evt(str(job_id), rnd=42))
    # q1 is gone — only q2 sees it.
    assert q1.qsize() == 0
    evt = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert evt.round == 42


@pytest.mark.unit
async def test_unsubscribe_last_subscriber_drops_job_entry() -> None:
    bus = EventsBus()
    job_id = uuid4()
    q = await bus.subscribe(job_id)
    await bus.unsubscribe(job_id, q)
    # Internal map should no longer contain the job.
    assert job_id not in bus._queues  # type: ignore[attr-defined]


@pytest.mark.unit
async def test_mark_closed_pushes_none_sentinel_to_all_subscribers() -> None:
    bus = EventsBus()
    job_id = uuid4()
    q1 = await bus.subscribe(job_id)
    q2 = await bus.subscribe(job_id)

    await bus.mark_closed(job_id)

    s1 = await asyncio.wait_for(q1.get(), timeout=1.0)
    s2 = await asyncio.wait_for(q2.get(), timeout=1.0)
    assert s1 is None
    assert s2 is None
    assert bus.is_closed(job_id)


@pytest.mark.unit
async def test_slow_consumer_does_not_block_publishers() -> None:
    """A subscriber that never drains its queue should not block put_nowait once full.

    The bus uses ``put_nowait``; when the queue is at maxsize=2048 the
    excess events are dropped (logged as ``EventsBus queue full ...``).
    We force-fill a small queue and assert that further publishes return
    promptly without raising.
    """
    bus = EventsBus()
    job_id = uuid4()

    # Inject a small queue manually to make the test fast.
    small: asyncio.Queue = asyncio.Queue(maxsize=4)
    async with bus._lock:  # type: ignore[attr-defined]
        bus._queues[job_id].add(small)  # type: ignore[attr-defined]

    # Publish more events than the queue can hold; must not raise.
    for i in range(20):
        await bus.publish(job_id, _evt(str(job_id), rnd=i))

    # First 4 made it in; the rest were dropped via QueueFull.
    assert small.qsize() == 4


@pytest.mark.unit
async def test_subscriber_disconnect_after_close_still_safe() -> None:
    """A subscriber that unsubscribes after mark_closed must not raise."""
    bus = EventsBus()
    job_id = uuid4()
    q = await bus.subscribe(job_id)
    await bus.mark_closed(job_id)
    # Drain the sentinel.
    sentinel = await asyncio.wait_for(q.get(), timeout=1.0)
    assert sentinel is None
    # Unsubscribe after close — must be idempotent.
    await bus.unsubscribe(job_id, q)
    # Calling again must also be safe.
    await bus.unsubscribe(job_id, q)


@pytest.mark.unit
async def test_concurrent_publish_subscribe_consistency() -> None:
    """Concurrent publishers + subscribers don't deadlock or lose subscribers."""
    bus = EventsBus()
    job_id = uuid4()

    async def subscriber() -> int:
        q = await bus.subscribe(job_id)
        try:
            evt = await asyncio.wait_for(q.get(), timeout=2.0)
            return 1 if evt is not None else 0
        finally:
            await bus.unsubscribe(job_id, q)

    async def publisher() -> None:
        # Wait briefly so subscribers register first.
        await asyncio.sleep(0.05)
        for _ in range(5):
            await bus.publish(job_id, _evt(str(job_id)))

    subs = [asyncio.create_task(subscriber()) for _ in range(5)]
    pubs = [asyncio.create_task(publisher()) for _ in range(2)]
    sub_results = await asyncio.gather(*subs)
    await asyncio.gather(*pubs)
    assert sum(sub_results) == 5
