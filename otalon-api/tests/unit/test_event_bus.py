"""Unit tests for the SSE EventBus.

Tests publish/subscribe, topic filtering, max connections, and heartbeat.
Uses dedicated event loops to avoid interfering with the default loop.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Coroutine
from typing import Any, TypeVar

import pytest

from otalon_api.services.event_bus import EventBus

_T = TypeVar("_T")


def _run_in_new_loop(coro: Coroutine[Any, Any, _T]) -> _T:
    """Run async coroutine in a fresh event loop, then clean up.

    Creates a new loop, runs the coroutine, closes the loop, and
    restores a fresh default loop for any subsequent tests.

    Args:
        coro: An awaitable coroutine.

    Returns:
        The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


class TestEventBusSubscribe:
    """Tests for EventBus subscription and event delivery."""

    @pytest.mark.unit
    def test_subscriber_receives_events(self) -> None:
        """Subscriber receives published events via the subscribe generator."""

        async def _test() -> list[dict[str, Any]]:
            bus = EventBus(max_connections=10)
            received: list[dict[str, Any]] = []

            async def subscriber() -> None:
                async for event in bus.subscribe(topics=["anomaly"]):
                    received.append(event)
                    break

            sub_task = asyncio.create_task(subscriber())
            await asyncio.sleep(0.05)
            await bus.publish("anomaly", {"level": "high"})
            await asyncio.sleep(0.05)
            sub_task.cancel()
            try:
                await sub_task
            except asyncio.CancelledError:
                pass
            return received

        received = _run_in_new_loop(_test())
        assert len(received) == 1
        assert received[0]["event"] == "anomaly"
        assert json.loads(received[0]["data"]) == {"level": "high"}

    @pytest.mark.unit
    def test_topic_filter_only_matching(self) -> None:
        """Subscriber with topics=['anomaly'] only receives anomaly events."""

        async def _test() -> list[dict[str, Any]]:
            bus = EventBus(max_connections=10)
            received: list[dict[str, Any]] = []

            async def subscriber() -> None:
                async for event in bus.subscribe(topics=["anomaly"]):
                    received.append(event)
                    if len(received) >= 1:
                        break

            sub_task = asyncio.create_task(subscriber())
            await asyncio.sleep(0.05)
            await bus.publish("topology", {"msg": "topo"})
            await asyncio.sleep(0.02)
            await bus.publish("anomaly", {"msg": "anom"})
            await asyncio.sleep(0.05)
            sub_task.cancel()
            try:
                await sub_task
            except asyncio.CancelledError:
                pass
            return received

        received = _run_in_new_loop(_test())
        assert len(received) == 1
        assert received[0]["event"] == "anomaly"
        assert json.loads(received[0]["data"]) == {"msg": "anom"}

    @pytest.mark.unit
    def test_wildcard_subscriber_receives_all(self) -> None:
        """Subscriber with topics=['*'] receives events from all topics."""

        async def _test() -> list[dict[str, Any]]:
            bus = EventBus(max_connections=10)
            received: list[dict[str, Any]] = []

            async def subscriber() -> None:
                async for event in bus.subscribe(topics=["*"]):
                    received.append(event)
                    if len(received) >= 2:
                        break

            sub_task = asyncio.create_task(subscriber())
            await asyncio.sleep(0.05)
            await bus.publish("topology", {"msg": "topo"})
            await asyncio.sleep(0.02)
            await bus.publish("anomaly", {"msg": "anom"})
            await asyncio.sleep(0.05)
            sub_task.cancel()
            try:
                await sub_task
            except asyncio.CancelledError:
                pass
            return received

        received = _run_in_new_loop(_test())
        assert len(received) == 2
        events = [r["event"] for r in received]
        assert "topology" in events
        assert "anomaly" in events


class TestEventBusPublish:
    """Tests for EventBus publish behavior."""

    @pytest.mark.unit
    def test_publish_to_specific_topic(self) -> None:
        """Only subscribers of the specific topic receive published events."""

        async def _test() -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
            bus = EventBus(max_connections=10)
            anomaly_events: list[dict[str, Any]] = []
            health_events: list[dict[str, Any]] = []

            async def anomaly_sub() -> None:
                async for event in bus.subscribe(topics=["anomaly"]):
                    anomaly_events.append(event)
                    break

            async def health_sub() -> None:
                async for event in bus.subscribe(topics=["health"]):
                    health_events.append(event)
                    break

            t1 = asyncio.create_task(anomaly_sub())
            t2 = asyncio.create_task(health_sub())
            await asyncio.sleep(0.05)

            await bus.publish("anomaly", {"alert": True})
            await asyncio.sleep(0.05)

            t1.cancel()
            t2.cancel()
            for t in (t1, t2):
                try:
                    await t
                except asyncio.CancelledError:
                    pass
            return anomaly_events, health_events

        anomaly_events, health_events = _run_in_new_loop(_test())
        assert len(anomaly_events) == 1
        assert len(health_events) == 0


class TestEventBusMaxConnections:
    """Tests for EventBus connection limit."""

    @pytest.mark.unit
    def test_max_connections_reached(self) -> None:
        """When max connections is reached, new subscriptions raise RuntimeError."""

        async def _test() -> None:
            bus = EventBus(max_connections=2)
            tasks = []

            async def sub() -> None:
                async for _ in bus.subscribe():
                    break

            for _ in range(2):
                task = asyncio.create_task(sub())
                tasks.append(task)

            await asyncio.sleep(0.05)
            assert bus.connection_count == 2

            with pytest.raises(RuntimeError, match="Maximum SSE connections reached"):
                async for _ in bus.subscribe():
                    break

            for t in tasks:
                t.cancel()
                try:
                    await t
                except asyncio.CancelledError:
                    pass

        _run_in_new_loop(_test())

    @pytest.mark.unit
    def test_connection_count_decrements_on_disconnect(self) -> None:
        """Connection count decrements when a subscriber disconnects."""

        async def _test() -> None:
            bus = EventBus(max_connections=5)

            async def sub() -> None:
                async for _ in bus.subscribe():
                    break

            task = asyncio.create_task(sub())
            await asyncio.sleep(0.05)
            assert bus.connection_count == 1

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            await asyncio.sleep(0.05)
            assert bus.connection_count == 0

        _run_in_new_loop(_test())

    @pytest.mark.unit
    def test_release_decrements_when_generator_abandoned_without_aclose(self) -> None:
        """release() frees a connection even if the generator is never aclose()-ed.

        Reproduces the production leak: sse-starlette cancels (and abandons)
        the streaming generator on client disconnect instead of calling
        ``aclose()``, so the generator ``finally`` never runs. The deterministic
        ``register``/``release`` pair (release driven by the client-close hook)
        must still decrement the count. Without the fix this stayed at 1 and
        eventually saturated ``max_connections`` (HTTP 429 for every client).
        """

        async def _test() -> tuple[int, int]:
            bus = EventBus(max_connections=5)
            queue, topics = bus.register(["health"])
            gen = bus.subscribe  # not started; simulate the real generator lifecycle
            _ = gen
            after_register = bus.connection_count
            # Simulate sse-starlette abandoning the stream: no aclose(), the
            # response layer instead invokes the client-close hook -> release().
            bus.release(queue, topics)
            after_release = bus.connection_count
            return after_register, after_release

        after_register, after_release = _run_in_new_loop(_test())
        assert after_register == 1
        assert after_release == 0

    @pytest.mark.unit
    def test_release_is_idempotent(self) -> None:
        """Calling release() twice for one connection only decrements once.

        The close hook and the generator ``finally`` can both fire; the second
        call must be a no-op so the count is never driven below the real number
        of live connections.
        """

        async def _test() -> tuple[int, int, int]:
            bus = EventBus(max_connections=5)
            q1, t1 = bus.register(["health"])
            q2, t2 = bus.register(["jobs"])
            base = bus.connection_count
            bus.release(q1, t1)
            once = bus.connection_count
            bus.release(q1, t1)  # duplicate release of the same connection
            twice = bus.connection_count
            bus.release(q2, t2)
            return base, once, twice

        base, once, twice = _run_in_new_loop(_test())
        assert base == 2
        assert once == 1
        assert twice == 1  # duplicate release did NOT double-decrement

    @pytest.mark.unit
    def test_no_429_after_many_register_release_cycles(self) -> None:
        """Many register/release cycles never saturate the cap (leak guard).

        Directly models the operator navigating the Operations pages many
        times: each visit registers then releases SSE streams. With the leak
        the count climbed monotonically to ``max_connections`` and the next
        register raised RuntimeError (surfaced as HTTP 429). With the fix the
        count returns to zero after every release.
        """

        async def _test() -> int:
            bus = EventBus(max_connections=3)
            for _ in range(50):
                q, t = bus.register(["*"])
                assert bus.connection_count == 1
                bus.release(q, t)
                assert bus.connection_count == 0
            return bus.connection_count

        final = _run_in_new_loop(_test())
        assert final == 0


class TestEventBusHeartbeat:
    """Tests for EventBus heartbeat functionality."""

    @pytest.mark.unit
    def test_heartbeat_after_interval(self) -> None:
        """After HEARTBEAT_INTERVAL with no events, a heartbeat event is yielded."""

        async def _test() -> list[dict[str, Any]]:
            bus = EventBus(max_connections=10)
            bus.HEARTBEAT_INTERVAL = 0.1

            received: list[dict[str, Any]] = []

            async def subscriber() -> None:
                async for event in bus.subscribe(topics=["anomaly"]):
                    received.append(event)
                    break

            task = asyncio.create_task(subscriber())
            await asyncio.sleep(0.3)

            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass
            return received

        received = _run_in_new_loop(_test())
        assert len(received) >= 1
        assert received[0]["event"] == "heartbeat"
        assert received[0]["data"] == "{}"
