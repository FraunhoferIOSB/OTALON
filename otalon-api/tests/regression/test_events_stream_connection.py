"""SSE connection-accounting regression for /api/v1/events/stream.

Phase-7 exhaustive finding: sse-starlette cancels the streaming generator on
client disconnect WITHOUT calling ``aclose()``, so the generator ``finally``
did not run in production and the connection count climbed monotonically to
``max_connections``. After that every new stream (the live SSE indicator,
health and jobs topics on all Operations pages) returned HTTP 429.

These drive the real :func:`event_stream` generator with a fake request whose
``is_disconnected()`` we control, so the exact production code path
(register -> poll disconnect -> ``finally`` release) is exercised
deterministically and independently of the sse-starlette version. This file
holds NO destructive database fixture — it only touches the in-memory event
bus — so it is safe to run against any environment.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterable
from datetime import datetime, timezone
from typing import Any, cast

import pytest
from fastapi import Request

from otalon_api.api.v1 import events as events_module
from otalon_api.services.event_bus import get_event_bus

pytestmark = [pytest.mark.integration]

_READ_TIMEOUT_S = 5.0


async def _run_consume(gen: AsyncIterable[Any]) -> None:
    """Drive an SSE generator to completion (helper for accounting tests)."""
    async for _ in gen:
        pass


class TestGlobalEventStreamConnectionAccounting:
    """The global /api/v1/events/stream must not leak SSE connection slots."""

    @staticmethod
    def _fake_request(disconnected: dict[str, bool]) -> Request:
        """Build a minimal object exposing an awaitable ``is_disconnected``."""

        class _FakeRequest:
            async def is_disconnected(self) -> bool:
                return disconnected["value"]

        return cast(Request, _FakeRequest())

    def test_event_stream_releases_slot_on_client_disconnect(self) -> None:
        """The stream generator releases its connection slot once the client disconnects."""

        async def _run() -> tuple[int, int, int]:
            bus = get_event_bus()
            bus._connection_count = 0
            bus._subscribers.clear()
            events_module._DISCONNECT_POLL_S = 0.05

            disconnected = {"value": False}
            response = await events_module.event_stream(self._fake_request(disconnected), topics="health")
            gen = response.body_iterator
            base_after_register = bus.connection_count  # already registered before iteration

            task = asyncio.create_task(_run_consume(gen))
            await asyncio.sleep(0.15)
            mid = bus.connection_count
            # Signal disconnect; the generator must break and run finally.
            disconnected["value"] = True
            await asyncio.wait_for(task, timeout=_READ_TIMEOUT_S)
            after = bus.connection_count
            return base_after_register, mid, after

        base, mid, after = asyncio.run(_run())
        assert base == 1
        assert mid == 1
        assert after == 0

    def test_repeated_streams_do_not_saturate_cap(self) -> None:
        """Repeated connect/disconnect cycles keep the count bounded (no 429 creep)."""

        async def _run() -> int:
            bus = get_event_bus()
            bus._connection_count = 0
            bus._subscribers.clear()
            bus._max_connections = 3
            events_module._DISCONNECT_POLL_S = 0.05

            for _ in range(10):
                disconnected = {"value": False}
                response = await events_module.event_stream(self._fake_request(disconnected), topics="jobs")
                gen = response.body_iterator
                task = asyncio.create_task(_run_consume(gen))
                await asyncio.sleep(0.1)
                assert bus.connection_count == 1
                disconnected["value"] = True
                await asyncio.wait_for(task, timeout=_READ_TIMEOUT_S)
                assert bus.connection_count == 0
            return bus.connection_count

        final = asyncio.run(_run())
        assert final == 0

    def test_event_stream_serializes_datetime_payload(self) -> None:
        """Published datetime values are emitted as valid SSE JSON."""

        async def _run() -> dict[str, object]:
            bus = get_event_bus()
            bus._connection_count = 0
            bus._subscribers.clear()
            disconnected = {"value": False}
            response = await events_module.event_stream(self._fake_request(disconnected), topics="health")
            generator = response.body_iterator
            await bus.publish(
                "health",
                {"observed_at": datetime(2026, 7, 24, 18, 38, tzinfo=timezone.utc)},
            )
            event = await asyncio.wait_for(generator.__anext__(), timeout=_READ_TIMEOUT_S)
            await generator.aclose()
            return json.loads(event["data"])

        payload = asyncio.run(_run())
        assert payload == {"observed_at": "2026-07-24T18:38:00+00:00"}
