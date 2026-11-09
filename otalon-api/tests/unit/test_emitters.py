"""Unit tests for the SSE background emitter tasks.

Each test verifies one emitter in isolation using mocked services and a
real EventBus.  Tests run in dedicated event loops to avoid cross-test
interference.

All interval constants are patched to small values (0.05 s) so that tests
run in milliseconds rather than tens of seconds.

Coverage areas:
- KPI emitter extracts ``result["data"][0]`` (not the envelope)
- Health emitter publishes the full payload directly
- Anomaly emitter publishes only new or changed groups (change-detection)
- Topology emitter publishes the full graph payload
- All emitters terminate cleanly on ``asyncio.CancelledError``
- All emitters continue after a transient ``Exception`` (resilience)
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

import otalon_api.services.emitters as emitters_module
from otalon_api.services.emitters import anomaly_emitter, health_emitter, kpi_emitter, topology_emitter
from otalon_api.services.event_bus import EventBus

FAST_INTERVAL: float = 0.05


def _run_in_new_loop(coro):
    """Run an async coroutine in a fresh event loop and return its result.

    Creates a new event loop, executes the coroutine, then closes the loop
    and installs a fresh default loop for subsequent tests.

    Args:
        coro: Awaitable coroutine to run.

    Returns:
        The coroutine's return value.
    """
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()
        asyncio.set_event_loop(asyncio.new_event_loop())


def _make_bus() -> EventBus:
    """Return a fresh EventBus instance for test isolation.

    Returns:
        A new :class:`EventBus` instance.
    """
    return EventBus(max_connections=10)


class TestKpiEmitter:
    """Tests for the KPI background emitter."""

    @pytest.mark.unit
    def test_publishes_inner_data_object(self) -> None:
        """KPI emitter must publish ``result["data"][0]``, not the envelope."""

        kpi_payload = {
            "signal_color": "ok",
            "anomaly_count": 1,
            "classified_count": 0,
            "device_count": 5,
            "connection_count": 12,
        }

        async def _test() -> list[dict[str, Any]]:
            bus = _make_bus()
            service = MagicMock()
            service.get_kpis = AsyncMock(return_value={"data": [kpi_payload], "row_count": 1})

            collected: list[dict[str, Any]] = []

            async def _collect() -> None:
                async for event in bus.subscribe(topics=["kpi"]):
                    if event.get("event") == "kpi":
                        collected.append(event)
                        break

            with patch.object(emitters_module, "KPI_INTERVAL_S", FAST_INTERVAL):
                collect_task = asyncio.create_task(_collect())
                emitter_task = asyncio.create_task(kpi_emitter(bus, service))

                await asyncio.sleep(FAST_INTERVAL * 3)

                emitter_task.cancel()
                collect_task.cancel()
                for t in (emitter_task, collect_task):
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass

            return collected

        import json

        received = _run_in_new_loop(_test())
        assert len(received) == 1
        data = json.loads(received[0]["data"])
        assert data == kpi_payload
        assert "row_count" not in data

    @pytest.mark.unit
    def test_skips_publish_on_empty_data(self) -> None:
        """KPI emitter must not publish when ``result["data"]`` is empty."""

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            service.get_kpis = AsyncMock(return_value={"data": [], "row_count": 0})

            publish_calls: list[Any] = []
            original_publish = bus.publish

            async def _spy_publish(topic: str, data: dict[str, Any]) -> None:
                publish_calls.append((topic, data))
                await original_publish(topic, data)

            bus.publish = _spy_publish

            with patch.object(emitters_module, "KPI_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(kpi_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 3)
                emitter_task.cancel()
                try:
                    await emitter_task
                except asyncio.CancelledError:
                    pass

            return len(publish_calls)

        call_count = _run_in_new_loop(_test())
        assert call_count == 0

    @pytest.mark.unit
    def test_cancelled_error_stops_emitter(self) -> None:
        """KPI emitter terminates cleanly when cancelled."""

        async def _test() -> None:
            bus = _make_bus()
            service = MagicMock()
            service.get_kpis = AsyncMock(return_value={"data": [{"signal_color": "ok"}], "row_count": 1})

            with patch.object(emitters_module, "KPI_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(kpi_emitter(bus, service))
                await asyncio.sleep(0.02)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            assert emitter_task.done()

        _run_in_new_loop(_test())

    @pytest.mark.unit
    def test_continues_after_exception(self) -> None:
        """KPI emitter continues running after a transient exception."""

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            call_count = 0

            async def _flaky_get_kpis(**_kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise ConnectionError("transient DB error")
                return {"data": [{"signal_color": "ok"}], "row_count": 1}

            service.get_kpis = _flaky_get_kpis

            with patch.object(emitters_module, "KPI_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(kpi_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 5)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            return call_count

        calls = _run_in_new_loop(_test())
        assert calls >= 2


class TestHealthEmitter:
    """Tests for the health background emitter."""

    @pytest.mark.unit
    def test_publishes_full_payload(self) -> None:
        """Health emitter must publish the service output without unwrapping."""

        health_payload = {
            "services": [{"name": "Postgres", "running": True, "detail": "ok", "timestamp": 1.0}],
            "overall_status": "healthy",
        }

        async def _test() -> list[dict[str, Any]]:
            bus = _make_bus()
            service = MagicMock()
            service.check_all = AsyncMock(return_value=health_payload)

            collected: list[dict[str, Any]] = []

            async def _collect() -> None:
                async for event in bus.subscribe(topics=["health"]):
                    if event.get("event") == "health":
                        collected.append(event)
                        break

            with patch.object(emitters_module, "HEALTH_INTERVAL_S", FAST_INTERVAL):
                collect_task = asyncio.create_task(_collect())
                emitter_task = asyncio.create_task(health_emitter(bus, service))

                await asyncio.sleep(FAST_INTERVAL * 3)

                emitter_task.cancel()
                collect_task.cancel()
                for t in (emitter_task, collect_task):
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass

            return collected

        import json

        received = _run_in_new_loop(_test())
        assert len(received) == 1
        data = json.loads(received[0]["data"])
        assert data == health_payload
        assert "overall_status" in data
        assert "services" in data

    @pytest.mark.unit
    def test_cancelled_error_stops_emitter(self) -> None:
        """Health emitter terminates cleanly when cancelled."""

        async def _test() -> None:
            bus = _make_bus()
            service = MagicMock()
            service.check_all = AsyncMock(return_value={"services": [], "overall_status": "healthy"})

            with patch.object(emitters_module, "HEALTH_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(health_emitter(bus, service))
                await asyncio.sleep(0.02)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            assert emitter_task.done()

        _run_in_new_loop(_test())

    @pytest.mark.unit
    def test_continues_after_exception(self) -> None:
        """Health emitter continues running after a transient exception."""

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            call_count = 0

            async def _flaky_check_all() -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise TimeoutError("probe timeout")
                return {"services": [], "overall_status": "unhealthy"}

            service.check_all = _flaky_check_all

            with patch.object(emitters_module, "HEALTH_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(health_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 5)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            return call_count

        calls = _run_in_new_loop(_test())
        assert calls >= 2


class TestAnomalyEmitter:
    """Tests for the anomaly background emitter with change-detection."""

    @pytest.mark.unit
    def test_publishes_individual_groups(self) -> None:
        """Anomaly emitter must publish each group as a separate event."""

        groups = [
            {"id": "aaa", "end_timestamp": "2024-01-01T00:00:00Z"},
            {"id": "bbb", "end_timestamp": "2024-01-01T00:05:00Z"},
        ]

        async def _test() -> list[dict[str, Any]]:
            bus = _make_bus()
            service = MagicMock()
            service.get_anomaly_groups = AsyncMock(return_value={"data": groups, "row_count": 2})

            published: list[dict[str, Any]] = []

            async def _collect() -> None:
                async for event in bus.subscribe(topics=["anomaly"]):
                    if event.get("event") == "anomaly":
                        published.append(event)
                    if len(published) >= 2:
                        break

            with patch.object(emitters_module, "ANOMALY_INTERVAL_S", FAST_INTERVAL):
                collect_task = asyncio.create_task(_collect())
                emitter_task = asyncio.create_task(anomaly_emitter(bus, service))

                await asyncio.sleep(FAST_INTERVAL * 4)

                emitter_task.cancel()
                collect_task.cancel()
                for t in (emitter_task, collect_task):
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass

            return published

        import json

        received = _run_in_new_loop(_test())
        assert len(received) == 2
        ids = {json.loads(ev["data"])["id"] for ev in received}
        assert ids == {"aaa", "bbb"}

    @pytest.mark.unit
    def test_change_detection_skips_unchanged_groups(self) -> None:
        """Anomaly emitter must not re-publish groups whose end_timestamp did not change."""

        groups = [{"id": "aaa", "end_timestamp": "2024-01-01T00:00:00Z"}]

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            service.get_anomaly_groups = AsyncMock(return_value={"data": groups, "row_count": 1})

            publish_calls = 0
            original_publish = bus.publish

            async def _spy(topic: str, data: dict[str, Any]) -> None:
                nonlocal publish_calls
                if topic == "anomaly":
                    publish_calls += 1
                await original_publish(topic, data)

            bus.publish = _spy

            with patch.object(emitters_module, "ANOMALY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(anomaly_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 5)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            return publish_calls

        calls = _run_in_new_loop(_test())
        assert calls == 1

    @pytest.mark.unit
    def test_change_detection_republishes_on_end_timestamp_change(self) -> None:
        """Anomaly emitter must re-publish a group when end_timestamp changes."""

        initial_group = {"id": "aaa", "end_timestamp": "2024-01-01T00:00:00Z"}
        updated_group = {"id": "aaa", "end_timestamp": "2024-01-01T00:05:00Z"}

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            call_count = 0

            async def _alternating_get(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                group = initial_group if call_count == 1 else updated_group
                return {"data": [group], "row_count": 1}

            service.get_anomaly_groups = _alternating_get

            publish_calls = 0
            original_publish = bus.publish

            async def _spy(topic: str, data: dict[str, Any]) -> None:
                nonlocal publish_calls
                if topic == "anomaly":
                    publish_calls += 1
                await original_publish(topic, data)

            bus.publish = _spy

            with patch.object(emitters_module, "ANOMALY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(anomaly_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 5)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            return publish_calls

        calls = _run_in_new_loop(_test())
        assert calls == 2

    @pytest.mark.unit
    def test_cancelled_error_stops_emitter(self) -> None:
        """Anomaly emitter terminates cleanly when cancelled."""

        async def _test() -> None:
            bus = _make_bus()
            service = MagicMock()
            service.get_anomaly_groups = AsyncMock(return_value={"data": [], "row_count": 0})

            with patch.object(emitters_module, "ANOMALY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(anomaly_emitter(bus, service))
                await asyncio.sleep(0.02)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            assert emitter_task.done()

        _run_in_new_loop(_test())

    @pytest.mark.unit
    def test_continues_after_exception(self) -> None:
        """Anomaly emitter continues running after a transient exception."""

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            call_count = 0

            async def _flaky(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise RuntimeError("DB unavailable")
                return {"data": [], "row_count": 0}

            service.get_anomaly_groups = _flaky

            with patch.object(emitters_module, "ANOMALY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(anomaly_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 5)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            return call_count

        calls = _run_in_new_loop(_test())
        assert calls >= 2


class TestTopologyEmitter:
    """Tests for the topology background emitter."""

    @pytest.mark.unit
    def test_publishes_full_graph_payload(self) -> None:
        """Topology emitter must publish the full graph dict without unwrapping."""

        graph_payload = {
            "nodes": [{"id": "1", "label": "PLC-01"}],
            "edges": [],
            "meta": {"node_count": 1, "edge_count": 0, "truncated": False},
        }

        async def _test() -> list[dict[str, Any]]:
            bus = _make_bus()
            service = MagicMock()
            service.get_topology = AsyncMock(return_value=graph_payload)

            collected: list[dict[str, Any]] = []

            async def _collect() -> None:
                async for event in bus.subscribe(topics=["topology"]):
                    if event.get("event") == "topology":
                        collected.append(event)
                        break

            with patch.object(emitters_module, "TOPOLOGY_INTERVAL_S", FAST_INTERVAL):
                collect_task = asyncio.create_task(_collect())
                emitter_task = asyncio.create_task(topology_emitter(bus, service))

                await asyncio.sleep(FAST_INTERVAL * 3)

                emitter_task.cancel()
                collect_task.cancel()
                for t in (emitter_task, collect_task):
                    try:
                        await t
                    except asyncio.CancelledError:
                        pass

            return collected

        import json

        received = _run_in_new_loop(_test())
        assert len(received) == 1
        data = json.loads(received[0]["data"])
        assert data == graph_payload
        assert "nodes" in data
        assert "edges" in data
        assert "meta" in data

    @pytest.mark.unit
    def test_passes_rolling_time_window_to_service(self) -> None:
        """Topology emitter must pass a start/stop time range to get_topology."""

        captured_kwargs: list[dict[str, Any]] = []

        async def _test() -> None:
            bus = _make_bus()
            service = MagicMock()

            async def _capture_get_topology(**kwargs: Any) -> dict[str, Any]:
                captured_kwargs.append(kwargs)
                return {"nodes": [], "edges": [], "meta": {"node_count": 0, "edge_count": 0}}

            service.get_topology = _capture_get_topology

            with patch.object(emitters_module, "TOPOLOGY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(topology_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 3)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

        _run_in_new_loop(_test())
        assert len(captured_kwargs) >= 1
        kwargs = captured_kwargs[0]
        assert "start" in kwargs
        assert "stop" in kwargs
        assert isinstance(kwargs["start"], datetime)
        assert isinstance(kwargs["stop"], datetime)
        delta = kwargs["stop"] - kwargs["start"]
        assert abs(delta.total_seconds() - 30 * 60) < 5

    @pytest.mark.unit
    def test_cancelled_error_stops_emitter(self) -> None:
        """Topology emitter terminates cleanly when cancelled."""

        async def _test() -> None:
            bus = _make_bus()
            service = MagicMock()
            service.get_topology = AsyncMock(
                return_value={"nodes": [], "edges": [], "meta": {"node_count": 0, "edge_count": 0}}
            )

            with patch.object(emitters_module, "TOPOLOGY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(topology_emitter(bus, service))
                await asyncio.sleep(0.02)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            assert emitter_task.done()

        _run_in_new_loop(_test())

    @pytest.mark.unit
    def test_continues_after_exception(self) -> None:
        """Topology emitter continues running after a transient exception."""

        async def _test() -> int:
            bus = _make_bus()
            service = MagicMock()
            call_count = 0

            async def _flaky(**_kwargs: Any) -> dict[str, Any]:
                nonlocal call_count
                call_count += 1
                if call_count == 1:
                    raise IOError("InfluxDB timeout")
                return {"nodes": [], "edges": [], "meta": {"node_count": 0, "edge_count": 0}}

            service.get_topology = _flaky

            with patch.object(emitters_module, "TOPOLOGY_INTERVAL_S", FAST_INTERVAL):
                emitter_task = asyncio.create_task(topology_emitter(bus, service))
                await asyncio.sleep(FAST_INTERVAL * 5)
                emitter_task.cancel()
                await asyncio.gather(emitter_task, return_exceptions=True)

            return call_count

        calls = _run_in_new_loop(_test())
        assert calls >= 2
