"""Unit tests for the CacheManager and its wiring into services (B-09).

Covers:

* :class:`CacheManager` API: namespaces, hit/miss counters, snapshot.
* :meth:`DashboardKpiService.get_kpis` hits the cache on repeated calls.
* :meth:`TopologyService.get_topology` hits the cache on repeated calls.
* The ``/api/v1/status/health`` endpoint exposes cache stats.
"""

from __future__ import annotations

from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest

from otalon_api.repositories.cache import CacheManager
from otalon_api.services.dashboard_kpi_service import DashboardKpiService
from otalon_api.services.topology_service import TopologyService


class TestCacheManagerCore:
    """Direct unit tests for :class:`CacheManager`."""

    @pytest.mark.unit
    def test_get_or_compute_miss_then_hit(self) -> None:
        """First call is a miss, second call within TTL is a hit."""
        mgr = CacheManager()
        calls = {"n": 0}

        def compute() -> int:
            calls["n"] += 1
            return 42

        a = mgr.get_or_compute("dashboard_kpis", "k1", compute)
        b = mgr.get_or_compute("dashboard_kpis", "k1", compute)

        assert a == 42
        assert b == 42
        assert calls["n"] == 1
        snap = mgr.stats_snapshot()["dashboard_kpis"]
        assert snap["hits"] == 1
        assert snap["misses"] == 1
        assert snap["hit_ratio"] == 0.5

    @pytest.mark.unit
    def test_get_or_compute_distinct_keys_are_independent(self) -> None:
        """Different keys are independent cache slots."""
        mgr = CacheManager()
        calls: list[str] = []

        def compute(value: str):
            calls.append(value)
            return value

        mgr.get_or_compute("topology", "k1", lambda: compute("a"))
        mgr.get_or_compute("topology", "k2", lambda: compute("b"))
        mgr.get_or_compute("topology", "k1", lambda: compute("a"))

        assert calls == ["a", "b"]  # second "k1" hit, no recompute
        snap = mgr.stats_snapshot()["topology"]
        assert snap["hits"] == 1
        assert snap["misses"] == 2

    @pytest.mark.unit
    def test_unknown_namespace_raises(self) -> None:
        """Looking up an unknown namespace raises ``KeyError``."""
        mgr = CacheManager()
        with pytest.raises(KeyError, match="Unknown cache namespace"):
            mgr.get_or_compute("nope", "k", lambda: 1)

    @pytest.mark.unit
    def test_clear_all_evicts_but_keeps_stats(self) -> None:
        """``clear_all`` empties caches but does not reset counters."""
        mgr = CacheManager()
        mgr.get_or_compute("topology", "k", lambda: 1)
        mgr.clear_all()
        snap = mgr.stats_snapshot()["topology"]
        assert snap["size"] == 0
        assert snap["misses"] == 1  # stats survive eviction

    @pytest.mark.unit
    def test_stats_snapshot_shape(self) -> None:
        """The snapshot contains all expected namespaces and fields."""
        mgr = CacheManager()
        snap = mgr.stats_snapshot()
        assert set(snap.keys()) == {
            "stations",
            "anomalies",
            "port_rules",
            "dashboard_kpis",
            "topology",
        }
        for entry in snap.values():
            assert {"hits", "misses", "total", "hit_ratio", "size", "maxsize", "ttl"} <= entry.keys()

    @pytest.mark.unit
    def test_legacy_attribute_access(self) -> None:
        """Backward-compatible direct cache attributes still work."""
        mgr = CacheManager()
        # Should not raise, and each is a cachetools.TTLCache.
        assert mgr.stations.maxsize > 0
        assert mgr.anomalies.maxsize > 0
        assert mgr.port_rules.maxsize > 0


class TestDashboardKpiCaching:
    """Verify that B-09 caching reduces repository calls for ``get_kpis``."""

    @pytest.mark.unit
    async def test_repeated_get_kpis_hits_cache(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """Two ``get_kpis`` calls with the same range trigger one DB pass."""
        mock_postgres_repo.query_dashboard_kpis.return_value = {"total_alarm_groups": 0}
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_influx_repo.list_ids_between.return_value = []
        mock_influx_repo.query_top_connections.return_value = []

        cache_manager = CacheManager()
        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings, cache_manager)
        start = datetime(2026, 4, 1, 10, 0, 0)
        stop = datetime(2026, 4, 1, 12, 0, 0)

        await service.get_kpis(start=start, stop=stop)
        await service.get_kpis(start=start, stop=stop)

        # Only one underlying repo call across both invocations.
        assert mock_postgres_repo.query_dashboard_kpis.call_count == 1
        assert mock_postgres_repo.query_anomaly_groups.call_count == 1

        snap = cache_manager.stats_snapshot()["dashboard_kpis"]
        assert snap["hits"] == 1
        assert snap["misses"] == 1

    @pytest.mark.unit
    async def test_different_ranges_are_separate_cache_keys(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """Calls with different ranges miss the cache independently."""
        mock_postgres_repo.query_dashboard_kpis.return_value = {"total_alarm_groups": 0}
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_influx_repo.list_ids_between.return_value = []
        mock_influx_repo.query_top_connections.return_value = []

        cache_manager = CacheManager()
        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings, cache_manager)

        await service.get_kpis(
            start=datetime(2026, 4, 1, 10, 0, 0),
            stop=datetime(2026, 4, 1, 11, 0, 0),
        )
        await service.get_kpis(
            start=datetime(2026, 4, 1, 11, 0, 0),
            stop=datetime(2026, 4, 1, 12, 0, 0),
        )

        assert mock_postgres_repo.query_dashboard_kpis.call_count == 2

    @pytest.mark.unit
    async def test_uncached_when_no_cache_manager(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """When no CacheManager is supplied, the service stays uncached."""
        mock_postgres_repo.query_dashboard_kpis.return_value = {"total_alarm_groups": 0}
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_postgres_repo.query_device_count.return_value = 0
        mock_influx_repo.list_ids_between.return_value = []
        mock_influx_repo.query_top_connections.return_value = []

        service = DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)

        await service.get_kpis(start=None, stop=None)
        await service.get_kpis(start=None, stop=None)
        assert mock_postgres_repo.query_dashboard_kpis.call_count == 2


class TestTopologyCaching:
    """Verify that B-09 caching reduces repository calls for ``get_topology``."""

    @pytest.mark.unit
    async def test_repeated_get_topology_hits_cache(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """Two ``get_topology`` calls with identical args use the cache."""
        mock_postgres_repo.query_devices.return_value = []
        mock_postgres_repo.query_network_interfaces_for_devices.return_value = {}
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.list_ids_between.return_value = []

        cache_manager = CacheManager()
        service = TopologyService(
            postgres_repo=mock_postgres_repo,
            influx_repo=mock_influx_repo,
            settings=mock_settings,
            override_store=None,
            cache_manager=cache_manager,
        )

        start = datetime(2026, 4, 1, 10, 0, 0)
        stop = datetime(2026, 4, 1, 12, 0, 0)
        await service.get_topology(start=start, stop=stop)
        await service.get_topology(start=start, stop=stop)

        # Underlying device query made only once.
        assert mock_postgres_repo.query_devices.call_count == 1
        assert mock_influx_repo.list_ids_between.call_count == 1
        snap = cache_manager.stats_snapshot()["topology"]
        assert snap["hits"] == 1
        assert snap["misses"] == 1

    @pytest.mark.unit
    async def test_different_node_limit_misses(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """Cache key includes ``node_limit`` so different limits miss."""
        mock_postgres_repo.query_devices.return_value = []
        mock_postgres_repo.query_network_interfaces_for_devices.return_value = {}
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.list_ids_between.return_value = []

        cache_manager = CacheManager()
        service = TopologyService(
            postgres_repo=mock_postgres_repo,
            influx_repo=mock_influx_repo,
            settings=mock_settings,
            override_store=None,
            cache_manager=cache_manager,
        )

        start = datetime(2026, 4, 1, 10, 0, 0)
        stop = datetime(2026, 4, 1, 12, 0, 0)
        await service.get_topology(start=start, stop=stop, node_limit=50)
        await service.get_topology(start=start, stop=stop, node_limit=100)
        assert mock_postgres_repo.query_devices.call_count == 2

    @pytest.mark.unit
    async def test_uncached_when_no_cache_manager(
        self,
        mock_postgres_repo: MagicMock,
        mock_influx_repo: MagicMock,
        mock_settings,
    ) -> None:
        """When no CacheManager is supplied, the topology service stays uncached."""
        mock_postgres_repo.query_devices.return_value = []
        mock_postgres_repo.query_network_interfaces_for_devices.return_value = {}
        mock_postgres_repo.query_anomaly_groups.return_value = []
        mock_influx_repo.list_ids_between.return_value = []

        service = TopologyService(
            postgres_repo=mock_postgres_repo,
            influx_repo=mock_influx_repo,
            settings=mock_settings,
            override_store=None,
        )
        start = datetime(2026, 4, 1, 10, 0, 0)
        stop = datetime(2026, 4, 1, 12, 0, 0)
        await service.get_topology(start=start, stop=stop)
        await service.get_topology(start=start, stop=stop)
        assert mock_postgres_repo.query_devices.call_count == 2


class TestHealthEndpointExposesCacheStats:
    """The /api/v1/status/health endpoint must expose cache stats (B-09)."""

    @pytest.mark.unit
    def test_health_payload_contains_caches_field(self) -> None:
        """The health response body contains a top-level ``caches`` dict."""
        from unittest.mock import patch

        from fastapi.testclient import TestClient

        from otalon_api.dependencies import (
            get_cache_manager,
            get_health_incident_service,
            get_health_service,
        )
        from otalon_api.main import app
        from otalon_api.settings import Settings

        cache_manager = CacheManager()
        # Pre-warm one cache so the snapshot has non-zero counters.
        cache_manager.get_or_compute("topology", "k", lambda: {"x": 1})

        fake_health = MagicMock()
        fake_health.check_all = AsyncMock(return_value={"services": [], "overall_status": "healthy"})
        empty_summaries = {
            "active_incidents": [],
            "unacknowledged_incidents": [],
            "recent_incidents": [],
        }
        fake_incidents = MagicMock()
        fake_incidents.summaries_async = AsyncMock(return_value=empty_summaries)
        fake_incidents.latch_overall_status = lambda payload, summaries: None

        dependencies = (
            get_cache_manager,
            get_health_service,
            get_health_incident_service,
        )
        previous = {dependency: app.dependency_overrides.get(dependency) for dependency in dependencies}
        present = {dependency: dependency in app.dependency_overrides for dependency in dependencies}
        app.dependency_overrides[get_cache_manager] = lambda: cache_manager
        app.dependency_overrides[get_health_service] = lambda: fake_health
        app.dependency_overrides[get_health_incident_service] = lambda: fake_incidents
        try:
            with patch(
                "otalon_api.middleware.auth.get_settings",
                return_value=Settings(admin_api_key="test-suite-key-do-not-use-in-prod"),
            ):
                client = TestClient(app, headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"})
                resp = client.get("/api/v1/status/health?detail=true")
                assert resp.status_code == 200
                body = resp.json()
                assert "caches" in body
                assert "topology" in body["caches"]
                assert body["caches"]["topology"]["misses"] == 1
                assert body["caches"]["topology"]["size"] == 1
        finally:
            for dependency in dependencies:
                if present[dependency]:
                    app.dependency_overrides[dependency] = previous[dependency]
                else:
                    app.dependency_overrides.pop(dependency, None)
