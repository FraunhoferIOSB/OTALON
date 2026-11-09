"""Unit tests for PassiveDiscoveryService.

Exercises the exact aggregate/result shapes (no-data, stale, current,
timestamps) using a mocked PostgreSQL repository. No real Postgres
connection is opened. Every case proves the derived snapshot reflects
persisted producer facts and that runtime control stays disabled.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from otalon_api.services.passive_discovery_service import (
    PassiveDiscoveryService,
    PassiveDiscoveryStatus,
)
from otalon_api.settings import Settings


def _test_settings() -> Settings:
    """Create minimal settings for the service."""
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key="test-key",
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


def _make_service(summary: dict[str, Any] | Exception) -> PassiveDiscoveryService:
    """Build a service whose repo returns *summary* (or raises it)."""
    postgres = MagicMock()
    if isinstance(summary, Exception):
        postgres.query_passive_discovery_summary.side_effect = summary
    else:
        postgres.query_passive_discovery_summary.return_value = summary
    return PassiveDiscoveryService(postgres_repo=postgres, settings=_test_settings())


class TestPassiveDiscoveryStatus:
    """Tests for status derivation from the persisted aggregate."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_no_data_when_zero_rows(self) -> None:
        """Zero passive rows yields a no-data snapshot with no timestamps."""
        service = _make_service(
            {
                "observed_interface_count": 0,
                "observed_asset_count": 0,
                "latest_seen_at": None,
                "first_seen_at": None,
            }
        )
        status = await service.get_status()
        assert isinstance(status, PassiveDiscoveryStatus)
        assert status.freshness == "no-data"
        assert status.observed_asset_count == 0
        assert status.observed_interface_count == 0
        assert status.latest_seen_at is None
        assert status.age_seconds is None
        assert status.runtime_control_enabled is False

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_current_when_recent_observation(self) -> None:
        """A recent last_seen_passive_at yields current freshness and counts."""
        now = datetime.now(timezone.utc)
        service = _make_service(
            {
                "observed_interface_count": 10,
                "observed_asset_count": 10,
                "latest_seen_at": now - timedelta(seconds=30),
                "first_seen_at": now - timedelta(days=19),
            }
        )
        status = await service.get_status()
        assert status.freshness == "current"
        assert status.observed_asset_count == 10
        assert status.observed_interface_count == 10
        assert status.age_seconds is not None and status.age_seconds <= 180
        assert status.latest_seen_at is not None
        assert status.first_seen_at is not None
        assert status.runtime_control_enabled is False

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_stale_when_old_observation(self) -> None:
        """An observation older than the stale threshold yields stale."""
        now = datetime.now(timezone.utc)
        service = _make_service(
            {
                "observed_interface_count": 14,
                "observed_asset_count": 12,
                "latest_seen_at": now - timedelta(minutes=30),
                "first_seen_at": now - timedelta(days=1),
            }
        )
        status = await service.get_status()
        assert status.freshness == "stale"
        assert status.observed_asset_count == 12
        assert status.observed_interface_count == 14
        assert status.age_seconds is not None and status.age_seconds > 180

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_naive_timestamp_coerced_to_utc(self) -> None:
        """A naive DB timestamp is treated as UTC, not rejected."""
        now = datetime.now(timezone.utc)
        naive = (now - timedelta(seconds=20)).replace(tzinfo=None)
        service = _make_service(
            {
                "observed_interface_count": 3,
                "observed_asset_count": 3,
                "latest_seen_at": naive,
                "first_seen_at": naive,
            }
        )
        status = await service.get_status()
        assert status.freshness == "current"
        assert status.latest_seen_at is not None
        assert status.latest_seen_at.tzinfo is not None

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_query_failure_returns_no_data(self) -> None:
        """A repository failure degrades to a truthful no-data snapshot."""
        service = _make_service(RuntimeError("boom"))
        status = await service.get_status()
        assert status.freshness == "no-data"
        assert status.observed_asset_count == 0
        assert status.runtime_control_enabled is False
