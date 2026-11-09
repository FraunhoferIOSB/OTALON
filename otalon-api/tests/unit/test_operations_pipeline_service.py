"""Unit tests for OperationsPipelineService.

Tests state derivation for source freshness, Influx write freshness and
attention aggregation using mocked repositories. No real Influx/Postgres
connections are required.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest

from otalon_api.services.operations_pipeline_service import (
    OperationsPipelineService,
)
from otalon_api.settings import Settings


def _test_settings(cadence_seconds: int = 5) -> Settings:
    """Create settings with a configurable poll cadence."""
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
        pipeline_poll_interval_seconds=cadence_seconds,
    )


def _make_service(
    influx: Any | None = None,
    postgres: Any | None = None,
    settings: Settings | None = None,
) -> OperationsPipelineService:
    """Build a service with mocked repositories."""
    if influx is None:
        influx = MagicMock()
    if postgres is None:
        postgres = MagicMock()
    return OperationsPipelineService(
        influx_repo=influx,
        postgres_repo=postgres,
        settings=settings or _test_settings(),
    )


class TestSourceFreshness:
    """Tests for per-source freshness state derivation."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_all_sources_current(self) -> None:
        """When every source is younger than the stale threshold, state is current."""
        now = datetime.now(timezone.utc)
        influx = MagicMock()
        influx.query_last_record_time.return_value = now - timedelta(seconds=4)
        influx.query_record_count_since.return_value = 2

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = now - timedelta(seconds=30)
        postgres.query_recent_anomaly_series_count.return_value = 42

        service = _make_service(influx=influx, postgres=postgres)
        result = await service.get_pipeline()

        assert len(result.sources) == 3
        for source in result.sources:
            assert source.state == "current"
            assert source.age_seconds is not None
            assert source.age_seconds < 15
            assert source.records_per_hour == 2
            assert source.expected_interval_seconds == 5

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_stale_source_when_age_exceeds_threshold(self) -> None:
        """A source older than k*cadence is reported stale."""
        now = datetime.now(timezone.utc)

        def _last_record(measurement: str, lookback_hours: int = 24, **_kwargs: Any) -> datetime:
            if measurement == "proto_traffic":
                return now - timedelta(seconds=60)
            return now - timedelta(seconds=4)

        influx = MagicMock()
        influx.query_last_record_time.side_effect = _last_record
        influx.query_record_count_since.return_value = 100

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = now - timedelta(seconds=30)
        postgres.query_recent_anomaly_series_count.return_value = 10

        service = _make_service(influx=influx, postgres=postgres)
        result = await service.get_pipeline()

        states = {s.name: s.state for s in result.sources}
        assert states["conn"] == "current"
        assert states["mac"] == "current"
        assert states["proto"] == "stale"

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_no_data_when_source_has_no_record(self) -> None:
        """A measurement with no rows yields no-data with null age."""
        now = datetime.now(timezone.utc)

        def _last_record(measurement: str, lookback_hours: int = 24, **_kwargs: Any) -> datetime | None:
            if measurement == "mac_traffic":
                return None
            return now - timedelta(seconds=4)

        influx = MagicMock()
        influx.query_last_record_time.side_effect = _last_record
        influx.query_record_count_since.return_value = 50

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = now - timedelta(seconds=30)
        postgres.query_recent_anomaly_series_count.return_value = 10

        service = _make_service(influx=influx, postgres=postgres)
        result = await service.get_pipeline()

        mac = next(s for s in result.sources if s.name == "mac")
        assert mac.state == "no-data"
        assert mac.last_record is None
        assert mac.age_seconds is None
        assert mac.records_per_hour == 0

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_expected_interval_comes_from_settings(self) -> None:
        """The configured cadence is surfaced in each source entry."""
        influx = MagicMock()
        influx.query_last_record_time.return_value = datetime.now(timezone.utc)
        influx.query_record_count_since.return_value = 1
        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = None

        service = _make_service(
            influx=influx,
            postgres=postgres,
            settings=_test_settings(cadence_seconds=10),
        )
        result = await service.get_pipeline()

        for source in result.sources:
            assert source.expected_interval_seconds == 10

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_records_per_hour_uses_a_full_hour_window_for_batched_writes(self) -> None:
        """Fresh batched sources keep their observed hourly count instead of a one-minute false zero."""
        now = datetime.now(timezone.utc)
        influx = MagicMock()
        influx.query_last_record_time.return_value = now - timedelta(seconds=4)
        influx.query_record_count_since.return_value = 37
        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = None

        service = _make_service(influx=influx, postgres=postgres)
        result = await service.get_pipeline()

        assert all(source.records_per_hour == 37 for source in result.sources)
        called_since = influx.query_record_count_since.call_args_list[0].args[1]
        assert abs((now - called_since.to_pydatetime()).total_seconds() - 3600) < 0.1


class TestInfluxAndDetection:
    """Tests for aggregate Influx and detection freshness."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_influx_last_write_is_max_across_measurements(self) -> None:
        """Influx last_write is the latest timestamp across all three measurements."""
        now = datetime.now(timezone.utc)
        timestamps = {
            "network_metrics": now - timedelta(seconds=20),
            "mac_traffic": now - timedelta(seconds=10),
            "proto_traffic": now - timedelta(seconds=30),
        }

        def _last_record(measurement: str, lookback_hours: int = 24, **_kwargs: Any) -> datetime | None:
            return timestamps.get(measurement)

        influx = MagicMock()
        influx.query_last_record_time.side_effect = _last_record
        influx.query_record_count_since.return_value = 10

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = now - timedelta(seconds=30)
        postgres.query_recent_anomaly_series_count.return_value = 10

        service = _make_service(influx=influx, postgres=postgres)
        result = await service.get_pipeline()

        assert result.influx.last_write == timestamps["mac_traffic"]
        assert result.influx.age_seconds == 10

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_detection_fields_null_when_no_anomalies(self) -> None:
        """When PostgreSQL has no anomalies, detection fields are null."""
        influx = MagicMock()
        influx.query_last_record_time.return_value = datetime.now(timezone.utc)
        influx.query_record_count_since.return_value = 0

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = None

        service = _make_service(influx=influx, postgres=postgres)
        result = await service.get_pipeline()

        assert result.detection.last_cycle is None
        assert result.detection.age_seconds is None
        assert result.detection.series_evaluated is None


class TestAttentionAggregation:
    """Tests for attention finding aggregation."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_stale_source_emits_high_finding(self) -> None:
        """A stale source produces a High-urgency finding linking to Data Sources."""
        now = datetime.now(timezone.utc)

        def _last_record(measurement: str, lookback_hours: int = 24, **_kwargs: Any) -> datetime:
            if measurement == "proto_traffic":
                return now - timedelta(seconds=120)
            return now

        influx = MagicMock()
        influx.query_last_record_time.side_effect = _last_record
        influx.query_record_count_since.return_value = 10

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = now
        postgres.query_recent_anomaly_series_count.return_value = 10

        service = _make_service(influx=influx, postgres=postgres)
        findings = await service.get_attention()

        priorities = {f["priority"] for f in findings}
        assert "High" in priorities
        assert all(f["priority"] in {"High", "Medium", "Low"} for f in findings)
        data_source_links = [f for f in findings if f["link"]["route"] == "/operations/data-sources"]
        assert len(data_source_links) >= 1

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_no_priority_codes_in_response(self) -> None:
        """Raw P2/P3 codes must never appear in attention findings."""
        influx = MagicMock()
        influx.query_last_record_time.return_value = None
        influx.query_record_count_since.return_value = 0
        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = None

        service = _make_service(influx=influx, postgres=postgres)
        findings = await service.get_attention()

        for finding in findings:
            assert "P2" not in finding["title"]
            assert "P3" not in finding["title"]
            assert not finding["priority"].startswith("P")

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_stale_title_under_a_minute_reads_less_than_one_min(self) -> None:
        """A source stale for <60s renders '<1 min', never '0 min'."""
        now = datetime.now(timezone.utc)

        def _last_record(measurement: str, lookback_hours: int = 24, **_kwargs: Any) -> datetime:
            # proto: 40s old with a 5s cadence (k*cadence=15s) -> stale, <1 min
            if measurement == "proto_traffic":
                return now - timedelta(seconds=40)
            return now

        influx = MagicMock()
        influx.query_last_record_time.side_effect = _last_record
        influx.query_record_count_since.return_value = 10

        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = now
        postgres.query_recent_anomaly_series_count.return_value = 10

        service = _make_service(influx=influx, postgres=postgres)
        findings = await service.get_attention()

        stale = [f for f in findings if "stale" in f["title"]]
        assert stale, "expected a stale finding"
        assert "<1 min" in stale[0]["title"]
        assert "0 min" not in stale[0]["title"]


class TestSharedNowBoundary:
    """Tests for the shared now/since boundary between service and repo."""

    @pytest.mark.unit
    @pytest.mark.asyncio
    async def test_shared_now_is_passed_to_repo_query(self) -> None:
        """The service passes its single ``now`` boundary into the repo query."""
        now = datetime.now(timezone.utc)
        influx = MagicMock()
        influx.query_last_record_time.return_value = now
        influx.query_record_count_since.return_value = 1
        postgres = MagicMock()
        postgres.query_last_anomaly_time.return_value = None

        service = _make_service(influx=influx, postgres=postgres)
        await service.get_pipeline()

        assert influx.query_last_record_time.call_count == 3
        for call in influx.query_last_record_time.call_args_list:
            assert "now" in call.kwargs
            assert call.kwargs["now"] is not None
