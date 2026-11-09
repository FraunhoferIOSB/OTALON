"""Unit + smoke tests for MAC and Proto parallel subrouters (MSAP Wave C).

Covers:
- C.1: parallel /timeseries/mac and /timeseries/proto endpoints
- C.2: parallel /anomalies/mac and /anomalies/proto endpoints
- C.4: per-source feature catalogs distinct from conn ALL_FEATURES
- E-C3: conn endpoints remain reachable; no route shadowing.
"""

from __future__ import annotations

from collections.abc import Iterator
from typing import Any, Callable
from unittest.mock import MagicMock

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from otalon_api.api.schemas.timeseries import FeaturesResponse
from otalon_api.dependencies import get_mac_timeseries_service, get_proto_hash_resolver, get_proto_timeseries_service
from otalon_api.domain.netcap.models import ALL_FEATURES, MAC_FEATURES, PROTO_FEATURES
from otalon_api.domain.netcap.proto_resolver import ProtoHashResolver
from otalon_api.main import app
from otalon_api.services.source_timeseries_service import SourceTimeseriesService
from otalon_api.settings import Settings

START_STR = "2026-03-06T21:08:00Z"
STOP_STR = "2026-03-06T22:08:00Z"
SAMPLE_MAC = "00:11:22:33:44:55"
SAMPLE_PROTOCOL = "Ethernet:ARP"


def _make_mock_settings() -> Settings:
    """Create test settings without real DB connections."""
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
        timezone_name="Europe/Berlin",
        default_sample_max_points=500,
    )


def _make_mac_service() -> SourceTimeseriesService:
    """Build a mock-backed SourceTimeseriesService for MAC traffic."""
    repo = MagicMock()
    sample = pd.DataFrame(
        {
            "time": pd.to_datetime(["2026-03-06T21:10:00"]),
            "out_total_packets": [10],
            "out_total_volume": [1000],
            "mac_address": [SAMPLE_MAC],
        }
    )
    sample.attrs["bucket_seconds"] = 1
    repo.query_timeseries.return_value = sample
    repo.list_ids_between.return_value = [SAMPLE_MAC]
    settings = _make_mock_settings()
    return SourceTimeseriesService(
        influx_repo=repo,
        settings=settings,
        measurement="mac_traffic",
        id_tag="mac_address",
        features=MAC_FEATURES,
    )


def _make_proto_service() -> SourceTimeseriesService:
    """Build a mock-backed SourceTimeseriesService for Proto traffic."""
    repo = MagicMock()
    sample = pd.DataFrame(
        {
            "time": pd.to_datetime(["2026-03-06T21:10:00"]),
            "proto_total_packets": [20],
            "proto_total_volume": [2000],
            "protocol": [SAMPLE_PROTOCOL],
        }
    )
    sample.attrs["bucket_seconds"] = 1
    repo.query_timeseries.return_value = sample
    repo.list_ids_between.return_value = [SAMPLE_PROTOCOL]
    settings = _make_mock_settings()
    return SourceTimeseriesService(
        influx_repo=repo,
        settings=settings,
        measurement="proto_traffic",
        id_tag="protocol",
        features=PROTO_FEATURES,
    )


def _make_proto_resolver() -> ProtoHashResolver:
    """Build a mock-backed ProtoHashResolver."""
    repo = MagicMock()
    repo.query_distinct_tags.return_value = [SAMPLE_PROTOCOL]
    return ProtoHashResolver(influx_repo=repo)


@pytest.fixture()
def mac_proto_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Provide a TestClient with MAC/Proto services overridden."""
    app.dependency_overrides[get_mac_timeseries_service] = _make_mac_service
    app.dependency_overrides[get_proto_timeseries_service] = _make_proto_service
    app.dependency_overrides[get_proto_hash_resolver] = _make_proto_resolver
    test_key = "test-suite-key-do-not-use-in-prod"
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: Settings(admin_api_key=test_key))
    client = TestClient(app, headers={"X-API-Key": test_key})
    yield client
    app.dependency_overrides.clear()


class TestMacTimeseriesEndpoints:
    """C.1 / C.4 — MAC timeseries endpoints."""

    @pytest.mark.unit
    def test_mac_ids(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/mac/ids returns 200 with MAC list."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/mac/ids",
            params={"start": START_STR, "stop": STOP_STR},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 1
        assert body["data"][0]["id"] == SAMPLE_MAC

    @pytest.mark.unit
    def test_mac_data(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/mac/data returns 200 with datapoints."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/mac/data",
            params={
                "mac": SAMPLE_MAC,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["out_total_packets", "out_total_volume"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["series_id"] == SAMPLE_MAC
        assert body["row_count"] == 1
        assert "out_total_packets" in body["data"][0]

    @pytest.mark.unit
    def test_mac_plot(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/mac/plot returns 200."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/mac/plot",
            params={
                "mac": SAMPLE_MAC,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["out_total_packets"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["series_id"] == SAMPLE_MAC
        assert body["row_count"] == 1

    @pytest.mark.unit
    def test_mac_features(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/mac/features returns MAC catalog, not conn catalog (E-C2)."""
        resp = mac_proto_client.get("/api/v1/timeseries/mac/features")
        assert resp.status_code == 200
        body = resp.json()
        FeaturesResponse.model_validate(body)
        assert set(body["features"]) == set(MAC_FEATURES)
        assert "packet_count" not in body["features"]

    @pytest.mark.unit
    def test_mac_data_rejects_conn_feature(self, mac_proto_client: TestClient) -> None:
        """MAC /data rejects a conn-only feature with 400."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/mac/data",
            params={
                "mac": SAMPLE_MAC,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["packet_count"],
            },
        )
        assert resp.status_code == 400
        assert "Invalid feature" in resp.json()["detail"]


class TestProtoTimeseriesEndpoints:
    """C.1 / C.4 — Proto timeseries endpoints."""

    @pytest.mark.unit
    def test_proto_ids(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/proto/ids returns 200 with protocol list."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/proto/ids",
            params={"start": START_STR, "stop": STOP_STR},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["count"] == 1
        assert body["data"][0]["id"] == SAMPLE_PROTOCOL

    @pytest.mark.unit
    def test_proto_data(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/proto/data returns 200 with datapoints."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/proto/data",
            params={
                "protocol": SAMPLE_PROTOCOL,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["proto_total_packets", "proto_total_volume"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["series_id"] == SAMPLE_PROTOCOL
        assert body["row_count"] == 1
        assert "proto_total_packets" in body["data"][0]

    @pytest.mark.unit
    def test_proto_plot(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/proto/plot returns 200."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/proto/plot",
            params={
                "protocol": SAMPLE_PROTOCOL,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["proto_total_packets"],
            },
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["series_id"] == SAMPLE_PROTOCOL
        assert body["row_count"] == 1

    @pytest.mark.unit
    def test_proto_features(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/proto/features returns Proto catalog, not conn catalog (E-C2)."""
        resp = mac_proto_client.get("/api/v1/timeseries/proto/features")
        assert resp.status_code == 200
        body = resp.json()
        FeaturesResponse.model_validate(body)
        assert set(body["features"]) == set(PROTO_FEATURES)
        assert "packet_count" not in body["features"]

    @pytest.mark.unit
    def test_proto_data_rejects_mac_feature(self, mac_proto_client: TestClient) -> None:
        """Proto /data rejects a MAC-only feature with 400."""
        resp = mac_proto_client.get(
            "/api/v1/timeseries/proto/data",
            params={
                "protocol": SAMPLE_PROTOCOL,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["out_total_packets"],
            },
        )
        assert resp.status_code == 400
        assert "Invalid feature" in resp.json()["detail"]


class TestConnRegression:
    """E-C3 — conn endpoints remain reachable after mac/proto mount."""

    @pytest.mark.unit
    def test_conn_features_untouched(self, mac_proto_client: TestClient) -> None:
        """GET /timeseries/features still returns conn catalog."""
        resp = mac_proto_client.get("/api/v1/timeseries/features")
        assert resp.status_code == 200
        body = resp.json()
        assert set(body["features"]) == set(ALL_FEATURES)


class TestAsyncThreadOffload:
    """API-007: router endpoints must call blocking service code via asyncio.to_thread."""

    @pytest.mark.unit
    def test_mac_data_uses_to_thread(self, mac_proto_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """GET /timeseries/mac/data offloads the sync service call to a thread."""
        to_thread_calls: list[Callable[..., Any]] = []

        async def fake_to_thread(func: Callable[..., Any], *args: object, **kwargs: object) -> object:
            to_thread_calls.append(func)
            return func(*args, **kwargs)

        monkeypatch.setattr("otalon_api.api.v1.timeseries_mac_proto.asyncio.to_thread", fake_to_thread)

        resp = mac_proto_client.get(
            "/api/v1/timeseries/mac/data",
            params={
                "mac": SAMPLE_MAC,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["out_total_packets"],
            },
        )
        assert resp.status_code == 200
        assert any(func.__name__ == "get_between" for func in to_thread_calls)

    @pytest.mark.unit
    def test_proto_data_uses_to_thread(self, mac_proto_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """GET /timeseries/proto/data offloads the sync service call to a thread."""
        to_thread_calls: list[Callable[..., Any]] = []

        async def fake_to_thread(func: Callable[..., Any], *args: object, **kwargs: object) -> object:
            to_thread_calls.append(func)
            return func(*args, **kwargs)

        monkeypatch.setattr("otalon_api.api.v1.timeseries_mac_proto.asyncio.to_thread", fake_to_thread)

        resp = mac_proto_client.get(
            "/api/v1/timeseries/proto/data",
            params={
                "protocol": SAMPLE_PROTOCOL,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["proto_total_packets"],
            },
        )
        assert resp.status_code == 200
        # The proto route offloads a wrapper that performs the service call
        # AND the protocol resolution in one hop, because the resolver hits
        # InfluxDB synchronously on a cache miss (SUITE-035 / QUA-08).
        assert any(func.__name__ == "_query_and_resolve" for func in to_thread_calls)
