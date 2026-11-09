"""Router-level metric validation for GET /api/v1/anomalies/bounds.

Round-4 regression: the chart endpoint must accept each module's own feature
family (so NoBounds MAC/proto rows can chart) while rejecting arbitrary metrics
with HTTP 400. The initial coverage only exercised Connection features.

Round-4 audit finding B (Contracts P2 + Safety P3): validation must be
module-specific, not a global union. A cross-family metric/module pair (e.g.
``module=conn`` + ``metric=proto_total_packets``) and an unknown module must be
rejected with HTTP 400 *before* the service is called, while the legacy default
``netcap`` module keeps accepting connection metrics. These tests add both
wrong-family directions, an unknown-module case, and a legacy-netcap valid
metric.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi.testclient import TestClient

from otalon_api import dependencies
from otalon_api.domain.netcap.models import ALL_FEATURES, MAC_FEATURES, PROTO_FEATURES
from otalon_api.main import app

_START = "2026-03-06T21:00:00Z"
_STOP = "2026-03-06T22:00:00Z"


class _RecordingBoundsService:
    """Stub BoundsService recording forwarded calls; returns a valid envelope."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    async def get_timeseries_with_bounds(self, **kwargs: Any) -> dict[str, Any]:
        self.calls.append(kwargs)
        return {
            "data": [],
            "row_count": 0,
            "parameters": {
                "uci": kwargs["uci"],
                "feature": kwargs["metric"],
                "start": _START,
                "stop": _STOP,
            },
        }


def _request(client: TestClient, metric: str, module: str) -> Any:
    return client.get(
        "/api/v1/anomalies/bounds",
        params={
            "uci": "series-x",
            "metric": metric,
            "module": module,
            "start": _START,
            "stop": _STOP,
        },
        headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
    )


@pytest.mark.unit
def test_mac_feature_is_accepted_and_forwarded(api_client: TestClient) -> None:
    """One MAC feature is accepted (200) and forwarded to the service verbatim."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    mac_metric = MAC_FEATURES[0]
    try:
        response = _request(api_client, mac_metric, "mac_traffic")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 200
    assert len(stub.calls) == 1
    assert stub.calls[0]["metric"] == mac_metric
    assert stub.calls[0]["module"] == "mac_traffic"


@pytest.mark.unit
def test_proto_feature_is_accepted_and_forwarded(api_client: TestClient) -> None:
    """One PROTO feature is accepted (200) and forwarded to the service verbatim."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    proto_metric = PROTO_FEATURES[0]
    try:
        response = _request(api_client, proto_metric, "proto_traffic")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 200
    assert len(stub.calls) == 1
    assert stub.calls[0]["metric"] == proto_metric
    assert stub.calls[0]["module"] == "proto_traffic"


@pytest.mark.unit
def test_arbitrary_metric_is_rejected(api_client: TestClient) -> None:
    """An arbitrary metric is rejected with HTTP 400 and never reaches the service."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    try:
        response = _request(api_client, "definitely_not_a_feature", "conn")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 400
    assert "Invalid metric" in response.json()["detail"]
    assert stub.calls == []


@pytest.mark.unit
def test_conn_module_rejects_proto_metric(api_client: TestClient) -> None:
    """module=conn + a proto-only metric is rejected 400 before the service."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    try:
        response = _request(api_client, PROTO_FEATURES[0], "conn")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 400
    detail = response.json()["detail"]
    assert "Invalid metric" in detail
    assert "conn" in detail
    assert stub.calls == []


@pytest.mark.unit
def test_proto_module_rejects_conn_metric(api_client: TestClient) -> None:
    """module=proto_traffic + a conn-only metric is rejected 400 before the service."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    try:
        response = _request(api_client, ALL_FEATURES[0], "proto_traffic")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 400
    assert "Invalid metric" in response.json()["detail"]
    assert stub.calls == []


@pytest.mark.unit
def test_mac_module_rejects_proto_metric(api_client: TestClient) -> None:
    """module=mac_traffic + a proto-only metric is rejected 400 before the service."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    try:
        response = _request(api_client, PROTO_FEATURES[0], "mac_traffic")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 400
    assert "Invalid metric" in response.json()["detail"]
    assert stub.calls == []


@pytest.mark.unit
def test_unknown_module_is_rejected(api_client: TestClient) -> None:
    """An unknown module is rejected with HTTP 400 and never reaches the service."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    try:
        response = _request(api_client, ALL_FEATURES[0], "not_a_module")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 400
    assert "Unknown module" in response.json()["detail"]
    assert stub.calls == []


@pytest.mark.unit
def test_legacy_netcap_module_accepts_conn_metric(api_client: TestClient) -> None:
    """The legacy default module ``netcap`` still accepts a connection metric."""
    stub = _RecordingBoundsService()
    app.dependency_overrides[dependencies.get_bounds_service] = lambda: stub
    conn_metric = ALL_FEATURES[0]
    try:
        response = _request(api_client, conn_metric, "netcap")
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 200
    assert len(stub.calls) == 1
    assert stub.calls[0]["metric"] == conn_metric
    assert stub.calls[0]["module"] == "netcap"
