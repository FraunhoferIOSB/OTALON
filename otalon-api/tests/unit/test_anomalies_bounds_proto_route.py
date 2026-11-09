"""End-to-end router regression for proto-hash chart retrieval.

Round-4 audit finding A (P1): the production generic endpoint
``GET /api/v1/anomalies/bounds`` calls ``BoundsService`` with the default
``normalize=True``. Every prior test either passed ``normalize=False`` directly
to the service or injected a recording stub, so the real route + real service +
default-normalize path was never exercised — and it corrupted numeric proto
hashes into ``"<hash>////////"``.

This test wires the **real** :class:`BoundsService` (only the Influx/PG repos
and the resolver are mocked at the boundary) behind the real router, sends a
numeric proto hash exactly as the UI does, and asserts the full contract:
Influx queried by resolved plaintext, PG queried by the original numeric hash,
response identity canonical, response protocol readable.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from otalon_api import dependencies
from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.main import app
from otalon_api.services.bounds_service import BoundsService
from otalon_api.settings import Settings

_START = "2026-03-06T21:00:00Z"
_STOP = "2026-03-06T22:00:00Z"
_PROTOCOL = "Ethernet:IPv4:UDP:DNS"
_METRIC = "proto_total_packets"


class _StubResolver:
    """Boundary stub mapping the one known proto hash to its plaintext."""

    def __init__(self, protocol: str) -> None:
        self._map = {proto_series_hash(protocol): protocol}

    def resolve(self, hash_value: str) -> str:
        return self._map.get(hash_value, hash_value)


def _mock_influx() -> MagicMock:
    influx = MagicMock()
    influx.query_timeseries.return_value = pd.DataFrame({"time": pd.to_datetime([_START]), _METRIC: [7.0]})
    return influx


@pytest.mark.unit
def test_generic_bounds_route_resolves_numeric_proto_hash_end_to_end(
    api_client: TestClient,
    mock_settings: Settings,
) -> None:
    """Real service + generic route + numeric hash + default normalize."""
    canonical_hash = proto_series_hash(_PROTOCOL)
    influx = _mock_influx()
    postgres = MagicMock()
    postgres.query_bounds.return_value = []
    real_service = BoundsService(
        influx,
        postgres,
        mock_settings,
        aggregation_service=None,
        proto_resolver=_StubResolver(_PROTOCOL),  # type: ignore[arg-type]
    )

    app.dependency_overrides[dependencies.get_bounds_service] = lambda: real_service
    try:
        response = api_client.get(
            "/api/v1/anomalies/bounds",
            params={
                "uci": canonical_hash,
                "metric": _METRIC,
                "module": "proto_traffic",
                "start": _START,
                "stop": _STOP,
            },
            headers={"X-API-Key": "test-suite-key-do-not-use-in-prod"},
        )
    finally:
        app.dependency_overrides.pop(dependencies.get_bounds_service, None)

    assert response.status_code == 200
    body = response.json()

    # Influx tag is the resolved plaintext protocol (not the corrupted hash).
    influx_kwargs = influx.query_timeseries.call_args.kwargs
    assert influx_kwargs["tags"] == {"protocol": _PROTOCOL}
    assert "/" not in str(influx_kwargs["tags"]["protocol"])

    # PG bounds key is the original numeric hash, never slash-corrupted.
    pg_kwargs = postgres.query_bounds.call_args.kwargs
    assert pg_kwargs["series_id"] == canonical_hash
    assert "/" not in pg_kwargs["series_id"]

    # Response identity stays canonical; readable protocol is exposed.
    assert body["parameters"]["uci"] == canonical_hash
    assert body["protocol"] == _PROTOCOL
