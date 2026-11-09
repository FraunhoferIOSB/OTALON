"""Unit tests for the async thread offload of the conn timeseries router (API-007)."""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any, Callable

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_aggregation_service, get_timeseries_service
from otalon_api.main import app
from otalon_api.settings import Settings

START_STR = "2026-03-06T21:08:00Z"
STOP_STR = "2026-03-06T22:08:00Z"
SAMPLE_UCI = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/6/192.168.0.1/192.168.0.2/12345/80/PROFINET_DCE_RPC"


def _make_sample_df() -> pd.DataFrame:
    return pd.DataFrame(
        {
            "time": pd.to_datetime(["2026-03-06T21:10:00"]),
            "packet_count": [10],
        }
    )


class _StubTimeseriesService:
    """Sync service stub whose method names must appear in asyncio.to_thread calls."""

    def get_between(
        self,
        uci: str,
        start: datetime,
        stop: datetime,
        features: list[str],
        aggregate: str | None = None,
        sample_max_points: int | None = None,
        preserve_extrema: bool = True,
    ) -> tuple[pd.DataFrame, int | None]:
        return _make_sample_df(), None

    def get_plot_data(
        self,
        uci: str,
        start: datetime,
        stop: datetime,
        features: list[str],
        sample_max_points: int = 500,
        preserve_extrema: bool = True,
    ) -> tuple[pd.DataFrame, int | None]:
        return _make_sample_df(), None

    def list_ids(
        self,
        start: datetime,
        stop: datetime,
        nonzero: bool = False,
        fields: list[str] | None = None,
        group_wildcards: bool = False,
        aggregation_service: Any = None,
    ) -> list[str] | list[dict[str, Any]]:
        return [SAMPLE_UCI]

    def profiled_series_ids(self, series_ids: list[str]) -> set[str]:
        return set(series_ids)

    def find_active_siblings(
        self,
        uci: str,
        start: datetime,
        stop: datetime,
        fields: list[str] | None = None,
    ) -> list[dict[str, str]]:
        return []


class _StubAggregationService:
    """Sync aggregation stub whose method names must appear in asyncio.to_thread calls."""

    def resolve_and_aggregate(
        self,
        wildcard_uci: str,
        start: datetime,
        stop: datetime,
        features: list[str],
    ) -> pd.DataFrame:
        return _make_sample_df()

    def aggregate_wildcard_timeseries(
        self,
        wildcard_uci: str,
        members: list[str],
        start: datetime,
        stop: datetime,
        features: list[str],
    ) -> pd.DataFrame:
        return _make_sample_df()

    def build_wildcard_groups(self, ucis: list[str]) -> dict[str, tuple[list[str], bool]]:
        return {SAMPLE_UCI: ([SAMPLE_UCI], True)}


def _make_timeseries_service() -> _StubTimeseriesService:
    return _StubTimeseriesService()


def _make_aggregation_service() -> _StubAggregationService:
    return _StubAggregationService()


@pytest.fixture()
def conn_timeseries_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """Provide a TestClient with conn timeseries services overridden."""
    app.dependency_overrides[get_timeseries_service] = _make_timeseries_service
    app.dependency_overrides[get_aggregation_service] = _make_aggregation_service
    test_key = "test-suite-key-do-not-use-in-prod"
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: Settings(admin_api_key=test_key))
    client = TestClient(app, headers={"X-API-Key": test_key})
    yield client
    app.dependency_overrides.clear()


@pytest.mark.unit
class TestConnTimeseriesAsyncOffload:
    """API-007: conn timeseries endpoints must not block the event loop."""

    def _patch_to_thread(self, monkeypatch: pytest.MonkeyPatch) -> list[Callable[..., Any]]:
        """Patch the router's asyncio.to_thread and return captured callables."""
        to_thread_calls: list[Callable[..., Any]] = []

        async def fake_to_thread(func: Callable[..., Any], *args: object, **kwargs: object) -> object:
            to_thread_calls.append(func)
            return func(*args, **kwargs)

        monkeypatch.setattr("otalon_api.api.v1.timeseries.asyncio.to_thread", fake_to_thread)
        return to_thread_calls

    def test_conn_data_uses_to_thread(
        self, conn_timeseries_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /timeseries/data offloads sync service calls via asyncio.to_thread."""
        to_thread_calls = self._patch_to_thread(monkeypatch)

        resp = conn_timeseries_client.get(
            "/api/v1/timeseries/data",
            params={
                "uci": SAMPLE_UCI,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["packet_count"],
            },
        )
        assert resp.status_code == 200
        assert any(func.__name__ == "get_between" for func in to_thread_calls)

    def test_conn_plot_uses_to_thread(
        self, conn_timeseries_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /timeseries/plot offloads sync service calls via asyncio.to_thread."""
        to_thread_calls = self._patch_to_thread(monkeypatch)

        resp = conn_timeseries_client.get(
            "/api/v1/timeseries/plot",
            params={
                "uci": SAMPLE_UCI,
                "start": START_STR,
                "stop": STOP_STR,
                "features": ["packet_count"],
            },
        )
        assert resp.status_code == 200
        assert any(func.__name__ == "get_plot_data" for func in to_thread_calls)

    def test_conn_ids_uses_to_thread(self, conn_timeseries_client: TestClient, monkeypatch: pytest.MonkeyPatch) -> None:
        """GET /timeseries/ids offloads sync service calls via asyncio.to_thread."""
        to_thread_calls = self._patch_to_thread(monkeypatch)

        resp = conn_timeseries_client.get(
            "/api/v1/timeseries/ids",
            params={"start": START_STR, "stop": STOP_STR},
        )
        assert resp.status_code == 200
        assert any(func.__name__ == "list_ids" for func in to_thread_calls)

    def test_conn_siblings_uses_to_thread(
        self, conn_timeseries_client: TestClient, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """GET /timeseries/siblings offloads sync service calls via asyncio.to_thread."""
        to_thread_calls = self._patch_to_thread(monkeypatch)

        resp = conn_timeseries_client.get(
            "/api/v1/timeseries/siblings",
            params={"uci": SAMPLE_UCI, "start": START_STR, "stop": STOP_STR},
        )
        assert resp.status_code == 200
        assert any(func.__name__ == "find_active_siblings" for func in to_thread_calls)
