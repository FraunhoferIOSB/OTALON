"""Unit tests for the PCAP proxy router and service (TODO B-05).

Uses ``respx`` to mock the upstream PCAP recorder at port 9090.
Covers:

* Happy path: alarm exists, recorder returns chunks, response envelope
  carries the summarised list + totals.
* Alarm not found in PostgreSQL → 404.
* Upstream transport timeout → 504 (distinct from generic connect error).
* Upstream connect error / unreachable → 502.
* Upstream returns 401 / 403 (future auth layer) → 502 with auth-failure
  detail.
* Upstream returns malformed (non-list) body → 502.
* Service-not-configured guard → 503.
* ``X-API-Key`` forwarding when configured.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, AsyncIterator
from unittest.mock import MagicMock

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient

from otalon_api.api.v1.pcap import router as pcap_router
from otalon_api.dependencies import get_postgres_repo
from otalon_api.services.pcap_proxy_service import PcapProxyService

UPSTREAM_BASE = "http://pcap-recorder:9090"
ALARM_ID = "11111111-2222-3333-4444-555555555555"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def mock_postgres() -> MagicMock:
    """PostgresRepository mock with a populated default alarm."""
    repo = MagicMock()
    repo.get_anomaly_group_by_id = MagicMock(
        return_value={
            "id": ALARM_ID,
            "start_timestamp": datetime(2026, 2, 13, 9, 0, 0, tzinfo=timezone.utc),
            "end_timestamp": datetime(2026, 2, 13, 9, 5, 0, tzinfo=timezone.utc),
            "module": "netcap",
        }
    )
    return repo


@pytest.fixture()
def app_with_proxy(mock_postgres: MagicMock) -> FastAPI:
    """Minimal FastAPI app exposing only the PCAP router.

    Avoids the heavy ``otalon_api.main`` lifespan: only the router + a stubbed
    ``PcapProxyService`` + an overridden ``get_postgres_repo`` dependency.
    """
    app = FastAPI()
    app.state.pcap_proxy_service = PcapProxyService(base_url=UPSTREAM_BASE, api_key="", timeout=2.0)
    app.include_router(pcap_router)
    app.dependency_overrides[get_postgres_repo] = lambda: mock_postgres
    return app


@pytest.fixture()
def client(app_with_proxy: FastAPI) -> TestClient:
    """Synchronous FastAPI test client bound to the proxy-only app."""
    return TestClient(app_with_proxy)


@pytest.fixture()
def mock_upstream() -> AsyncIterator[respx.MockRouter]:
    """``respx`` mock router scoped to the upstream base URL."""
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_BASE) as mock:
        yield mock


# ── Happy path ────────────────────────────────────────────────────────


def test_by_alarm_happy_path(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Alarm exists + recorder returns 2 chunks → summarised envelope."""
    raw_chunks: list[dict[str, Any]] = [
        {
            "chunk_id": "20260213_090000.pcap",
            "path": "/shared/pcap/buffer/20260213_090000.pcap",
            "start_ts": "2026-02-13T09:00:00",
            "end_ts": "2026-02-13T09:00:30",
            "size_bytes": 1048576,
            "is_anomaly": False,
            "labels": {},
        },
        {
            "chunk_id": "20260213_090030.pcap",
            "path": "/shared/pcap/archive/20260213_090030.pcap",
            "start_ts": "2026-02-13T09:00:30",
            "end_ts": "2026-02-13T09:01:00",
            "size_bytes": 524288,
            "is_anomaly": True,
            "labels": {"alarm_group": ALARM_ID},
        },
    ]
    route = mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=raw_chunks))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["alarm_id"] == ALARM_ID
    assert body["chunk_count"] == 2
    assert body["total_size_bytes"] == 1048576 + 524288
    assert len(body["chunks"]) == 2
    assert body["chunks"][0]["chunk_id"] == "20260213_090000.pcap"
    assert body["chunks"][0]["download_url"].endswith("/20260213_090000.pcap")
    assert body["chunks"][1]["is_anomaly"] is True

    # Recorder was called with the alarm's UTC window + format=json.
    assert route.called
    sent_params = dict(route.calls.last.request.url.params)
    assert sent_params.get("format") == "json"
    assert "2026-02-13T09:00:00" in sent_params.get("start_ts", "")
    assert "2026-02-13T09:05:00" in sent_params.get("end_ts", "")


def test_by_alarm_empty_window(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Alarm exists but the recorder has no overlapping chunks."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["chunk_count"] == 0
    assert body["total_size_bytes"] == 0
    assert body["chunks"] == []


# ── Failure modes ─────────────────────────────────────────────────────


def test_alarm_not_found_returns_404(
    client: TestClient,
    mock_upstream: respx.MockRouter,
    mock_postgres: MagicMock,
) -> None:
    """Unknown alarm ID → 404, recorder is never called."""
    mock_postgres.get_anomaly_group_by_id.return_value = None
    route = mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 404
    assert ALARM_ID in resp.json()["detail"]
    assert not route.called


def test_upstream_timeout_returns_504(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """``httpx.ReadTimeout`` from recorder → 504 (distinct from 502)."""
    mock_upstream.get("/chunks").mock(side_effect=httpx.ReadTimeout("slow"))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 504
    detail = resp.json()["detail"]
    assert "timed out" in detail
    assert "ReadTimeout" in detail


def test_upstream_connect_error_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """``httpx.ConnectError`` from recorder → 502."""
    mock_upstream.get("/chunks").mock(side_effect=httpx.ConnectError("connection refused"))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 502
    assert "unreachable" in resp.json()["detail"]
    assert "ConnectError" in resp.json()["detail"]


def test_upstream_auth_failure_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 401 (future auth layer) → 502 with auth-failure detail."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(401, json={"detail": "missing key"}))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 502
    assert "auth failure" in resp.json()["detail"]
    assert "401" in resp.json()["detail"]


def test_upstream_403_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 403 also collapses to 502 with auth-failure detail."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(403, json={"detail": "forbidden"}))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 502
    assert "auth failure" in resp.json()["detail"]


def test_upstream_500_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 500 → proxy 502 (internal collaborator failure)."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(500, json={"detail": "tcpdump crashed"}))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert "status 500" in detail
    assert "tcpdump crashed" in detail


def test_upstream_returns_non_list_body(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Recorder returns a dict instead of a list → 502 (malformed)."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json={"unexpected": "shape"}))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 502
    assert "malformed" in resp.json()["detail"]


def test_service_not_configured_returns_503(
    mock_postgres: MagicMock,
) -> None:
    """No proxy attached to app.state → 503."""
    app = FastAPI()
    app.include_router(pcap_router)
    app.dependency_overrides[get_postgres_repo] = lambda: mock_postgres
    c = TestClient(app)
    resp = c.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 503
    assert "pcap proxy service not configured" in resp.json()["detail"]


# ── Header injection ──────────────────────────────────────────────────


def test_api_key_forwarded_when_configured(
    mock_postgres: MagicMock,
) -> None:
    """``X-API-Key`` is injected when ``api_key`` is set."""
    app = FastAPI()
    app.state.pcap_proxy_service = PcapProxyService(base_url=UPSTREAM_BASE, api_key="secret-xyz", timeout=2.0)
    app.include_router(pcap_router)
    app.dependency_overrides[get_postgres_repo] = lambda: mock_postgres

    with respx.mock(assert_all_called=False, base_url=UPSTREAM_BASE) as mock:
        route = mock.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
        c = TestClient(app)
        resp = c.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
        assert resp.status_code == 200
        assert route.called
        assert route.calls.last.request.headers.get("X-API-Key") == "secret-xyz"


def test_api_key_not_sent_when_empty(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """No ``X-API-Key`` header when ``api_key`` is empty (recorder has no auth today)."""
    route = mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 200
    assert route.called
    assert "X-API-Key" not in route.calls.last.request.headers


# ── Chunk-summary edge cases ──────────────────────────────────────────


def test_chunk_without_id_is_skipped(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Recorder rows without ``chunk_id`` are silently dropped."""
    mock_upstream.get("/chunks").mock(
        return_value=httpx.Response(
            200,
            json=[
                {"chunk_id": "20260213_090000.pcap", "size_bytes": 100},
                {"path": "/orphan", "size_bytes": 999},  # no chunk_id, no filename
            ],
        )
    )
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["chunk_count"] == 1
    assert body["total_size_bytes"] == 100


def test_chunk_id_falls_back_to_filename(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """If only ``filename`` is present (legacy field) it is used as chunk_id."""
    mock_upstream.get("/chunks").mock(
        return_value=httpx.Response(
            200,
            json=[{"filename": "20260213_090000.pcap", "size_bytes": 42}],
        )
    )
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}")
    assert resp.status_code == 200
    body = resp.json()
    assert body["chunks"][0]["chunk_id"] == "20260213_090000.pcap"


# ── Dependency on raw service (sanity) ────────────────────────────────


@pytest.mark.asyncio
async def test_service_list_chunks_passes_params() -> None:
    """``PcapProxyService.list_chunks_in_range`` forwards params verbatim."""
    svc = PcapProxyService(base_url=UPSTREAM_BASE, api_key="", timeout=1.0)
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_BASE) as mock:
        route = mock.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
        status, body = await svc.list_chunks_in_range("2026-02-13T09:00:00Z", "2026-02-13T09:05:00Z")
    assert status == 200
    assert body == []
    assert route.called
    q = dict(route.calls.last.request.url.params)
    assert q["start_ts"] == "2026-02-13T09:00:00Z"
    assert q["end_ts"] == "2026-02-13T09:05:00Z"
    assert q["format"] == "json"


@pytest.mark.asyncio
async def test_service_translates_transport_error() -> None:
    """``httpx.TransportError`` → :class:`UpstreamUnreachable`."""
    from otalon_api.services.pcap_proxy_service import UpstreamUnreachable

    svc = PcapProxyService(base_url=UPSTREAM_BASE, api_key="", timeout=1.0)
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_BASE) as mock:
        mock.get("/chunks").mock(side_effect=httpx.ConnectError("nope"))
        with pytest.raises(UpstreamUnreachable) as exc_info:
            await svc.list_chunks_in_range("a", "b")
    assert "ConnectError" in str(exc_info.value)
