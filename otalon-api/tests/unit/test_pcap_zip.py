"""Unit tests for the PCAP-alarm ZIP-bundle endpoint.

Covers ``GET /api/v1/pcap/by-alarm/{alarm_id}/zip``:

* Happy path: 3 mocked chunks → 200, ``application/zip``, archive
  unpacks to ``chunk-001.pcap`` … ``chunk-003.pcap`` plus a
  ``metadata.json`` manifest with the correct alarm window.
* Alarm-not-found → 404 (recorder not called).
* Alarm exists but zero chunks → 404 (clear detail).
* Recorder lists OK but per-chunk fetch returns 500 →
  the chunk is skipped, archive still streams (resilient behaviour).
* Recorder listing returns 500 → 502.
* Recorder listing times out → 504.
* Proxy not configured on ``app.state`` → 503.
* Conducts a small smoke check that the ``Content-Disposition``
  header carries the alarm id.
"""

from __future__ import annotations

import io
import json
import zipfile
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
ALARM_ID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def mock_postgres() -> MagicMock:
    """PostgresRepository mock with a populated default alarm."""
    repo = MagicMock()
    repo.get_anomaly_group_by_id = MagicMock(
        return_value={
            "id": ALARM_ID,
            "start_timestamp": datetime(2026, 5, 19, 12, 0, 0, tzinfo=timezone.utc),
            "end_timestamp": datetime(2026, 5, 19, 12, 10, 0, tzinfo=timezone.utc),
            "module": "netcap",
        }
    )
    return repo


@pytest.fixture()
def app_with_proxy(mock_postgres: MagicMock) -> FastAPI:
    """Minimal FastAPI app exposing the PCAP router with a real proxy."""
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


def _chunk_listing() -> list[dict[str, Any]]:
    """Build a 3-chunk listing in alarm-time order."""
    return [
        {
            "chunk_id": "20260519_120000.pcap",
            "path": "/shared/pcap/buffer/20260519_120000.pcap",
            "start_ts": "2026-05-19T12:00:00",
            "end_ts": "2026-05-19T12:00:30",
            "size_bytes": 11,
            "is_anomaly": False,
            "labels": {},
        },
        {
            "chunk_id": "20260519_120030.pcap",
            "path": "/shared/pcap/buffer/20260519_120030.pcap",
            "start_ts": "2026-05-19T12:00:30",
            "end_ts": "2026-05-19T12:01:00",
            "size_bytes": 11,
            "is_anomaly": True,
            "labels": {"alarm_group": ALARM_ID},
        },
        {
            "chunk_id": "20260519_120100.pcap",
            "path": "/shared/pcap/buffer/20260519_120100.pcap",
            "start_ts": "2026-05-19T12:01:00",
            "end_ts": "2026-05-19T12:01:30",
            "size_bytes": 11,
            "is_anomaly": False,
            "labels": {},
        },
    ]


# ── Happy path ────────────────────────────────────────────────────────


def test_zip_happy_path(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """3 chunks → 200 ZIP with chunk-001..003.pcap + metadata.json."""
    chunks = _chunk_listing()
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=chunks))
    for i, c in enumerate(chunks):
        body = f"PCAP-BYTES-{i}".encode()
        mock_upstream.get(f"/chunks/{c['chunk_id']}").mock(
            return_value=httpx.Response(
                200,
                content=body,
                headers={"Content-Type": "application/octet-stream"},
            )
        )

    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    cd = resp.headers["content-disposition"]
    assert "attachment" in cd
    assert f"alarm-{ALARM_ID}.zip" in cd

    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        names = zf.namelist()
        assert "chunk-001.pcap" in names
        assert "chunk-002.pcap" in names
        assert "chunk-003.pcap" in names
        assert "metadata.json" in names
        assert zf.read("chunk-001.pcap") == b"PCAP-BYTES-0"
        assert zf.read("chunk-002.pcap") == b"PCAP-BYTES-1"
        assert zf.read("chunk-003.pcap") == b"PCAP-BYTES-2"

        manifest = json.loads(zf.read("metadata.json"))
        assert manifest["alarm_id"] == ALARM_ID
        assert manifest["chunk_count"] == 3
        assert manifest["alarm_window"]["start"].startswith("2026-05-19T12:00:00")
        assert manifest["alarm_window"]["end"].startswith("2026-05-19T12:10:00")
        assert manifest["alarm_window"]["duration_s"] == 600.0
        assert len(manifest["chunks"]) == 3
        assert manifest["chunks"][0]["archive_name"] == "chunk-001.pcap"
        assert manifest["chunks"][0]["chunk_id"] == "20260519_120000.pcap"
        assert manifest["chunks"][0]["size_bytes"] == len(b"PCAP-BYTES-0")
        assert "generated_at" in manifest


def test_zip_orders_chunks_by_start_ts(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Listing in random order is sorted by ``start_ts`` before zipping."""
    chunks = _chunk_listing()
    shuffled = [chunks[2], chunks[0], chunks[1]]
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=shuffled))
    for i, c in enumerate(chunks):
        mock_upstream.get(f"/chunks/{c['chunk_id']}").mock(return_value=httpx.Response(200, content=f"P{i}".encode()))

    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        assert zf.read("chunk-001.pcap") == b"P0"
        assert zf.read("chunk-002.pcap") == b"P1"
        assert zf.read("chunk-003.pcap") == b"P2"


# ── Failure modes ─────────────────────────────────────────────────────


def test_zip_alarm_not_found_returns_404(
    client: TestClient,
    mock_upstream: respx.MockRouter,
    mock_postgres: MagicMock,
) -> None:
    """Unknown alarm → 404 (recorder is never called)."""
    mock_postgres.get_anomaly_group_by_id.return_value = None
    route = mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 404
    assert ALARM_ID in resp.json()["detail"]
    assert not route.called


def test_zip_empty_chunks_returns_404(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Alarm exists but recorder has 0 chunks → 404 with clear detail."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=[]))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 404
    assert "no PCAP chunks" in resp.json()["detail"]
    assert ALARM_ID in resp.json()["detail"]


def test_zip_recorder_returns_500_for_listing(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Recorder 500 on the listing call → proxy 502."""
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(500, json={"detail": "tcpdump crashed"}))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 502
    detail = resp.json()["detail"]
    assert "status 500" in detail


def test_zip_recorder_listing_times_out(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Recorder times out on the listing call → 504."""
    mock_upstream.get("/chunks").mock(side_effect=httpx.ReadTimeout("slow"))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 504
    detail = resp.json()["detail"]
    assert "timed out" in detail


def test_zip_service_not_configured_returns_503(
    mock_postgres: MagicMock,
) -> None:
    """No proxy attached to ``app.state`` → 503."""
    app = FastAPI()
    app.include_router(pcap_router)
    app.dependency_overrides[get_postgres_repo] = lambda: mock_postgres
    c = TestClient(app)
    resp = c.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 503
    assert "pcap proxy service not configured" in resp.json()["detail"]


def test_zip_skips_chunk_that_returns_404(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """One chunk rotated out (404) → archive still streams the others.

    Resilient behaviour: rather than aborting the whole bundle, the
    missing chunk is logged and skipped. The manifest reflects what
    actually made it in.
    """
    chunks = _chunk_listing()
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=chunks))
    mock_upstream.get(f"/chunks/{chunks[0]['chunk_id']}").mock(return_value=httpx.Response(200, content=b"FIRST"))
    mock_upstream.get(f"/chunks/{chunks[1]['chunk_id']}").mock(
        return_value=httpx.Response(404, json={"detail": "rotated"})
    )
    mock_upstream.get(f"/chunks/{chunks[2]['chunk_id']}").mock(return_value=httpx.Response(200, content=b"THIRD"))

    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 200
    with zipfile.ZipFile(io.BytesIO(resp.content)) as zf:
        names = zf.namelist()
        # Skipped chunk's slot is left out, the others keep their
        # original index so the order maps cleanly back to the alarm
        # listing.
        assert "chunk-001.pcap" in names
        assert "chunk-002.pcap" not in names
        assert "chunk-003.pcap" in names
        assert "metadata.json" in names
        assert zf.read("chunk-001.pcap") == b"FIRST"
        assert zf.read("chunk-003.pcap") == b"THIRD"
        manifest = json.loads(zf.read("metadata.json"))
        assert manifest["chunk_count"] == 2
        assert [c["archive_name"] for c in manifest["chunks"]] == [
            "chunk-001.pcap",
            "chunk-003.pcap",
        ]
        assert manifest["chunks"][0]["chunk_id"] == chunks[0]["chunk_id"]
        assert manifest["chunks"][1]["chunk_id"] == chunks[2]["chunk_id"]


# ── Header smoke ─────────────────────────────────────────────────────


def test_zip_content_disposition_filename(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """``Content-Disposition`` header announces ``alarm-<id>.zip``."""
    chunks = _chunk_listing()[:1]
    mock_upstream.get("/chunks").mock(return_value=httpx.Response(200, json=chunks))
    mock_upstream.get(f"/chunks/{chunks[0]['chunk_id']}").mock(return_value=httpx.Response(200, content=b"X"))
    resp = client.get(f"/api/v1/pcap/by-alarm/{ALARM_ID}/zip")
    assert resp.status_code == 200
    assert resp.headers["content-type"] == "application/zip"
    assert resp.headers["content-disposition"] == (f'attachment; filename="alarm-{ALARM_ID}.zip"')
