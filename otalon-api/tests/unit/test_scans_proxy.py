"""Unit tests for the scan-proxy router and service (Wave C / scan--api-proxy).

Uses ``respx`` to mock the upstream ``otalon-scan:8091`` HTTP service.
Covers happy paths for all 10 endpoints, upstream error propagation,
transport-error → 502 mapping, SSE byte-for-byte forwarding,
SSE upstream-status error frames, and ``Last-Event-ID`` forwarding.
"""

from __future__ import annotations

import asyncio
import json
import re
from typing import Iterator

import httpx
import pytest
import respx
from fastapi import FastAPI
from fastapi.testclient import TestClient
from loguru import logger

from otalon_api.api.v1.scans import router as scans_router
from otalon_api.services.scan_proxy_service import ScanProxyService, UpstreamUnreachable

UPSTREAM_BASE = "http://otalon-scan:8091"
API_KEY = "test-key-xyz"


# ── Fixtures ──────────────────────────────────────────────────────────


@pytest.fixture()
def app_with_proxy() -> FastAPI:
    """Build a minimal FastAPI app exposing only the scans router.

    Avoids the full ``otalon_api.main`` lifespan (which boots Postgres, Influx,
    SSE emitters, etc.) — we only need the router + an injected
    ``ScanProxyService``.
    """
    app = FastAPI()
    app.state.scan_proxy_service = ScanProxyService(base_url=UPSTREAM_BASE, api_key=API_KEY, timeout=2.0)
    app.include_router(scans_router)
    return app


@pytest.fixture()
def client(app_with_proxy: FastAPI) -> TestClient:
    """Synchronous FastAPI test client bound to the proxy-only app."""
    return TestClient(app_with_proxy)


@pytest.fixture()
def mock_upstream() -> Iterator[respx.MockRouter]:
    """Yield a ``respx`` mock router scoped to the upstream base URL."""
    with respx.mock(assert_all_called=False, base_url=UPSTREAM_BASE) as mock:
        yield mock


# ── REST happy paths ──────────────────────────────────────────────────


def test_modules_happy_path(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/modules forwards to upstream, returns body verbatim,
    and injects the X-API-Key header."""
    route = mock_upstream.get("/modules").mock(
        return_value=httpx.Response(200, json={"modules": ["arp_scan", "port_scan"]})
    )
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 200
    assert resp.json() == {"modules": ["arp_scan", "port_scan"]}
    assert route.called
    sent = route.calls.last.request
    assert sent.headers.get("X-API-Key") == API_KEY


def test_start_scan_forwards_body_to_scans_start(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """POST /api/v1/scans → upstream POST /scans/start with body verbatim."""
    body = {"module_name": "arp_scan", "overrides": {"target_subnet": "192.168.0.0/24"}}
    route = mock_upstream.post("/scans/start").mock(
        return_value=httpx.Response(
            200,
            json={
                "run_id": "r-1",
                "scan_id": "s-1",
                "module_name": "arp_scan",
                "status": "running",
            },
        )
    )
    resp = client.post("/api/v1/scans", json=body)
    assert resp.status_code == 200
    assert resp.json()["scan_id"] == "s-1"
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == body


def test_list_scans_forwards_query_params(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/scans?status=...&limit=... preserves query parameters."""
    route = mock_upstream.get("/scans").mock(return_value=httpx.Response(200, json={"scans": []}))
    resp = client.get("/api/v1/scans", params={"status": "running", "module": "arp_scan", "limit": 10})
    assert resp.status_code == 200
    assert route.called
    sent = route.calls.last.request
    q = dict(sent.url.params)
    assert q.get("status") == "running"
    assert q.get("module") == "arp_scan"
    assert q.get("limit") == "10"
    # since/offset were not provided → must not be sent
    assert "since" not in q
    assert "offset" not in q


def test_get_scan_detail(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/scans/{scan_id} → upstream GET /scans/{scan_id}."""
    route = mock_upstream.get("/scans/scan-42").mock(
        return_value=httpx.Response(200, json={"scan_id": "scan-42", "status": "completed"})
    )
    resp = client.get("/api/v1/scans/scan-42")
    assert resp.status_code == 200
    assert resp.json()["status"] == "completed"
    assert route.called


def test_delete_scan_forwards_method_and_emits_empty_204(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """DELETE /api/v1/scans/{id} forwards verbatim; 204 carries no body."""
    route = mock_upstream.delete("/scans/scan-42").mock(return_value=httpx.Response(204))
    resp = client.delete("/api/v1/scans/scan-42")
    assert resp.status_code == 204
    assert resp.content == b""
    assert route.called


def test_delete_scan_propagates_404(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """DELETE /api/v1/scans/{id} forwards upstream 404 transparently."""
    mock_upstream.delete("/scans/missing").mock(return_value=httpx.Response(404, json={"detail": "scan not found"}))
    resp = client.delete("/api/v1/scans/missing")
    assert resp.status_code == 404


def test_scan_id_path_allows_both_get_and_delete(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """``/scans/{scan_id}`` must expose GET and DELETE on one route.

    Regression for the route-shadowing bug (UI-014): GET and DELETE
    were registered as two separate same-path APIRoutes, so Starlette
    matched only the first and the second returned 405.
    """
    resp = client.options("/api/v1/scans/scan-1")
    allow = resp.headers.get("allow", "")
    methods = {m.strip() for m in allow.split(",")}
    assert {"GET", "DELETE"} <= methods


def test_abort_scan_maps_to_stop_alias(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """POST /api/v1/scans/{id}/abort → upstream POST /scans/{id}/stop."""
    route = mock_upstream.post("/scans/scan-7/stop").mock(
        return_value=httpx.Response(200, json={"run_id": "scan-7", "stopped": True})
    )
    resp = client.post("/api/v1/scans/scan-7/abort")
    assert resp.status_code == 200
    assert resp.json() == {"run_id": "scan-7", "stopped": True}
    assert route.called


def test_device_scans_endpoint(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/devices/{id}/scans is 1:1."""
    route = mock_upstream.get("/devices/dev-3/scans").mock(return_value=httpx.Response(200, json={"scans": []}))
    resp = client.get("/api/v1/devices/dev-3/scans")
    assert resp.status_code == 200
    assert route.called


def test_device_observations_endpoint(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/devices/{id}/observations is 1:1."""
    route = mock_upstream.get("/devices/dev-3/observations").mock(
        return_value=httpx.Response(200, json={"observations": []})
    )
    resp = client.get("/api/v1/devices/dev-3/observations")
    assert resp.status_code == 200
    assert route.called


def test_patch_vulnerability(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """PATCH /api/v1/vulnerabilities/{id} forwards body and method verbatim."""
    body = {"status": "mitigated"}
    route = mock_upstream.patch("/vulnerabilities/v-1").mock(
        return_value=httpx.Response(200, json={"vuln_id": "v-1", "status": "mitigated"})
    )
    resp = client.patch("/api/v1/vulnerabilities/v-1", json=body)
    assert resp.status_code == 200
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == body


def test_lookup_vulnerabilities(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """POST /api/v1/vulnerabilities/lookup forwards body verbatim (Task 3.2)."""
    body = {"all": True}
    route = mock_upstream.post("/vulnerabilities/lookup").mock(
        return_value=httpx.Response(
            200,
            json={
                "assets_checked": 2,
                "eligible_assets": 2,
                "total_hits": 3,
                "assets_with_hits": 1,
                "scan_id": "s-1",
            },
        )
    )
    resp = client.post("/api/v1/vulnerabilities/lookup", json=body)
    assert resp.status_code == 200
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == body


def test_lookup_vulnerabilities_propagates_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Transport error on lookup SHALL map to proxy 502."""
    mock_upstream.post("/vulnerabilities/lookup").mock(side_effect=httpx.ConnectError("connection refused"))
    resp = client.post("/api/v1/vulnerabilities/lookup", json={"all": True})
    assert resp.status_code == 502
    assert "upstream otalon-scan unreachable" in resp.json()["detail"]


def test_lookup_vulnerabilities_propagates_202(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Async upstream 202 + job_id propagates verbatim (SCAN-026 WB.3).

    The 502-fix contract: the async ``POST`` now returns 202 Accepted
    with ``{job_id, status, eligible_assets}`` — both status and body
    must pass through the proxy unchanged.
    """
    body = {"all": True}
    upstream_reply = {
        "job_id": "abcdabcd-1234-1234-1234-abcdabcdabcd",
        "status": "running",
        "eligible_assets": 4,
    }
    route = mock_upstream.post("/vulnerabilities/lookup").mock(return_value=httpx.Response(202, json=upstream_reply))
    resp = client.post("/api/v1/vulnerabilities/lookup", json=body)
    assert resp.status_code == 202
    assert resp.json() == upstream_reply
    assert route.called


def test_list_lookups_forwards_pagination(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/vulnerabilities/lookups forwards limit/offset (WB.3)."""
    upstream_reply = {
        "lookups": [
            {"job_id": "j-1", "status": "completed", "summary": {"cves_found": 2}},
            {"job_id": "j-2", "status": "failed", "error": "boom"},
        ]
    }
    route = mock_upstream.get("/vulnerabilities/lookups").mock(return_value=httpx.Response(200, json=upstream_reply))
    resp = client.get("/api/v1/vulnerabilities/lookups", params={"limit": 20, "offset": 5})
    assert resp.status_code == 200
    assert resp.json() == upstream_reply
    assert route.called
    q = dict(route.calls.last.request.url.params)
    assert q.get("limit") == "20"
    assert q.get("offset") == "5"


def test_list_lookups_drops_none_params(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Absent pagination params → outbound URL has no query string."""
    route = mock_upstream.get("/vulnerabilities/lookups").mock(return_value=httpx.Response(200, json={"lookups": []}))
    resp = client.get("/api/v1/vulnerabilities/lookups")
    assert resp.status_code == 200
    assert dict(route.calls.last.request.url.params) == {}


def test_get_lookup_detail(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/vulnerabilities/lookups/{id} → upstream detail verbatim."""
    job_id = "abcdabcd-1234-1234-1234-abcdabcdabcd"
    upstream_reply = {
        "job_id": job_id,
        "status": "completed",
        "summary": {"cves_found": 5, "critical": 2},
    }
    route = mock_upstream.get(f"/vulnerabilities/lookups/{job_id}").mock(
        return_value=httpx.Response(200, json=upstream_reply)
    )
    resp = client.get(f"/api/v1/vulnerabilities/lookups/{job_id}")
    assert resp.status_code == 200
    assert resp.json() == upstream_reply
    assert route.called


def test_get_lookup_propagates_404(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 404 on lookup detail propagates verbatim."""
    mock_upstream.get("/vulnerabilities/lookups/missing").mock(
        return_value=httpx.Response(404, json={"detail": "cve lookup not found"})
    )
    resp = client.get("/api/v1/vulnerabilities/lookups/missing")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "cve lookup not found"}


def test_lookups_literal_not_captured_by_vuln_id(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """``/vulnerabilities/lookups`` is matched literally, not by a param route."""
    route = mock_upstream.get("/vulnerabilities/lookups").mock(return_value=httpx.Response(200, json={"lookups": []}))
    resp = client.get("/api/v1/vulnerabilities/lookups")
    assert resp.status_code == 200
    assert route.called
    assert route.calls.last.request.url.path == "/vulnerabilities/lookups"


def test_lookup_events_stream_bytes_verbatim(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Lookup SSE bytes flow byte-for-byte; no-buffer headers set (WB.3)."""
    payload = (
        b'event: progress\ndata: {"device_id": 1, "cve_count": 2}\n\n'
        b'event: done\ndata: {"job_id": "j-1", "status": "completed", '
        b'"cves_found": 2, "critical": 1}\n\n'
    )
    mock_upstream.get("/vulnerabilities/lookups/j-1/events").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=payload,
        )
    )
    with client.stream("GET", "/api/v1/vulnerabilities/lookups/j-1/events") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert resp.headers.get("cache-control") == "no-cache"
        assert resp.headers.get("x-accel-buffering") == "no"
        received = b"".join(chunk for chunk in resp.iter_bytes())
    assert payload in received
    assert b"event: done" in received


def test_lookup_events_upstream_404_emits_error_frame(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 404 on lookup SSE connect → single in-stream error frame."""
    mock_upstream.get("/vulnerabilities/lookups/missing/events").mock(
        return_value=httpx.Response(404, json={"detail": "no such job"})
    )
    with client.stream("GET", "/api/v1/vulnerabilities/lookups/missing/events") as resp:
        assert resp.status_code == 200
        body = b"".join(chunk for chunk in resp.iter_bytes())
    assert b"event: error" in body
    assert b'"reason": "upstream_status"' in body
    assert b'"status": 404' in body


def test_lookup_events_forwards_last_event_id(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Last-Event-ID inbound → forwarded on outbound lookup SSE request."""
    payload = b'event: progress\ndata: {"index": 1}\n\n'
    route = mock_upstream.get("/vulnerabilities/lookups/j-2/events").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=payload,
        )
    )
    with client.stream(
        "GET",
        "/api/v1/vulnerabilities/lookups/j-2/events",
        headers={"Last-Event-ID": "3"},
    ) as resp:
        for _ in resp.iter_bytes():
            pass
    assert route.called
    sent = route.calls.last.request
    assert sent.headers.get("Last-Event-ID") == "3"
    assert sent.headers.get("X-API-Key") == API_KEY


def test_delete_device(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """DELETE /api/v1/devices/{id} forwards method verbatim."""
    route = mock_upstream.delete("/devices/dev-9").mock(
        return_value=httpx.Response(200, json={"device_id": "dev-9", "deleted": True})
    )
    resp = client.delete("/api/v1/devices/dev-9")
    assert resp.status_code == 200
    assert route.called


def test_delete_devices_bulk_forwards_body_to_devices(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """DELETE /api/v1/devices forwards the JSON body verbatim and returns 200."""
    payload = {"ids": [1, 2, 3]}
    upstream_reply = {"deleted": [1, 3], "not_found": [2]}
    route = mock_upstream.delete("/devices").mock(return_value=httpx.Response(200, json=upstream_reply))
    resp = client.request("DELETE", "/api/v1/devices", json=payload)
    assert resp.status_code == 200
    assert resp.json() == upstream_reply
    assert route.called
    sent_body = json.loads(route.calls.last.request.content)
    assert sent_body == payload
    # The outbound call carries the operator API key.
    assert route.calls.last.request.headers.get("X-API-Key") == API_KEY


def test_delete_devices_bulk_propagates_422(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 422 (validation) on bulk delete SHALL propagate verbatim."""
    mock_upstream.delete("/devices").mock(
        return_value=httpx.Response(
            422,
            json={"detail": [{"loc": ["body", "ids"], "msg": "List should have at least 1 item"}]},
        )
    )
    resp = client.request("DELETE", "/api/v1/devices", json={"ids": []})
    assert resp.status_code == 422
    assert "at least 1 item" in json.dumps(resp.json())


def test_delete_devices_bulk_upstream_unreachable_returns_502(
    client: TestClient, mock_upstream: respx.MockRouter
) -> None:
    """Transport error on bulk delete SHALL map to proxy 502."""
    mock_upstream.delete("/devices").mock(side_effect=httpx.ConnectError("connection refused"))
    resp = client.request("DELETE", "/api/v1/devices", json={"ids": [1]})
    assert resp.status_code == 502
    assert "upstream otalon-scan unreachable" in resp.json()["detail"]


# ── Error propagation ────────────────────────────────────────────────


def test_upstream_404_propagates(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 404 → proxy 404 with verbatim body."""
    mock_upstream.get("/scans/missing").mock(return_value=httpx.Response(404, json={"detail": "scan not found"}))
    resp = client.get("/api/v1/scans/missing")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "scan not found"}


def test_upstream_500_propagates(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 500 → proxy 500 with verbatim body."""
    mock_upstream.get("/modules").mock(return_value=httpx.Response(500, json={"detail": "internal scanner error"}))
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 500
    assert resp.json() == {"detail": "internal scanner error"}


def test_upstream_connect_error_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream connect error → proxy 502 with stable error envelope."""
    mock_upstream.get("/modules").mock(side_effect=httpx.ConnectError("connection refused"))
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 502
    body = resp.json()
    assert "upstream otalon-scan unreachable" in body["detail"]
    assert "ConnectError" in body["detail"]


def test_upstream_timeout_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream timeout (ReadTimeout) → proxy 502."""
    mock_upstream.get("/modules").mock(side_effect=httpx.ReadTimeout("slow"))
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 502
    assert "upstream otalon-scan unreachable" in resp.json()["detail"]
    assert "ReadTimeout" in resp.json()["detail"]


# ── SSE proxy ─────────────────────────────────────────────────────────


def _sse_payload() -> bytes:
    """Return a small valid SSE payload."""
    return b'event: progress\ndata: {"percent": 42}\n\n' b'event: progress\ndata: {"percent": 88}\n\n'


def test_sse_streams_bytes_verbatim(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """SSE bytes flow byte-for-byte; required no-buffer headers are set."""
    payload = _sse_payload()
    mock_upstream.get("/scans/sse-1/events").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=payload,
        )
    )
    with client.stream("GET", "/api/v1/scans/sse-1/events") as resp:
        assert resp.status_code == 200
        assert resp.headers["content-type"].startswith("text/event-stream")
        assert resp.headers.get("cache-control") == "no-cache"
        assert resp.headers.get("x-accel-buffering") == "no"
        received = b"".join(chunk for chunk in resp.iter_bytes())
    assert payload in received


def test_sse_upstream_404_emits_error_frame(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 404 on SSE connect → single in-stream error frame."""
    mock_upstream.get("/scans/missing/events").mock(return_value=httpx.Response(404, json={"detail": "no such scan"}))
    with client.stream("GET", "/api/v1/scans/missing/events") as resp:
        assert resp.status_code == 200  # SSE was opened to client
        body = b"".join(chunk for chunk in resp.iter_bytes())
    assert b"event: error" in body
    assert b'"reason": "upstream_status"' in body
    assert b'"status": 404' in body


def test_sse_forwards_last_event_id(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Last-Event-ID inbound → forwarded on outbound upstream request."""
    payload = b'event: progress\ndata: {"percent": 7}\n\n'
    route = mock_upstream.get("/scans/sse-resume/events").mock(
        return_value=httpx.Response(
            200,
            headers={"content-type": "text/event-stream"},
            content=payload,
        )
    )
    with client.stream(
        "GET",
        "/api/v1/scans/sse-resume/events",
        headers={"Last-Event-ID": "17"},
    ) as resp:
        # Drain so the upstream call actually happens.
        for _ in resp.iter_bytes():
            pass
    assert route.called
    sent = route.calls.last.request
    assert sent.headers.get("Last-Event-ID") == "17"
    assert sent.headers.get("X-API-Key") == API_KEY


# ── Log injection hardening (API-006) ─────────────────────────────────


def test_transport_error_log_uses_repr_path_and_method() -> None:
    """WARNING log for transport error uses repr() for path and method.

    Regression: a crafted path with control characters must not inject raw
    newlines/control chars into the log output; ``repr()`` quoting ensures
    the logged form is safe and unambiguous.

    Assertions:
    - The logged message contains the repr-quoted path (e.g.
      ``'GET'`` instead of ``GET``, ``'/foo\\nbar'`` instead of raw newline).
    - The upstream-unreachable log pattern is still emitted.
    """
    from unittest.mock import AsyncMock, patch

    service = ScanProxyService(base_url="http://unreachable:1", api_key="test-key")

    # Capture loguru records via a list sink.
    records: list[str] = []
    handler_id = logger.add(lambda msg: records.append(msg), format="{message}")
    try:
        with patch.object(httpx.AsyncClient, "request", new_callable=AsyncMock) as mock_request:
            mock_request.side_effect = httpx.ConnectError("connection refused")
            with pytest.raises(UpstreamUnreachable):
                # path contains a control character that would inject a raw newline
                asyncio.run(service._request("GET", "/foo\nbar"))
    finally:
        logger.remove(handler_id)

    assert len(records) >= 1, "Expected at least one log record"
    msg = records[0]
    # Check the repr form is present: path '/foo\\nbar' is quoted, not raw
    assert "upstream" in msg
    assert "'GET'" in msg, "repr(method) should use single quotes"
    assert (
        "'/foo\\nbar'" in msg or "'/foo\\\\nbar'" in msg
    ), "repr(path) should quote the path with control chars escaped"


# ── Header injection (REST) ──────────────────────────────────────────


def test_rest_outbound_carries_api_key(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Every REST outbound call carries X-API-Key (sanity check)."""
    mock_upstream.get("/devices/dev-1/scans").mock(return_value=httpx.Response(200, json={"scans": []}))
    mock_upstream.get("/devices/dev-1/observations").mock(return_value=httpx.Response(200, json={"observations": []}))
    client.get("/api/v1/devices/dev-1/scans")
    client.get("/api/v1/devices/dev-1/observations")
    # All recorded calls carried the key.
    for call in mock_upstream.calls:
        assert call.request.headers.get("X-API-Key") == API_KEY


# ── Service-level negative case (no proxy in app.state) ──────────────


def test_service_not_configured_returns_503() -> None:
    """Router returns 503 if no ScanProxyService was attached to app.state."""
    app = FastAPI()
    app.include_router(scans_router)
    c = TestClient(app)
    resp = c.get("/api/v1/modules")
    assert resp.status_code == 503
    assert "scan proxy service not configured" in resp.json()["detail"]


def test_get_interfaces_happy_path(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/scans/interfaces forwards to upstream, returns body verbatim."""
    route = mock_upstream.get("/scans/interfaces").mock(
        return_value=httpx.Response(
            200,
            json=[
                {
                    "name": "enp4s0",
                    "ipv4": "192.168.0.5",
                    "subnet": "192.168.0.0/24",
                    "is_up": True,
                    "role": "active-scan-port",
                    "mac": "aa:bb:cc:dd:ee:ff",
                }
            ],
        )
    )
    resp = client.get("/api/v1/scans/interfaces")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data) == 1
    assert data[0]["name"] == "enp4s0"
    assert route.called


def test_get_module_schema_happy_path(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """GET /api/v1/scans/modules/{name}/schema forwards to upstream."""
    route = mock_upstream.get("/scans/modules/port_scan/schema").mock(
        return_value=httpx.Response(
            200,
            json={
                "accepted_keys": ["target_ip", "port_range", "timing_template"],
                "requires_auth": False,
            },
        )
    )
    resp = client.get("/api/v1/scans/modules/port_scan/schema")
    assert resp.status_code == 200
    data = resp.json()
    assert "target_ip" in data["accepted_keys"]
    assert data["requires_auth"] is False
    assert route.called


def test_interfaces_literal_route_not_captured_by_scan_id(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """``/scans/interfaces`` MUST be matched as a literal path, not swallowed
    by the ``{scan_id}`` parameter route."""
    route = mock_upstream.get("/scans/interfaces").mock(return_value=httpx.Response(200, json=[]))
    resp = client.get("/api/v1/scans/interfaces")
    assert resp.status_code == 200
    assert route.called
    sent = route.calls.last.request
    assert sent.url.path == "/scans/interfaces"


def test_module_schema_upstream_404_propagates(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 404 on module schema → proxy 404 with verbatim body."""
    mock_upstream.get("/scans/modules/unknown/schema").mock(
        return_value=httpx.Response(404, json={"detail": "module not found"})
    )
    resp = client.get("/api/v1/scans/modules/unknown/schema")
    assert resp.status_code == 404
    assert resp.json() == {"detail": "module not found"}


def test_module_schema_invalid_name_returns_4xx(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Invalid module name (not matching [a-z0-9_]+) SHALL be rejected with 4xx
    and MUST NOT reach the upstream proxy service (API-005)."""
    mock_upstream.get(re.compile(r"/scans/modules/.+/schema")).mock(
        return_value=httpx.Response(200, json={"should": "not_reach"})
    )
    invalid_names = ["Foo!", "a b", "evil;cmd", "has-dash"]
    for name in invalid_names:
        resp = client.get(f"/api/v1/scans/modules/{name}/schema")
        assert resp.status_code in (404, 422), f"expected 4xx for name={name!r}, got {resp.status_code}"
        assert len(mock_upstream.calls) == 0, f"upstream was called for invalid name={name!r} — {mock_upstream.calls}"


def test_module_schema_path_traversal_not_called(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Path-traversal attempt in module name SHALL NOT reach upstream.

    The path ``/api/v1/scans/modules/../etc/schema`` is normalised by the
    HTTP client before it reaches FastAPI, so the route never matches.
    This asserts the outer layer of defence-in-depth: a path traversal
    pattern in the URL yields 404 without an upstream call (API-005).
    """
    mock_upstream.get("/scans/etc/schema").mock(return_value=httpx.Response(200, json={"should": "not_reach"}))
    resp = client.get("/api/v1/scans/modules/../etc/schema")
    assert resp.status_code in (404, 422)
    assert len(mock_upstream.calls) == 0, "upstream must not be called on path-traversal attempt"


def test_interfaces_upstream_unreachable_returns_502(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Transport error on interfaces → proxy 502."""
    mock_upstream.get("/scans/interfaces").mock(side_effect=httpx.ConnectError("connection refused"))
    resp = client.get("/api/v1/scans/interfaces")
    assert resp.status_code == 502
    assert "upstream otalon-scan unreachable" in resp.json()["detail"]


# ── Misc: list_scans drops None-valued params ────────────────────────


def test_list_scans_drops_none_params(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """All optional params absent → outbound URL has no query string."""
    route = mock_upstream.get("/scans").mock(return_value=httpx.Response(200, json={"scans": []}))
    resp = client.get("/api/v1/scans")
    assert resp.status_code == 200
    assert route.called
    sent = route.calls.last.request
    assert dict(sent.url.params) == {}


# ── JSON-decoding fallback ───────────────────────────────────────────


def test_non_json_upstream_body_wrapped_in_detail(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Non-JSON upstream body is surfaced as ``{"detail": "<text>"}``."""
    mock_upstream.get("/modules").mock(return_value=httpx.Response(200, content=b"plain text not json"))
    resp = client.get("/api/v1/modules")
    assert resp.status_code == 200
    assert resp.json() == {"detail": "plain text not json"}


def test_post_scan_propagates_upstream_validation_error(client: TestClient, mock_upstream: respx.MockRouter) -> None:
    """Upstream 422 (validation) → proxy 422 verbatim."""
    mock_upstream.post("/scans/start").mock(
        return_value=httpx.Response(
            422,
            json={"detail": [{"loc": ["overrides"], "msg": "unknown field"}]},
        )
    )
    resp = client.post("/api/v1/scans", json={"module_name": "nope"})
    assert resp.status_code == 422
    assert "unknown field" in json.dumps(resp.json())
