"""Scan + device proxy router.

Forwards UI requests to the ``otalon-scan:8091`` service so the
browser only needs network access to ``otalon-api``. Mounted at
``/api/v1``; see ``openspec/changes/scan--api-proxy/`` for the full
contract.

The router is a thin translator: no business logic, no extra validation
beyond shape. Request bodies are accepted as ``dict[str, Any]`` and
forwarded verbatim. Upstream HTTP responses propagate verbatim (status +
JSON body). Transport-level failures collapse to HTTP 502 with a stable
error envelope.

SSE (``GET /scans/{scan_id}/events``) forwards raw bytes via
``httpx.AsyncClient.stream`` + ``StreamingResponse``. The
``Last-Event-ID`` request header is forwarded if present.
"""

from __future__ import annotations

import json
from typing import Any, AsyncIterator, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException, Path, Query, Request, Response
from fastapi.responses import JSONResponse, StreamingResponse

from otalon_api.middleware.rate_limit import enforce_lookup_rate_limit
from otalon_api.services.scan_proxy_service import ScanProxyService, UpstreamUnreachable

router = APIRouter(prefix="/api/v1", tags=["scans"])


def _service(request: Request) -> ScanProxyService:
    """Return the configured :class:`ScanProxyService` from app state."""
    svc: ScanProxyService | None = getattr(request.app.state, "scan_proxy_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="scan proxy service not configured")
    return svc


def _handle_rest(status: int, body: Any) -> JSONResponse:
    """Wrap an upstream ``(status, body)`` pair into a JSONResponse."""
    return JSONResponse(content=body, status_code=status)


def _handle_rest_maybe_empty(status: int, body: Any) -> Response:
    """Wrap an upstream ``(status, body)`` pair, supporting empty bodies.

    Empty-body responses (HTTP 204 / 205) are forwarded as a bare
    :class:`Response` with no body, because HTTP forbids a body on those
    statuses and :class:`JSONResponse` would otherwise serialise the
    proxy's empty fallback dict. All other statuses fall through to
    :func:`_handle_rest`.
    """
    if status in (204, 205):
        return Response(status_code=status)
    return _handle_rest(status, body)


# ── REST proxies ──────────────────────────────────────────────────────


@router.get("/modules")
async def get_modules(request: Request) -> JSONResponse:
    """Proxy ``GET /modules`` to ``otalon-scan:8091``."""
    svc = _service(request)
    try:
        status, body = await svc.get_modules()
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.post("/scans")
async def post_scan(request: Request, body: dict[str, Any]) -> JSONResponse:
    """Trigger a scan. Body is forwarded verbatim to upstream ``POST /scans/start``."""
    svc = _service(request)
    try:
        status, resp_body = await svc.start_scan(body)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, resp_body)


@router.get("/scans")
async def list_scans(
    request: Request,
    status: Optional[str] = Query(default=None),
    module: Optional[str] = Query(default=None),
    since: Optional[str] = Query(default=None),
    limit: Optional[int] = Query(default=None, ge=1, le=1000),
    offset: Optional[int] = Query(default=None, ge=0),
) -> JSONResponse:
    """Proxy ``GET /scans`` with optional ``status / module / since / limit / offset``."""
    svc = _service(request)
    params: dict[str, Any] = {
        "status": status,
        "module": module,
        "since": since,
        "limit": limit,
        "offset": offset,
    }
    try:
        st, body = await svc.list_scans(params)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(st, body)


@router.get("/scans/interfaces")
async def get_scan_interfaces(request: Request) -> JSONResponse:
    """Proxy ``GET /scans/interfaces`` to ``otalon-scan:8091``."""
    svc = _service(request)
    try:
        status, body = await svc.get_interfaces()
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.get("/scans/modules/{name}/schema")
async def get_module_schema(
    name: str = Path(pattern=r"^[a-z0-9_]+$"),
    request: Request = None,  # type: ignore[assignment]  # noqa: B008  # injected by FastAPI
) -> JSONResponse:
    """Proxy ``GET /scans/modules/{name}/schema`` to ``otalon-scan:8091``."""
    svc = _service(request)
    try:
        status, body = await svc.get_module_schema(name)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.api_route("/scans/{scan_id}", methods=["GET", "DELETE"])
async def get_or_delete_scan(scan_id: str, request: Request) -> Response:
    """Proxy ``GET`` and ``DELETE`` for ``/scans/{scan_id}``.

    Both verbs share a single :class:`APIRoute`. Starlette matches the
    first route whose path matches and only inspects that route's
    methods (it does not aggregate methods across sibling same-path
    routes), so registering ``GET`` and ``DELETE`` as separate routes
    left whichever came first reachable and the other shadowed with a
    405. Carrying both methods on one route keeps both reachable.

    ``GET`` returns the upstream JSON verbatim. ``DELETE`` forwards 204
    (success) and 404 (scan not found) transparently, emitting an empty
    body on 204 per the HTTP spec.
    """
    svc = _service(request)
    if request.method == "DELETE":
        try:
            status, body = await svc.delete_scan(scan_id)
        except UpstreamUnreachable as exc:
            raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
        return _handle_rest_maybe_empty(status, body)
    try:
        status, body = await svc.get_scan(scan_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.post("/scans/{scan_id}/abort")
async def abort_scan(scan_id: str, request: Request) -> JSONResponse:
    """Proxy ``POST /scans/{scan_id}/abort`` (upstream alias ``/stop``)."""
    svc = _service(request)
    try:
        status, body = await svc.abort_scan(scan_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.delete("/scans")
async def delete_scans_bulk(request: Request, body: dict[str, Any]) -> JSONResponse:
    """Proxy ``DELETE /scans`` (bulk reaper).

    Forwards the ``{"ids": [str, ...]}`` body verbatim to upstream
    ``otalon-scan``. Returns 200 with
    ``{"deleted": [...], "not_found": [...]}`` on success.

    Registered before :func:`get_or_delete_scan` so the literal
    ``/scans`` path matches this handler instead of being consumed by
    the ``/scans/{scan_id}`` path-parameter route (F-4).
    """
    svc = _service(request)
    try:
        status, resp_body = await svc.delete_scans_bulk(body)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, resp_body)


@router.get("/devices/{device_id}/scans")
async def get_device_scans(device_id: str, request: Request) -> JSONResponse:
    """Proxy ``GET /devices/{device_id}/scans``."""
    svc = _service(request)
    try:
        status, body = await svc.get_device_scans(device_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.get("/devices/{device_id}/observations")
async def get_device_observations(device_id: str, request: Request) -> JSONResponse:
    """Proxy ``GET /devices/{device_id}/observations``."""
    svc = _service(request)
    try:
        status, body = await svc.get_device_observations(device_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.patch("/vulnerabilities/{vuln_id}")
async def patch_vulnerability(vuln_id: str, request: Request, body: dict[str, Any]) -> JSONResponse:
    """Proxy ``PATCH /vulnerabilities/{vuln_id}`` (Q8 status transitions)."""
    svc = _service(request)
    try:
        status, resp_body = await svc.patch_vulnerability(vuln_id, body)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, resp_body)


@router.post("/vulnerabilities/lookup", dependencies=[Depends(enforce_lookup_rate_limit)])
async def lookup_vulnerabilities(request: Request, body: dict[str, Any]) -> JSONResponse:
    """Proxy ``POST /vulnerabilities/lookup`` (Welle C / Task 3.2).

    Forwards the JSON body verbatim to upstream ``otalon-scan``.
    Upstream status and body propagate transparently; transport errors
    become HTTP 502.
    """
    svc = _service(request)
    try:
        status, resp_body = await svc.lookup_vulnerabilities(body)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, resp_body)


@router.get("/vulnerabilities/lookups")
async def list_cve_lookups(
    request: Request,
    limit: Optional[int] = Query(default=None, ge=1, le=1000),
    offset: Optional[int] = Query(default=None, ge=0),
) -> JSONResponse:
    """Proxy ``GET /vulnerabilities/lookups`` (SCAN-026 WB.3).

    Forwards the optional ``limit`` / ``offset`` pagination params and
    returns the upstream ``{lookups: [...]}`` body verbatim. Registered
    before :func:`get_cve_lookup` so the literal ``/lookups`` path is not
    consumed by the ``/lookups/{job_id}`` path-parameter route.
    """
    svc = _service(request)
    params: dict[str, Any] = {"limit": limit, "offset": offset}
    try:
        status, body = await svc.list_lookups(params)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.get("/vulnerabilities/lookups/{job_id}")
async def get_cve_lookup(job_id: str, request: Request) -> JSONResponse:
    """Proxy ``GET /vulnerabilities/lookups/{job_id}`` (SCAN-026 WB.3).

    Returns the upstream job-header (``summary`` / ``error`` included)
    verbatim — including a 404 for an unknown id.
    """
    svc = _service(request)
    try:
        status, body = await svc.get_lookup(job_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.post("/vulnerabilities/lookups/{job_id}/stop")
async def stop_cve_lookup(job_id: str, request: Request) -> JSONResponse:
    """Proxy ``POST /vulnerabilities/lookups/{job_id}/stop`` (R-02).

    Forwards the operator's stop request to upstream ``otalon-scan``,
    which flags the in-flight lookup task for cooperative cancellation.
    Upstream status and body (``{job_id, stopped}``) propagate verbatim —
    including a 404 for an unknown id; transport errors become HTTP 502.
    """
    svc = _service(request)
    try:
        status, body = await svc.stop_lookup(job_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, body)


@router.get("/vulnerabilities/lookups/{job_id}/events")
async def stream_cve_lookup_events(job_id: str, request: Request) -> StreamingResponse:
    """Stream upstream CVE-lookup SSE bytes byte-for-byte (SCAN-026 WB.3).

    Mirrors :func:`stream_scan_events`: forwards the upstream
    ``text/event-stream`` (``progress`` events + the terminal
    ``done`` / ``failed`` event) verbatim with ``timeout=None`` so a
    long-running lookup never trips a read timeout. On upstream HTTP
    error (initial connect) or mid-stream disconnect it emits a single
    in-stream ``event: error`` frame and closes; the downstream HTTP
    status stays 200 per SSE convention.
    """
    svc = _service(request)
    last_event_id = request.headers.get("last-event-id")

    async def _proxy_iter() -> AsyncIterator[bytes]:
        try:
            async for chunk in svc.stream_lookup_events(job_id, last_event_id=last_event_id):
                yield chunk
        except httpx.HTTPStatusError as exc:
            payload = json.dumps({"reason": "upstream_status", "status": exc.response.status_code})
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")
        except Exception as exc:
            payload = json.dumps(
                {
                    "reason": "upstream_disconnected",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")

    return StreamingResponse(
        _proxy_iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )


@router.delete("/devices")
async def delete_devices_bulk(request: Request, body: dict[str, Any]) -> JSONResponse:
    """Proxy ``DELETE /devices`` (bulk reaper).

    Forwards the ``{"ids": [int, ...]}`` body verbatim to upstream
    ``otalon-scan``. Returns 200 with
    ``{"deleted": [...], "not_found": [...]}`` on success. Upstream
    validation / auth errors (422 / 401 / 403) propagate verbatim.

    Registered before :func:`delete_device` so the literal ``/devices``
    path matches this handler instead of being consumed by the
    ``/devices/{device_id}`` path-parameter route.
    """
    svc = _service(request)
    try:
        status, resp_body = await svc.delete_devices_bulk(body)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, resp_body)


@router.patch("/devices/{device_id}")
async def patch_device_identity(device_id: str, request: Request, body: dict[str, Any]) -> JSONResponse:
    """Proxy ``PATCH /devices/{device_id}`` (SCAN-023 manual override).

    Forwards the partial identity body verbatim to upstream
    ``otalon-scan``, which writes and locks the supplied fields against
    scan-overwrite and returns the updated device. Upstream status and
    body (200 / 404 / 422 / 401 / 403) propagate transparently.
    """
    svc = _service(request)
    try:
        status, resp_body = await svc.patch_device_identity(device_id, body)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest(status, resp_body)


@router.delete("/devices/{device_id}")
async def delete_device(device_id: str, request: Request) -> Response:
    """Proxy ``DELETE /devices/{device_id}`` (Q3 manual reaper).

    Forwards 204 (success) and 404 (device not found) transparently to
    the UI. 204 responses are emitted with an empty body per HTTP spec.
    """
    svc = _service(request)
    try:
        status, body = await svc.delete_device(device_id)
    except UpstreamUnreachable as exc:
        raise HTTPException(status_code=502, detail=f"upstream otalon-scan unreachable: {exc}") from exc
    return _handle_rest_maybe_empty(status, body)


# ── SSE proxy ─────────────────────────────────────────────────────────


@router.get("/scans/{scan_id}/events")
async def stream_scan_events(scan_id: str, request: Request) -> StreamingResponse:
    """Stream upstream SSE bytes byte-for-byte.

    On upstream HTTP error (initial connect): emit a single
    ``event: error`` frame and close the stream. On mid-stream
    disconnect: emit a final ``event: error`` frame and close the
    stream. The downstream HTTP status stays 200 in both cases — the
    SSE response is successfully opened to the client; errors are
    delivered in-stream per SSE convention.
    """
    svc = _service(request)
    last_event_id = request.headers.get("last-event-id")

    async def _proxy_iter() -> AsyncIterator[bytes]:
        try:
            async for chunk in svc.stream_events(scan_id, last_event_id=last_event_id):
                yield chunk
        except httpx.HTTPStatusError as exc:
            payload = json.dumps({"reason": "upstream_status", "status": exc.response.status_code})
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")
        except Exception as exc:
            payload = json.dumps(
                {
                    "reason": "upstream_disconnected",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            yield f"event: error\ndata: {payload}\n\n".encode("utf-8")

    return StreamingResponse(
        _proxy_iter(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
