"""Service that proxies otalon-scan REST + SSE endpoints.

Mirrors the :class:`SubagentService` shape: thin translator from inbound
``otalon-api`` requests to outbound ``otalon-scan:8091`` requests.
Injects an operator-level ``X-API-Key`` header on every outbound call
(required by the Wave-B F-02 auth layer on the upstream side).

The service does **not** re-validate request bodies beyond shape. Upstream
owns the contract. REST responses propagate verbatim (status + JSON body).
SSE streams are forwarded byte-for-byte via ``httpx.AsyncClient.stream``.

Errors:

- ``httpx.HTTPStatusError`` (any non-2xx upstream HTTP response) flows
  through unwrapped so the router can propagate status + body.
- Transport-level errors (``httpx.ConnectError``,
  ``httpx.ConnectTimeout``, ``httpx.ReadTimeout``,
  ``httpx.RemoteProtocolError``, …) are converted to
  :class:`UpstreamUnreachable` so the router can emit a stable 502 envelope.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Optional

import httpx
from loguru import logger


class UpstreamUnreachable(Exception):
    """Raised when the upstream ``otalon-scan`` service is not reachable.

    Wraps the underlying ``httpx`` transport exception. The router maps
    this to HTTP 502 with a stable error envelope.
    """


class ScanProxyService:
    """Proxy to ``otalon-scan:8091`` REST + SSE endpoints."""

    def __init__(self, base_url: str, api_key: str, *, timeout: float = 5.0) -> None:
        """Initialise the proxy service.

        Args:
            base_url: Base URL of the upstream service, e.g.
                ``http://otalon-scan:8091``.
            api_key: Operator-level API key injected via ``X-API-Key``
                on every outbound call.
            timeout: Per-request timeout in seconds for REST calls. The
                SSE stream uses ``timeout=None``.
        """
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout

    # ── headers ───────────────────────────────────────────────────

    def _rest_headers(self) -> dict[str, str]:
        """Return REST request headers including the operator API key."""
        return {"X-API-Key": self._api_key, "Accept": "application/json"}

    def _sse_headers(self, last_event_id: Optional[str] = None) -> dict[str, str]:
        """Return SSE request headers including the operator API key.

        Forwards ``Last-Event-ID`` if the inbound client supplied one.
        """
        headers = {"X-API-Key": self._api_key, "Accept": "text/event-stream"}
        if last_event_id:
            headers["Last-Event-ID"] = last_event_id
        return headers

    # ── request helper ────────────────────────────────────────────

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: Optional[dict[str, Any]] = None,
        json_body: Optional[Any] = None,
    ) -> tuple[int, Any]:
        """Issue a REST call to the upstream and return ``(status, body)``.

        ``body`` is the parsed JSON when the upstream emits a valid JSON
        response, otherwise the raw response text wrapped in
        ``{"detail": "<text>"}``. Non-2xx upstream responses are
        propagated through the tuple (the router decides how to render
        them). Transport errors raise :class:`UpstreamUnreachable`.
        """
        url = f"{self._base}{path}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.request(
                    method,
                    url,
                    headers=self._rest_headers(),
                    params=params,
                    json=json_body,
                )
        except httpx.TransportError as exc:
            logger.warning(
                "scan-proxy: upstream {} {} unreachable ({}: {})",
                repr(method),
                repr(path),
                type(exc).__name__,
                exc,
            )
            raise UpstreamUnreachable(f"{type(exc).__name__}: {exc}") from exc

        try:
            body: Any = resp.json()
        except Exception:
            body = {"detail": resp.text}
        return resp.status_code, body

    # ── REST proxies ──────────────────────────────────────────────

    async def get_modules(self) -> tuple[int, Any]:
        """Proxy ``GET /modules``."""
        return await self._request("GET", "/modules")

    async def get_interfaces(self) -> tuple[int, Any]:
        """Proxy ``GET /scans/interfaces``."""
        return await self._request("GET", "/scans/interfaces")

    async def get_module_schema(self, name: str) -> tuple[int, Any]:
        """Proxy ``GET /scans/modules/{name}/schema``."""
        return await self._request("GET", f"/scans/modules/{name}/schema")

    async def start_scan(self, body: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``POST /scans`` → upstream ``POST /scans/start``.

        Upstream rename to the v1 contract path is tracked in design.md
        Decision 6; this method posts to the upstream-current path so v1
        callers get a working endpoint immediately.
        """
        return await self._request("POST", "/scans/start", json_body=body)

    async def list_scans(self, params: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``GET /scans`` with optional query parameters."""
        cleaned = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "/scans", params=cleaned)

    async def get_scan(self, scan_id: str) -> tuple[int, Any]:
        """Proxy ``GET /scans/{scan_id}``."""
        return await self._request("GET", f"/scans/{scan_id}")

    async def abort_scan(self, scan_id: str) -> tuple[int, Any]:
        """Proxy ``POST /scans/{scan_id}/abort`` → upstream ``.../stop``.

        Upstream rename to ``/abort`` is tracked in design.md Decision 6.
        """
        return await self._request("POST", f"/scans/{scan_id}/stop")

    async def get_device_scans(self, device_id: str) -> tuple[int, Any]:
        """Proxy ``GET /devices/{device_id}/scans``."""
        return await self._request("GET", f"/devices/{device_id}/scans")

    async def get_device_observations(self, device_id: str) -> tuple[int, Any]:
        """Proxy ``GET /devices/{device_id}/observations``."""
        return await self._request("GET", f"/devices/{device_id}/observations")

    async def patch_vulnerability(self, vuln_id: str, body: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``PATCH /vulnerabilities/{vuln_id}``."""
        return await self._request("PATCH", f"/vulnerabilities/{vuln_id}", json_body=body)

    async def lookup_vulnerabilities(self, body: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``POST /vulnerabilities/lookup`` (Welle C / Task 3.2).

        The upstream endpoint is async (SCAN-026 WA.4): it returns
        ``202 Accepted`` with ``{job_id, status, eligible_assets}``
        immediately. That status + body propagate verbatim through this
        tuple — the 502 timeout path is structurally gone (design.md § D3).
        """
        return await self._request("POST", "/vulnerabilities/lookup", json_body=body)

    async def list_lookups(self, params: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``GET /vulnerabilities/lookups`` (SCAN-026 WB.3).

        Forwards the optional ``limit`` / ``offset`` query parameters
        (``None`` values are dropped). Returns the upstream
        ``{lookups: [...]}`` body and status verbatim.
        """
        cleaned = {k: v for k, v in params.items() if v is not None}
        return await self._request("GET", "/vulnerabilities/lookups", params=cleaned)

    async def get_lookup(self, job_id: str) -> tuple[int, Any]:
        """Proxy ``GET /vulnerabilities/lookups/{job_id}`` (SCAN-026 WB.3)."""
        return await self._request("GET", f"/vulnerabilities/lookups/{job_id}")

    async def stop_lookup(self, job_id: str) -> tuple[int, Any]:
        """Proxy ``POST /vulnerabilities/lookups/{job_id}/stop`` (R-02).

        Forwards the operator's stop request; upstream flags the in-flight
        lookup task for cooperative cancellation and returns
        ``{job_id, stopped}``. Status and body propagate verbatim.
        """
        return await self._request("POST", f"/vulnerabilities/lookups/{job_id}/stop")

    async def patch_device_identity(self, device_id: str, body: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``PATCH /devices/{device_id}`` (SCAN-023 manual override).

        Forwards the partial identity body verbatim. Upstream writes and
        locks the supplied fields and returns the updated device; 404 /
        422 / 401 / 403 propagate verbatim.
        """
        return await self._request("PATCH", f"/devices/{device_id}", json_body=body)

    async def delete_device(self, device_id: str) -> tuple[int, Any]:
        """Proxy ``DELETE /devices/{device_id}``."""
        return await self._request("DELETE", f"/devices/{device_id}")

    async def delete_devices_bulk(self, body: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``DELETE /devices`` (bulk reaper).

        Forwards the JSON body verbatim. Upstream validates the
        ``{"ids": [int, ...]}`` shape and returns 200 with
        ``{"deleted": [...], "not_found": [...]}`` on success or 422 /
        401 / 403 on a client / auth error — all propagated verbatim.
        """
        return await self._request("DELETE", "/devices", json_body=body)

    async def delete_scan(self, scan_id: str) -> tuple[int, Any]:
        """Proxy ``DELETE /scans/{scan_id}``."""
        return await self._request("DELETE", f"/scans/{scan_id}")

    async def delete_scans_bulk(self, body: dict[str, Any]) -> tuple[int, Any]:
        """Proxy ``DELETE /scans`` (bulk reaper).

        Forwards the JSON body verbatim. Upstream validates the
        ``{"ids": [str, ...]}`` shape and returns 200 with
        ``{"deleted": [...], "not_found": [...]}`` on success.
        """
        return await self._request("DELETE", "/scans", json_body=body)

    # ── SSE proxy ─────────────────────────────────────────────────

    async def _stream(
        self,
        path: str,
        *,
        last_event_id: Optional[str] = None,
    ) -> AsyncIterator[bytes]:
        """Yield raw SSE bytes from an upstream ``path`` verbatim.

        Shared transport for every SSE proxy: opens an
        ``httpx.AsyncClient(timeout=None)`` so a long-lived stream never
        trips a read timeout, and forwards raw byte chunks unchanged.

        Args:
            path: Upstream SSE path (e.g. ``/scans/{id}/events``).
            last_event_id: Optional ``Last-Event-ID`` value to forward.

        Yields:
            Raw byte chunks from the upstream ``text/event-stream``.

        Raises:
            httpx.HTTPStatusError: If the upstream returns an HTTP error
                on the initial connect (4xx / 5xx). The router catches
                this and emits a final ``event: error`` frame.
            Exception: Any transport-level / mid-stream failure is
                re-raised after a WARNING log. The router catches this
                and emits a final ``event: error`` frame.
        """
        url = f"{self._base}{path}"
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream(
                    "GET",
                    url,
                    headers=self._sse_headers(last_event_id),
                ) as resp:
                    if resp.status_code >= 400:
                        body = await resp.aread()
                        raise httpx.HTTPStatusError(
                            f"upstream SSE {resp.status_code}: {body!r}",
                            request=resp.request,
                            response=resp,
                        )
                    async for chunk in resp.aiter_raw():
                        yield chunk
        except httpx.HTTPStatusError:
            raise
        except Exception as exc:
            logger.warning(
                "scan-proxy: SSE upstream disconnected ({}: {})",
                type(exc).__name__,
                exc,
            )
            raise

    async def stream_events(
        self,
        scan_id: str,
        *,
        last_event_id: Optional[str] = None,
    ) -> AsyncIterator[bytes]:
        """Yield raw SSE bytes from the upstream scan stream verbatim.

        Args:
            scan_id: Upstream scan identifier (path parameter).
            last_event_id: Optional ``Last-Event-ID`` value to forward.

        Yields:
            Raw byte chunks from the upstream ``text/event-stream``.
        """
        async for chunk in self._stream(f"/scans/{scan_id}/events", last_event_id=last_event_id):
            yield chunk

    async def stream_lookup_events(
        self,
        job_id: str,
        *,
        last_event_id: Optional[str] = None,
    ) -> AsyncIterator[bytes]:
        """Yield raw SSE bytes from the upstream CVE-lookup stream (WB.3).

        Mirrors :meth:`stream_events` with ``timeout=None`` so the
        long-lived lookup progress stream is forwarded byte-for-byte. The
        upstream emits ``progress`` events plus a terminal ``done`` /
        ``failed`` event (design.md § D5) that the UI / notification layer
        consumes.

        Args:
            job_id: Upstream CVE-lookup job id (path parameter).
            last_event_id: Optional ``Last-Event-ID`` value to forward.

        Yields:
            Raw byte chunks from the upstream ``text/event-stream``.
        """
        async for chunk in self._stream(f"/vulnerabilities/lookups/{job_id}/events", last_event_id=last_event_id):
            yield chunk
