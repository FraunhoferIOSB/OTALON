"""Service that proxies PCAP recorder REST endpoints.

Thin async wrapper around ``httpx.AsyncClient`` mirroring the
:class:`ScanProxyService` shape: takes an inbound request from
``otalon-api``, forwards it to the upstream PCAP recorder
(default ``http://pcap-recorder:9090``), and returns ``(status, body)``
or raises :class:`UpstreamUnreachable` on transport-level failures.

Two operations are supported today:

* ``list_chunks_in_range`` — ``GET /chunks?start_ts=…&end_ts=…&format=json``;
  used by the by-alarm endpoint to enumerate chunk metadata.
* ``health_check`` — ``GET /health``; used for service-state probing
  (mounted by the router so a misconfigured recorder is visible).

The recorder currently has no authentication layer. If
``api_key`` is non-empty the proxy still forwards an ``X-API-Key``
header so the deployment is ready when the recorder gains auth
(see ``.dev/audit/pcap_recorder/`` findings).
"""

from __future__ import annotations

from typing import Any, AsyncIterator

import httpx
from loguru import logger


class UpstreamUnreachable(Exception):
    """Raised when the upstream PCAP recorder is not reachable.

    Wraps the underlying ``httpx`` transport exception so the router
    can render a stable 502 envelope.
    """


class PcapProxyService:
    """Proxy to the PCAP recorder REST API on port 9090."""

    def __init__(self, base_url: str, api_key: str = "", *, timeout: float = 10.0) -> None:
        """Initialise the proxy service.

        Args:
            base_url: Base URL of the upstream service, e.g.
                ``http://pcap-recorder:9090``.
            api_key: Optional ``X-API-Key`` value injected on every
                outbound call. Empty string disables the header.
            timeout: Per-request timeout in seconds.
        """
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        if not api_key:
            logger.warning(
                "PcapProxyService: no api_key configured — X-API-Key header will NOT be sent to {}",
                self._base,
            )

    def _rest_headers(self) -> dict[str, str]:
        """Return REST headers, including ``X-API-Key`` when configured."""
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    async def _request(
        self,
        method: str,
        path: str,
        *,
        params: dict[str, Any] | None = None,
    ) -> tuple[int, Any]:
        """Issue a REST call and return ``(status, body)``.

        ``body`` is the parsed JSON when the upstream emits valid JSON,
        otherwise the raw response text wrapped in ``{"detail": "…"}``.
        Non-2xx upstream responses propagate through the tuple unchanged.
        Transport errors raise :class:`UpstreamUnreachable`.
        """
        url = f"{self._base}{path}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.request(
                    method,
                    url,
                    headers=self._rest_headers(),
                    params=params,
                )
        except httpx.TransportError as exc:
            logger.warning(
                "pcap-proxy: upstream {} {} unreachable ({}: {})",
                method,
                path,
                type(exc).__name__,
                exc,
            )
            raise UpstreamUnreachable(f"{type(exc).__name__}: {exc}") from exc

        try:
            body: Any = resp.json()
        except Exception:
            body = {"detail": resp.text}
        return resp.status_code, body

    async def list_chunks_in_range(self, start_ts: str, end_ts: str) -> tuple[int, Any]:
        """Proxy ``GET /chunks?start_ts=…&end_ts=…&format=json``.

        Args:
            start_ts: ISO-8601 start timestamp.
            end_ts: ISO-8601 end timestamp.

        Returns:
            ``(status, body)`` where ``body`` is the parsed upstream
            payload (a list of chunk metadata dicts on success).
        """
        return await self._request(
            "GET",
            "/chunks",
            params={"start_ts": start_ts, "end_ts": end_ts, "format": "json"},
        )

    async def health_check(self) -> tuple[int, Any]:
        """Proxy ``GET /health``."""
        return await self._request("GET", "/health")

    async def stream_chunk(self, chunk_id: str, *, byte_chunk_size: int = 65536) -> AsyncIterator[bytes]:
        """Stream a single PCAP chunk file from the recorder.

        Issues ``GET /chunks/{chunk_id}?format=pcap`` against the upstream
        and yields the response body in ``byte_chunk_size`` slices without
        buffering the full file in memory. The recorder responds with
        ``Content-Type: application/octet-stream`` and a ``FileResponse``.

        Args:
            chunk_id: Recorder chunk identifier (filename).
            byte_chunk_size: Read-buffer size in bytes (default 64 KiB).

        Yields:
            Raw PCAP bytes, in order.

        Raises:
            UpstreamUnreachable: Transport-level failure (timeout, connect
                error, etc.). The exception message starts with the
                ``httpx`` exception class name so the router can route
                timeouts to 504 vs other transport errors to 502.
            httpx.HTTPStatusError: Wrapped non-2xx upstream response so
                the caller can inspect ``exc.response.status_code``.
        """
        url = f"{self._base}/chunks/{chunk_id}"
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                async with client.stream(
                    "GET",
                    url,
                    headers=self._rest_headers(),
                    params={"format": "pcap"},
                ) as resp:
                    if resp.status_code >= 400:
                        await resp.aread()
                        raise httpx.HTTPStatusError(
                            f"upstream chunk fetch failed: {resp.status_code}",
                            request=resp.request,
                            response=resp,
                        )
                    async for piece in resp.aiter_bytes(chunk_size=byte_chunk_size):
                        if piece:
                            yield piece
        except httpx.TransportError as exc:
            logger.warning(
                "pcap-proxy: chunk stream {} unreachable ({}: {})",
                chunk_id,
                type(exc).__name__,
                exc,
            )
            raise UpstreamUnreachable(f"{type(exc).__name__}: {exc}") from exc
