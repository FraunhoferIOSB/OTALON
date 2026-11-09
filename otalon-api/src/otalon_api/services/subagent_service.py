"""Service that proxies otalon-ai (subagent classification) endpoints.

The AI service holds all real state (PG persistence, worker pool, MCP
sessions). This service is a thin translator: validates inputs, forwards
HTTP, rewrites the SSE ``events_url`` so the browser uses the API proxy
instead of contacting otalon-ai directly.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, Dict, Optional, cast

import httpx
from loguru import logger


class SubagentService:
    """Proxy to ``otalon-ai`` REST + SSE endpoints."""

    def __init__(self, base_url: str, *, api_key: str = "", timeout: float = 5.0) -> None:
        """Configure the outbound proxy to otalon-ai.

        Args:
            base_url: Base URL of the AI service (e.g. ``http://otalon-ai:9100``).
            api_key: X-API-Key sent with every request. The AI service protects
                the ``/jobs`` prefix via ``OTALON_AI_ALLOWED_KEYS``; without a
                matching key every call is rejected with 401.
            timeout: HTTP timeout for synchronous calls.
        """
        self._base = base_url.rstrip("/")
        self._api_key = api_key
        self._timeout = timeout
        if not api_key:
            logger.warning(
                "SubagentService: no api_key configured — X-API-Key header will NOT be sent to {}",
                self._base,
            )

    # ── headers ───────────────────────────────────────────────────

    def _rest_headers(self) -> Dict[str, str]:
        """Return REST headers including the AI service API key."""
        headers: Dict[str, str] = {"Accept": "application/json"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    def _sse_headers(self) -> Dict[str, str]:
        """Return SSE headers including the AI service API key."""
        headers: Dict[str, str] = {"Accept": "text/event-stream"}
        if self._api_key:
            headers["X-API-Key"] = self._api_key
        return headers

    # ── REST proxies ──────────────────────────────────────────────

    async def start_classification(self, *, alarm_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        """POST /jobs on otalon-ai. ``alarm_id`` from path is merged in.

        Rewrites ``events_url`` to point at the API's SSE proxy.
        """
        body = dict(payload)
        body["alarm_id"] = alarm_id
        body.setdefault("trigger_source", "ui")
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(f"{self._base}/jobs", json=body, headers=self._rest_headers())
        if resp.status_code >= 400:
            raise httpx.HTTPStatusError(
                f"otalon-ai returned {resp.status_code}: {resp.text}",
                request=resp.request,
                response=resp,
            )
        data = cast(Dict[str, Any], resp.json())
        # Rewrite events_url for the API's SSE proxy
        job_id = data.get("job_id")
        if job_id:
            data["events_url"] = f"/api/v1/subagent-jobs/{job_id}/events"
        return data

    async def list_jobs(
        self,
        *,
        alarm_id: Optional[str] = None,
        status: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
        summary: bool = True,
    ) -> Dict[str, Any]:
        params: Dict[str, Any] = {"limit": limit, "offset": offset, "summary": summary}
        if alarm_id is not None:
            params["alarm_id"] = alarm_id
        if status is not None:
            params["status"] = status
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(f"{self._base}/jobs", params=params, headers=self._rest_headers())
        resp.raise_for_status()
        return cast(Dict[str, Any], resp.json())

    async def get_job(self, job_id: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.get(f"{self._base}/jobs/{job_id}", headers=self._rest_headers())
        if resp.status_code == 404:
            raise httpx.HTTPStatusError("job not found", request=resp.request, response=resp)
        resp.raise_for_status()
        return cast(Dict[str, Any], resp.json())

    async def cancel_job(self, job_id: str) -> Dict[str, Any]:
        async with httpx.AsyncClient(timeout=self._timeout) as client:
            resp = await client.post(f"{self._base}/jobs/{job_id}/cancel", headers=self._rest_headers())
        if resp.status_code == 404:
            raise httpx.HTTPStatusError("job not active", request=resp.request, response=resp)
        resp.raise_for_status()
        return cast(Dict[str, Any], resp.json())

    # ── SSE proxy ─────────────────────────────────────────────────

    async def stream_events(self, job_id: str) -> AsyncIterator[bytes]:
        """Yield raw SSE bytes from the agent's stream verbatim."""
        url = f"{self._base}/jobs/{job_id}/events"
        try:
            async with httpx.AsyncClient(timeout=None) as client:
                async with client.stream("GET", url, headers=self._sse_headers()) as resp:
                    if resp.status_code >= 400:
                        body = await resp.aread()
                        raise httpx.HTTPStatusError(
                            f"agent SSE {resp.status_code}: {body!r}",
                            request=resp.request,
                            response=resp,
                        )
                    async for chunk in resp.aiter_raw():
                        yield chunk
        except Exception as exc:
            logger.warning("subagent SSE proxy disconnected: {}", exc)
            raise
