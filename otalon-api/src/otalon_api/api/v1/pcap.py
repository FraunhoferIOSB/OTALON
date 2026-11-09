"""PCAP proxy router (Wave C / TODO B-05).

Bridges the frontend's PCAP-download flow to the upstream PCAP recorder
on port 9090. The frontend only talks to ``otalon-api`` so this
router (a) looks up the alarm window in PostgreSQL via the existing
:class:`AnomalyService`, (b) asks the recorder which chunks overlap that
window, and (c) returns a compact metadata envelope the UI can render.

Mounted under ``/api/v1``. Authentication: none (matches every other
data endpoint in this file tree; only ``/api/v1/admin/*`` is gated).
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, NoReturn, cast

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import StreamingResponse
from loguru import logger

from otalon_api.api.schemas.pcap import PcapByAlarmResponse, PcapChunkSummary
from otalon_api.dependencies import get_postgres_repo
from otalon_api.repositories.postgres_repo import PostgresRepository
from otalon_api.services.pcap_proxy_service import PcapProxyService, UpstreamUnreachable
from otalon_api.services.pcap_zip_service import stream_alarm_zip

router = APIRouter(prefix="/api/v1/pcap", tags=["pcap"])


def _service(request: Request) -> PcapProxyService:
    """Return the configured :class:`PcapProxyService` from app state.

    Raises:
        HTTPException: 503 if no service was attached during lifespan
            startup (misconfiguration).
    """
    svc = getattr(request.app.state, "pcap_proxy_service", None)
    if svc is None:
        raise HTTPException(status_code=503, detail="pcap proxy service not configured")
    return cast(PcapProxyService, svc)


def _iso(value: Any) -> str:
    """Coerce a timestamp value (datetime or string) to an ISO-8601 string.

    The recorder's ``GET /chunks`` accepts any ISO-8601 representation
    Pydantic can parse, so this helper just normalises the few shapes the
    PostgreSQL repo can return.

    A ``NULL`` timestamp is unprocessable input for this request, not a
    server fault: the alarm row exists but cannot be turned into a PCAP
    time range. It is reported as 422 rather than 500 (API-06).
    """
    if value is None:
        raise HTTPException(
            status_code=422,
            detail="alarm has no start/end timestamp; cannot resolve a PCAP time range",
        )
    if hasattr(value, "isoformat"):
        return cast(str, value.isoformat())
    return str(value)


def _raise_for_upstream(exc: UpstreamUnreachable) -> NoReturn:
    """Translate :class:`UpstreamUnreachable` into 502 vs 504.

    Mirrors the by-alarm endpoint behaviour: any message that mentions
    a timeout-class transport error is rendered as 504, everything else
    (connect-refused, DNS failure, generic transport error) as 502.
    """
    msg = str(exc)
    if "Timeout" in msg or "ReadTimeout" in msg or "ConnectTimeout" in msg:
        raise HTTPException(
            status_code=504,
            detail=f"upstream pcap-recorder timed out: {msg}",
        ) from exc
    raise HTTPException(
        status_code=502,
        detail=f"upstream pcap-recorder unreachable: {msg}",
    ) from exc


def _summarise_chunks(
    raw_chunks: list[dict[str, Any]],
) -> tuple[list[PcapChunkSummary], int]:
    """Convert recorder ``ChunkResponse`` rows into proxy summaries.

    Returns ``(summaries, total_size_bytes)``. Unknown fields are
    discarded; the recorder may add fields over time, and the proxy
    should be tolerant.
    """
    summaries: list[PcapChunkSummary] = []
    total_size = 0
    for raw in raw_chunks:
        chunk_id = str(raw.get("chunk_id") or raw.get("filename") or "")
        if not chunk_id:
            continue
        size_bytes = int(raw.get("size_bytes") or 0)
        total_size += size_bytes
        summaries.append(
            PcapChunkSummary(
                chunk_id=chunk_id,
                start_ts=raw.get("start_ts"),
                end_ts=raw.get("end_ts"),
                size_bytes=size_bytes,
                is_anomaly=bool(raw.get("is_anomaly", False)),
                labels=raw.get("labels") or {},
                download_url=f"/api/v1/pcap/chunk/{chunk_id}",
            )
        )
    return summaries, total_size


@router.get(
    "/by-alarm/{alarm_id}",
    response_model=PcapByAlarmResponse,
    summary="List PCAP chunks recorded during an alarm's time window.",
    responses={
        404: {"description": "Alarm group not found."},
        502: {"description": "Upstream PCAP recorder is unreachable."},
        503: {"description": "PCAP proxy service is not configured."},
        504: {"description": "Upstream PCAP recorder timed out."},
    },
)
async def get_pcap_by_alarm(
    alarm_id: str,
    request: Request,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> PcapByAlarmResponse:
    """Return the PCAP chunks the recorder holds for an alarm group.

    Resolves the alarm's ``start_timestamp`` / ``end_timestamp`` from
    PostgreSQL, then proxies ``GET /chunks`` on the upstream PCAP
    recorder. The recorder is the source of truth for which chunks still
    exist on disk; older chunks may have rotated out of the ringbuffer.

    Args:
        alarm_id: Alarm group UUID.
        request: FastAPI request (used to reach ``app.state``).
        postgres_repo: Injected PostgreSQL repository for the alarm lookup.

    Returns:
        :class:`PcapByAlarmResponse` with the alarm window and chunk list.

    Raises:
        HTTPException: 404 if the alarm does not exist, 502 if the
            recorder is unreachable, 504 on upstream timeout.
    """
    alarm = await asyncio.to_thread(postgres_repo.get_anomaly_group_by_id, alarm_id)
    if alarm is None:
        raise HTTPException(status_code=404, detail=f"alarm not found: {alarm_id}")

    start_iso = _iso(alarm.get("start_timestamp"))
    end_iso = _iso(alarm.get("end_timestamp"))

    svc = _service(request)
    try:
        status, body = await svc.list_chunks_in_range(start_iso, end_iso)
    except UpstreamUnreachable as exc:
        # Map upstream timeouts to 504 so the frontend can distinguish
        # "slow recorder" from "recorder offline" (502).
        _raise_for_upstream(exc)

    if status == 401 or status == 403:
        logger.warning(
            "pcap-proxy: upstream rejected request for alarm {} with status {}",
            alarm_id,
            status,
        )
        raise HTTPException(
            status_code=502,
            detail=f"upstream pcap-recorder auth failure (status {status})",
        )
    if status >= 400:
        # 4xx / 5xx from the recorder bubble up as 502; the recorder is
        # an internal collaborator, not a client-facing one.
        detail = body.get("detail") if isinstance(body, dict) else body
        raise HTTPException(
            status_code=502,
            detail=f"upstream pcap-recorder error (status {status}): {detail}",
        )

    if not isinstance(body, list):
        logger.warning(
            "pcap-proxy: upstream returned non-list body for alarm {}: {!r}",
            alarm_id,
            type(body).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="upstream pcap-recorder returned malformed body (expected list)",
        )

    chunks, total_size = _summarise_chunks(body)
    return PcapByAlarmResponse(
        alarm_id=alarm_id,
        start_ts=start_iso,
        end_ts=end_iso,
        chunk_count=len(chunks),
        total_size_bytes=total_size,
        chunks=chunks,
    )


async def _resolve_alarm_chunks(
    alarm_id: str,
    request: Request,
    postgres_repo: PostgresRepository,
) -> tuple[str, str, list[dict[str, Any]]]:
    """Look up the alarm window and the recorder's chunk list.

    Shared helper between the JSON ``by-alarm`` endpoint and the ZIP
    download. Returns ``(start_iso, end_iso, raw_chunks)``.

    Raises:
        HTTPException: 404 if the alarm is unknown, 502/504 on upstream
            transport problems, 502 on upstream HTTP failure or
            malformed body.
    """
    alarm = await asyncio.to_thread(postgres_repo.get_anomaly_group_by_id, alarm_id)
    if alarm is None:
        raise HTTPException(status_code=404, detail=f"alarm not found: {alarm_id}")

    start_iso = _iso(alarm.get("start_timestamp"))
    end_iso = _iso(alarm.get("end_timestamp"))

    svc = _service(request)
    try:
        status, body = await svc.list_chunks_in_range(start_iso, end_iso)
    except UpstreamUnreachable as exc:
        _raise_for_upstream(exc)

    if status == 401 or status == 403:
        logger.warning(
            "pcap-proxy: upstream rejected request for alarm {} with status {}",
            alarm_id,
            status,
        )
        raise HTTPException(
            status_code=502,
            detail=f"upstream pcap-recorder auth failure (status {status})",
        )
    if status >= 400:
        detail = body.get("detail") if isinstance(body, dict) else body
        raise HTTPException(
            status_code=502,
            detail=f"upstream pcap-recorder error (status {status}): {detail}",
        )
    if not isinstance(body, list):
        logger.warning(
            "pcap-proxy: upstream returned non-list body for alarm {}: {!r}",
            alarm_id,
            type(body).__name__,
        )
        raise HTTPException(
            status_code=502,
            detail="upstream pcap-recorder returned malformed body (expected list)",
        )
    return start_iso, end_iso, body


@router.get(
    "/by-alarm/{alarm_id}/zip",
    summary="Download all PCAP chunks for an alarm as a single ZIP archive.",
    response_class=StreamingResponse,
    responses={
        200: {
            "description": "ZIP archive stream.",
            "content": {"application/zip": {}},
        },
        404: {"description": "Alarm group not found or has no chunks."},
        502: {"description": "Upstream PCAP recorder is unreachable."},
        503: {"description": "PCAP proxy service is not configured."},
        504: {"description": "Upstream PCAP recorder timed out."},
    },
)
async def get_pcap_by_alarm_zip(
    alarm_id: str,
    request: Request,
    postgres_repo: PostgresRepository = Depends(get_postgres_repo),
) -> StreamingResponse:
    """Stream a ZIP bundle of every chunk recorded during the alarm.

    The archive contains the raw PCAP chunks (zero-padded
    ``chunk-001.pcap``, ``chunk-002.pcap``, … in alarm-time order) plus
    a ``metadata.json`` manifest describing the alarm window and per-
    chunk timing. Chunks are streamed end-to-end from the upstream
    recorder; nothing buffers the bundle.

    Args:
        alarm_id: Alarm group UUID.
        request: FastAPI request (used to reach ``app.state``).
        postgres_repo: Injected PostgreSQL repository for the alarm lookup.

    Returns:
        A :class:`StreamingResponse` emitting ``application/zip`` bytes
        with a ``Content-Disposition: attachment`` header.

    Raises:
        HTTPException: 404 if the alarm is unknown or the recorder has
            zero chunks for the window; 502/504 on upstream failures;
            503 if the proxy service is not configured.
    """
    start_iso, end_iso, raw_chunks = await _resolve_alarm_chunks(alarm_id, request, postgres_repo)

    ordered = [c for c in raw_chunks if c.get("chunk_id") or c.get("filename")]
    ordered.sort(key=lambda c: str(c.get("start_ts") or ""))
    if not ordered:
        raise HTTPException(
            status_code=404,
            detail=f"alarm has no PCAP chunks: {alarm_id}",
        )

    svc = _service(request)

    async def _generator() -> AsyncIterator[bytes]:
        """Stream ZIP bytes; translate upstream errors mid-stream.

        Once the response has started, FastAPI cannot rewrite the
        status code. We therefore catch :class:`UpstreamUnreachable`
        here only for logging — the connection drops, the client sees
        a truncated transfer. Pre-stream failures are already handled
        by :func:`_resolve_alarm_chunks` above.
        """
        try:
            async for piece in stream_alarm_zip(
                alarm_id=alarm_id,
                start_iso=start_iso,
                end_iso=end_iso,
                chunks=ordered,
                proxy=svc,
            ):
                yield piece
        except UpstreamUnreachable as exc:
            logger.warning(
                "pcap-zip: upstream failure mid-stream for alarm {} ({})",
                alarm_id,
                exc,
            )
            return

    filename = f"alarm-{alarm_id}.zip"
    headers = {"Content-Disposition": f'attachment; filename="{filename}"'}
    return StreamingResponse(
        _generator(),
        media_type="application/zip",
        headers=headers,
    )
