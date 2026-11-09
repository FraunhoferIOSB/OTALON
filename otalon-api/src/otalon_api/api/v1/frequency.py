"""Frequency-profile router.

Exposes the learned cadence and the derived rhythm state per series so
the connections-page RHYTHM lane can render real detector values instead
of inferring them.

UI-101 adds the operator correction contract below
``/api/v1/frequency/{series_id}``: a non-mutating ``override/preview``,
an audited ``override/apply`` guarded by the preview's exact
``before_snapshot``, an advisory ``override/suggest``, and the per-series
``history`` read. Only ``tolerance_factor.override`` and
``absence_factor.override`` are writable; a stale snapshot is rejected
with HTTP 409 ``RhythmCorrectionConflict`` and mutates nothing.
"""

from __future__ import annotations

import asyncio
from datetime import datetime
from typing import Any
from urllib.parse import unquote

import psycopg2
from fastapi import APIRouter, Depends, HTTPException, Path, Query
from loguru import logger

from otalon_api.api.schemas.frequency import (
    FrequencyEventsResponse,
    FrequencyHistoryResponse,
    FrequencyOverrideApplyRequest,
    FrequencyOverrideApplyResponse,
    FrequencyOverridePreviewRequest,
    FrequencyOverridePreviewResponse,
    FrequencyOverrideRequest,
    FrequencyOverrideSuggestion,
    FrequencyProfileListResponse,
    FrequencyProfileResponse,
)
from otalon_api.dependencies import get_frequency_service
from otalon_api.middleware.auth import require_operator_api_key
from otalon_api.repositories.postgres_repo import FrequencyProfileNotFound, RhythmCorrectionConflict
from otalon_api.services.frequency_service import SUPPORTED_MODULES, FrequencyService

router = APIRouter(prefix="/api/v1/frequency", tags=["frequency"])

MAX_SERIES_ID_LENGTH: int = 512
"""Upper bound on one series identifier (QUA-12); live maximum is 113."""

MAX_SERIES_FILTER: int = 512
"""Upper bound on the repeated ``uci`` filter (QUA-12).

Each requested series widens the ``IN`` list and produces one response
entry even when unprofiled, so the cardinality is capped. The live
database holds 88 profiles across all three modules, so the cap never
truncates a real fleet request.
"""

MAX_HISTORY_LIMIT: int = 500
"""Upper bound on per-series history rows returned in one response."""

MAX_EVENT_LIMIT: int = 200
"""Upper bound on per-series rhythm anomaly episodes in one response.

A single silent PROFINET flow accumulates hundreds of absence episodes
per day, so an operator-facing timeline must be capped rather than
streaming the whole table into the drawer.
"""


def _validate_module(module: str) -> None:
    """Reject modules the frequency monitor does not profile.

    Args:
        module: Requested detection module name.

    Raises:
        HTTPException: 400 when the module carries no frequency profiles.
    """
    if module not in SUPPORTED_MODULES:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid module '{module}'. Allowed: {', '.join(sorted(SUPPORTED_MODULES))}",
        )


@router.get("/profile", response_model=FrequencyProfileResponse)
async def get_frequency_profile(
    uci: str = Query(max_length=MAX_SERIES_ID_LENGTH),
    module: str = Query(default="conn", max_length=64),
    since: datetime | None = Query(default=None, description="Inclusive absence-history window start"),
    service: FrequencyService = Depends(get_frequency_service),
) -> FrequencyProfileResponse:
    """Return the frequency profile and rhythm state for one series.

    A series without a trained profile is a normal outcome, not a 404:
    the response carries ``has_profile = false`` and
    ``state = "no_profile"`` so the client can render that state without
    treating it as a failure.

    Args:
        uci: Series identifier (UCI for the ``conn`` module).
        module: Detection module name.
        service: Injected frequency service.

    Returns:
        The profile response for the requested series.
    """
    _validate_module(module)
    if not uci:
        raise HTTPException(status_code=400, detail="uci must not be empty")

    try:
        return await service.get_profile(module=module, series_id=uci, since=since)
    except asyncio.TimeoutError as exc:
        logger.error("get_frequency_profile timed out for uci={}: {}", uci, exc)
        raise HTTPException(status_code=504, detail="Frequency profile query timed out") from exc
    except psycopg2.Error as exc:
        logger.error("get_frequency_profile DB error for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query frequency profile") from exc
    except Exception as exc:
        logger.error("get_frequency_profile failed for uci={}: {}", uci, exc)
        raise HTTPException(status_code=500, detail="Failed to query frequency profile") from exc


@router.get("/profiles", response_model=FrequencyProfileListResponse)
async def list_frequency_profiles(
    module: str = Query(default="conn", max_length=64),
    uci: list[str] | None = Query(default=None, max_length=MAX_SERIES_FILTER),
    since: datetime | None = Query(default=None, description="Inclusive absence-history window start"),
    service: FrequencyService = Depends(get_frequency_service),
) -> FrequencyProfileListResponse:
    """List frequency profiles for a module, optionally filtered by series.

    Args:
        module: Detection module name.
        uci: Optional repeated series filter. Omitted returns the whole
            module.
        service: Injected frequency service.

    Returns:
        Envelope with one entry per profile.
    """
    _validate_module(module)

    try:
        data = await service.list_profiles(module=module, series_ids=uci, since=since)
    except asyncio.TimeoutError as exc:
        logger.error("list_frequency_profiles timed out for module={}: {}", module, exc)
        raise HTTPException(status_code=504, detail="Frequency profile query timed out") from exc
    except psycopg2.Error as exc:
        logger.error("list_frequency_profiles DB error for module={}: {}", module, exc)
        raise HTTPException(status_code=500, detail="Failed to query frequency profiles") from exc
    except Exception as exc:
        logger.error("list_frequency_profiles failed for module={}: {}", module, exc)
        raise HTTPException(status_code=500, detail="Failed to query frequency profiles") from exc

    return FrequencyProfileListResponse(module=module, count=len(data), data=data)


def _resolve_series(series_id: str, override: str | None = None) -> str:
    """Resolve the canonical series identifier for a correction request.

    Series identifiers are UCIs containing ``/``. Starlette decodes
    percent-escapes before route matching, so a raw UCI cannot survive a
    single path segment: ``%2F`` becomes ``/`` and the route no longer
    matches. The established bounds-correction routes solve this by
    treating an explicit ``series_id`` in the request as authoritative
    and the path segment as a best-effort fallback; this mirrors that
    contract, taking the value from the request body (POST) or the
    ``series_id`` query parameter (GET).

    Args:
        series_id: Raw path segment.
        override: Authoritative identifier supplied by body or query.

    Returns:
        The canonical series identifier.

    Raises:
        HTTPException: 400 when the identifier resolves to empty.
    """
    resolved = override if override else unquote(series_id)
    if not resolved:
        raise HTTPException(status_code=400, detail="series_id must not be empty")
    return resolved


def _requested_overrides(body: FrequencyOverrideRequest) -> dict[str, Any]:
    """Extract only the override fields the client explicitly supplied.

    An omitted field means "leave as is"; an explicit ``null`` clears the
    override. Distinguishing the two is what makes restore-to-default a
    first-class, audited operation instead of an ambiguous empty payload.

    Args:
        body: Validated request payload.

    Returns:
        Mapping of supplied payload field names to their values.
    """
    supplied = body.requested_fields() & {
        "tolerance_factor_override",
        "absence_factor_override",
    }
    return {field: getattr(body, field) for field in supplied}


@router.post("/{series_id}/override/preview", response_model=FrequencyOverridePreviewResponse)
async def preview_frequency_override(
    series_id: str,
    body: FrequencyOverridePreviewRequest,
    module: str = "conn",
    suggest: bool = Query(default=False, description="Attach an advisory suggestion to the preview"),
    service: FrequencyService = Depends(get_frequency_service),
    _operator: Any = Depends(require_operator_api_key),
) -> FrequencyOverridePreviewResponse:
    """Preview an override correction without mutating any state.

    Args:
        series_id: Series identifier path segment.
        body: Requested override values.
        module: Detection module name.
        suggest: Whether to include an advisory proposal.
        service: Injected frequency service.
        _operator: Enforced operator authorization.

    Returns:
        Diff, ``before_snapshot`` and detector-threshold impact.
    """
    _validate_module(module)
    resolved = _resolve_series(series_id, body.series_id)
    try:
        return await service.preview_override(
            module=module,
            series_id=resolved,
            requested=_requested_overrides(body),
            include_suggestion=suggest,
        )
    except FrequencyProfileNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except psycopg2.Error as exc:
        logger.error("preview_frequency_override DB error for series={}: {}", resolved, exc)
        raise HTTPException(status_code=500, detail="Failed to preview frequency correction") from exc


@router.post("/{series_id}/override/apply", response_model=FrequencyOverrideApplyResponse)
async def apply_frequency_override(
    series_id: str,
    body: FrequencyOverrideApplyRequest,
    module: str = "conn",
    service: FrequencyService = Depends(get_frequency_service),
    _operator: Any = Depends(require_operator_api_key),
) -> FrequencyOverrideApplyResponse:
    """Commit an audited override correction guarded by the preview snapshot.

    Args:
        series_id: Series identifier path segment.
        body: Override values, exact ``before_snapshot`` and audited reason.
        module: Detection module name.
        service: Injected frequency service.
        _operator: Enforced operator authorization.

    Returns:
        The audit id, diff, refreshed profile, and notification outcome.

    Raises:
        HTTPException: 409 when the snapshot is stale; nothing is mutated.
    """
    _validate_module(module)
    resolved = _resolve_series(series_id, body.series_id)
    try:
        return await service.apply_override(
            module=module,
            series_id=resolved,
            requested=_requested_overrides(body),
            before_snapshot=body.before_snapshot.model_dump(),
            reason=body.reason,
        )
    except RhythmCorrectionConflict as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except FrequencyProfileNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except psycopg2.Error as exc:
        logger.error("apply_frequency_override DB error for series={}: {}", resolved, exc)
        raise HTTPException(status_code=500, detail="Failed to apply frequency correction") from exc


@router.get("/{series_id}/override/suggest", response_model=FrequencyOverrideSuggestion)
async def suggest_frequency_override(
    series_id: str = Path(max_length=MAX_SERIES_ID_LENGTH),
    module: str = Query(default="conn", max_length=64),
    uci: str | None = Query(
        default=None,
        max_length=MAX_SERIES_ID_LENGTH,
        description="Authoritative series identifier when it contains '/'",
    ),
    service: FrequencyService = Depends(get_frequency_service),
    _operator: Any = Depends(require_operator_api_key),
) -> FrequencyOverrideSuggestion:
    """Return an advisory factor proposal with its evidence provenance.

    Args:
        series_id: Series identifier path segment.
        module: Detection module name.
        uci: Authoritative series identifier, used when it contains '/'.
        service: Injected frequency service.
        _operator: Enforced operator authorization.

    Returns:
        Suggested factors plus observations, window days, and method.
    """
    _validate_module(module)
    resolved = _resolve_series(series_id, uci)
    try:
        return await service.suggest_override(module=module, series_id=resolved)
    except FrequencyProfileNotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except psycopg2.Error as exc:
        logger.error("suggest_frequency_override DB error for series={}: {}", resolved, exc)
        raise HTTPException(status_code=500, detail="Failed to compute frequency suggestion") from exc


@router.get("/{series_id}/events", response_model=FrequencyEventsResponse)
async def get_frequency_events(
    series_id: str = Path(max_length=MAX_SERIES_ID_LENGTH),
    module: str = Query(default="conn", max_length=64),
    uci: str | None = Query(
        default=None,
        max_length=MAX_SERIES_ID_LENGTH,
        description="Authoritative series identifier when it contains '/'",
    ),
    since: datetime | None = Query(default=None, description="Inclusive event-window start; omit for all history"),
    limit: int = Query(default=50, ge=1, le=MAX_EVENT_LIMIT),
    service: FrequencyService = Depends(get_frequency_service),
    _operator: Any = Depends(require_operator_api_key),
) -> FrequencyEventsResponse:
    """Return the rhythm anomaly episodes for exactly one series.

    Complements the aggregate ``recent_*_count`` fields on the profile
    read: those report how many episodes fell in the window, this reports
    which ones. A series that never deviated returns a normal empty
    envelope rather than a 404.

    Args:
        series_id: Series identifier path segment.
        module: Detection module name.
        uci: Authoritative series identifier, used when it contains '/'.
        since: Inclusive lower bound on ``start_ts``; omitted means all
            persisted history, still bounded by ``limit``.
        limit: Maximum number of episodes.
        service: Injected frequency service.
        _operator: Enforced operator authorization.

    Returns:
        The per-series anomaly episodes, newest first.
    """
    _validate_module(module)
    resolved = _resolve_series(series_id, uci)
    try:
        return await service.get_events(module=module, series_id=resolved, since=since, limit=limit)
    except asyncio.TimeoutError as exc:
        logger.error("get_frequency_events timed out for series={}: {}", resolved, exc)
        raise HTTPException(status_code=504, detail="Frequency event query timed out") from exc
    except psycopg2.Error as exc:
        logger.error("get_frequency_events DB error for series={}: {}", resolved, exc)
        raise HTTPException(status_code=500, detail="Failed to query frequency events") from exc


@router.get("/{series_id}/history", response_model=FrequencyHistoryResponse)
async def get_frequency_history(
    series_id: str = Path(max_length=MAX_SERIES_ID_LENGTH),
    module: str = Query(default="conn", max_length=64),
    uci: str | None = Query(
        default=None,
        max_length=MAX_SERIES_ID_LENGTH,
        description="Authoritative series identifier when it contains '/'",
    ),
    limit: int = Query(default=200, ge=1, le=MAX_HISTORY_LIMIT),
    service: FrequencyService = Depends(get_frequency_service),
    _operator: Any = Depends(require_operator_api_key),
) -> FrequencyHistoryResponse:
    """Return the chronological correction history for exactly one series.

    An operator-corrected series that was never changed is a normal empty
    envelope, not a 404.

    Args:
        series_id: Series identifier path segment.
        module: Detection module name.
        uci: Authoritative series identifier, used when it contains '/'.
        limit: Maximum number of audit rows.
        service: Injected frequency service.
        _operator: Enforced operator authorization.

    Returns:
        The per-series audit records, newest first.
    """
    _validate_module(module)
    resolved = _resolve_series(series_id, uci)
    try:
        return await service.get_history(module=module, series_id=resolved, limit=limit)
    except psycopg2.Error as exc:
        logger.error("get_frequency_history DB error for series={}: {}", resolved, exc)
        raise HTTPException(status_code=500, detail="Failed to query frequency history") from exc
