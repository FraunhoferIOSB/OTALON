"""Training-orchestrator endpoints (OpenSpec ``add-chat-triggered-boundary-retraining``
plus ML-training-decoupling, see ``.dev/concepts/ml-training-decoupling.md``).

Three endpoints behind the existing ``X-API-Key`` operator-auth surface:

- ``POST /api/v1/training/retrain-boundaries`` — start a bounds +
  frequency calibration run asynchronously; returns the initial
  ``{state, started_at, job_ref, scope='bounds'}``.
  Returns 409 if any retrain (bounds OR ML) is already in progress.
- ``POST /api/v1/training/retrain-classifier`` — start an ML
  group-classifier retrain run; shares the same single-flight lock as
  the bounds endpoint and returns ``{..., scope='ml'}``.
- ``GET  /api/v1/training/retrain-boundaries/status`` — poll the
  orchestrator. Returns the most recent ``{state, detail, scope, …}``
  snapshot. The same status endpoint serves both retrain types; the
  ``scope`` field distinguishes them.

All paths are guarded by :class:`ApiKeyAuthMiddleware` via the
``/api/v1/training`` prefix added to
:data:`otalon_api.middleware.auth.PROTECTED_PATH_PREFIXES`, which enforces key
*validity* (any configured key). The label-source surface refines this:
``GET /label-sources`` is an authenticated read (any valid key), while
``POST /label-sources/upload`` is a filesystem-write endpoint gated by
:func:`require_operator_api_key` — operator-only and fail-closed (503) when no
keys are configured.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException, Request
from loguru import logger
from pydantic import BaseModel, Field

from otalon_api.dependencies import get_label_source_service, get_runtime_retrain_service
from otalon_api.domain.time.validation import RuntimeRetrainValidationError
from otalon_api.middleware.auth import require_operator_api_key
from otalon_api.services.label_source_service import (
    LABEL_SOURCE_MAX_TRANSPORT_BYTES,
    LabelSource,
    LabelSourceConflictError,
    LabelSourceList,
    LabelSourceService,
    LabelSourceTooLargeError,
    LabelSourceValidationError,
)
from otalon_api.services.runtime_retrain_service import (
    RuntimeRetrainBusy,
    RuntimeRetrainCooldown,
    RuntimeRetrainService,
)

router = APIRouter(prefix="/api/v1/training", tags=["training"])


class RetrainStartRequest(BaseModel):
    """Body for ``POST /api/v1/training/retrain-boundaries``."""

    window_start: str | None = Field(
        default=None,
        description=("ISO-8601 retrain-window start (YYYY-MM-DD HH:MM:SS). " "Must be strictly less than window_stop."),
    )
    window_stop: str | None = Field(
        default=None,
        description="ISO-8601 retrain-window stop (YYYY-MM-DD HH:MM:SS).",
    )
    intervals: list[tuple[str, str]] | None = Field(default=None, min_length=1)


class RetrainClassifierRequest(BaseModel):
    """Body for ``POST /api/v1/training/retrain-classifier``.

    Adds ``mitre_file`` on top of the bounds-retrain shape: the path to
    the MITRE technique JSON file used to label the ML training data.
    The api validates that ``mitre_file`` is a non-empty string; the
    file's existence, readability, and allow-listed location are
    validated on the otalon-clas worker (which owns the filesystem the
    labels live on) before any artifact is trained (audit B-07/B-08).
    """

    window_start: str | None = Field(
        default=None,
        description=(
            "ISO-8601 classifier-training-window start "
            "(YYYY-MM-DD HH:MM:SS). Must be strictly less than "
            "window_stop."
        ),
    )
    window_stop: str | None = Field(
        default=None,
        description="ISO-8601 classifier-training-window stop (YYYY-MM-DD HH:MM:SS).",
    )
    intervals: list[tuple[str, str]] | None = Field(default=None, min_length=1)
    mitre_file: str = Field(
        ...,
        description=(
            "Path to the MITRE-technique JSON file used to label the ML training data. "
            "Forwarded to ``TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE``."
        ),
    )


@router.get("/label-sources", response_model=LabelSourceList)
async def list_label_sources(
    service: LabelSourceService = Depends(get_label_source_service),
) -> LabelSourceList:
    """List valid shared ground-truth files without exposing host paths."""
    return await asyncio.to_thread(service.list_sources)


@router.post(
    "/label-sources/upload",
    response_model=LabelSource,
    status_code=201,
    dependencies=[Depends(require_operator_api_key)],
)
async def upload_label_source(
    request: Request,
    service: LabelSourceService = Depends(get_label_source_service),
) -> LabelSource:
    """Validate and atomically persist one bounded JSON ground-truth file.

    This is a persistent filesystem-write surface, so it is operator-only and
    fail-closed: :func:`require_operator_api_key` returns 401 for a
    missing/invalid key, 403 for a valid non-operator (viewer) key, and 503 when
    no keys are configured (an unconfigured deployment must never accept a
    write). It matches the workspace mutation pattern in
    ``operations_config.py``. The GET listing remains an authenticated read
    (any valid key), since it exposes no host paths and performs no write.

    The transport ceiling (:data:`LABEL_SOURCE_MAX_TRANSPORT_BYTES`) bounds the
    raw ``{filename, content}`` JSON body safely above worst-case JSON string
    escaping of a valid <=5 MiB file (``content`` is a JSON-escaped string, so
    ~6x inflation is possible). The *decoded* label content is still enforced
    strict <=5 MiB downstream, so an over-large decoded payload fails with 413
    even when its transport size is under the ceiling.
    """
    content_length = request.headers.get("content-length")
    try:
        if content_length and int(content_length) > LABEL_SOURCE_MAX_TRANSPORT_BYTES:
            raise HTTPException(status_code=413, detail="label source upload exceeds the transport size limit")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail="invalid content-length header") from exc
    try:
        raw_body = await request.body()
        if len(raw_body) > LABEL_SOURCE_MAX_TRANSPORT_BYTES:
            raise HTTPException(status_code=413, detail="label source upload exceeds the transport size limit")
        body = json.loads(raw_body)
        if not isinstance(body, dict) or not isinstance(body.get("filename"), str):
            raise LabelSourceValidationError("JSON body requires filename and content")
        raw_content = body.get("content")
        if not isinstance(raw_content, str):
            raise LabelSourceValidationError("JSON body requires string content")
        content = raw_content.encode("utf-8")
        return await asyncio.to_thread(service.save_upload, body["filename"], content)
    except LabelSourceConflictError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except LabelSourceTooLargeError as exc:
        raise HTTPException(status_code=413, detail=str(exc)) from exc
    except (LabelSourceValidationError, UnicodeEncodeError, ValueError) as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


def _legacy_window(
    body: RetrainStartRequest | RetrainClassifierRequest,
) -> tuple[str, str]:
    """Return compatibility window values for service boundary calls."""
    if body.window_start and body.window_stop:
        return body.window_start, body.window_stop
    if body.intervals:
        return body.intervals[0][0], body.intervals[-1][1]
    raise ValueError("intervals or window_start/window_stop is required")


class RetrainStatusResponse(BaseModel):
    """Body for both endpoints; mirrors :class:`RetrainStatus.to_dict`.

    ``scope`` reports which retrain type the current (or most recent)
    run represents — ``"bounds"`` for a bounds + frequency calibration,
    ``"ml"`` for an ML group-classifier training run. ``None`` only at
    process boot, before any run has been started.
    """

    state: str
    detail: str
    job_ref: str | None = None
    scope: str | None = None
    started_at: str | None = None
    finished_at: str | None = None
    window_start: str | None = None
    window_stop: str | None = None
    intervals: list[tuple[str, str]] = Field(default_factory=list)
    history_snapshot_rows: int = 0
    error: str | None = None
    mitre_file: str | None = None
    busy: bool = False


@router.post("/retrain-boundaries", response_model=RetrainStatusResponse)
async def start_retrain_boundaries(
    body: RetrainStartRequest,
    service: RuntimeRetrainService = Depends(get_runtime_retrain_service),
) -> RetrainStatusResponse:
    """Start a chat-triggered boundary retraining run.

    Validates the retrain window at the orchestration boundary (ISO-8601
    + strict ``window_start < window_stop``), then spawns the background
    orchestrator. Returns immediately with an initial status snapshot;
    the chat surface polls ``GET .../status`` for progress.

    Args:
        body: Validated retrain-window payload.
        service: Injected orchestrator singleton.

    Returns:
        The initial :class:`RetrainStatusResponse` snapshot.

    Raises:
        HTTPException: 400 on invalid window, 409 when another run is
            already in progress.
    """
    try:
        window_start, window_stop = _legacy_window(body)
        status = await service.start(
            window_start=window_start,
            window_stop=window_stop,
            intervals=body.intervals,
            requested_by="operator",
        )
    except RuntimeRetrainValidationError as exc:
        logger.warning("start_retrain_boundaries rejected: {}", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        logger.warning("start_retrain_boundaries missing window: {}", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeRetrainBusy as exc:
        logger.warning("start_retrain_boundaries 409: {}", exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeRetrainCooldown as exc:
        logger.warning("start_retrain_boundaries cooldown: {}", exc)
        raise HTTPException(
            status_code=429,
            detail={"message": str(exc), "retry_after": exc.retry_after},
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    return RetrainStatusResponse.model_validate(status.to_dict())


@router.post("/retrain-classifier", response_model=RetrainStatusResponse)
async def start_retrain_classifier(
    body: RetrainClassifierRequest,
    service: RuntimeRetrainService = Depends(get_runtime_retrain_service),
) -> RetrainStatusResponse:
    """Start a chat-triggered ML classifier retraining run.

    Validates the retrain window at the orchestration boundary (ISO-8601
    + strict ``window_start < window_stop``) and that ``mitre_file`` is a
    non-empty string. The file's existence/readability/allow-listed
    location is validated on the otalon-clas worker before training
    (audit B-07/B-08). Shares the same single-flight busy lock as
    ``retrain-boundaries``: a parallel trigger of EITHER returns HTTP 409.

    Args:
        body: Validated retrain payload (window + MITRE-technique file).
        service: Injected orchestrator singleton.

    Returns:
        The initial :class:`RetrainStatusResponse` snapshot with
        ``scope='ml'``.

    Raises:
        HTTPException: 400 on invalid window or missing MITRE file, 409
            when another run (bounds OR ML) is already in progress.
    """
    try:
        window_start, window_stop = _legacy_window(body)
        status = await service.start_classifier(
            window_start=window_start,
            window_stop=window_stop,
            intervals=body.intervals,
            mitre_file=body.mitre_file,
            requested_by="operator",
        )
    except RuntimeRetrainValidationError as exc:
        logger.warning("start_retrain_classifier rejected: {}", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except ValueError as exc:
        logger.warning("start_retrain_classifier missing window: {}", exc)
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except RuntimeRetrainBusy as exc:
        logger.warning("start_retrain_classifier 409: {}", exc)
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except RuntimeRetrainCooldown as exc:
        logger.warning("start_retrain_classifier cooldown: {}", exc)
        raise HTTPException(
            status_code=429,
            detail={"message": str(exc), "retry_after": exc.retry_after},
            headers={"Retry-After": str(exc.retry_after)},
        ) from exc
    return RetrainStatusResponse.model_validate(status.to_dict())


@router.get("/retrain-boundaries/status", response_model=RetrainStatusResponse)
async def get_retrain_boundaries_status(
    service: RuntimeRetrainService = Depends(get_runtime_retrain_service),
) -> RetrainStatusResponse:
    """Return the most recent orchestrator status snapshot.

    Side-effect free; safe to poll at any cadence the chat surface
    chooses (spec: "transitioning over time toward ``live`` or
    ``failed``"). The same endpoint serves both retrain types — the
    ``scope`` field on the response distinguishes them.

    Args:
        service: Injected orchestrator singleton.

    Returns:
        The current :class:`RetrainStatusResponse`.
    """
    status = service.get_status()
    return RetrainStatusResponse.model_validate(status.to_dict())
