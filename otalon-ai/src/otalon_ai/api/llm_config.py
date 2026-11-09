"""Internal live-LLM configuration endpoint (AI-045 Wave 1).

``PUT /internal/v1/llm-config`` receives a validated configuration from
otalon-api (the operator saved it in the "AI Connection" tab) and swaps
the chat provider + jobs settings WITHOUT a container restart. Per
design.md § D3 the order is:

1. Build the new chat provider from the overridden settings FIRST.
   Any failure → HTTP 422, no swap at all (Task 1.5).
2. Swap ``ChatAgentLoop`` provider (atomic under its lock) and the
   ``WorkerPool`` settings reference.
3. Log ``llm-config applied chat model=<x> job model=<y> source=live``
   — model identifiers only, never any key (design D6).

``GET /internal/v1/llm-config`` reports the active configuration
(``base_url``, ``chat_model``, ``job_model``, ``applied_at``,
``source``). The response contains no key material (spec
`agent--llm-live-config` § "report its active configuration without
the key").

Authentication: the router is mounted under the ``/internal`` prefix,
which ``main.py`` adds to ``make_api_key_middleware``'s protected
prefixes. A caller without a key in ``OTALON_AI_ALLOWED_KEYS`` is
rejected by the middleware (401/403) before reaching these handlers.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, Literal, Optional

from fastapi import APIRouter, HTTPException, Request
from loguru import logger
from pydantic import BaseModel, Field

from otalon_ai.llm.factory import build_chat_provider
from otalon_ai.settings import Settings

router = APIRouter(prefix="/internal/v1", tags=["internal-llm-config"])


class LlmConfigUpdate(BaseModel):
    """Payload for a live configuration push from otalon-api."""

    base_url: Optional[str] = Field(
        default=None,
        description="New LiteLLM proxy base URL; None keeps the current one.",
    )
    chat_model: Optional[str] = Field(
        default=None, description="New chat model identifier."
    )
    chat_reasoning_effort: Optional[Literal["low", "medium", "high"]] = Field(
        default=None
    )
    job_model: Optional[str] = Field(
        default=None, description="New jobs model identifier."
    )
    job_reasoning_effort: Optional[Literal["low", "medium", "high"]] = Field(
        default=None
    )
    context_window: Optional[int] = Field(
        default=None,
        ge=4096,
        le=1000000,
        description="Maximum chat context window in tokens (AI-046); None keeps the current one.",
    )


class LlmConfigStatus(BaseModel):
    """Active configuration report — key material is never included."""

    base_url: str
    chat_model: str
    job_model: str
    applied_at: datetime
    source: Literal["env", "live"]


def _llm_state(request: Request) -> Dict[str, Any]:
    """Return a mutable state dict attached at startup by ``main``."""
    state: Optional[Dict[str, Any]] = getattr(request.app.state, "llm_config", None)
    if state is None:
        raise HTTPException(status_code=503, detail="llm-config not initialised")
    return state


@router.put("/llm-config", response_model=LlmConfigStatus)
async def put_llm_config(payload: LlmConfigUpdate, request: Request) -> LlmConfigStatus:
    """Apply a live configuration update (build first, then swap).

    Raises:
        HTTPException: 422 when the new settings or the provider build
            fail — the previous provider and settings stay active.
        HTTPException: 503 when the app state was never initialised.
    """
    state = _llm_state(request)
    chat_loop = getattr(request.app.state, "chat_loop", None)
    if chat_loop is None:
        raise HTTPException(status_code=503, detail="chat loop not initialised")
    worker_pool = getattr(request.app.state, "worker_pool", None)
    current: Settings = state["settings"]

    # Task 1.5: build from the OVERRIDES first. ``with_llm_overrides``
    # validates the new litellm section (empty base_url etc. →
    # ValueError); ``build_chat_provider`` fails on unusable values.
    # Either failure leaves the running system untouched → 422.
    try:
        new_settings = current.with_llm_overrides(
            base_url=payload.base_url,
            chat_model=payload.chat_model,
            chat_reasoning_effort=payload.chat_reasoning_effort,
            job_model=payload.job_model,
            job_reasoning_effort=payload.job_reasoning_effort,
            context_window=payload.context_window,
        )
        new_provider = build_chat_provider(new_settings)
    except ValueError as exc:
        raise HTTPException(
            status_code=422,
            detail=f"invalid llm configuration: {exc}",
        ) from exc
    except (
        Exception
    ) as exc:  # noqa: BLE001 — reason: any provider-build failure MUST map to 422 without leaking internals
        logger.warning("llm-config: provider build failed: {}", exc)
        raise HTTPException(
            status_code=422, detail="llm provider build failed"
        ) from exc

    # Swap (atomic under the loop's provider lock) + jobs settings.
    await chat_loop.swap_provider(new_provider)
    if worker_pool is not None:
        worker_pool.update_settings(new_settings)
    state["settings"] = new_settings
    # AI-046: the chat path (chat/router.py, chat/sse.py) reads app.state.settings, not the
    # llm_config copy. Without this sync a live context-window change never reaches the chat.
    request.app.state.settings = new_settings
    state["source"] = "live"
    state["applied_at"] = datetime.now(tz=timezone.utc)
    logger.info(
        "llm-config applied chat model={} job model={} source=live",
        new_settings.chat.llm_model,
        new_settings.jobs.llm_model,
    )
    return LlmConfigStatus(
        base_url=new_settings.litellm.base_url,
        chat_model=new_settings.chat.llm_model,
        job_model=new_settings.jobs.llm_model,
        applied_at=state["applied_at"],
        source="live",
    )


@router.get("/llm-config", response_model=LlmConfigStatus)
async def get_llm_config(request: Request) -> LlmConfigStatus:
    """Report the active configuration. Contains no key material."""
    state = _llm_state(request)
    settings: Settings = state["settings"]
    return LlmConfigStatus(
        base_url=settings.litellm.base_url,
        chat_model=settings.chat.llm_model,
        job_model=settings.jobs.llm_model,
        applied_at=state["applied_at"],
        source=state["source"],
    )
