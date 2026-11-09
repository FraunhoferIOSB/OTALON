"""Factory for building an LLM provider per request.

After Phase 9 of the ``replace-n8n-chat-orchestration`` change, both the
chat agent loop and the jobs worker pool route exclusively through the
LiteLLM proxy. The factory exposes two helpers:

- :func:`build_chat_provider` — picks ``settings.chat.llm_model`` and
  ``settings.chat.llm_reasoning_effort``. Used by the chat agent loop.
- :func:`build_jobs_provider` — picks ``settings.jobs.llm_model`` and
  ``settings.jobs.llm_reasoning_effort``. Used by ``WorkerPool``.

The previous ``build_provider`` / ``resolve_reasoning_effort`` helpers
(Azure / OpenAI-compat dispatch) and the ``LegacyLlmConfig`` shim were
removed in Phase 9 (tasks.md 9.2-9.4).
"""

from __future__ import annotations

from typing import Optional

from otalon_ai.llm.litellm_provider import LiteLLMProvider
from otalon_ai.settings import Settings


def build_chat_provider(settings: Settings, *, model: Optional[str] = None) -> LiteLLMProvider:
    """Construct the chat-surface LiteLLM provider.

    Per design.md § "Per-surface env-var matrix" the chat surface reads
    ``CHAT_LLM_MODEL`` and ``CHAT_LLM_REASONING_EFFORT``. The optional
    ``model`` override exists for future per-request model selection (e.g.
    a faster model on retry); not exposed in the public API today.
    """
    return LiteLLMProvider(
        base_url=settings.litellm.base_url,
        api_key=settings.litellm.api_key,
        model=model or settings.chat.llm_model,
        default_reasoning_effort=settings.chat.llm_reasoning_effort,
    )


def build_jobs_provider(settings: Settings, *, model: Optional[str] = None) -> LiteLLMProvider:
    """Construct the jobs-surface LiteLLM provider.

    Picks ``settings.jobs.llm_model`` / ``settings.jobs.llm_reasoning_effort``
    so chat + jobs can run on different models without code change. Used by
    :class:`src.jobs.worker_pool.WorkerPool` from Phase 9 onwards.

    Per Cluster d / B1 (SSRF close): the endpoint is sourced exclusively
    from :class:`Settings` — callers cannot inject one via this signature.
    """
    return LiteLLMProvider(
        base_url=settings.litellm.base_url,
        api_key=settings.litellm.api_key,
        model=model or settings.jobs.llm_model,
        default_reasoning_effort=settings.jobs.llm_reasoning_effort,
    )
