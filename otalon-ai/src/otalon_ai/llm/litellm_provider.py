"""LiteLLM provider — single LLM gateway for chat AND jobs surfaces.

Per design.md § Decision 2 both the chat agent loop and the inherited
subagent worker issue chat-completions exclusively against the LiteLLM
proxy at ``LITELLM_BASE_URL`` via the OpenAI Python SDK. The proxy is the
runtime; the OpenAI SDK is the wire format. We deliberately do NOT depend
on the ``litellm`` PyPI package (per spec ``agent--llm-backends`` and
tasks.md 1.2).

The provider implements the inherited :class:`src.llm.base.LlmProvider`
protocol so the jobs worker call site is unchanged. The chat agent loop
calls the sync method via ``asyncio.to_thread`` for non-streaming turns
AND consumes the streaming async iterator via :meth:`chat_completion_stream`
for real token-by-token SSE (Cluster c / HC3).

When ``reasoning_effort`` is set, the provider OMITS ``temperature`` from
the request body. Reasoning-class models (gpt-5.4 reasoning, o-series)
reject non-default temperatures; the inherited Azure provider already
followed this rule and the same applies behind the LiteLLM proxy.
``reasoning_effort`` is passed as a top-level OpenAI SDK keyword.

HC3 streaming contract: :meth:`chat_completion_stream` returns an async
iterator. Cancelling the consumer (``asyncio.CancelledError``) closes the
underlying ``AsyncStream`` (and therefore the HTTPX response) so the
upstream LLM stops billing immediately. The chat agent loop's SSE
endpoint uses this for disconnect-cancel.
"""

from __future__ import annotations

from typing import Any, AsyncIterator, List, Optional

from loguru import logger
from openai import AsyncOpenAI, OpenAI
from openai.types.chat import ChatCompletionChunk


class LiteLLMProvider:
    """OpenAI-SDK-against-LiteLLM-proxy chat-completion provider.

    Two-surface aware: callers from ``otalon_ai/chat/`` and
    ``otalon_ai/jobs/`` both
    instantiate one of these per request (cheap — the underlying HTTP
    client is connection-pooled by the OpenAI SDK). One sync client +
    one async client are constructed once per instance and reused.
    """

    name = "litellm"

    def __init__(
        self,
        base_url: str,
        api_key: str,
        *,
        model: str,
        default_reasoning_effort: Optional[str] = None,
        timeout: float = 120.0,
    ) -> None:
        if not base_url:
            raise ValueError("LiteLLMProvider: base_url is required")
        if not api_key:
            raise ValueError("LiteLLMProvider: api_key is required")
        if not model:
            raise ValueError("LiteLLMProvider: model is required")
        self.base_url = base_url
        self.model = model
        self.default_reasoning_effort = default_reasoning_effort
        self._client = OpenAI(base_url=base_url, api_key=api_key, timeout=timeout)
        # Separate AsyncOpenAI client for streaming. Cheap to construct;
        # connection-pooled internally by httpx.AsyncClient.
        self._async_client = AsyncOpenAI(base_url=base_url, api_key=api_key, timeout=timeout)

    # --- lifecycle (AI-045 Task 1.8) ------------------------------------

    async def close(self) -> None:
        """Close both underlying clients; safe to call more than once.

        Called by :meth:`ChatAgentLoop.swap_provider` once the last
        in-flight turn has released its reference to a retired
        provider, so the pooled HTTP connections do not leak on live
        config changes. Failures are logged, never raised — a failed
        close of a retired provider must not disturb the running chat.
        """
        try:
            self._client.close()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("LiteLLMProvider.close() sync client raised: {}", exc)
        try:
            await self._async_client.close()
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("LiteLLMProvider.close() async client raised: {}", exc)

    # --- protocol-conforming sync method -------------------------------

    def chat_completion(
        self,
        messages: List[dict[str, Any]],
        tools: List[dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> Any:
        """One synchronous chat-completion request. Returns the SDK response.

        ``reasoning_effort`` precedence: per-call argument wins over the
        provider's ``default_reasoning_effort`` set at construction time.
        """
        effective_effort = reasoning_effort if reasoning_effort is not None else self.default_reasoning_effort
        kwargs = self._build_request_kwargs(messages, tools, temperature, effective_effort)
        logger.trace(
            "LiteLLMProvider chat_completion model={} reasoning_effort={} tool_count={}",
            self.model,
            effective_effort,
            len(tools) if tools else 0,
        )
        return self._client.chat.completions.create(**kwargs)

    # --- HC3: streaming async path -------------------------------------

    async def chat_completion_stream(
        self,
        messages: List[dict[str, Any]],
        tools: List[dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> AsyncIterator[ChatCompletionChunk]:
        """Yield ``ChatCompletionChunk`` objects as the model produces them.

        Per Cluster c / HC3: the underlying call sets ``stream=True`` so
        the OpenAI SDK returns an :class:`openai.AsyncStream`. We iterate
        chunks and yield them; on consumer cancellation we close the
        stream (``await stream.close()``) inside a ``finally`` so the
        upstream HTTP response is aborted and the LLM stops billing.
        ``stream_options.include_usage=True`` asks the proxy to send a
        terminal chunk with the cumulative usage so callers can report
        ``tokens_used`` honestly without a second round-trip.
        """
        effective_effort = reasoning_effort if reasoning_effort is not None else self.default_reasoning_effort
        kwargs = self._build_request_kwargs(messages, tools, temperature, effective_effort)
        kwargs["stream"] = True
        # include_usage emits a terminal chunk with the cumulative usage
        # block so the agent loop can keep its honest token accounting.
        kwargs["stream_options"] = {"include_usage": True}
        logger.trace(
            "LiteLLMProvider chat_completion_stream model={} reasoning_effort={} tool_count={}",
            self.model,
            effective_effort,
            len(tools) if tools else 0,
        )
        stream = await self._async_client.chat.completions.create(**kwargs)
        try:
            async for chunk in stream:
                yield chunk
        finally:
            # Always close — covers normal completion AND consumer cancel
            # (asyncio.CancelledError propagates through the finally).
            # If the underlying response is already closed the call is a
            # no-op; we swallow exceptions here to never mask the
            # original CancelledError.
            try:
                await stream.close()
            except Exception as exc:  # pragma: no cover - defensive
                logger.debug("LiteLLMProvider: stream.close() raised: {}", exc)

    # --- helpers -------------------------------------------------------

    def _build_request_kwargs(
        self,
        messages: List[dict[str, Any]],
        tools: List[dict[str, Any]],
        temperature: float,
        effective_effort: Optional[str],
    ) -> dict[str, Any]:
        """Assemble the shared request kwargs for sync + streaming paths."""
        kwargs: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "tools": tools or None,
        }
        if effective_effort:
            kwargs["reasoning_effort"] = effective_effort
        elif tools and self._rejects_tools_with_reasoning(self.model):
            # The GPT-6 family (sol/terra/luna/astra) answers 400 to function tools on
            # /v1/chat/completions unless reasoning_effort is explicitly "none". Verified
            # live 2026-11-09 against the LiteLLM proxy; other providers are untouched.
            kwargs["reasoning_effort"] = "none"
        else:
            kwargs["temperature"] = temperature
        return kwargs

    @staticmethod
    def _rejects_tools_with_reasoning(model: str) -> bool:
        """True for model ids that need reasoning_effort=none to accept function tools."""
        name = (model or "").lower()
        # strip a LiteLLM route prefix like "litellm/gpt-6-luna"
        name = name.rsplit("/", 1)[-1]
        return name.startswith("gpt-6")
