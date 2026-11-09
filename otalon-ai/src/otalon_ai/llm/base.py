"""Abstract LLM provider protocol used by chat (streaming) and jobs (sync)."""

from __future__ import annotations

from typing import Any, AsyncIterator, List, Optional, Protocol


class LlmProvider(Protocol):
    """Minimal interface for an OpenAI-compatible chat-completion provider.

    Two call surfaces:

    - Jobs surface (sync, inherited): :meth:`chat_completion` — one
      synchronous request returning the SDK ``ChatCompletion``.
    - Chat surface (async streaming, HC3): :meth:`chat_completion_stream`
      — yields raw ``ChatCompletionChunk`` objects token-by-token so the
      SSE endpoint can pipe tokens to the UI as the model produces them.

    Concrete providers SHALL implement both. The chat agent loop relies
    on the async iterator for real streaming + disconnect-cancel; cancelling
    the consumer SHALL propagate as :class:`asyncio.CancelledError` into
    the iterator so the provider can close the upstream HTTP connection
    and stop billing immediately.
    """

    name: str
    model: str

    def chat_completion(
        self,
        messages: List[dict[str, Any]],
        tools: List[dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> Any:
        """Issue a chat completion. Returns the raw OpenAI SDK ``ChatCompletion``."""
        ...

    def chat_completion_stream(
        self,
        messages: List[dict[str, Any]],
        tools: List[dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> AsyncIterator[Any]:
        """Stream chunks of a chat completion. Returns an async iterator of ``ChatCompletionChunk``.

        The returned iterator MUST be safely cancellable: if the consumer
        is cancelled (``asyncio.CancelledError``), the underlying HTTP
        stream SHALL be closed so the upstream LLM stops billing. This
        is the cost-leak fix referenced as HC3 in the review TODO.
        """
        ...
