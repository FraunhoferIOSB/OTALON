"""Chat streaming endpoint — Server-Sent Events.

Per spec ``chat--orchestration`` § "Chat service SHALL expose a streaming
endpoint via Server-Sent Events", this exposes
``POST /api/v1/chat/stream/{session_id}`` returning ``text/event-stream``.

Implementation (Cluster c / HC3 + A3):

- Real token-by-token streaming. The endpoint consumes
  :meth:`ChatAgentLoop.run_chat_turn_stream` which itself consumes the
  provider's async streaming chat-completion (``stream=True``). Tokens
  arrive as they are produced by the LLM; tool-call boundaries
  interleave naturally between rounds.
- Disconnect-cancel. A dedicated coroutine consumes the ASGI
  ``receive`` channel directly looking for ``http.disconnect`` (the
  same pattern Starlette's :class:`StreamingResponse.listen_for_disconnect`
  uses). When that arrives we cancel the producer task; the cancellation
  propagates into the LLM provider's stream's ``finally`` block which
  closes the upstream HTTP response so the LLM stops billing. We use a
  raw ``receive`` rather than polling ``Request.is_disconnected`` because
  the latter wraps its read in an :class:`anyio.CancelScope` that
  swallows cancellation from the parent task — that approach hangs the
  endpoint in practice.
- JSON envelope (A3). Every SSE ``data:`` line is a SINGLE JSON object
  ``{"type": "...", ...}``. This preserves multi-line content (Markdown
  code blocks) which the previous newline-collapsing format silently
  mangled. The event NAME (``event: <name>``) is kept for legacy
  EventSource consumers but the content is now fully inside the JSON
  payload.

Emitted event names:

- ``token``: ``{"type": "token", "delta": "..."}``
- ``tool_call_started``: ``{"type": "tool_call_started", "name": "...", "args": {...}}``
- ``tool_call_completed``: ``{"type": "tool_call_completed", "name": "...", "ok": bool,
  "result_preview": "..."}`` (or ``"error": "..."`` on failure)
- ``final``: ``{"type": "final", "content": "...", "tokens_used": int|null,
  "prompt_tokens": int|null, "completion_tokens": int|null,
  "tool_calls_count": int, "duration_ms": int, "cap_reached": bool,
  "source": "otalon-ai"}``
- ``error``: ``{"type": "error", "message": "...", "source": "fallback"}``
"""

from __future__ import annotations

import asyncio
import json
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, MutableMapping, Optional

from fastapi import APIRouter, Request
from fastapi.responses import StreamingResponse
from loguru import logger
from openai import APIConnectionError, APIError
from pydantic import BaseModel, Field

from otalon_ai.chat.agent_loop import ChatAgentLoop, StreamEvent
from otalon_ai.chat.router import _extract_ui_context_markdown
from otalon_ai.settings import Settings

router = APIRouter(prefix="/api/v1/chat", tags=["chat-stream"])


class StreamRequest(BaseModel):
    """Body of ``POST /api/v1/chat/stream/{session_id}``."""

    message: str = Field(..., min_length=0)
    metadata: Dict[str, Any] | None = None


def _format_sse(event: str, payload: Dict[str, Any]) -> bytes:
    """Serialise one SSE event with a single JSON ``data:`` payload (A3).

    The full payload is JSON-encoded onto ONE line so multi-line content
    (Markdown code blocks, multi-line strings inside tool args, etc.) is
    preserved verbatim — clients parse ``JSON.parse(data)`` and recover
    the original string with newlines intact. This replaces the previous
    ``data.replace("\\n", "\\\\n")`` hack which destroyed code-block
    rendering in the chat UI.
    """
    line = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return f"event: {event}\ndata: {line}\n\n".encode("utf-8")


def _event_name(event: StreamEvent) -> str:
    """Map a typed stream event to its SSE ``event:`` name."""
    return str(event.get("type", "message"))


async def _generate(
    loop: ChatAgentLoop,
    session_id: str,
    user_message: str,
    *,
    ui_context_markdown: Optional[str],
    receive: Callable[[], Awaitable[MutableMapping[str, Any]]],
    context_window: int,
) -> AsyncIterator[bytes]:
    """Yield SSE-formatted bytes for one chat turn with disconnect-cancel.

    Runs the streaming chat-turn as a producer task and a single
    disconnect-watcher task that consumes the ASGI receive channel
    looking for ``http.disconnect``. The disconnect-watcher is created
    ONCE for the lifetime of the request (not per-iteration) so the
    ``await receive()`` call is never cancelled-and-restarted —
    cancelling a half-consumed ``receive`` interacts badly with
    Starlette's anyio scopes in tests.
    """
    queue: asyncio.Queue[Optional[StreamEvent]] = asyncio.Queue(maxsize=256)

    async def _produce() -> None:
        """Run the agent loop stream and push events into the queue."""
        try:
            async for event in loop.run_chat_turn_stream(
                session_id,
                user_message,
                ui_context_markdown=ui_context_markdown,
            ):
                await queue.put(event)
        except asyncio.CancelledError:
            logger.info("chat sse: producer cancelled (session={})", session_id)
            raise
        except APIConnectionError as exc:
            logger.warning("chat sse: LiteLLM unreachable (session={}): {}", session_id, exc)
            await queue.put({"type": "error", "message": "LLM proxy unreachable", "source": "fallback"})
        except APIError as exc:
            logger.warning("chat sse: LiteLLM API error (session={}): {}", session_id, exc)
            await queue.put({"type": "error", "message": str(exc), "source": "fallback"})
        except Exception as exc:  # pragma: no cover - defensive
            logger.exception("chat sse: unexpected error (session={}): {}", session_id, exc)
            await queue.put({"type": "error", "message": "internal error", "source": "fallback"})
        finally:
            await queue.put(None)  # sentinel: end-of-stream

    async def _watch_disconnect() -> None:
        """Block on ``receive()`` until an ``http.disconnect`` arrives.

        Mirrors Starlette's :meth:`StreamingResponse.listen_for_disconnect`.
        Created once and never restarted; cancelled by the outer
        ``finally`` when the response completes normally.
        """
        while True:
            message = await receive()
            if message.get("type") == "http.disconnect":
                return

    producer = asyncio.create_task(_produce(), name=f"chat-sse-producer:{session_id}")
    watcher = asyncio.create_task(_watch_disconnect(), name=f"chat-sse-watch:{session_id}")

    try:
        while True:
            get_task = asyncio.create_task(queue.get(), name=f"chat-sse-get:{session_id}")
            done, _pending = await asyncio.wait(
                {get_task, watcher},
                return_when=asyncio.FIRST_COMPLETED,
            )

            if watcher in done:
                # Client disconnected (or watcher errored). Cancel the
                # producer so the upstream LLM stream is closed and
                # billing stops (HC3 cost-leak guard).
                logger.info("chat sse: client disconnected (session={}); cancelling LLM call", session_id)
                get_task.cancel()
                try:
                    await get_task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001 - drain
                    pass
                producer.cancel()
                try:
                    await producer
                except (asyncio.CancelledError, Exception):  # noqa: BLE001 - drain
                    pass
                return

            event = get_task.result()
            if event is None:
                return

            if event.get("type") == "final":
                event = {**event, "context_window": context_window}
                if "source" not in event:
                    event = {**event, "source": "otalon-ai"}

            yield _format_sse(_event_name(event), event)
    finally:
        # Tear down both tasks. Idempotent if already done.
        for task in (watcher, producer):
            if not task.done():
                task.cancel()
                try:
                    await task
                except (asyncio.CancelledError, Exception):  # noqa: BLE001 - drain
                    pass


@router.post("/stream/{session_id}")
async def chat_stream(
    session_id: str,
    payload: StreamRequest,
    request: Request,
) -> StreamingResponse:
    """Stream one chat turn as Server-Sent Events (real token streaming)."""
    loop: ChatAgentLoop = request.app.state.chat_loop
    ui_context = _extract_ui_context_markdown(payload.metadata)

    settings: Settings = request.app.state.settings
    return StreamingResponse(
        _generate(
            loop,
            session_id,
            payload.message,
            ui_context_markdown=ui_context,
            receive=request.receive,
            context_window=settings.chat.model_context_window,
        ),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
