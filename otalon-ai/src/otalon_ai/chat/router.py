"""Chat HTTP router — synchronous endpoint.

Per spec ``chat--orchestration`` § "Chat service SHALL expose a synchronous
HTTP endpoint compatible with the n8n webhook contract", this exposes
``POST /api/v1/chat``. The request body is wire-compatible with
``otalon-ui/server/api/chat.post.ts`` so the UI cutover is a single
``CHAT_WEBHOOK_URL`` flip.

Error envelope: when the OpenAI SDK raises ``APIConnectionError`` (LiteLLM
proxy unreachable), the endpoint returns HTTP 200 with
``{role: "assistant", content: <fallback>, source: "fallback"}`` mirroring
the existing UI fallback shape. Other unexpected exceptions surface as
HTTP 500 with the structured error envelope. The UI's 60 s timeout window
is honoured: long tool-augmented runs SHOULD use the SSE endpoint
(:mod:`src.chat.sse`).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Literal, Optional

from fastapi import APIRouter, Request
from loguru import logger
from openai import APIConnectionError, APIError
from pydantic import BaseModel, Field

from otalon_ai.chat.agent_loop import ChatAgentLoop
from otalon_ai.chat.session_store import ChatSessionStore
from otalon_ai.settings import Settings

router = APIRouter(prefix="/api/v1/chat", tags=["chat"])


class ChatRequest(BaseModel):
    """Request body of ``POST /api/v1/chat``.

    Wire-compatible with the n8n webhook contract that
    ``otalon-ui/server/api/chat.post.ts`` posts today.
    """

    session_id: str = Field(..., min_length=1, max_length=128)
    message: str = Field(..., min_length=0)
    history: Optional[List[Dict[str, Any]]] = None  # accepted but not used (we own history)
    metadata: Optional[Dict[str, Any]] = None


class ChatResponse(BaseModel):
    """Response body of ``POST /api/v1/chat`` (matching n8n's shape).

    The UI consumes only ``role`` and ``content``; the remaining fields
    are observability hints (the UI ignores unknown keys per
    ``chat.post.ts``).
    """

    role: str = "assistant"
    content: str
    source: str = "otalon-ai"
    tokens_used: Optional[int] = None
    prompt_tokens: Optional[int] = None
    completion_tokens: Optional[int] = None
    context_window: Optional[int] = None
    tool_calls_count: Optional[int] = None
    duration_ms: Optional[int] = None


class ChatHistoryMessage(BaseModel):
    """One displayable turn in a chat session."""

    role: Literal["user", "assistant"]
    content: str


class ChatSessionResponse(BaseModel):
    """Response body of ``GET /api/v1/chat/sessions/{session_id}``."""

    session_id: str
    messages: List[ChatHistoryMessage]


def _strip_kontext_prefix(content: str) -> str:
    """Remove the ``[Kontext: …]`` prefix from a user message.

    If ``content`` starts with ``[Kontext: `` everything up to and
    including the first ``]\n\n`` occurrence is removed. If the pattern
    is not found the content is returned unchanged.
    """
    prefix = "[Kontext: "
    if not content.startswith(prefix):
        return content
    end = content.find("]\n\n")
    if end == -1:
        return content
    return content[end + 3 :]


def _extract_ui_context_markdown(metadata: Optional[Dict[str, Any]]) -> Optional[str]:
    """Pull the markdown UI-context string from the request metadata.

    The UI's ``shared/renderUiContextMarkdown.ts`` serialises the active
    tab / selected entity into a markdown blob and places it under
    ``metadata.ui_context_markdown`` (older keys: ``ui_context`` as a
    nested dict). We accept either: a direct markdown string under the
    new key, or a structured dict under the old key with the agent loop
    falling back to its own concatenation.
    """
    if not metadata:
        return None
    direct = metadata.get("ui_context_markdown")
    if isinstance(direct, str) and direct.strip():
        return direct
    # Legacy: structured ui_context object — stringify via JSON. The
    # agent loop wraps the whole thing in `[Kontext: ...]`.
    legacy = metadata.get("ui_context")
    if isinstance(legacy, dict) and legacy:
        import json as _json

        return _json.dumps(legacy, ensure_ascii=False)
    return None


@router.post("", response_model=ChatResponse)
async def chat(payload: ChatRequest, request: Request) -> ChatResponse:
    """Run one chat turn and return the assistant message.

    Failure-mode envelope mirrors the existing UI fallback (HTTP 200 with
    ``source="fallback"``) so the operator-facing error message renders
    inline in the chat history instead of an HTTP error banner.
    """
    loop: ChatAgentLoop = request.app.state.chat_loop
    settings: Settings = request.app.state.settings

    ui_context = _extract_ui_context_markdown(payload.metadata)

    try:
        result = await loop.run_chat_turn(
            payload.session_id,
            payload.message,
            ui_context_markdown=ui_context,
        )
    except APIConnectionError as exc:
        logger.warning(
            "chat router: LiteLLM proxy unreachable (session={}): {}",
            payload.session_id,
            exc,
        )
        return ChatResponse(
            content=settings.chat.fallback_message,
            source="fallback",
        )
    except APIError as exc:
        # Other OpenAI/LiteLLM-side errors (rate limit, bad request, etc.)
        # also degrade to the friendly fallback rather than HTTP 5xx so
        # the operator sees an in-chat error.
        logger.warning(
            "chat router: LiteLLM API error (session={}): {}",
            payload.session_id,
            exc,
        )
        return ChatResponse(
            content=settings.chat.fallback_message,
            source="fallback",
        )

    return ChatResponse(
        content=result.content,
        tokens_used=result.tokens_used,
        prompt_tokens=result.prompt_tokens,
        completion_tokens=result.completion_tokens,
        context_window=settings.chat.model_context_window,
        tool_calls_count=result.tool_calls_count,
        duration_ms=result.duration_ms,
    )


@router.get("/sessions/{session_id}", response_model=ChatSessionResponse)
async def get_chat_session(session_id: str, request: Request) -> ChatSessionResponse:
    """Return the displayable message history for a session.

    Filters to ``user`` and plain ``assistant`` messages with non-empty
    content.  Messages carrying ``tool_calls`` are excluded.  The
    ``[Kontext: …]`` prefix is stripped from user messages.  An unknown
    session returns an empty message list (idempotent for fresh clients).
    """
    store: ChatSessionStore = request.app.state.chat_store
    # AI-02: blocking psycopg2 I/O runs off the event loop.
    raw = await asyncio.to_thread(store.load, session_id)

    displayable: List[ChatHistoryMessage] = []
    for msg in raw:
        role = msg.get("role")
        content = msg.get("content")
        if role not in ("user", "assistant"):
            continue
        if not isinstance(content, str) or not content.strip():
            continue
        if role == "assistant" and msg.get("tool_calls"):
            continue
        clean = _strip_kontext_prefix(content) if role == "user" else content
        displayable.append(ChatHistoryMessage(role=role, content=clean))

    return ChatSessionResponse(session_id=session_id, messages=displayable)
