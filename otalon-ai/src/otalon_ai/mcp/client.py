"""MCP streamable-http client helpers (shared).

Provides the low-level ``acquire_session`` context manager used by the
inherited jobs worker AND by the new chat registry. The schema-translation
helpers (``mcp_tool_to_openai_function`` / ``apply_allow_list``) live in
``otalon_ai.mcp.schema``; they are re-exported here for backward
compatibility with the inherited ``otalon_ai/jobs/worker_pool.py`` import
path.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from loguru import logger
from mcp import ClientSession
from mcp.client.streamable_http import streamablehttp_client
from mcp.shared.exceptions import McpError
from mcp.types import ErrorData

# Re-export so inherited callers (`from otalon_ai.mcp.client import
# mcp_tool_to_openai_function, apply_allow_list`) keep working without
# rewriting their imports during Phase 5.
from otalon_ai.mcp.schema import (
    apply_allow_list,
    mcp_tool_to_openai_function,
)

__all__ = [
    "ErrorData",
    "McpError",
    "acquire_session",
    "apply_allow_list",
    "mcp_tool_to_openai_function",
]


def _ensure_mcp_path(url: str) -> str:
    """Ensure the URL ends with ``/mcp`` (FastMCP's streamable-http mount).

    Operators typically configure ``MCP_URL=http://otalon-mcp:9000`` and
    expect things to "just work". FastMCP mounts streamable-http at ``/mcp``
    by default, so we normalise the URL transparently here.
    """
    stripped = url.rstrip("/")
    if stripped.endswith("/mcp"):
        return stripped + "/"
    if stripped.endswith("/mcp/"):
        return stripped
    return stripped + "/mcp/"


@asynccontextmanager
async def acquire_session(
    url: str,
    *,
    api_key: Optional[str] = None,
) -> AsyncIterator[ClientSession]:
    """Open a streamable-http MCP session, initialise it, yield, close on exit.

    The wrapper guarantees that the session is closed cleanly when the
    ``async with`` block exits — even on exceptions.

    When ``api_key`` is a non-empty string it is sent as the ``X-API-Key``
    request header. otalon-mcp is fail-closed on
    ``OTALON_MCP_ALLOWED_KEYS`` (see ``otalon-mcp/src/otalon_mcp/server.py``),
    so an unauthenticated session receives HTTP 503
    ``API key authentication unavailable``. The credential is passed only
    through the transport header — never placed in the URL, query, body,
    or any log line.
    """
    target = _ensure_mcp_path(url)
    headers = {"X-API-Key": api_key} if api_key else None
    logger.debug(
        "Opening MCP streamable-http session to {} (authenticated={})",
        target,
        bool(headers),
    )
    async with streamablehttp_client(target, headers=headers) as (read, write, _close):
        async with ClientSession(read, write) as session:
            await session.initialize()
            yield session
    logger.debug("Closed MCP session to {}", target)
