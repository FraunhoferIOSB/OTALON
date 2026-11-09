"""Multi-server MCP registry shared by chat and jobs surfaces.

Per spec ``chat--orchestration`` § "Chat service SHALL discover MCP tools
at startup and use a session-per-call policy" (amended by
``amend-mcp-registry-session-policy``):

- One :class:`McpRegistry` instance lives in the FastAPI app state.
- **Tool catalogue:** populated lazily on the first
  :meth:`list_openai_tools` call from a transient discovery session
  per server; cached for the process lifetime. The catalogue is the
  long-lived state — :class:`mcp.ClientSession` instances are not.
  A discovery cycle in which **every** configured server failed at the
  transport/protocol level (e.g. a container still starting up and
  replying ``503``) is NOT cached: it produced no authoritative view of
  any server, so the empty aggregate is transient and the next
  :meth:`list_openai_tools` call retries. A cycle in which at least one
  server responded — including a healthy server that legitimately
  advertises zero tools — IS cached, and partial multi-server success
  keeps the tools that were discovered.
- **Session-per-call:** every :meth:`call_tool` invocation opens a
  fresh :class:`mcp.ClientSession` via ``acquire_session`` and closes
  it inside the same ``async with`` block. No :class:`ClientSession`
  instance SHALL persist beyond a single call. This is robust against
  streamable-http reconnects, proxy timeouts and mid-call disconnects,
  at the cost of one extra HTTP round-trip per tool call.
- **Collision handling:** tool names that appear on more than one
  server are prefixed ``<server-name>__``; otherwise the name is
  unprefixed.
- **Cache invalidation:** the catalogue is refreshed only when
  :meth:`call_tool` observes the JSON-RPC method-not-found error code
  (``-32601``) from the server. Transport-level errors do NOT invalidate
  the catalogue — they propagate as exceptions that the orchestration
  loop surfaces as a ``tool`` message to the LLM. Ordinary tool failures
  reported as ``CallToolResult.isError=True`` payloads (e.g. MITRE
  answering "technique not found") likewise leave the catalogue intact:
  the payload is surfaced to the caller unchanged (AI-05 — the previous
  substring heuristic re-executed tools on ordinary failures).
"""

from __future__ import annotations

import asyncio
from typing import Any, Dict, List, Optional, Set, Tuple

from loguru import logger

from otalon_ai.mcp.client import McpError, acquire_session
from otalon_ai.mcp.schema import mcp_tool_to_openai_function, sanitize_tool_name
from otalon_ai.settings import McpServerEntry

PREFIX_SEP = "__"

# JSON-RPC method-not-found error code. This is the ONLY server-side
# signal that may trigger the refresh-and-retry recovery in
# :meth:`McpRegistry.call_tool` (AI-04).
_METHOD_NOT_FOUND = -32601

# Raw (dotted) names of the write-capable tools registered by otalon-mcp
# (see ``otalon-mcp/src/otalon_mcp/mcp_tools.py``). A tool in this set is NEVER
# auto-replayed after a failure: re-executing e.g.
# ``training.retrain_classifier`` on a spurious -32601 would double-book
# a retrain (AI-04). The error is surfaced to the LLM instead.
_MUTATING_TOOL_NAMES: frozenset[str] = frozenset(
    {
        "training.retrain_boundaries",
        "training.retrain_classifier",
        "correct_rhythm_profile",
        "postgres.write_bounds",
        "postgres.expand_bounds",
        "postgres.replace_bounds",
        "postgres.add_anomaly_suppression",
        "postgres.remove_anomaly_suppression",
        "postgres.add_device",
        "postgres.update_device",
        "postgres.delete_device",
        "postgres.add_interface",
        "postgres.update_interface",
        "postgres.delete_interface",
        "pcap.flag_anomaly",
        "mitre.update_stix_data",
        "agent.classify_alert",
    }
)


class _ToolEntry:
    """Internal record mapping a public-facing tool name to its origin."""

    __slots__ = ("server_name", "url", "api_key", "raw_name", "openai_spec")

    def __init__(
        self,
        server_name: str,
        url: str,
        raw_name: str,
        openai_spec: dict[str, Any],
        api_key: str | None = None,
    ) -> None:
        self.server_name = server_name
        self.url = url
        self.api_key = api_key
        self.raw_name = raw_name
        self.openai_spec = openai_spec


class McpRegistry:
    """Registry of MCP tools across one or more streamable-http servers."""

    def __init__(
        self,
        servers: List[McpServerEntry],
        *,
        request_timeout_seconds: int = 60,
    ) -> None:
        if not servers:
            raise ValueError("McpRegistry: at least one server required")
        # Detect duplicate server names — they would make the collision-prefix
        # ambiguous.
        names = [s.name for s in servers]
        if len(set(names)) != len(names):
            raise ValueError(f"McpRegistry: duplicate server names: {names}")
        self._servers = servers
        self._timeout = request_timeout_seconds
        # public-facing name -> _ToolEntry. Populated on first list_openai_tools.
        self._tools: Optional[Dict[str, _ToolEntry]] = None
        self._lock = asyncio.Lock()

    # --- discovery ------------------------------------------------------

    async def _discover_server(self, server: McpServerEntry) -> Optional[List[Tuple[str, Any]]]:
        """Return ``(raw_name, mcp_tool)`` pairs for one server.

        Returns ``None`` when discovery failed at the transport/protocol
        level (connect refused, timeout, ``503`` during a startup race,
        malformed handshake). ``None`` is deliberately distinct from an
        empty list: an empty list means the server responded and
        legitimately advertises zero tools, whereas ``None`` means we
        have no authoritative view of this server and must not treat its
        absence as a valid empty catalogue.
        """
        try:
            async with asyncio.timeout(self._timeout):
                async with acquire_session(server.url, api_key=server.api_key) as session:
                    listing = await session.list_tools()
                    return [(t.name, t) for t in (listing.tools or [])]
        except Exception as exc:  # connect / network / protocol error
            logger.warning(
                "McpRegistry: discovery failed for server={} url={}: {}",
                server.name,
                server.url,
                exc,
            )
            return None

    async def _refresh(self) -> Optional[Dict[str, _ToolEntry]]:
        """Re-fetch all servers, build the unified table with collision logic.

        Returns ``None`` when **every** configured server failed
        discovery — the caller uses this to avoid caching a transient
        empty aggregate. Otherwise returns the unified table built from
        the servers that did respond (partial success keeps the tools it
        found; a lone healthy server with zero tools yields an empty
        but authoritative dict).
        """
        per_server: Dict[str, List[Tuple[str, Any]]] = {}
        any_server_responded = False
        for server in self._servers:
            discovered = await self._discover_server(server)
            if discovered is None:
                per_server[server.name] = []
            else:
                any_server_responded = True
                per_server[server.name] = discovered

        if not any_server_responded:
            logger.warning(
                "McpRegistry: discovery failed for all {} configured server(s); "
                "not caching the transient empty catalogue (will retry next call)",
                len(self._servers),
            )
            return None

        # Count raw-name occurrences across servers to decide prefixing.
        raw_counts: Dict[str, int] = {}
        for tools in per_server.values():
            for raw_name, _ in tools:
                raw_counts[raw_name] = raw_counts.get(raw_name, 0) + 1

        unified: Dict[str, _ToolEntry] = {}
        for server in self._servers:
            for raw_name, tool in per_server[server.name]:
                if raw_counts.get(raw_name, 0) > 1:
                    declared = f"{server.name}{PREFIX_SEP}{raw_name}"
                else:
                    declared = raw_name
                # The OpenAI tool-call protocol restricts ``function.name`` to
                # ``^[a-zA-Z0-9_-]+$`` so any dot-namespaced MCP name (e.g.
                # ``postgres.read_alarms``) must be sanitized before it is
                # advertised. The registry indexes its lookup table by the
                # sanitized name so the LLM-emitted ``call.function.name``
                # routes back to the original MCP raw name.
                public_name = sanitize_tool_name(declared)
                spec = mcp_tool_to_openai_function(tool, name_override=public_name)
                unified[public_name] = _ToolEntry(
                    server_name=server.name,
                    url=server.url,
                    raw_name=raw_name,
                    openai_spec=spec,
                    api_key=server.api_key,
                )

        logger.info(
            "McpRegistry: discovered {} tool(s) across {} server(s)",
            len(unified),
            len(self._servers),
        )
        return unified

    async def list_openai_tools(
        self,
        *,
        force_refresh: bool = False,
        allow_list: Optional[List[str]] = None,
    ) -> List[dict[str, Any]]:
        """Return the cached unified OpenAI tool list (lazily fetched).

        Allow-list semantics:

        - ``allow_list=None`` → no filtering (passthrough). Used by the
          jobs surface (which applies its own allow-list inside
          :class:`WorkerPool` via :func:`apply_allow_list`) AND by the
          chat surface in the production default per design.md § Q2
          ("no allow-list in chat (full passthrough)"). Restored to
          chat on 2026-05-19 after a regression where the chat config
          shipped ``allowed_tools=[]`` and silently disabled all
          MCP tools.
        - ``allow_list=[]`` → strict default-deny opt-in (Cluster d /
          B5). ZERO tools returned — operators set this explicitly
          when they want chat locked down.
        - ``allow_list=["a", "b"]`` → only tools whose public-facing
          name matches an entry are returned. Unknown names in the
          allow-list are silently ignored (operators may pre-allow
          tools that are not yet provisioned).
        """
        async with self._lock:
            if self._tools is None or force_refresh:
                refreshed = await self._refresh()
                # ``None`` == every configured server failed discovery
                # this cycle. Only commit a non-``None`` result to the
                # long-lived cache; a transient total failure must NOT
                # poison ``self._tools`` for the process lifetime — the
                # next call then retries. If a valid catalogue already
                # exists, keep it rather than blanking it.
                if refreshed is not None:
                    self._tools = refreshed
            # Snapshot the view to serve for THIS call: the committed
            # cache if present, else an empty catalogue for the transient
            # failure case (``self._tools`` stays ``None`` → retried next
            # call).
            tools = self._tools if self._tools is not None else {}
        if allow_list is None:
            return [entry.openai_spec for entry in tools.values()]
        # Sanitize the allow-list so operators can keep writing dotted MCP
        # names in config (``postgres.read_alarms``) — the registry handles
        # the translation to the sanitized public surface internally.
        allowed: Set[str] = {sanitize_tool_name(n) for n in allow_list}
        return [entry.openai_spec for name, entry in tools.items() if name in allowed]

    # --- tool execution ------------------------------------------------

    async def _invoke_once(self, entry: _ToolEntry, arguments: Dict[str, Any]) -> Any:
        """Open a fresh session, call one tool, close the session.

        Per spec ``chat--orchestration`` § "``call_tool`` opens a fresh
        session every invocation": no :class:`ClientSession` outlives
        this method. Both transport errors and protocol errors propagate
        unchanged so :meth:`call_tool` can decide whether to refresh the
        catalogue or re-raise to the caller.
        """
        async with asyncio.timeout(self._timeout):
            async with acquire_session(entry.url, api_key=entry.api_key) as session:
                return await session.call_tool(entry.raw_name, arguments=arguments)

    async def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        allow_list: Optional[List[str]] = None,
    ) -> str:
        """Execute a tool call against the originating MCP server.

        Implements the amended ``chat--orchestration`` spec:

        - Opens a fresh :class:`mcp.ClientSession` for the call and
          closes it before returning. No long-lived session state.
        - If the server signals the JSON-RPC method-not-found error code
          (``-32601``) AND the tool is not flagged mutating
          (:data:`_MUTATING_TOOL_NAMES`), the registry performs one full
          re-discovery cycle, replaces the cached catalogue, and retries
          the call exactly once against the refreshed catalogue. The
          retry result (success or error) is surfaced to the caller.
          Any other :class:`McpError` propagates unchanged (AI-04), and
          mutating tools are never auto-replayed.
        - Transport-level errors (timeout, ``ConnectionError``,
          generic ``Exception`` from the streamable-http layer) are
          re-raised unchanged. The cached catalogue is NOT invalidated
          — the failure is per-session, not per-catalogue. The chat
          agent loop catches and converts the exception into a ``tool``
          message for the LLM.

        Per Cluster d / B5 (chat tool allow-list, default-deny): when
        ``allow_list`` is provided, names not in the list raise
        :class:`PermissionError` BEFORE any MCP traffic.

        Returns the joined text content blocks. MCP servers may also
        return structured data; we stringify because the OpenAI tool
        protocol expects a string ``content``.
        """
        # Default-deny gate BEFORE any cache work / network I/O. The
        # allow-list is sanitized so operator-supplied dotted names
        # match the LLM-emitted (sanitized) ``name``.
        if allow_list is not None and name not in {sanitize_tool_name(n) for n in allow_list}:
            raise PermissionError(f"tool {name!r} is not in the caller's allow-list")
        # Ensure the lookup table is populated (transient discovery
        # session per server, then closed). If every configured server
        # failed discovery this cycle the catalogue stays uncached
        # (``self._tools is None``) — the tool is genuinely unavailable
        # right now, so surface a KeyError rather than dereferencing a
        # missing catalogue.
        await self.list_openai_tools()
        if self._tools is None:
            raise KeyError(f"Unknown MCP tool: {name!r} (tool discovery unavailable)")
        entry = self._tools.get(name)
        if entry is None:
            raise KeyError(f"Unknown MCP tool: {name!r}")

        # First attempt. Only the JSON-RPC method-not-found code
        # (-32601) on a non-mutating tool triggers the refresh-and-retry
        # recovery (AI-04); every other McpError propagates unchanged so
        # the agent loop surfaces it to the LLM. An isError=True result
        # is an ordinary tool failure: its payload is returned as-is
        # without invalidating the catalogue (AI-05).
        try:
            result = await self._invoke_once(entry, arguments)
            retryable = False
        except McpError as exc:
            code = getattr(getattr(exc, "error", None), "code", None)
            retryable = code == _METHOD_NOT_FOUND and entry.raw_name not in _MUTATING_TOOL_NAMES
            if not retryable:
                if code == _METHOD_NOT_FOUND:
                    logger.warning(
                        "McpRegistry: refusing to auto-replay mutating tool {!r} after -32601: {}",
                        entry.raw_name,
                        exc,
                    )
                raise
            logger.info(
                "McpRegistry: method-not-found for tool {!r}: {}; " "refreshing catalogue and retrying once",
                name,
                exc,
            )

        if retryable:
            # Full re-discovery cycle, then exactly one retry against
            # the refreshed catalogue.
            await self.list_openai_tools(force_refresh=True)
            entry = self._tools.get(name) if self._tools is not None else None
            if entry is None:
                raise KeyError(f"Unknown MCP tool after refresh: {name!r}")
            result = await self._invoke_once(entry, arguments)

        # Extract text content. MCP `CallToolResult.content` is a list
        # of ContentBlock; we only handle TextContent here, which is
        # the overwhelming common case for otalon-mcp tools.
        parts: List[str] = []
        for block in getattr(result, "content", []) or []:
            text = getattr(block, "text", None)
            if isinstance(text, str):
                parts.append(text)
        return "\n".join(parts) if parts else ""

    # --- inspection (used by tests) ------------------------------------

    def server_names(self) -> List[str]:
        return [s.name for s in self._servers]
