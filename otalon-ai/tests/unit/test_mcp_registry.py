"""Unit tests for the session-per-call policy of :class:`McpRegistry`.

These tests pin the behaviour added by OpenSpec change
``amend-mcp-registry-session-policy``:

(a) Every :meth:`McpRegistry.call_tool` invocation opens-and-closes its
    own ``ClientSession``. No session instance survives across calls.
(b) The cached tool catalogue survives transport disconnects. Only a
    server-side "tool not found" signal triggers a refresh-and-retry.
(c) A mid-call transport error propagates as an exception (the chat
    agent loop turns it into a ``tool`` message; the registry itself
    does not silently swallow the failure).

The schema-translation tests for the same registry live in
``test_mcp_schema_translation.py``; this file focuses purely on the
session lifecycle / cache invalidation contract.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from typing import Any, AsyncIterator, Dict, List, Optional

import pytest

from otalon_ai.mcp.client import ErrorData, McpError
from otalon_ai.mcp.registry import McpRegistry
from otalon_ai.settings import McpServerEntry

# --- fakes --------------------------------------------------------------


@dataclass
class _MockMcpTool:
    name: str
    description: Optional[str] = ""
    inputSchema: Any = field(default_factory=lambda: {"type": "object"})  # noqa: N815


@dataclass
class _Block:
    text: str


@dataclass
class _Result:
    content: List[_Block]
    isError: bool = False


class _CountingSession:
    """Fake MCP session that records how many times it was used.

    The counter lives on the shared :class:`_SessionLedger` so multiple
    sessions created during a single test contribute to a single
    enter/exit pair count.
    """

    def __init__(self, ledger: "_SessionLedger", tools: List[_MockMcpTool], behaviour: "_CallBehaviour") -> None:
        self._ledger = ledger
        self._tools = tools
        self._behaviour = behaviour

    async def __aenter__(self) -> "_CountingSession":
        self._ledger.enters += 1
        self._ledger.currently_open += 1
        return self

    async def __aexit__(self, *exc: Any) -> None:  # noqa: D401
        self._ledger.exits += 1
        self._ledger.currently_open -= 1

    async def list_tools(self) -> Any:
        class _Listing:
            def __init__(self, tools: List[_MockMcpTool]) -> None:
                self.tools = tools

        return _Listing(self._tools)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return self._behaviour.next_response(name, arguments)


@dataclass
class _SessionLedger:
    """Counts session enter/exit events to prove session-per-call."""

    enters: int = 0
    exits: int = 0
    currently_open: int = 0


@dataclass
class _CallBehaviour:
    """Programmable response sequence for ``session.call_tool``."""

    responses: List[Any] = field(default_factory=list)
    calls: int = 0

    def next_response(self, name: str, arguments: Dict[str, Any]) -> Any:
        idx = self.calls
        self.calls += 1
        if idx >= len(self.responses):
            return _Result(content=[_Block(text=f"called {name} args={arguments}")])
        item = self.responses[idx]
        if isinstance(item, BaseException):
            raise item
        if callable(item):
            return item(name, arguments)
        return item


def _patch_acquire(
    monkeypatch: pytest.MonkeyPatch,
    *,
    ledger: _SessionLedger,
    tools_by_url: Dict[str, List[_MockMcpTool]],
    behaviour_by_url: Optional[Dict[str, _CallBehaviour]] = None,
) -> None:
    """Replace ``acquire_session`` with a counting fake."""
    behaviour_by_url = behaviour_by_url or {}

    @asynccontextmanager
    async def fake_acquire(url: str, *, api_key: object = None) -> AsyncIterator[_CountingSession]:
        tools = tools_by_url.get(url)
        if tools is None:
            raise ConnectionError(f"no fake configured for {url}")
        behaviour = behaviour_by_url.get(url, _CallBehaviour())
        session = _CountingSession(ledger, tools, behaviour)
        async with session as opened:
            yield opened

    monkeypatch.setattr("otalon_ai.mcp.registry.acquire_session", fake_acquire)


@pytest.fixture
def single_server() -> List[McpServerEntry]:
    return [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")]


# --- (a) session-per-call lifecycle ------------------------------------


async def test_call_tool_opens_and_closes_session_each_call(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """Three sequential ``call_tool`` invocations SHALL result in three
    distinct enter/exit pairs and zero open sessions between calls.
    """
    ledger = _SessionLedger()
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ping")]},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    # Prime the catalogue. Discovery opens-and-closes its own session,
    # giving us a known starting baseline.
    await reg.list_openai_tools()
    baseline_enters = ledger.enters
    baseline_exits = ledger.exits
    assert baseline_enters == baseline_exits == 1
    assert ledger.currently_open == 0

    for _ in range(3):
        await reg.call_tool("ping", {})
        # After every call, NO session SHALL remain open.
        assert ledger.currently_open == 0

    assert ledger.enters - baseline_enters == 3
    assert ledger.exits - baseline_exits == 3


async def test_registry_holds_no_long_lived_session_attribute(
    single_server: List[McpServerEntry],
) -> None:
    """Regression guard: the registry SHALL NOT expose any ``_session``
    style attribute that could outlive a single :meth:`call_tool` call.

    Per the amended spec, long-lived ``ClientSession``s are explicitly
    forbidden. We assert this structurally so an accidental
    reintroduction during a future refactor fails this test before it
    reaches production.
    """
    reg = McpRegistry(single_server, request_timeout_seconds=2)
    long_lived_session_attrs = [
        name for name in vars(reg) if "session" in name.lower() and not name.startswith("_servers")
    ]
    assert long_lived_session_attrs == [], f"registry exposes long-lived session attributes: {long_lived_session_attrs}"


# --- (b) catalogue cache survives transport disconnects ----------------


async def test_catalogue_cache_survives_transport_disconnect(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """A transport-level failure during ``call_tool`` SHALL NOT invalidate
    the cached tool catalogue. The next :meth:`list_openai_tools` call
    SHALL serve the cached entries without re-fetching.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(responses=[ConnectionError("EOF mid-call")])
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ping")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    # Prime the catalogue.
    tools_before = await reg.list_openai_tools()
    assert [t["function"]["name"] for t in tools_before] == ["ping"]
    discovery_enters_after_prime = ledger.enters
    assert discovery_enters_after_prime == 1

    # Mid-call transport error.
    with pytest.raises(ConnectionError):
        await reg.call_tool("ping", {})

    # The catalogue cache MUST still be valid: a subsequent
    # ``list_openai_tools()`` call returns the same entries without
    # opening a new discovery session.
    enters_before_second_listing = ledger.enters
    tools_after = await reg.list_openai_tools()
    enters_after_second_listing = ledger.enters

    assert [t["function"]["name"] for t in tools_after] == ["ping"]
    assert (
        enters_after_second_listing == enters_before_second_listing
    ), "transport disconnect must NOT trigger a catalogue re-fetch"


# --- (c) mid-call transport error surfaces as exception ----------------


async def test_mid_call_transport_error_propagates_as_exception(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """A transport error during ``call_tool`` SHALL propagate as an
    exception (the orchestration loop turns it into a tool-result
    message). The registry SHALL NOT silently return an empty string
    or hide the failure.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(responses=[ConnectionError("socket closed")])
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ping")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    with pytest.raises(ConnectionError, match="socket closed"):
        await reg.call_tool("ping", {})

    # And no session is left open after the failure unwinds.
    assert ledger.currently_open == 0
    assert ledger.enters == ledger.exits


# --- (bonus) refresh-and-retry on server-side "tool not found" ---------
#
# AI-05 amended this contract: the ``isError=True`` + "not found" text
# heuristic re-executed tools on ORDINARY failures (e.g. MITRE answering
# "technique not found"). Only the JSON-RPC -32601 code now triggers the
# recovery (see ``test_iserror_not_found_text_does_not_trigger_refresh_and_retry``
# and the AI-04 block below).


async def test_mcp_error_triggers_refresh_and_retry(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """``McpError`` raised during ``call_tool`` SHALL also trigger a
    single refresh-and-retry — the same recovery path as the
    ``isError=True`` text marker.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(
        responses=[
            McpError(ErrorData(code=-32601, message="method not found")),
            _Result(content=[_Block(text="recovered")]),
        ]
    )
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ping")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    out = await reg.call_tool("ping", {})

    assert out == "recovered"
    assert behaviour.calls == 2


# --- (regression) transient discovery failure must not poison the cache -


class _FlakyAcquire:
    """Programmable ``acquire_session`` replacement keyed on attempt count.

    The first ``fail_first`` discovery attempts against a URL raise a
    transport error (server still starting → 503 / connection refused);
    every attempt afterwards yields a healthy session exposing ``tools``.
    """

    def __init__(
        self,
        ledger: "_SessionLedger",
        tools: List[_MockMcpTool],
        *,
        fail_first: int,
    ) -> None:
        self._ledger = ledger
        self._tools = tools
        self._fail_first = fail_first
        self.attempts = 0

    @asynccontextmanager
    async def __call__(self, url: str, *, api_key: object = None) -> AsyncIterator[_CountingSession]:
        self.attempts += 1
        if self.attempts <= self._fail_first:
            raise ConnectionError("503 Service Unavailable during startup race")
        session = _CountingSession(self._ledger, self._tools, _CallBehaviour())
        async with session as opened:
            yield opened


async def test_transient_discovery_failure_does_not_poison_cache(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """Reproduces the P8N Phase-7 false-success bug.

    The very first discovery attempt fails (all configured servers
    unreachable during the container startup race), producing a
    zero-tool aggregate. Under the old code that empty result was cached
    for the process lifetime and every later chat turn saw NO tools —
    the LLM then hallucinated a fake ``job_ref``. The registry MUST
    instead treat a total discovery failure as *not cached* and retry on
    the next :meth:`list_openai_tools` call, returning the real tool once
    the server is healthy.
    """
    ledger = _SessionLedger()
    flaky = _FlakyAcquire(ledger, [_MockMcpTool(name="training_retrain_boundaries")], fail_first=1)
    monkeypatch.setattr("otalon_ai.mcp.registry.acquire_session", flaky)

    reg = McpRegistry(single_server, request_timeout_seconds=2)

    # First turn: server still coming up → discovery fails for every
    # configured server → empty aggregate. This MUST NOT be cached.
    first = await reg.list_openai_tools()
    assert first == [], "transient failure should surface as an empty list this turn"

    # Second turn: server healthy. A retry MUST happen and return the
    # real tool instead of serving the poisoned empty cache forever.
    second = await reg.list_openai_tools()
    assert [t["function"]["name"] for t in second] == [
        "training_retrain_boundaries"
    ], "empty catalogue from a transient failure must be retried, not cached"


async def test_healthy_empty_catalogue_is_cached(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """A legitimately healthy server advertising zero tools is a valid
    empty catalogue and SHALL be cached — no repeated discovery.
    """
    ledger = _SessionLedger()
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": []},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    first = await reg.list_openai_tools()
    enters_after_first = ledger.enters
    second = await reg.list_openai_tools()
    enters_after_second = ledger.enters

    assert first == []
    assert second == []
    assert enters_after_first == 1, "healthy discovery opens exactly one session"
    assert enters_after_second == enters_after_first, "healthy empty catalogue must be cached, not re-fetched"


async def test_successful_discovery_is_cached_normally(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """After a successful discovery the catalogue is cached: a second
    :meth:`list_openai_tools` call does NOT open a new discovery session.
    """
    ledger = _SessionLedger()
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ping")]},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    await reg.list_openai_tools()
    enters_after_first = ledger.enters
    await reg.list_openai_tools()

    assert enters_after_first == 1
    assert ledger.enters == enters_after_first, "successful discovery must cache and not re-fetch"


async def test_partial_multi_server_success_retains_discovered_tools(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """When one of several servers fails discovery but another succeeds,
    the successfully discovered tools SHALL be retained and cached — a
    single failing peer must not discard a healthy peer's catalogue.
    """
    servers = [
        McpServerEntry(name="up", url="http://up:9000/mcp"),
        McpServerEntry(name="down", url="http://down:9000/mcp"),
    ]
    ledger = _SessionLedger()

    @asynccontextmanager
    async def fake_acquire(url: str, *, api_key: object = None) -> AsyncIterator[_CountingSession]:
        if "down" in url:
            raise ConnectionError("peer down")
        session = _CountingSession(ledger, [_MockMcpTool(name="ping")], _CallBehaviour())
        async with session as opened:
            yield opened

    monkeypatch.setattr("otalon_ai.mcp.registry.acquire_session", fake_acquire)

    reg = McpRegistry(servers, request_timeout_seconds=2)
    first = await reg.list_openai_tools()
    enters_after_first = ledger.enters
    second = await reg.list_openai_tools()

    assert [t["function"]["name"] for t in first] == ["ping"]
    assert [t["function"]["name"] for t in second] == ["ping"]
    assert ledger.enters == enters_after_first, "partial success must be cached, not re-discovered"


# --- AI-04: retry only on JSON-RPC -32601, never for mutating tools ----


async def test_non_method_not_found_mcp_error_does_not_retry(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """AI-04: only the JSON-RPC method-not-found code (-32601) may trigger
    the refresh-and-retry. Any other ``McpError`` (here: -32602 invalid
    params) MUST propagate unchanged with NO catalogue refresh and NO
    re-execution of the call.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(
        responses=[
            McpError(ErrorData(code=-32602, message="invalid params")),
            _Result(content=[_Block(text="should-never-run")]),
        ]
    )
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ping")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    with pytest.raises(McpError):
        await reg.call_tool("ping", {})

    assert behaviour.calls == 1, "non-(-32601) McpError must NOT re-execute the tool"


async def test_method_not_found_never_replays_mutating_tool(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """AI-04: even a genuine -32601 must NOT auto-replay a tool flagged as
    mutating — a retrain double-booking is worse than a surfaced error.
    The error propagates to the caller (the agent loop surfaces it to the
    LLM) after exactly one execution.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(
        responses=[
            McpError(ErrorData(code=-32601, message="method not found")),
            _Result(content=[_Block(text="double-booked")]),
        ]
    )
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="training.retrain_classifier")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    with pytest.raises(McpError):
        await reg.call_tool("training_retrain_classifier", {})

    assert behaviour.calls == 1, "mutating tools must NEVER be auto-replayed"


async def test_method_not_found_retries_read_only_tool(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """AI-04 positive control: -32601 on a non-mutating tool still gets the
    single refresh-and-retry recovery.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(
        responses=[
            McpError(ErrorData(code=-32601, message="method not found")),
            _Result(content=[_Block(text="recovered")]),
        ]
    )
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="postgres.read_alarms")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    out = await reg.call_tool("postgres_read_alarms", {})

    assert out == "recovered"
    assert behaviour.calls == 2


# --- AI-05: no substring heuristic on ordinary tool-failure text -------


async def test_iserror_not_found_text_does_not_trigger_refresh_and_retry(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    """AI-05: a ``CallToolResult`` with ``isError=True`` whose text merely
    CONTAINS "not found" (an ordinary tool failure, e.g. MITRE reporting
    'technique not found') MUST NOT trigger catalogue invalidation or a
    blind re-execution. The error payload is surfaced to the caller as-is
    after exactly one call.
    """
    ledger = _SessionLedger()
    behaviour = _CallBehaviour(
        responses=[
            _Result(content=[_Block(text="technique T9999 not found")], isError=True),
            _Result(content=[_Block(text="should-never-run")]),
        ]
    )
    _patch_acquire(
        monkeypatch,
        ledger=ledger,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="mitre.get_technique_by_id")]},
        behaviour_by_url={"http://test:9000/mcp": behaviour},
    )

    reg = McpRegistry(single_server, request_timeout_seconds=2)
    await reg.list_openai_tools()
    enters_after_prime = ledger.enters

    out = await reg.call_tool("mitre_get_technique_by_id", {})

    assert "not found" in out, "the tool error payload must surface to the caller"
    assert behaviour.calls == 1, "isError text must NOT re-execute the tool"
    # Session-per-call: exactly ONE additional session for the invocation
    # itself. A refresh-and-retry would open two more (re-discovery +
    # retry invocation).
    assert ledger.enters == enters_after_prime + 1, "isError text must NOT invalidate the catalogue"
