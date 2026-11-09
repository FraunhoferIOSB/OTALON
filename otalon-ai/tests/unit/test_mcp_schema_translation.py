"""Unit tests for :mod:`src.mcp.schema` and :mod:`src.mcp.registry`.

The MCP discovery and ``session.call_tool`` paths are mocked because they
require a live MCP server. The schema-translation helpers are pure
functions and need no mocking.

Covers the spec requirements:

- Single MCP server, no collisions → unprefixed names.
- Two servers with a colliding tool name → both renamed ``<server>__name``.
- MCP server unreachable at startup → empty cache, retry on next call.
- ``description: null`` → empty string.
- Missing ``type`` on object schema → defaults to ``"object"``.
- Allow-list filtering.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import pytest

from otalon_ai.mcp.registry import PREFIX_SEP, McpRegistry
from otalon_ai.mcp.schema import (
    apply_allow_list,
    build_name_mapping,
    mcp_tool_to_openai_function,
    sanitize_schema,
    sanitize_tool_name,
)
from otalon_ai.settings import McpServerEntry

OPENAI_TOOL_NAME_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

# --- schema helpers -----------------------------------------------------


@dataclass
class _MockMcpTool:
    name: str
    description: Optional[str] = ""
    inputSchema: Any = None  # noqa: N815 — mirrors MCP SDK casing


def test_sanitize_schema_replaces_null_description() -> None:
    schema = {"description": None, "type": "object", "properties": {}}
    cleaned = sanitize_schema(schema)
    assert cleaned["description"] == ""
    assert cleaned["type"] == "object"


def test_sanitize_schema_drops_other_nulls() -> None:
    schema = {"type": "object", "title": None, "properties": {"x": {"type": "string"}}}
    cleaned = sanitize_schema(schema)
    assert "title" not in cleaned
    assert cleaned["properties"]["x"]["type"] == "string"


def test_sanitize_schema_recurses_into_lists() -> None:
    schema = {"items": [{"description": None, "type": "string"}]}
    cleaned = sanitize_schema(schema)
    assert cleaned["items"][0]["description"] == ""


def test_sanitize_schema_passthrough_primitives() -> None:
    assert sanitize_schema(42) == 42
    assert sanitize_schema("hello") == "hello"
    assert sanitize_schema(None) is None


def test_mcp_tool_to_openai_function_defaults_object_type() -> None:
    tool = _MockMcpTool(name="ping", description="echo", inputSchema={"properties": {}})
    spec = mcp_tool_to_openai_function(tool)
    assert spec["type"] == "function"
    assert spec["function"]["name"] == "ping"
    assert spec["function"]["description"] == "echo"
    assert spec["function"]["parameters"]["type"] == "object"


def test_mcp_tool_to_openai_function_uses_name_override() -> None:
    tool = _MockMcpTool(name="ping", description=None, inputSchema={"type": "object"})
    spec = mcp_tool_to_openai_function(tool, name_override="serverA__ping")
    assert spec["function"]["name"] == "serverA__ping"
    assert spec["function"]["description"] == ""


def test_apply_allow_list_filters() -> None:
    tools = [_MockMcpTool(name="a"), _MockMcpTool(name="b"), _MockMcpTool(name="c")]
    filtered, unknown = apply_allow_list(tools, ["a", "c", "x.y.unknown"])
    assert [t.name for t in filtered] == ["a", "c"]
    assert unknown == ["b"]


# --- McpRegistry -------------------------------------------------------


class _FakeListing:
    def __init__(self, tools: List[_MockMcpTool]) -> None:
        self.tools = tools


class _FakeSession:
    def __init__(self, tools: List[_MockMcpTool], call_result_text: str = "ok") -> None:
        self._tools = tools
        self._call_result_text = call_result_text

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:  # noqa: D401
        return None

    async def list_tools(self) -> _FakeListing:
        return _FakeListing(self._tools)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        class _Block:
            text = f"called {name} with {arguments}"

        class _Result:
            content = [_Block()]

        return _Result()


def _patch_acquire(monkeypatch: pytest.MonkeyPatch, *, tools_by_url: Dict[str, List[_MockMcpTool]]) -> None:
    """Replace ``acquire_session`` to yield fake sessions per URL."""
    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def fake_acquire(url: str, *, api_key: object = None):  # type: ignore[no-untyped-def]
        tools = tools_by_url.get(url)
        if tools is None:
            raise ConnectionError(f"no fake for {url}")
        async with _FakeSession(tools) as session:
            yield session

    monkeypatch.setattr("otalon_ai.mcp.registry.acquire_session", fake_acquire)


@pytest.fixture
def single_server() -> List[McpServerEntry]:
    return [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")]


@pytest.fixture
def two_servers() -> List[McpServerEntry]:
    return [
        McpServerEntry(name="alpha", url="http://alpha/mcp"),
        McpServerEntry(name="beta", url="http://beta/mcp"),
    ]


async def test_single_server_no_collision(monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]) -> None:
    _patch_acquire(
        monkeypatch,
        tools_by_url={
            "http://test:9000/mcp": [_MockMcpTool(name="postgres.read_alarms", inputSchema={"type": "object"})]
        },
    )
    reg = McpRegistry(single_server, request_timeout_seconds=2)
    tools = await reg.list_openai_tools()
    names = [t["function"]["name"] for t in tools]
    # Dotted MCP names are sanitized so the advertised OpenAI tool name
    # matches the ``^[a-zA-Z0-9_-]+$`` pattern.
    assert names == ["postgres_read_alarms"]
    assert all(OPENAI_TOOL_NAME_RE.fullmatch(n) for n in names)


async def test_two_servers_colliding_name_prefixed(
    monkeypatch: pytest.MonkeyPatch, two_servers: List[McpServerEntry]
) -> None:
    _patch_acquire(
        monkeypatch,
        tools_by_url={
            "http://alpha/mcp": [_MockMcpTool(name="core.ping", inputSchema={"type": "object"})],
            "http://beta/mcp": [_MockMcpTool(name="core.ping", inputSchema={"type": "object"})],
        },
    )
    reg = McpRegistry(two_servers, request_timeout_seconds=2)
    tools = await reg.list_openai_tools()
    names = sorted(t["function"]["name"] for t in tools)
    # ``alpha__core.ping`` would violate the OpenAI pattern → also sanitized.
    assert names == [
        f"alpha{PREFIX_SEP}core_ping",
        f"beta{PREFIX_SEP}core_ping",
    ]
    assert all(OPENAI_TOOL_NAME_RE.fullmatch(n) for n in names)


async def test_unreachable_server_yields_empty_then_retries(
    monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]
) -> None:
    # First call: no fakes registered → ConnectionError → empty cache.
    _patch_acquire(monkeypatch, tools_by_url={})
    reg = McpRegistry(single_server, request_timeout_seconds=2)
    tools = await reg.list_openai_tools()
    assert tools == []

    # Recovery: re-patch with real tools and force refresh — registry must
    # re-fetch and now return the tool list.
    _patch_acquire(
        monkeypatch,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="ok.tool", inputSchema={"type": "object"})]},
    )
    tools = await reg.list_openai_tools(force_refresh=True)
    assert [t["function"]["name"] for t in tools] == ["ok_tool"]


async def test_call_tool_routes_to_origin_server(
    monkeypatch: pytest.MonkeyPatch, two_servers: List[McpServerEntry]
) -> None:
    _patch_acquire(
        monkeypatch,
        tools_by_url={
            "http://alpha/mcp": [_MockMcpTool(name="alpha.unique", inputSchema={"type": "object"})],
            "http://beta/mcp": [_MockMcpTool(name="beta.unique", inputSchema={"type": "object"})],
        },
    )
    reg = McpRegistry(two_servers, request_timeout_seconds=2)
    # The LLM emits the SANITIZED tool name; the registry must route the
    # call to the originating MCP server using the RAW (dotted) name.
    out = await reg.call_tool("alpha_unique", {"x": 1})
    # The fake session echoes the raw name back into the result text so we
    # can prove the registry resolved sanitized → raw correctly.
    assert "alpha.unique" in out
    assert "{'x': 1}" in out


async def test_call_tool_unknown_raises(monkeypatch: pytest.MonkeyPatch, single_server: List[McpServerEntry]) -> None:
    _patch_acquire(
        monkeypatch,
        tools_by_url={"http://test:9000/mcp": [_MockMcpTool(name="known", inputSchema={"type": "object"})]},
    )
    reg = McpRegistry(single_server, request_timeout_seconds=2)
    with pytest.raises(KeyError):
        await reg.call_tool("does.not.exist", {})


def test_registry_rejects_empty_servers() -> None:
    with pytest.raises(ValueError):
        McpRegistry([], request_timeout_seconds=2)


def test_registry_rejects_duplicate_server_names() -> None:
    with pytest.raises(ValueError):
        McpRegistry(
            [
                McpServerEntry(name="x", url="http://1"),
                McpServerEntry(name="x", url="http://2"),
            ]
        )


# --- sanitize_tool_name + build_name_mapping --------------------------


def test_sanitize_tool_name_replaces_dots() -> None:
    assert sanitize_tool_name("postgres.read_alarms") == "postgres_read_alarms"
    assert sanitize_tool_name("mitre.get_technique_by_id") == "mitre_get_technique_by_id"
    assert sanitize_tool_name("influx.list_recent_time_series_ids") == "influx_list_recent_time_series_ids"


def test_sanitize_tool_name_passthrough_for_already_clean() -> None:
    assert sanitize_tool_name("already_clean-name") == "already_clean-name"
    assert sanitize_tool_name("ping") == "ping"


def test_sanitize_tool_name_replaces_arbitrary_illegal_chars() -> None:
    # Whitespace, slashes, colons, parens — all illegal under the OpenAI pattern.
    assert sanitize_tool_name("a/b:c d(e)") == "a_b_c_d_e_"
    assert OPENAI_TOOL_NAME_RE.fullmatch(sanitize_tool_name("a/b:c d(e)"))


def test_sanitize_tool_name_handles_empty_string() -> None:
    assert sanitize_tool_name("") == ""


def test_tool_definitions_from_mcp_match_openai_pattern() -> None:
    """All produced tool definitions SHALL match ``^[a-zA-Z0-9_-]+$``.

    Mirrors the production MCP tool surface (dotted namespacing) so we
    notice immediately if any new translation path leaks a non-conformant
    name back into the OpenAI request body.
    """
    raw_names = [
        "postgres.read_alarms",
        "postgres.read_alarm_details",
        "influx.list_recent_time_series_ids",
        "mitre.get_technique_by_id",
        "pcap.get_chunks_by_alarm_id",
    ]
    tools = [_MockMcpTool(name=n, inputSchema={"type": "object"}) for n in raw_names]
    specs = [mcp_tool_to_openai_function(t) for t in tools]
    names = [s["function"]["name"] for s in specs]
    assert all(OPENAI_TOOL_NAME_RE.fullmatch(n) for n in names), names


def test_build_name_mapping_round_trip() -> None:
    """``sanitized → raw`` resolves back to the original MCP tool name."""
    raw_names = [
        "postgres.read_alarms",
        "influx.list_time_series",
        "mitre.get_technique_by_id",
        "already_clean",
    ]
    sanitized_to_raw, raw_to_sanitized = build_name_mapping(raw_names)
    for raw in raw_names:
        sanitized = raw_to_sanitized[raw]
        assert OPENAI_TOOL_NAME_RE.fullmatch(sanitized), sanitized
        assert sanitized_to_raw[sanitized] == raw


def test_build_name_mapping_detects_collision() -> None:
    """Two distinct raw names that share a sanitized name SHALL raise."""
    with pytest.raises(ValueError, match="sanitize collision"):
        build_name_mapping(["a.b", "a_b"])


def test_tool_result_message_name_field_is_sanitized() -> None:
    """If a caller chooses to set a ``name`` on a tool-result message,
    sanitize it through :func:`sanitize_tool_name` first.

    This is a documentation/regression test: it pins the contract that
    any ``name`` field flowing to the OpenAI Responses-API (which LiteLLM
    forwards for ``gpt-5.*``) MUST be sanitized before transit.
    """
    raw = "postgres.read_alarms"
    tool_result_msg = {
        "role": "tool",
        "tool_call_id": "call_abc",
        "name": sanitize_tool_name(raw),
        "content": "ok",
    }
    assert OPENAI_TOOL_NAME_RE.fullmatch(tool_result_msg["name"])
    assert tool_result_msg["name"] == "postgres_read_alarms"
