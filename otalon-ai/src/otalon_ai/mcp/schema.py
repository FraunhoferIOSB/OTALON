"""MCP JSON-schema → OpenAI tool-spec translation.

Extracted from the inherited ``otalon_ai/mcp/client.py`` (which re-exports
these helpers as a backward-compat shim) so the chat and jobs surfaces both
consume the same canonical translation.

Per design.md § Decision 5:

- The MCP tool's ``inputSchema`` is dropped verbatim into ``function.parameters``.
- The tool description is reused as the OpenAI ``function.description``.
- ``description: null`` is normalised to an empty string because some local
  LLM endpoints (LM Studio Jinja templates etc.) reject ``null``.

Tool-name sanitization (post-cut E2E fix, 2026-05-18):

The OpenAI Responses-API (which LiteLLM forwards to for ``gpt-5.4``,
``gpt-5.5-2`` etc.) requires every ``name`` field on input items and tool
definitions to match ``^[a-zA-Z0-9_-]+$``. MCP servers in this workspace
expose dotted, namespaced names (``postgres.read_alarms``,
``influx.list_time_series``, ``mitre.get_technique_by_id`` …) which break
the pattern. :func:`sanitize_tool_name` provides the canonical one-way
substitution (``.`` → ``_``, every other illegal codepoint → ``_``).
Round-tripping a sanitized name back to the original MCP tool name is the
caller's responsibility — for jobs use :func:`build_name_mapping`; for chat
the :class:`McpRegistry` keeps its own mapping table.
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Set, Tuple

_SANITIZE_PATTERN = re.compile(r"[^a-zA-Z0-9_-]")


def sanitize_tool_name(name: str) -> str:
    """Make ``name`` safe for the OpenAI ``^[a-zA-Z0-9_-]+$`` pattern.

    Every codepoint outside ``[a-zA-Z0-9_-]`` is replaced by an underscore.
    The replacement is deterministic so the same input always produces the
    same output (callers can build a reverse lookup map safely).

    Examples:
        ``postgres.read_alarms`` → ``postgres_read_alarms``
        ``mitre.get_technique_by_id`` → ``mitre_get_technique_by_id``
        ``already_clean-name`` → ``already_clean-name``
    """
    if not name:
        return name
    return _SANITIZE_PATTERN.sub("_", name)


def build_name_mapping(raw_names: Iterable[str]) -> Tuple[Dict[str, str], Dict[str, str]]:
    """Build ``(sanitized→raw, raw→sanitized)`` maps for a set of tool names.

    Raises :class:`ValueError` if two distinct raw names collide on the
    same sanitized name (e.g. ``a.b`` and ``a_b``). At the deployment scale
    documented in design.md no MCP server exposes names that collide under
    the dot→underscore rule, so the check is cheap and surfaces drift
    early.
    """
    sanitized_to_raw: Dict[str, str] = {}
    raw_to_sanitized: Dict[str, str] = {}
    for raw in raw_names:
        sanitized = sanitize_tool_name(raw)
        existing = sanitized_to_raw.get(sanitized)
        if existing is not None and existing != raw:
            raise ValueError(f"sanitize collision: {raw!r} and {existing!r} both map to {sanitized!r}")
        sanitized_to_raw[sanitized] = raw
        raw_to_sanitized[raw] = sanitized
    return sanitized_to_raw, raw_to_sanitized


def sanitize_schema(schema: Any) -> Any:
    """Recursively normalise a JSON schema for LLM consumption.

    - replace ``description: null`` with ``description: ""``
    - drop other ``null`` values from object schemas
    - leave lists and primitive values untouched

    The function is total: any input shape returns. Non-dict / non-list
    values are returned as-is.
    """
    if isinstance(schema, dict):
        cleaned: dict[str, Any] = {}
        for key, value in schema.items():
            if value is None and key == "description":
                cleaned[key] = ""
            elif value is None:
                continue
            else:
                cleaned[key] = sanitize_schema(value)
        return cleaned
    if isinstance(schema, list):
        return [sanitize_schema(item) for item in schema]
    return schema


def mcp_tool_to_openai_function(tool: Any, *, name_override: str | None = None) -> dict[str, Any]:
    """Convert one MCP ``Tool`` to OpenAI's function-call schema.

    ``name_override`` is used by the registry to prefix names when the
    same tool name appears on multiple MCP servers (collision handling).

    The ``function.name`` is sanitized through :func:`sanitize_tool_name`
    so the resulting tool definition always matches the OpenAI
    ``^[a-zA-Z0-9_-]+$`` pattern. Callers who need to map the LLM-emitted
    tool name back to the original MCP tool name should keep their own
    mapping (or use :func:`build_name_mapping`).
    """
    schema: Any = tool.inputSchema if hasattr(tool, "inputSchema") else {}
    if isinstance(schema, dict) and "type" not in schema:
        schema["type"] = "object"
    schema = sanitize_schema(schema)
    declared_name = name_override or tool.name
    return {
        "type": "function",
        "function": {
            "name": sanitize_tool_name(declared_name),
            "description": (getattr(tool, "description", None) or ""),
            "parameters": schema,
        },
    }


def apply_allow_list(
    tools: Iterable[Any],
    allow_list: Iterable[str],
) -> Tuple[List[Any], List[str]]:
    """Filter MCP tools to those in ``allow_list``.

    Returns ``(filtered_tools, unknown_names)`` where ``unknown_names`` are
    tool names the MCP server exposed but the allow-list does not include.
    Callers should log a warning once per session for unknown_names.
    """
    allow: Set[str] = set(allow_list)
    filtered: List[Any] = []
    unknown: List[str] = []
    for tool in tools:
        if tool.name in allow:
            filtered.append(tool)
        else:
            unknown.append(tool.name)
    return filtered, unknown
