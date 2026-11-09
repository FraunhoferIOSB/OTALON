"""Regression tests for the runtime-retrain tool visibility in otalon-ai.

The ``runtime-retraining-control-plane`` change makes retraining a
*chat-triggered, in-process* operator action: a chat-triggered MCP tool
orchestrates the retrain, otalon-clas trains in-process and publishes
atomically, and the terminal job state is ``succeeded`` or ``failed``
(there is NO container restart and no ``live`` mode-restore step). Three
runtime-retrain tools exist — ``training.retrain_boundaries``,
``training.retrain_classifier`` and ``training.get_retrain_status`` — and
two deliberate choices the tests below pin down:

1. **Chat MUST see all three.** The chat surface uses a curated
   allow-list (``chat.allowed_tools`` in the production config). Because
   runtime retraining is a spec-required chat-operator action, all three
   training tools MUST appear in that allow-list; otherwise the chat LLM
   never sees them and the operator cannot trigger a retrain from chat
   (bug AI-014). The classifier tool in particular MUST be reachable so
   the mandated operator Chat path can invoke ``retrain_classifier``.
   Autonomous misuse is prevented by the tool's own confirmation-gated
   system prompt and the api-side single-flight lock, not by hiding the
   tool from chat.
2. **Jobs MUST NOT see them.** Runtime retraining is an operator-driven,
   chat-triggered action. The classification jobs surface is an
   autonomous worker that runs without operator review; exposing
   ``training.*`` to it would let a subagent trigger a retrain of
   otalon-clas without operator confirmation. The production
   ``jobs.allowed_tools`` allow-list deliberately omits the whole
   ``training.*`` namespace.
"""

from __future__ import annotations

import json
from contextlib import asynccontextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, AsyncIterator, Dict, List, Optional, cast

import pytest

from otalon_ai.mcp.registry import McpRegistry
from otalon_ai.settings import McpServerEntry

# Server-side (dotted) names the otalon-mcp server registers for the
# runtime-retrain feature (see otalon-mcp/src/mcp_tools.py:1695).
_TRAINING_RAW_NAMES = (
    "training.retrain_boundaries",
    "training.retrain_classifier",
    "training.get_retrain_status",
)
# Sanitized (OpenAI-safe) public names the registry advertises + routes by
# (dots → underscores; see src/mcp/schema.py:sanitize_tool_name).
_TRAINING_PUBLIC_NAMES = (
    "training_retrain_boundaries",
    "training_retrain_classifier",
    "training_get_retrain_status",
)


def _load_production_config() -> dict[str, Any]:
    """Load ``otalon-ai/config/config.json`` as a dict.

    Returns:
        The parsed configuration dictionary.
    """
    here = Path(__file__).resolve()
    config_path = here.parents[2] / "config" / "config.json"
    assert config_path.exists(), f"production config not found at {config_path}"
    return cast(dict[str, Any], json.loads(config_path.read_text(encoding="utf-8")))


def test_chat_allow_list_includes_training_tools() -> None:
    """Chat's curated allow-list MUST include all three runtime-retrain tools.

    Runtime retraining is a chat-triggered operator action, so
    ``training.retrain_boundaries``, ``training.retrain_classifier`` and
    ``training.get_retrain_status`` MUST all appear in the chat allow-list.
    This is the AI-014 regression guard: a curated allow-list that omits
    any ``training.*`` tool silently makes that chat-triggered retrain
    unreachable — the classifier tool being the gap this test now closes.
    """
    cfg = _load_production_config()
    chat_cfg = cfg.get("chat", {})
    allowed = chat_cfg.get("allowed_tools")
    assert isinstance(allowed, list), (
        "chat.allowed_tools is expected to be a curated list. " f"Got: {type(allowed).__name__} = {allowed!r}"
    )
    for required in _TRAINING_RAW_NAMES:
        assert required in allowed, (
            f"chat.allowed_tools MUST include {required!r} so the operator "
            "can trigger runtime retraining from chat (AI-014). "
            f"Current training entries: {[t for t in allowed if t.startswith('training.')]}"
        )


def test_jobs_allowed_tools_does_not_include_training_tools() -> None:
    """Jobs MUST NOT see ``training.*`` — that would let a subagent retrain.

    Runtime retraining is a chat-operator action executed in-process
    (no container restart; terminal state ``succeeded``/``failed``).
    Exposing it to the autonomous classification jobs surface would mean a
    subagent could trigger a otalon-clas retrain without operator
    confirmation. The production ``jobs.allowed_tools`` list deliberately
    omits the ``training.*`` namespace.
    """
    cfg = _load_production_config()
    jobs_cfg = cfg.get("jobs", {})
    allowed = jobs_cfg.get("allowed_tools")
    assert isinstance(allowed, list), (
        "jobs.allowed_tools is expected to be a non-empty curated list. " f"Got: {type(allowed).__name__} = {allowed!r}"
    )
    training_tools_in_allowlist = [t for t in allowed if t.startswith("training.")]
    assert not training_tools_in_allowlist, (
        "jobs.allowed_tools deliberately omits the training.* namespace. "
        "Boundary retraining causes multi-minute detection downtime and "
        "must remain a chat-operator action, not a subagent tool. "
        f"Found: {training_tools_in_allowlist}"
    )


# --- registry-level proof (AI-014) -------------------------------------
#
# The config assertions above prove the allow-list *config* is correct.
# The tests below prove the *mechanism*: given the production chat
# allow-list, the McpRegistry actually advertises the training tools to
# the chat LLM and permits the call, while the jobs allow-list does not.
# No live :9100 / :9000 stack is needed — ``acquire_session`` is faked
# so discovery returns the same dotted names the real MCP server exposes.


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


class _FakeSession:
    """Minimal MCP session: lists the training tools and echoes calls."""

    def __init__(self, tools: List[_MockMcpTool]) -> None:
        self._tools = tools

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None

    async def list_tools(self) -> Any:
        class _Listing:
            def __init__(self, tools: List[_MockMcpTool]) -> None:
                self.tools = tools

        return _Listing(self._tools)

    async def call_tool(self, name: str, arguments: Dict[str, Any]) -> Any:
        return _Result(content=[_Block(text=f"called {name} args={arguments}")])


def _patch_training_discovery(monkeypatch: pytest.MonkeyPatch) -> None:
    """Fake ``acquire_session`` so discovery returns the training tools."""
    tools = [_MockMcpTool(name=raw) for raw in _TRAINING_RAW_NAMES]

    @asynccontextmanager
    async def fake_acquire(url: str, *, api_key: object = None) -> AsyncIterator[_FakeSession]:
        session = _FakeSession(tools)
        async with session as opened:
            yield opened

    monkeypatch.setattr("otalon_ai.mcp.registry.acquire_session", fake_acquire)


async def test_registry_advertises_training_tools_under_chat_allow_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """With the production chat allow-list, the registry hands all three
    runtime-retrain tools to the LLM (sanitized public names) — the exact
    behaviour AI-014 was missing (including ``retrain_classifier``).
    """
    _patch_training_discovery(monkeypatch)
    chat_allow_list = _load_production_config()["chat"]["allowed_tools"]

    reg = McpRegistry(
        [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")],
        request_timeout_seconds=2,
    )
    specs = await reg.list_openai_tools(allow_list=chat_allow_list)
    names = {spec["function"]["name"] for spec in specs}
    for public_name in _TRAINING_PUBLIC_NAMES:
        assert public_name in names, (
            f"chat tool list is missing {public_name!r}; the operator "
            "cannot trigger boundary retraining from chat (AI-014). "
            f"Advertised: {sorted(names)}"
        )


async def test_registry_call_tool_permitted_under_chat_allow_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chat allow-list also permits the retrain *call* (belt-and-braces
    gate in ``call_tool`` no longer raises ``PermissionError``).
    """
    _patch_training_discovery(monkeypatch)
    chat_allow_list = _load_production_config()["chat"]["allowed_tools"]

    reg = McpRegistry(
        [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")],
        request_timeout_seconds=2,
    )
    result = await reg.call_tool(
        "training_retrain_boundaries",
        {"window_start": "2026-07-01 12:00:00", "window_stop": "2026-07-01 12:30:00"},
        allow_list=chat_allow_list,
    )
    assert "called training.retrain_boundaries" in result


async def test_registry_permits_classifier_call_under_chat_allow_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chat allow-list also permits ``retrain_classifier`` with its
    classifier payload (``window_start``, ``window_stop``, ``mitre_file``)
    so the mandated operator Chat path can invoke it (AI-014 gap).
    """
    _patch_training_discovery(monkeypatch)
    chat_allow_list = _load_production_config()["chat"]["allowed_tools"]

    reg = McpRegistry(
        [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")],
        request_timeout_seconds=2,
    )
    result = await reg.call_tool(
        "training_retrain_classifier",
        {
            "window_start": "2026-07-01 12:00:00",
            "window_stop": "2026-07-01 12:30:00",
            "mitre_file": "/labels/mitre.json",
        },
        allow_list=chat_allow_list,
    )
    assert "called training.retrain_classifier" in result
    assert "mitre_file" in result


async def test_registry_permits_status_call_under_chat_allow_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The chat allow-list also permits the side-effect-free status poll."""
    _patch_training_discovery(monkeypatch)
    chat_allow_list = _load_production_config()["chat"]["allowed_tools"]

    reg = McpRegistry(
        [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")],
        request_timeout_seconds=2,
    )
    result = await reg.call_tool(
        "training_get_retrain_status",
        {},
        allow_list=chat_allow_list,
    )
    assert "called training.get_retrain_status" in result


async def test_registry_rejects_training_call_under_jobs_allow_list(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The jobs allow-list MUST still reject every runtime-retrain call — a
    subagent must never be able to trigger a otalon-clas retrain without
    operator confirmation. Covers both the bounds and classifier tools.
    """
    _patch_training_discovery(monkeypatch)
    jobs_allow_list = _load_production_config()["jobs"]["allowed_tools"]

    reg = McpRegistry(
        [McpServerEntry(name="otalon-mcp", url="http://test:9000/mcp")],
        request_timeout_seconds=2,
    )
    with pytest.raises(PermissionError):
        await reg.call_tool(
            "training_retrain_boundaries",
            {"window_start": "2026-07-01 12:00:00", "window_stop": "2026-07-01 12:30:00"},
            allow_list=jobs_allow_list,
        )
    with pytest.raises(PermissionError):
        await reg.call_tool(
            "training_retrain_classifier",
            {
                "window_start": "2026-07-01 12:00:00",
                "window_stop": "2026-07-01 12:30:00",
                "mitre_file": "/labels/mitre.json",
            },
            allow_list=jobs_allow_list,
        )
