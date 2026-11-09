"""Producer/consumer MCP auth-header contract tests.

These tests pin the Phase-7 correction for delegated batch
``p8-feedback-night-0721``: otalon-mcp is fail-closed on
    ``OTALON_MCP_ALLOWED_KEYS`` (``otalon-mcp/src/server.py:294``),
so every otalon-ai → otalon-mcp streamable-http session MUST
carry the consumer credential as an ``X-API-Key`` header, or the MCP
route answers ``503 {"detail": "API key authentication unavailable"}``
and chat/jobs silently enter a no-tools state.

The contract:

- ``acquire_session(url, api_key=...)`` opens the streamable-http
  transport with ``headers={"X-API-Key": <key>}``.
- EVERY registry discovery session, EVERY registry ``call_tool``
  session, AND the inherited jobs-worker session sends the header when
  a credential is configured.
- A configured-but-empty production credential fails fast and
  actionably rather than silently degrading to zero tools.
- The credential value never appears in a log record, ``repr`` or
  error string.

All boundary interception happens at ``streamablehttp_client`` (the
library we do not own), never at our own functions. Fake key values are
obviously non-secret.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Any, AsyncIterator, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import pytest

import otalon_ai.jobs.worker_pool as wp_mod
import otalon_ai.mcp.client as client_mod
from otalon_ai.jobs.events_bus import EventsBus
from otalon_ai.jobs.worker_pool import JobSpec, WorkerPool
from otalon_ai.mcp.client import acquire_session
from otalon_ai.mcp.registry import McpRegistry
from otalon_ai.settings import (
    ChatConfig,
    DbConfig,
    JobsConfig,
    LiteLLMConfig,
    McpConfig,
    McpServerEntry,
    Settings,
)

FAKE_KEY = "fake-mcp-consumer-key-DO-NOT-USE"


# --- boundary fakes -----------------------------------------------------


class _FakeTool:
    def __init__(self, name: str) -> None:
        self.name = name
        self.description = ""
        self.inputSchema = {"type": "object"}  # noqa: N815


class _FakeListing:
    def __init__(self, tools: List[_FakeTool]) -> None:
        self.tools = tools


class _FakeBlock:
    def __init__(self, text: str) -> None:
        self.text = text


class _FakeCallResult:
    def __init__(self, text: str) -> None:
        self.content = [_FakeBlock(text)]
        self.isError = False


class _FakeSession:
    async def initialize(self) -> None:
        return None

    async def list_tools(self) -> _FakeListing:
        return _FakeListing([_FakeTool("ping")])

    async def call_tool(self, _name: str, arguments: Dict[str, Any]) -> _FakeCallResult:
        return _FakeCallResult(f"ok args={arguments}")

    async def __aenter__(self) -> "_FakeSession":
        return self

    async def __aexit__(self, *exc: Any) -> None:
        return None


class _HeaderCapture:
    """Captures headers passed to ``streamablehttp_client`` per open."""

    def __init__(self) -> None:
        self.calls: List[Tuple[str, Optional[Dict[str, str]]]] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        capture = self

        @asynccontextmanager
        async def fake_streamable(
            url: str,
            *_args: Any,
            headers: Optional[Dict[str, str]] = None,
            **_kwargs: Any,
        ) -> AsyncIterator[Tuple[Any, Any, Any]]:
            capture.calls.append((url, headers))
            yield (object(), object(), None)

        # ClientSession(read, write) is constructed with our fakes; make it
        # return a _FakeSession regardless of positional transport args.
        def fake_client_session(*_a: Any, **_k: Any) -> _FakeSession:
            return _FakeSession()

        monkeypatch.setattr(client_mod, "streamablehttp_client", fake_streamable)
        monkeypatch.setattr(client_mod, "ClientSession", fake_client_session)

    def header_values(self) -> List[Optional[str]]:
        return [(headers or {}).get("X-API-Key") if headers is not None else None for _url, headers in self.calls]


@pytest.fixture
def capture(monkeypatch: pytest.MonkeyPatch) -> _HeaderCapture:
    cap = _HeaderCapture()
    cap.install(monkeypatch)
    return cap


# --- acquire_session low-level contract --------------------------------


async def test_acquire_session_sends_x_api_key_header(capture: _HeaderCapture) -> None:
    """A configured credential is sent as ``X-API-Key`` on the transport."""
    async with acquire_session("http://mcp:9000/mcp/", api_key=FAKE_KEY) as session:
        await session.list_tools()
    assert capture.header_values() == [FAKE_KEY]


async def test_acquire_session_omits_header_when_no_credential(
    capture: _HeaderCapture,
) -> None:
    """Without a credential no ``X-API-Key`` header is injected."""
    async with acquire_session("http://mcp:9000/mcp/", api_key=None) as session:
        await session.list_tools()
    assert capture.header_values() == [None]


# --- registry: every discovery + call session authenticates ------------


async def test_registry_discovery_and_call_send_credential(
    capture: _HeaderCapture,
) -> None:
    """Discovery AND call_tool sessions both carry the credential."""
    servers = [McpServerEntry(name="otalon-mcp", url="http://mcp:9000/mcp", api_key=FAKE_KEY)]
    reg = McpRegistry(servers, request_timeout_seconds=5)
    await reg.list_openai_tools()
    await reg.call_tool("ping", {})
    values = capture.header_values()
    assert len(values) >= 2
    assert all(v == FAKE_KEY for v in values)


# --- jobs worker session authenticates too -----------------------------


class _WorkerPoolAcquireCapture:
    """Captures the ``api_key`` kwarg the real ``WorkerPool._run_job`` path
    forwards to ``acquire_session`` at ``src/jobs/worker_pool.py:227``.

    The fake is installed at the module boundary
    (``src.jobs.worker_pool.acquire_session``) so the assertion exercises the
    genuine outer control flow — ``_run_job`` building the call itself —
    rather than a hand-written ``acquire_session`` invocation in the test.
    """

    def __init__(self) -> None:
        self.api_keys: List[Optional[str]] = []
        self.urls: List[str] = []

    def install(self, monkeypatch: pytest.MonkeyPatch) -> None:
        capture = self

        @asynccontextmanager
        async def fake_acquire_session(
            url: str,
            *,
            api_key: Optional[str] = None,
        ) -> AsyncIterator["_FakeSession"]:
            capture.urls.append(url)
            capture.api_keys.append(api_key)
            yield _FakeSession()

        monkeypatch.setattr(wp_mod, "acquire_session", fake_acquire_session)


def _worker_pool_settings() -> Settings:
    """Settings whose single MCP server carries the fake consumer key."""
    return Settings(
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        litellm=LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-fake"),
        mcp=McpConfig(servers=[McpServerEntry(name="otalon-mcp", url="http://mcp:9000/mcp", api_key=FAKE_KEY)]),
        chat=ChatConfig(llm_model="azure/gpt-5.4"),
        jobs=JobsConfig(llm_model="litellm/gpt-5.4", allowed_tools=["postgres.read_anomalies"], n_workers=1),
    )


class _WpFakeAlarmsRepo:
    def get_by_id(self, alarm_id: str) -> Dict[str, Any]:
        return {"id": alarm_id}


class _WpFakeBaselineRepo:
    def get_by_id(self, _bid: UUID) -> None:
        return None


class _WpFakeJobsRepo:
    def mark_running(self, _job_id: UUID) -> None:
        return None

    def mark_terminal(self, _job_id: UUID, **_kwargs: Any) -> None:
        return None

    def append_trace_entry(self, _job_id: UUID, _entry: Dict[str, Any]) -> None:
        return None

    def get_recent_durations(self, _n: int = 20) -> List[float]:
        return []


class _WpFakePromptLoader:
    def get(self, _variant: Any) -> str:
        return "SYS PROMPT"


def _worker_pool_spec() -> JobSpec:
    return JobSpec(
        job_id=uuid4(),
        alarm_id="alarm-1",
        prompt_variant="open",
        llm_provider="litellm",
        llm_model="litellm/gpt-5.4",
        llm_endpoint=None,
        reasoning_effort=None,
        timeout_seconds=60,
    )


async def _classify_stub(*, job_id: UUID, **_kwargs: Any) -> Dict[str, Any]:
    return {
        "status": "completed",
        "duration_seconds": 1.0,
        "tool_trace": [],
        "tokens_prompt": 0,
        "tokens_completion": 0,
        "step1_technical": None,
        "step2_classification": {"classifications": [{"technique_id": "T0846"}]},
    }


async def test_jobs_worker_session_sends_credential(monkeypatch: pytest.MonkeyPatch) -> None:
    """The real ``WorkerPool._run_job`` path forwards the configured key.

    Regression for ``src/jobs/worker_pool.py:227`` — the outer worker flow
    (not a hand-rolled ``acquire_session`` call) must pass
    ``self._settings.mcp.api_key`` as ``acquire_session(..., api_key=...)``.
    Only ``acquire_session`` plus the necessary collaborators are patched;
    ``_run_job`` itself is invoked unmodified, so the test goes red if line
    227 stops forwarding ``self._settings.mcp.api_key``.
    """
    acquire_capture = _WorkerPoolAcquireCapture()
    acquire_capture.install(monkeypatch)
    monkeypatch.setattr(wp_mod, "build_jobs_provider", lambda _settings, *, model=None: object())
    monkeypatch.setattr(wp_mod, "apply_allow_list", lambda tools, allowed: (list(tools), []))
    monkeypatch.setattr(wp_mod, "mcp_tool_to_openai_function", lambda _tool: {"type": "function", "function": {}})
    monkeypatch.setattr(wp_mod, "build_name_mapping", lambda _names: ({}, {}))
    monkeypatch.setattr(wp_mod, "classify_alarm", _classify_stub)

    pool = WorkerPool(
        settings=_worker_pool_settings(),
        prompts=_WpFakePromptLoader(),  # type: ignore[arg-type]
        bus=EventsBus(),
        jobs_repo=_WpFakeJobsRepo(),  # type: ignore[arg-type]
        alarms_repo=_WpFakeAlarmsRepo(),  # type: ignore[arg-type]
        baseline_repo=_WpFakeBaselineRepo(),  # type: ignore[arg-type]
    )

    await pool._run_job(_worker_pool_spec(), log_tag="[T]")

    assert acquire_capture.api_keys == [FAKE_KEY]
    assert acquire_capture.urls == ["http://mcp:9000/mcp"]


# --- fail-fast on missing production credential ------------------------


def test_mcp_config_requires_credential_when_enforced() -> None:
    """A configured-but-empty consumer credential fails fast, actionably."""
    with pytest.raises(ValueError, match="OTALON_MCP_API_KEY"):
        McpConfig(
            servers=[McpServerEntry(name="otalon-mcp", url="http://mcp:9000/mcp", api_key="")],
            require_api_key=True,
        )


def test_mcp_config_allows_missing_credential_by_default() -> None:
    """Default (dev / faked) config does not force a credential."""
    cfg = McpConfig(servers=[McpServerEntry(name="otalon-mcp", url="http://mcp:9000/mcp")])
    assert cfg.api_key is None


# --- no credential leak in logs / repr ---------------------------------


async def test_credential_not_leaked_in_logs(capture: _HeaderCapture, caplog: pytest.LogCaptureFixture) -> None:
    """The credential value never appears in emitted log output."""
    import logging

    from loguru import logger

    handler_id = logger.add(caplog.handler, format="{message}", level="DEBUG")
    try:
        with caplog.at_level(logging.DEBUG):
            async with acquire_session("http://mcp:9000/mcp/", api_key=FAKE_KEY) as session:
                await session.list_tools()
    finally:
        logger.remove(handler_id)
    assert FAKE_KEY not in caplog.text


def test_server_entry_repr_hides_credential() -> None:
    """``McpServerEntry`` repr/str never discloses the credential value."""
    entry = McpServerEntry(name="otalon-mcp", url="http://mcp:9000/mcp", api_key=FAKE_KEY)
    assert FAKE_KEY not in repr(entry)
    assert FAKE_KEY not in str(entry)
