"""Unit tests for the AI-045 live LLM configuration surface (Wave 1).

Covers every scenario of the spec ``agent--llm-live-config``:

1. Valid ``PUT /internal/v1/llm-config`` swaps the chat provider, log
   contains ``llm-config applied chat model=<x> job model=<y> source=live``.
2. Missing / invalid key → 401 or 403, nothing changes.
3. Build failure → 422, previous provider + settings stay active.
4. Turn consistency: a swap during a running turn leaves that turn on
   the old provider; the NEXT turn uses the new one (sync + stream).
5. Jobs built after ``WorkerPool.update_settings`` use the new model.
6. ``GET /internal/v1/llm-config`` reports active config with NO key
   material in the response (and none in the logs).

Also covers Task 1.8: a retired provider is closed after the last turn
holding it finishes (not immediately).
"""

from __future__ import annotations

import asyncio
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from loguru import logger
from otalon_common.auth.api_key import KeyRegistry
from otalon_common.auth.fastapi import make_api_key_middleware

from otalon_ai.api.llm_config import router as llm_config_router
from otalon_ai.chat.agent_loop import ChatAgentLoop
from otalon_ai.jobs.worker_pool import WorkerPool
from otalon_ai.llm.factory import build_jobs_provider
from otalon_ai.settings import ChatConfig, DbConfig, JobsConfig, LiteLLMConfig, Settings

# A key materialising the "never log / never return" contract.
SECRET_KEY = "sk-test-secret-xyz-456"

# ── Settings helper ───────────────────────────────────────────────────


def _make_settings(
    *,
    chat_model: str = "gpt-5.4",
    job_model: str = "gpt-5.4",
    base_url: str = "http://litellm:4000/v1",
) -> Settings:
    """Build a Settings instance without touching env or files."""
    return Settings(
        litellm=LiteLLMConfig(base_url=base_url, api_key=SECRET_KEY),
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        chat=ChatConfig(llm_model=chat_model),
        jobs=JobsConfig(llm_model=job_model, allowed_tools=["postgres.read_anomalies"]),
    )


# ── chat loop / pool recording stubs ─────────────────────────────────


class _RecordingLoop:
    """ChatAgentLoop stand-in recording swap_provider calls."""

    def __init__(self, model: str) -> None:
        self.model = model
        self.swaps: List[Any] = []

    async def swap_provider(self, new: Any) -> None:
        self.swaps.append(new)
        self.model = new.model


class _RecordingPool:
    """WorkerPool stand-in recording update_settings calls."""

    def __init__(self) -> None:
        self.updates: List[Settings] = []

    def update_settings(self, new: Settings) -> None:
        self.updates.append(new)


class _LogSink:
    """Collect loguru records for assertions."""

    def __init__(self) -> None:
        self.messages: List[str] = []

    def __call__(self, message: Any) -> None:
        self.messages.append(str(message))


# ── app fixture ───────────────────────────────────────────────────────


@pytest.fixture
def llm_app(monkeypatch: pytest.MonkeyPatch) -> FastAPI:
    """App mirroring main.py: /internal protected by the key registry."""
    monkeypatch.setenv(
        "OTALON_AI_ALLOWED_KEYS",
        "ui:viewer:ui-key-123,internal:operator:internal-key-456",
    )
    app = FastAPI()
    app.add_middleware(
        make_api_key_middleware(
            registry=KeyRegistry.from_env("OTALON_AI_ALLOWED_KEYS"),
            protected_prefixes=("/api/v1/chat", "/jobs", "/internal"),
        )
    )
    # Mirror main.py: the chat path reads app.state.settings and the live state copies it.
    _boot_settings = _make_settings()
    app.state.settings = _boot_settings
    app.state.llm_config = {
        "settings": _boot_settings,
        "source": "env",
        "applied_at": datetime.now(tz=timezone.utc),
    }
    app.state.chat_loop = _RecordingLoop("gpt-5.4")
    app.state.worker_pool = _RecordingPool()
    app.include_router(llm_config_router)
    return app


# ── mock provider primitives ──────────────────────────────────────────


@dataclass
class _MockUsage:
    total_tokens: int = 0
    prompt_tokens: int = 0
    completion_tokens: int = 0


@dataclass
class _MockMessage:
    role: str = "assistant"
    content: Optional[str] = None
    tool_calls: Optional[List[Any]] = None

    def model_dump(self, *, exclude_none: bool = False) -> Dict[str, Any]:
        return {"role": self.role, "content": self.content or ""}


@dataclass
class _MockChoice:
    message: _MockMessage
    finish_reason: str = "stop"
    index: int = 0


@dataclass
class _MockCompletion:
    choices: List[_MockChoice]
    usage: _MockUsage = field(default_factory=_MockUsage)


@dataclass
class _DeltaContent:
    content: Optional[str] = None
    tool_calls: Optional[List[Any]] = None


@dataclass
class _DeltaChoice:
    delta: _DeltaContent
    index: int = 0


@dataclass
class _StreamChunk:
    choices: List[_DeltaChoice]
    usage: Optional[_MockUsage] = None


class _ImmediateSyncLlm:
    """Sync provider answering immediately."""

    def __init__(self, model: str, reply: str) -> None:
        self.model = model
        self.reply = reply
        self.calls = 0
        self.name = "immediate-sync"

    def chat_completion(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> _MockCompletion:
        self.calls += 1
        return _MockCompletion(
            choices=[_MockChoice(message=_MockMessage(content=self.reply))]
        )


class _ImmediateStreamLlm:
    """Streaming provider answering immediately."""

    name = "immediate-stream"

    def __init__(self, model: str, reply: str) -> None:
        self.model = model
        self.reply = reply

    async def chat_completion_stream(
        self,
        messages: List[Dict[str, Any]],
        tools: List[Dict[str, Any]],
        *,
        temperature: float = 0.1,
        reasoning_effort: Optional[str] = None,
    ) -> Any:
        yield _StreamChunk(
            choices=[_DeltaChoice(delta=_DeltaContent(content=self.reply))]
        )


class _CloseableLlm(_ImmediateSyncLlm):
    """Immediate provider recording close() calls (Task 1.8)."""

    def __init__(self, model: str) -> None:
        super().__init__(model, f"reply-{model}")
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


class _ClosableStreamLlm(_ImmediateStreamLlm):
    """Streaming provider recording close() calls (Task 1.8)."""

    def __init__(self, model: str) -> None:
        super().__init__(model, f"reply-{model}")
        self.close_calls = 0

    async def close(self) -> None:
        self.close_calls += 1


class _EmptyMcp:
    async def list_openai_tools(
        self, *, force_refresh: bool = False, allow_list: Optional[List[str]] = None
    ) -> List[Dict[str, Any]]:
        return []

    async def call_tool(
        self,
        name: str,
        arguments: Dict[str, Any],
        *,
        allow_list: Optional[List[str]] = None,
    ) -> str:
        raise AssertionError("no tool calls expected")


class _InMemoryStore:
    def __init__(self) -> None:
        self.saved: List[List[Dict[str, Any]]] = []

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        return []

    def save(self, session_id: str, messages: List[Dict[str, Any]]) -> None:
        self.saved.append([dict(m) for m in messages])


# ── Scenario 1: valid update swaps the chat provider ───────────────────


def test_valid_update_swaps_chat_provider_and_logs(llm_app: FastAPI) -> None:
    chat_loop: _RecordingLoop = llm_app.state.chat_loop
    pool: _RecordingPool = llm_app.state.worker_pool
    sink = _LogSink()
    handler = logger.add(sink, level="INFO")
    try:
        with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
            resp = client.put(
                "/internal/v1/llm-config",
                json={"chat_model": "claude-opus-5-5", "job_model": "claude-opus-5-5"},
            )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["chat_model"] == "claude-opus-5-5"
        assert body["job_model"] == "claude-opus-5-5"
        # The chat provider was swapped to one built with the new model.
        assert len(chat_loop.swaps) == 1
        assert chat_loop.swaps[0].model == "claude-opus-5-5"
        # Jobs got the new settings reference.
        assert len(pool.updates) == 1
        assert pool.updates[0].jobs.llm_model == "claude-opus-5-5"
        # App state flipped to live.
        assert llm_app.state.llm_config["source"] == "live"
    finally:
        logger.remove(handler)
    log_text = "\n".join(sink.messages)
    assert (
        "llm-config applied chat model=claude-opus-5-5 job model=claude-opus-5-5 source=live"
        in log_text
    )
    # D6: the key is never logged.
    assert SECRET_KEY not in log_text


def test_live_push_applies_context_window_to_chat_settings(llm_app: FastAPI) -> None:
    """AI-046: a live push changes the chat context window without a restart.

    The chat router and SSE stream read ``settings.chat.model_context_window``; the
    push must set it on the authoritative settings object the live config points to.
    """
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        resp = client.put(
            "/internal/v1/llm-config",
            json={
                "chat_model": "claude-opus-5-5",
                "job_model": "claude-opus-5-5",
                "context_window": 256000,
            },
        )
    assert resp.status_code == 200, resp.text
    live_settings = llm_app.state.llm_config["settings"]
    assert live_settings.chat.model_context_window == 256000
    # The chat path reads app.state.settings (router.py, sse.py). It must see the same value,
    # otherwise a live change never reaches the chat. Gegenprobe: this line is the one that
    # failed before the sync was added.
    assert llm_app.state.settings.chat.model_context_window == 256000


def test_live_push_without_context_window_keeps_current_value(llm_app: FastAPI) -> None:
    before = llm_app.state.llm_config["settings"].chat.model_context_window
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        resp = client.put(
            "/internal/v1/llm-config",
            json={"chat_model": "claude-opus-5-5", "job_model": "claude-opus-5-5"},
        )
    assert resp.status_code == 200, resp.text
    assert llm_app.state.llm_config["settings"].chat.model_context_window == before


def test_out_of_range_context_window_is_rejected_without_change(
    llm_app: FastAPI,
) -> None:
    before = llm_app.state.llm_config["settings"].chat.model_context_window
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        resp = client.put(
            "/internal/v1/llm-config",
            json={
                "chat_model": "claude-opus-5-5",
                "job_model": "claude-opus-5-5",
                "context_window": 100,
            },
        )
    assert resp.status_code == 422, resp.text
    assert llm_app.state.llm_config["settings"].chat.model_context_window == before


def test_status_shows_live_source_and_models_after_update(llm_app: FastAPI) -> None:
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        assert client.get("/internal/v1/llm-config").json()["source"] == "env"
        client.put(
            "/internal/v1/llm-config",
            json={"chat_model": "claude-opus-5-5"},
        )
        status = client.get("/internal/v1/llm-config").json()
    assert status["source"] == "live"
    assert status["chat_model"] == "claude-opus-5-5"
    assert status["job_model"] == "gpt-5.4"


# ── Scenario 2: missing / invalid key ──────────────────────────────────


def test_put_without_key_is_rejected_without_change(llm_app: FastAPI) -> None:
    chat_loop: _RecordingLoop = llm_app.state.chat_loop
    with TestClient(llm_app) as client:
        resp = client.put("/internal/v1/llm-config", json={"chat_model": "evil-model"})
    assert resp.status_code in (401, 403)
    assert chat_loop.swaps == []
    assert llm_app.state.llm_config["source"] == "env"
    assert llm_app.state.llm_config["settings"].chat.llm_model == "gpt-5.4"


def test_put_with_wrong_key_is_rejected_without_change(llm_app: FastAPI) -> None:
    chat_loop: _RecordingLoop = llm_app.state.chat_loop
    with TestClient(llm_app, headers={"X-API-Key": "not-a-valid-key"}) as client:
        resp = client.put("/internal/v1/llm-config", json={"chat_model": "evil-model"})
    assert resp.status_code in (401, 403)
    assert chat_loop.swaps == []
    assert llm_app.state.llm_config["settings"].chat.llm_model == "gpt-5.4"


# ── Scenario 3: build failure keeps the old provider ───────────────────


def test_build_failure_blank_base_url_returns_422(llm_app: FastAPI) -> None:
    chat_loop: _RecordingLoop = llm_app.state.chat_loop
    pool: _RecordingPool = llm_app.state.worker_pool
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        resp = client.put(
            "/internal/v1/llm-config",
            json={"base_url": "   "},
        )
    assert resp.status_code == 422
    assert chat_loop.swaps == []
    assert pool.updates == []
    assert llm_app.state.llm_config["source"] == "env"
    # Old settings stay in place.
    assert llm_app.state.llm_config["settings"].chat.llm_model == "gpt-5.4"


def test_build_failure_empty_model_returns_422(llm_app: FastAPI) -> None:
    chat_loop: _RecordingLoop = llm_app.state.chat_loop
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        resp = client.put(
            "/internal/v1/llm-config",
            json={"chat_model": ""},
        )
    assert resp.status_code == 422
    assert chat_loop.swaps == []
    assert llm_app.state.llm_config["settings"].chat.llm_model == "gpt-5.4"


def test_previous_provider_still_used_after_build_failure(llm_app: FastAPI) -> None:
    chat_loop: _RecordingLoop = llm_app.state.chat_loop
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        client.put("/internal/v1/llm-config", json={"chat_model": ""})
        # The status endpoint still reports the ORIGINAL model.
        status = client.get("/internal/v1/llm-config")
    assert status.status_code == 200
    assert status.json()["chat_model"] == "gpt-5.4"
    assert status.json()["source"] == "env"
    assert chat_loop.model == "gpt-5.4"


# ── Scenario 4: in-flight turn finishes on its provider ────────────────


class _GatedStore(_InMemoryStore):
    """Store whose ``load`` blocks until the test releases it.

    Positioning the gate in ``load`` (which runs AFTER the provider
    reference is pinned but BEFORE the first LLM call) makes the swap
    land strictly between the pin and the first LLM round — the only
    window where a missing turn-localisation would be observable.
    """

    def __init__(self) -> None:
        super().__init__()
        self.loaded = threading.Event()
        self.release_gate = threading.Event()

    def load(self, session_id: str) -> List[Dict[str, Any]]:
        self.loaded.set()
        assert self.release_gate.wait(timeout=5), "test gate never released"
        return []


# ── Scenario 4: in-flight turn finishes on its provider ────────────────


def _build_agent_loop(llm: Any, store: Any = None) -> ChatAgentLoop:
    return ChatAgentLoop(
        llm=llm,  # type: ignore[arg-type]  # reason: test double matches LlmProvider structurally
        mcp_registry=_EmptyMcp(),  # type: ignore[arg-type]  # reason: minimal registry stand-in
        session_store=store if store is not None else _InMemoryStore(),  # type: ignore[arg-type]  # reason: in-memory persistence stand-in
        system_prompt="SYSTEM PROMPT",
        max_tool_rounds=4,
    )


async def test_swap_during_sync_turn_keeps_old_provider() -> None:
    """A swap between turn start and the first LLM round: the running
    turn MUST still finish on gpt-5.4; only the NEXT turn uses the new
    provider. This is the mutation-sensitive window — resolving
    ``self._llm`` per round instead of the pinned reference would
    answer ``from-new`` here."""
    old = _ImmediateSyncLlm("gpt-5.4", "from-old")
    new = _ImmediateSyncLlm("claude-opus-5-5", "from-new")
    store = _GatedStore()
    loop_ = _build_agent_loop(old, store)

    turn_task = asyncio.create_task(loop_.run_chat_turn("s1", "Hi"))
    # Turn is now parked inside store.load — after the provider pin.
    await asyncio.to_thread(store.loaded.wait, 5)
    await loop_.swap_provider(new)

    store.release_gate.set()
    result = await turn_task
    assert (
        result.content == "from-old"
    ), "in-flight turn must finish on the old provider"

    # The next turn uses the new provider.
    result2 = await loop_.run_chat_turn("s1", "next")
    assert result2.content == "from-new"
    assert old.calls == 1
    assert new.calls == 1


async def test_swap_during_streaming_turn_keeps_old_provider() -> None:
    """Same contract on the SSE path: a swap mid-turn leaves the
    running stream on gpt-5.4; the following turn uses claude-opus-5-5."""
    old = _ImmediateStreamLlm("gpt-5.4", "from-old")
    new = _ImmediateStreamLlm("claude-opus-5-5", "from-new")
    store = _GatedStore()
    loop_ = _build_agent_loop(old, store)

    events: List[Dict[str, Any]] = []

    async def consumer() -> None:
        async for event in loop_.run_chat_turn_stream("s1", "Hi"):
            events.append(event)

    turn_task = asyncio.create_task(consumer())
    await asyncio.to_thread(store.loaded.wait, 5)
    await loop_.swap_provider(new)

    store.release_gate.set()
    await turn_task
    final = events[-1]
    assert final["type"] == "final"
    assert (
        final["content"] == "from-old"
    ), "in-flight stream must finish on the old provider"

    events2 = [e async for e in loop_.run_chat_turn_stream("s1", "next")]
    assert events2[-1]["content"] == "from-new"


# ── Task 1.8: retired provider closed after the last turn ─────────────


async def test_retired_sync_provider_closed_after_last_turn() -> None:
    old = _CloseableLlm("gpt-5.4")
    store = _GatedStore()
    loop_ = _build_agent_loop(old, store)

    turn_task = asyncio.create_task(loop_.run_chat_turn("s1", "Hi"))
    await asyncio.to_thread(store.loaded.wait, 5)
    swap_task = asyncio.create_task(loop_.swap_provider(_ImmediateSyncLlm("new", "n")))
    await asyncio.sleep(0)
    assert old.close_calls == 0, "turn still in flight: must NOT be closed yet"
    store.release_gate.set()
    result = await turn_task
    await swap_task
    assert result.content == "reply-gpt-5.4"
    assert old.close_calls == 1, "retired provider must be closed after the last turn"


async def test_retired_stream_provider_closed_after_last_turn() -> None:
    old = _ClosableStreamLlm("gpt-5.4")
    store = _GatedStore()
    loop_ = _build_agent_loop(old, store)

    events: List[Dict[str, Any]] = []

    async def consumer() -> None:
        async for event in loop_.run_chat_turn_stream("s1", "Hi"):
            events.append(event)

    turn_task = asyncio.create_task(consumer())
    await asyncio.to_thread(store.loaded.wait, 5)
    await loop_.swap_provider(_ImmediateStreamLlm("new", "n"))
    assert old.close_calls == 0, "still in flight: must NOT be closed yet"
    store.release_gate.set()
    await turn_task
    assert old.close_calls == 1


async def test_swap_without_active_turns_closes_old_immediately() -> None:
    old = _CloseableLlm("gpt-5.4")
    loop_ = _build_agent_loop(old)
    await loop_.swap_provider(_ImmediateSyncLlm("new", "n"))
    assert old.close_calls == 1


# ── Scenario 5: new jobs use the updated settings ─────────────────────


def _make_pool(settings: Settings) -> WorkerPool:
    return WorkerPool(
        settings=settings,  # type: ignore[arg-type]  # reason: repo/loader args unused in this test
        prompts=object(),  # type: ignore[arg-type]  # reason: not exercised
        bus=object(),  # type: ignore[arg-type]  # reason: not exercised
        jobs_repo=object(),  # type: ignore[arg-type]  # reason: not exercised
        alarms_repo=object(),  # type: ignore[arg-type]  # reason: not exercised
        baseline_repo=object(),  # type: ignore[arg-type]  # reason: not exercised
    )


def test_worker_pool_builds_new_jobs_from_updated_settings() -> None:
    base = _make_settings(job_model="gpt-5.4")
    pool = _make_pool(base)
    assert build_jobs_provider(pool._settings).model == "gpt-5.4"

    updated = base.with_llm_overrides(job_model="claude-opus-5-5")
    pool.update_settings(updated)

    assert pool._settings is updated
    provider = build_jobs_provider(pool._settings, model=None)
    assert provider.model == "claude-opus-5-5"


# ── Scenario 6: status contains no key ─────────────────────────────────


def test_get_status_contains_no_key_material(llm_app: FastAPI) -> None:
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        client.put("/internal/v1/llm-config", json={"chat_model": "claude-opus-5-5"})
        resp = client.get("/internal/v1/llm-config")
    assert resp.status_code == 200
    assert "api_key" not in resp.text
    assert "key" not in resp.text
    assert SECRET_KEY not in resp.text
    body = resp.json()
    assert set(body.keys()) == {
        "base_url",
        "chat_model",
        "job_model",
        "applied_at",
        "source",
    }


def test_put_response_contains_no_key_material(llm_app: FastAPI) -> None:
    with TestClient(llm_app, headers={"X-API-Key": "internal-key-456"}) as client:
        resp = client.put(
            "/internal/v1/llm-config", json={"chat_model": "claude-opus-5-5"}
        )
    assert resp.status_code == 200
    assert SECRET_KEY not in resp.text
    assert "api_key" not in resp.text
