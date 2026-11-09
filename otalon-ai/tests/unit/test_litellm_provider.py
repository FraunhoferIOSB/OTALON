"""Unit tests for :class:`src.llm.litellm_provider.LiteLLMProvider`.

Validates exact SDK kwargs under both regimes:

- ``reasoning_effort`` set → SDK kwargs MUST omit ``temperature`` and MUST
  include top-level ``reasoning_effort``.
- ``reasoning_effort`` unset → request body MUST include ``temperature`` and
  MUST NOT include ``reasoning_effort``.

The OpenAI Python SDK is real; only the underlying HTTP transport is
mocked via :class:`httpx.MockTransport` so the body that would reach the
LiteLLM proxy can be inspected exactly as the SDK serialises it.

This test file replaces the inherited Azure-mock tests for the LLM layer
(per tasks.md § "Niedrig — Smoke-Test-Fixture für LiteLLM-Antwort" in
.dev/TODO_otalon-ai.md).
"""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, cast

import httpx
import pytest
from openai import OpenAI

from otalon_ai.llm.litellm_provider import LiteLLMProvider


def _fake_completion_response() -> Dict[str, Any]:
    """Minimal valid ChatCompletion payload."""
    return {
        "id": "chatcmpl-test",
        "object": "chat.completion",
        "created": 1700000000,
        "model": "azure/gpt-5.4",
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "ok", "tool_calls": None},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
    }


def _capture_transport(captured: List[Dict[str, Any]]) -> httpx.MockTransport:
    """Build an httpx.MockTransport that records every outbound request body."""

    def handler(request: httpx.Request) -> httpx.Response:
        body = request.content.decode("utf-8") if request.content else "{}"
        try:
            parsed = json.loads(body) if body else {}
        except json.JSONDecodeError:
            parsed = {"_raw": body}
        captured.append({"method": request.method, "url": str(request.url), "body": parsed})
        return httpx.Response(200, json=_fake_completion_response())

    return httpx.MockTransport(handler)


def _provider_with_capture(
    captured: List[Dict[str, Any]],
    *,
    model: str = "azure/gpt-5.4",
    default_reasoning_effort: Optional[str] = None,
) -> LiteLLMProvider:
    """Inject a mocked httpx transport into the provider's OpenAI client."""
    provider = LiteLLMProvider(
        base_url="http://fake-litellm:4000/v1",
        api_key="sk-test",
        model=model,
        default_reasoning_effort=default_reasoning_effort,
    )
    # Replace the SDK's internal OpenAI() with one wired to the mock transport.
    provider._client = OpenAI(
        base_url="http://fake-litellm:4000/v1",
        api_key="sk-test",
        http_client=httpx.Client(transport=_capture_transport(captured)),
    )
    return provider


# --- tests ---------------------------------------------------------------


def test_request_omits_temperature_when_reasoning_effort_set() -> None:
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured)
    provider.chat_completion(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        reasoning_effort="medium",
    )
    assert captured, "expected one captured request"
    body = captured[0]["body"]
    assert body["model"] == "azure/gpt-5.4"
    assert "temperature" not in body, f"body should not carry temperature: {body}"
    assert body.get("reasoning_effort") == "medium"


def test_sync_kwargs_use_top_level_reasoning_effort(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: List[Dict[str, Any]] = []
    provider = LiteLLMProvider(base_url="http://fake-litellm:4000/v1", api_key="sk-test", model="m")

    class _Completions:
        def create(self, **kwargs: Any) -> Dict[str, Any]:
            captured.append(kwargs)
            return _fake_completion_response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    provider._client = cast(Any, _Client())
    provider.chat_completion([], [], temperature=0.3, reasoning_effort="high")
    assert captured[0]["reasoning_effort"] == "high"
    assert "extra_body" not in captured[0]
    assert "temperature" not in captured[0]


def test_sync_kwargs_include_temperature_without_reasoning_effort() -> None:
    captured: List[Dict[str, Any]] = []
    provider = LiteLLMProvider(base_url="http://fake-litellm:4000/v1", api_key="sk-test", model="m")

    class _Completions:
        def create(self, **kwargs: Any) -> Dict[str, Any]:
            captured.append(kwargs)
            return _fake_completion_response()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    provider._client = cast(Any, _Client())
    provider.chat_completion([], [], temperature=0.3)
    assert captured[0]["temperature"] == 0.3
    assert "reasoning_effort" not in captured[0]
    assert "extra_body" not in captured[0]


@pytest.mark.asyncio
async def test_stream_kwargs_use_top_level_reasoning_effort() -> None:
    captured: List[Dict[str, Any]] = []
    provider = LiteLLMProvider(base_url="http://fake-litellm:4000/v1", api_key="sk-test", model="m")

    class _Stream:
        def __aiter__(self) -> "_Stream":
            return self

        async def __anext__(self) -> Any:
            raise StopAsyncIteration

        async def close(self) -> None:
            pass

    class _Completions:
        async def create(self, **kwargs: Any) -> _Stream:
            captured.append(kwargs)
            return _Stream()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    provider._async_client = cast(Any, _Client())
    async for _chunk in provider.chat_completion_stream([], [], temperature=0.3, reasoning_effort="high"):
        pass
    assert captured[0]["reasoning_effort"] == "high"
    assert "extra_body" not in captured[0]
    assert "temperature" not in captured[0]


@pytest.mark.asyncio
async def test_stream_kwargs_include_temperature_without_reasoning_effort() -> None:
    captured: List[Dict[str, Any]] = []
    provider = LiteLLMProvider(base_url="http://fake-litellm:4000/v1", api_key="sk-test", model="m")

    class _Stream:
        def __aiter__(self) -> "_Stream":
            return self

        async def __anext__(self) -> Any:
            raise StopAsyncIteration

        async def close(self) -> None:
            pass

    class _Completions:
        async def create(self, **kwargs: Any) -> _Stream:
            captured.append(kwargs)
            return _Stream()

    class _Chat:
        completions = _Completions()

    class _Client:
        chat = _Chat()

    provider._async_client = cast(Any, _Client())
    async for _chunk in provider.chat_completion_stream([], [], temperature=0.3):
        pass
    assert captured[0]["temperature"] == 0.3
    assert "reasoning_effort" not in captured[0]
    assert "extra_body" not in captured[0]


def test_request_includes_temperature_when_reasoning_effort_absent() -> None:
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured)
    provider.chat_completion(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        temperature=0.3,
    )
    body = captured[0]["body"]
    assert body["temperature"] == 0.3
    assert "reasoning_effort" not in body


def test_per_call_reasoning_effort_overrides_default() -> None:
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured, default_reasoning_effort="low")
    provider.chat_completion(
        messages=[{"role": "user", "content": "hi"}],
        tools=[],
        reasoning_effort="high",
    )
    assert captured[0]["body"]["reasoning_effort"] == "high"
    assert "temperature" not in captured[0]["body"]


def test_default_reasoning_effort_applied_when_call_omits() -> None:
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured, default_reasoning_effort="medium")
    provider.chat_completion(messages=[{"role": "user", "content": "hi"}], tools=[])
    body = captured[0]["body"]
    assert body["reasoning_effort"] == "medium"
    assert "temperature" not in body


def test_tools_list_propagates_to_wire() -> None:
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured)
    tools = [
        {
            "type": "function",
            "function": {"name": "ping", "description": "ping", "parameters": {"type": "object"}},
        }
    ]
    provider.chat_completion(messages=[{"role": "user", "content": "x"}], tools=tools)
    body = captured[0]["body"]
    assert body["tools"][0]["function"]["name"] == "ping"


def test_empty_tools_omits_tools_field() -> None:
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured)
    provider.chat_completion(messages=[{"role": "user", "content": "x"}], tools=[])
    body = captured[0]["body"]
    # OpenAI SDK drops the `tools` key when it's None (we pass `None` on empty).
    assert "tools" not in body or body["tools"] is None


def test_missing_credentials_raise() -> None:
    with pytest.raises(ValueError):
        LiteLLMProvider(base_url="", api_key="x", model="m")
    with pytest.raises(ValueError):
        LiteLLMProvider(base_url="http://x", api_key="", model="m")
    with pytest.raises(ValueError):
        LiteLLMProvider(base_url="http://x", api_key="x", model="")


def test_chat_and_jobs_factories_use_correct_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from otalon_ai.llm.factory import build_chat_provider, build_jobs_provider
    from otalon_ai.settings import ChatConfig, DbConfig, JobsConfig, LiteLLMConfig, Settings

    settings = Settings(
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        chat=ChatConfig(llm_model="openai/gpt-4o", llm_reasoning_effort=None),
        jobs=JobsConfig(llm_model="azure/gpt-5.4", llm_reasoning_effort="high", allowed_tools=["x.y"]),
        litellm=LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-x"),
    )
    chat = build_chat_provider(settings)
    jobs = build_jobs_provider(settings)
    assert chat.model == "openai/gpt-4o"
    assert chat.default_reasoning_effort is None
    assert jobs.model == "azure/gpt-5.4"
    assert jobs.default_reasoning_effort == "high"


_TOOL = {
    "type": "function",
    "function": {"name": "ping", "description": "t", "parameters": {"type": "object", "properties": {}}},
}


@pytest.mark.parametrize("model", ["litellm/gpt-6-luna", "gpt-6.1-sol", "gpt-6.1-terra", "gpt-6-astra"])
def test_gpt6_with_tools_sends_reasoning_effort_none(model: str) -> None:
    """GPT-6 family rejects function tools unless reasoning_effort=none (proxy 400 otherwise)."""
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured, model=model)
    provider.chat_completion(messages=[{"role": "user", "content": "hi"}], tools=[_TOOL])
    body = captured[0]["body"]
    assert body.get("reasoning_effort") == "none", body
    assert "temperature" not in body, body


def test_non_gpt6_model_with_tools_unchanged() -> None:
    """Gegenprobe: other providers keep the old body (temperature, no reasoning_effort)."""
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured, model="claude-haiku-5-5")
    provider.chat_completion(messages=[{"role": "user", "content": "hi"}], tools=[_TOOL])
    body = captured[0]["body"]
    assert "reasoning_effort" not in body, body
    assert "temperature" in body, body


def test_explicit_effort_wins_over_gpt6_none() -> None:
    """An explicit effort from the caller is never overridden by the GPT-6 default."""
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured, model="gpt-6-luna")
    provider.chat_completion(messages=[{"role": "user", "content": "hi"}], tools=[_TOOL], reasoning_effort="high")
    assert captured[0]["body"].get("reasoning_effort") == "high"


def test_gpt6_without_tools_unchanged() -> None:
    """Without tools the GPT-6 model keeps the old body (no forced none)."""
    captured: List[Dict[str, Any]] = []
    provider = _provider_with_capture(captured, model="gpt-6-luna")
    provider.chat_completion(messages=[{"role": "user", "content": "hi"}], tools=[])
    body = captured[0]["body"]
    assert "reasoning_effort" not in body, body
