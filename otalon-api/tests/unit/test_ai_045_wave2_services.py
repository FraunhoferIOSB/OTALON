"""Unit tests for AI-045 Wave 2 services (spec api--ai-connection).

Covers :class:`AIModelCatalogService` (D5) and :class:`AIRuntimeClient`
(D2/D4) at the behavioural level: identifier-only adoption, malformed
shapes, secret non-disclosure (D6) and the 200/422 contract of the live
push. All HTTP calls are faked with an ``httpx.MockTransport`` so no real
network is touched.
"""

from __future__ import annotations

from typing import Any

import httpx
import pytest

from otalon_api.services.ai_model_catalog_service import (
    AIModelCatalogService,
    ModelCatalogError,
)
from otalon_api.services.ai_runtime_client import (
    AIRuntimeClient,
    AIRuntimePushError,
)

pytestmark = pytest.mark.unit

_PROXY_KEY = "sk-proxy-secret-456"
_INTERNAL_KEY = "internal-key-456"


_REAL_ASYNC_CLIENT = httpx.AsyncClient
"""Captured before any monkeypatch: patching ``httpx.AsyncClient`` with a
factory that itself constructs ``httpx.AsyncClient`` would recurse into the
patched attribute, so the original class is bound once at import time."""


class _Env:
    """Minimal env-service fake exposing ``load`` and ``to_dict``."""

    def __init__(self, values: dict[str, str]) -> None:
        self._values = values

    def load(self) -> None:
        return None

    def to_dict(self) -> dict[str, str]:
        return dict(self._values)


class TestModelCatalog:
    @pytest.mark.asyncio
    async def test_adopts_only_data_ids_as_strings(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Identifiers only: numbers, missing-id entries and non-strings drop."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "object": "list",
                    "data": [
                        {"id": "gpt-5.4", "owned_by": "openai"},
                        {"id": 123},
                        {"owned_by": "no-id"},
                        {"id": None},
                        "not-a-dict",
                        {"id": "claude-opus-5-5"},
                    ],
                },
            )

        env = {"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": _PROXY_KEY}
        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        service = AIModelCatalogService(_Env(env))  # type: ignore[arg-type]
        models = await service.list_models()
        assert models == ["claude-opus-5-5", "gpt-5.4"]

    @pytest.mark.asyncio
    async def test_length_and_charset_bounds(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Over-long IDs and non-identifier characters are dropped."""

        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "data": [
                        {"id": "x" * 201},
                        {"id": "valid/model.name+1:foo"},
                        {"id": "bad id with spaces"},
                        {"id": "injection\tattempt"},
                        {"id": ""},
                    ]
                },
            )

        env = {"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": _PROXY_KEY}
        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        service = AIModelCatalogService(_Env(env))  # type: ignore[arg-type]
        models = await service.list_models()
        assert models == ["valid/model.name+1:foo"]

    @pytest.mark.asyncio
    async def test_no_data_list_yields_error(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, json={"unexpected": "shape"})

        env = {"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": _PROXY_KEY}
        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        service = AIModelCatalogService(_Env(env))  # type: ignore[arg-type]
        with pytest.raises(ModelCatalogError, match="no data list"):
            await service.list_models()

    @pytest.mark.asyncio
    async def test_unreachable_yields_error_without_body_or_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("proxy unreachable: sk-internal-detail")

        env = {"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": _PROXY_KEY}
        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        service = AIModelCatalogService(_Env(env))  # type: ignore[arg-type]
        with pytest.raises(ModelCatalogError) as excinfo:
            await service.list_models()
        message = str(excinfo.value)
        assert "sk-proxy-secret" not in message
        assert "proxy unreachable" not in message
        assert "ConnectError" in message

    @pytest.mark.asyncio
    async def test_non_2xx_yields_error_without_body(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(500, text="internal leak: sk-proxy-secret")

        env = {"LITELLM_BASE_URL": "https://llm.example.com", "LITELLM_API_KEY": _PROXY_KEY}
        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        service = AIModelCatalogService(_Env(env))  # type: ignore[arg-type]
        with pytest.raises(ModelCatalogError) as excinfo:
            await service.list_models()
        assert "sk-proxy-secret" not in str(excinfo.value)
        assert "internal leak" not in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_missing_config_yields_error(self) -> None:
        service = AIModelCatalogService(_Env({"LITELLM_BASE_URL": "", "LITELLM_API_KEY": ""}))  # type: ignore[arg-type]
        with pytest.raises(ModelCatalogError, match="not configured"):
            await service.list_models()

    @pytest.mark.asyncio
    async def test_placeholder_key_yields_error(self) -> None:
        service = AIModelCatalogService(
            _Env({"LITELLM_BASE_URL": "https://x", "LITELLM_API_KEY": "sk-no-key"})  # type: ignore[arg-type]
        )
        with pytest.raises(ModelCatalogError, match="not configured"):
            await service.list_models()

    @pytest.mark.asyncio
    async def test_authorization_bearer_sent(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, str] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["auth"] = request.headers.get("Authorization", "")
            seen["url"] = str(request.url)
            return httpx.Response(200, json={"data": [{"id": "m"}]})

        env = {"LITELLM_BASE_URL": "https://llm.example.com/v1", "LITELLM_API_KEY": _PROXY_KEY}
        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        service = AIModelCatalogService(_Env(env))  # type: ignore[arg-type]
        await service.list_models()
        assert seen["auth"] == f"Bearer {_PROXY_KEY}"
        assert seen["url"].endswith("/v1/models")


class TestAIRuntimeClient:
    @pytest.mark.asyncio
    async def test_push_sends_key_and_payload(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, Any] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["key"] = request.headers.get("X-API-Key", "")
            seen["path"] = request.url.path
            seen["body"] = request.read()
            return httpx.Response(200, json={"chat_model": "gpt-5.4", "job_model": "gpt-5.4", "applied_at": "now"})

        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        client = AIRuntimeClient("http://otalon-ai:9100")
        result = await client.push_llm_config(api_key=_INTERNAL_KEY, chat_model="gpt-5.4", job_model="gpt-5.4")
        assert seen["key"] == _INTERNAL_KEY
        assert seen["path"] == "/internal/v1/llm-config"
        assert result["chat_model"] == "gpt-5.4"

    @pytest.mark.asyncio
    async def test_push_422_maps_to_error_detail(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(422, text='{"detail": "invalid: secret sk-xyz"}')

        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        client = AIRuntimeClient("http://otalon-ai:9100")
        with pytest.raises(AIRuntimePushError) as excinfo:
            await client.push_llm_config(api_key=_INTERNAL_KEY, chat_model="m", job_model="m")
        assert "status 422" in str(excinfo.value)
        assert "sk-xyz" not in str(excinfo.value)

    @pytest.mark.asyncio
    async def test_push_transport_error_names_step_wo_secret(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectTimeout("timeout leaked-keyvalue")

        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        client = AIRuntimeClient("http://otalon-ai:9100")
        with pytest.raises(AIRuntimePushError) as excinfo:
            await client.push_llm_config(api_key=_INTERNAL_KEY, chat_model="m", job_model="m")
        assert "push request failed" in str(excinfo.value)
        assert "ConnectTimeout" in str(excinfo.value)
        assert "leaked-keyvalue" not in str(excinfo.value)


class TestRuntimeConfigReadBack:
    """AI-045 runtime_config path: a saved value is visible at once, no restart (no file)."""

    def test_saved_value_read_back_from_runtime_config_over_stale_file(self) -> None:
        from otalon_api.services.ai_connection_service import AIConnectionService

        class _Repo:
            def __init__(self) -> None:
                self.rows = {("otalon-ai", "ai.chat_model"): "claude-opus-5-5"}

            def get(self, service: str, key: str) -> dict[str, str] | None:
                value = self.rows.get((service, key))
                return None if value is None else {"value": value}

        class _Env:
            """File still holds the OLD model; runtime_config holds the new one."""

            def load(self) -> None:
                return None

            def to_dict(self) -> dict[str, str]:
                return {
                    "LITELLM_API_KEY": "sk-real-looking-test-value-1234",
                    "LITELLM_BASE_URL": "https://llm.example.com",
                    "CHAT_LLM_MODEL": "gpt-5.4",
                    "JOBS_LLM_MODEL": "gpt-5.4",
                }

        service = AIConnectionService(_Env(), runtime_repo=_Repo())
        meta = service.metadata()
        assert meta["chat_model"] == "claude-opus-5-5"
        assert meta["job_model"] == "gpt-5.4"
        assert meta["key_configured"] is True
        assert "sk-real-looking" not in str(meta)

    def test_file_fallback_when_runtime_config_empty(self) -> None:
        from otalon_api.services.ai_connection_service import AIConnectionService

        class _EmptyRepo:
            def get(self, service: str, key: str) -> None:
                return None

        class _Env:
            def load(self) -> None:
                return None

            def to_dict(self) -> dict[str, str]:
                return {"CHAT_LLM_MODEL": "gpt-5.4", "LITELLM_BASE_URL": "https://x.example.com"}

        meta = AIConnectionService(_Env(), runtime_repo=_EmptyRepo()).metadata()
        assert meta["chat_model"] == "gpt-5.4"


class TestSaveRefusesUnsafeTarget:
    """AI-045: an unsafe endpoint is refused at save, before any write or live push."""

    @pytest.mark.parametrize(
        "endpoint",
        ["http://example.com/v1", "http://127.0.0.1:4000/v1", "http://169.254.169.254/v1"],
    )
    def test_unsafe_endpoint_rejected_with_422_and_nothing_written(self, endpoint: str) -> None:
        from otalon_api.services.ai_connection_service import AIConnectionService

        # _validate_target raises ValueError; the save route maps that to HTTP 422.
        with pytest.raises(ValueError):
            AIConnectionService._validate_target(endpoint)

    def test_safe_private_http_is_not_refused(self) -> None:
        """Gegenprobe: the rule must not refuse a private http target (the proxy case)."""
        import ipaddress

        from otalon_api.services import ai_connection_service as mod

        # _classify_ip returns the class as a string: a private address may use http,
        # loopback is blocked for every scheme.
        assert mod._classify_ip(ipaddress.ip_address("10.105.5.230")) == "private"
        assert mod._classify_ip(ipaddress.ip_address("127.0.0.1")) == "blocked"


class TestConnectionTestUsesSavedEndpoint:
    """AI-045: the connectivity test must probe the endpoint the operator saved (runtime_config)."""

    @pytest.mark.asyncio
    async def test_probes_runtime_config_endpoint_not_stale_file(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import httpx

        from otalon_api.services import ai_connection_service as mod
        from otalon_api.services.ai_connection_service import AIConnectionService

        probed: list[str] = []

        class _Repo:
            def get(self, service: str, key: str) -> dict[str, str] | None:
                if key == "ai.endpoint":
                    return {"value": "http://saved.internal.example:4000/v1"}
                return None

        class _Env:
            def load(self) -> None:
                return None

            def to_dict(self) -> dict[str, str]:
                # file stays on the OLD endpoint; the key is present
                return {
                    "LITELLM_BASE_URL": "http://stale.internal.example:4000/v1",
                    "LITELLM_API_KEY": "sk-test-value-not-logged-1234",
                }

        def _fake_validate(endpoint: str) -> object:
            probed.append(endpoint)
            return type("Pinned", (), {"ip": "10.0.0.5"})()

        class _Transport(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
                probed.append(str(request.url))
                return httpx.Response(200, json={"data": []})

        monkeypatch.setattr(mod.AIConnectionService, "_validate_target", staticmethod(_fake_validate))
        monkeypatch.setattr(mod, "_PinnedAddressTransport", lambda ip: _Transport())

        svc = AIConnectionService(_Env(), runtime_repo=_Repo())
        result = await svc.test()

        assert result == {"success": True, "state": "ready"}
        assert probed[0].startswith("http://saved.internal.example:4000"), probed
        assert not any("stale.internal" in p for p in probed)


class TestRuntimeStatusWire:
    """AI-045 wire-level check: the GET status call must carry the internal key.

    The fake runtime client in test_operations_config.py never exercises the
    real HTTP call, so a missing X-API-Key only surfaced as a live 401 in the
    running stack. This test pins the header on the real client.
    """

    @pytest.mark.asyncio
    async def test_get_llm_config_status_sends_internal_key(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: dict[str, str | None] = {}

        def handler(request: httpx.Request) -> httpx.Response:
            seen["key"] = request.headers.get("X-API-Key")
            if seen["key"] != "wire-test-key":
                return httpx.Response(401, json={"detail": "unauthorized"})
            return httpx.Response(200, json={"chat_model": "gpt-5.4", "job_model": "gpt-5.4"})

        from otalon_api.services.ai_runtime_client import AIRuntimeClient

        transport = httpx.MockTransport(handler)

        def _factory(**kwargs: Any) -> httpx.AsyncClient:
            kwargs["transport"] = transport
            return _REAL_ASYNC_CLIENT(**kwargs)

        monkeypatch.setattr(httpx, "AsyncClient", _factory)
        client = AIRuntimeClient(base_url="http://otalon-ai:9100", timeout_s=5.0)
        status = await client.get_llm_config_status("wire-test-key")
        assert seen["key"] == "wire-test-key"
        assert status == {"chat_model": "gpt-5.4", "job_model": "gpt-5.4"}
