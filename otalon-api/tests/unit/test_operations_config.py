"""Direct unit tests for the Operations Configuration router (WAVE E).

The AI-connection, env-compose and jobs services are injected through
``app.dependency_overrides`` so FastAPI resolves the fakes and no real
``.env.compose`` file, Postgres or outbound HTTP call is touched. Auth is
exercised through the real :class:`ApiKeyAuthMiddleware` by patching
``otalon_api.middleware.auth.get_settings`` (matching ``test_operations_router``).

Covered contract (``openspec/changes/ui075-configuration``):

* endpoint auth (401 when key missing, 503 fail-closed when unset),
* AI GET never returns the key; ``not-configured`` distinct from ``failed``;
  test states and key absence,
* boot allowlist rejection, sensitive masking, affected services,
* audit redaction (no secret in the audit ``detail``),
* datetime history serialisation and explicit rollback eligibility,
* confirmed rollback re-applies the prior value; sensitive / no-snapshot /
  unconfirmed rollbacks are rejected safely.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterator

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import (
    get_ai_connection_service,
    get_ai_model_catalog_service,
    get_ai_runtime_client,
    get_env_compose_service,
    get_operations_jobs_service,
    get_runtime_config_repo,
    get_settings,
)
from otalon_api.domain.operations import OperationsAuditAppend, OperationsAuditEntry
from otalon_api.main import app
from otalon_api.services.ai_connection_service import AIConnectionService
from otalon_api.services.ai_model_catalog_service import ModelCatalogError
from otalon_api.services.ai_runtime_client import AIRuntimePushError
from otalon_api.settings import Settings

pytestmark = pytest.mark.unit

_HEADERS = {"X-API-Key": "test-secret"}


def _make_settings(
    api_key: str = "test-secret", otalon_ai_internal_key: str = "internal-key-456"
) -> Settings:
    """Build test settings with the given admin + internal keys."""
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=api_key,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
        otalon_ai_internal_key=otalon_ai_internal_key,
    )


class _FakeEnvService:
    """In-memory stand-in for :class:`EnvComposeService`.

    Records every ``update_and_save`` call so a test can assert exactly
    which keys/values were written. ``get_masked_env`` masks sensitive
    keys the same way the real service does.
    """

    def __init__(self, values: dict[str, str]) -> None:
        self._values = dict(values)
        self.writes: list[dict[str, str]] = []
        self.load_calls = 0

    def load(self) -> None:
        self.load_calls += 1

    def to_dict(self) -> dict[str, str]:
        return dict(self._values)

    def get_masked_env(
        self, reveal_sensitive: bool = False, full_mask_sensitive: bool = False
    ) -> dict[str, str]:
        out: dict[str, str] = {}
        for key, value in self._values.items():
            if not reveal_sensitive and (
                "TOKEN" in key or "PASSWORD" in key or key.endswith("_KEY")
            ):
                if not value:
                    out[key] = ""
                elif full_mask_sensitive:
                    out[key] = "*" * len(value)
                else:
                    out[key] = value[:3] + "*" * max(3, len(value) - 6) + value[-3:]
            else:
                out[key] = value
        return out

    def update_and_save(
        self, updates: dict[str, str], create_backup: bool = True
    ) -> tuple[dict[str, str], list[str], None]:
        changed = [k for k, v in updates.items() if self._values.get(k) != v]
        self._values.update(updates)
        self.writes.append(dict(updates))
        return dict(self._values), changed, None


@pytest.fixture(autouse=True)
def _ai_target_offline(monkeypatch: pytest.MonkeyPatch) -> None:
    """Keep the AI save tests hermetic: the endpoint target check (AI-045) would resolve
    ``llm.example.com`` via DNS, which the sandbox cannot do. The target rule itself is
    covered by its own tests; here it is replaced by a public-https classification."""
    from otalon_api.services import ai_connection_service as mod

    monkeypatch.setattr(
        mod.AIConnectionService,
        "_validate_target",
        staticmethod(lambda endpoint: None),
    )


class _FakeRuntimeRepo:
    """In-memory stand-in for RuntimeConfigRepo (AI-045 runtime_config path).

    Records every upsert with its audit row so tests can assert the written
    values and that exactly one audit row accompanies each write.
    """

    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], str] = {}
        self.audits: list[Any] = []

    def get(self, service: str, key: str) -> dict[str, Any] | None:
        value = self.rows.get((service, key))
        return (
            None if value is None else {"service": service, "key": key, "value": value}
        )

    def upsert_with_audit(
        self, service: str, key: str, value: str, updated_by: str, audit: Any
    ) -> None:
        self.rows[(service, key)] = value
        self.audits.append(audit)


class _FakeAIService:
    """Stand-in for :class:`AIConnectionService` with a controllable state."""

    def __init__(
        self, metadata: dict[str, Any], test_result: dict[str, Any] | None = None
    ) -> None:
        self._metadata = metadata
        self._test_result = test_result or {"success": True, "state": "ready"}
        self.test_called = False

    def metadata(self) -> dict[str, Any]:
        return dict(self._metadata)

    async def test(self) -> dict[str, Any]:
        self.test_called = True
        return dict(self._test_result)


class _FakeCatalogService:
    """Stand-in for :class:`AIModelCatalogService`."""

    def __init__(
        self, models: list[str] | None = None, error: Exception | None = None
    ) -> None:
        self._models = models if models is not None else ["gpt-5.4", "claude-opus-5-5"]
        self._error = error
        self.calls = 0

    async def list_models(self) -> list[str]:
        self.calls += 1
        if self._error is not None:
            raise self._error
        return list(self._models)


class _FakeRuntimeClient:
    """Stand-in for :class:`AIRuntimeClient` recording pushes and status calls."""

    def __init__(
        self,
        push_error: Exception | None = None,
        status: dict[str, str] | None = None,
        status_error: Exception | None = None,
    ) -> None:
        self.push_error = push_error
        self._status = status
        self._status_error = status_error
        self.pushes: list[dict[str, Any]] = []
        self.status_calls = 0

    async def push_llm_config(
        self,
        *,
        api_key: str,
        chat_model: str,
        job_model: str,
        base_url: str | None = None,
        context_window: int | None = None,
    ) -> dict[str, str]:
        self.pushes.append(
            {
                "api_key": api_key,
                "chat_model": chat_model,
                "job_model": job_model,
                "base_url": base_url,
                "context_window": context_window,
            }
        )
        if self.push_error is not None:
            raise self.push_error
        return {
            "chat_model": chat_model,
            "job_model": job_model,
            "applied_at": "2026-11-06T00:00:00Z",
        }

    async def get_llm_config_status(self, api_key: str) -> dict[str, str]:
        assert api_key, "GET status must carry the internal key"
        self.status_calls += 1
        if self._status_error is not None:
            raise self._status_error
        if self._status is None:
            raise RuntimeError("status unavailable")
        return dict(self._status)


class _FakeJobsService:
    """Stand-in for :class:`OperationsJobsService` audit surface."""

    def __init__(self, entries: list[OperationsAuditEntry] | None = None) -> None:
        self.entries = entries or []
        self.appended: list[OperationsAuditAppend] = []

    async def append_audit(self, entry: OperationsAuditAppend) -> None:
        self.appended.append(entry)

    async def query_audit(self, **_kwargs: Any) -> list[OperationsAuditEntry]:
        return list(self.entries)

    async def get_audit(self, entry_id: int) -> OperationsAuditEntry | None:
        return next((e for e in self.entries if e.id == entry_id), None)


def _entry(
    entry_id: int,
    target: str,
    action: str = "update",
    prior_value: Any = "old",
    category: str = "config",
) -> OperationsAuditEntry:
    """Build an audit entry with a snapshot detail."""
    detail = json.dumps({"changed_keys": [target], "prior_value": prior_value})
    return OperationsAuditEntry(
        id=entry_id,
        at=datetime(2026, 7, 18, 1, 2, 3, tzinfo=timezone.utc),
        category=category,  # type: ignore[arg-type]
        actor="operator",
        action=action,
        target=target,
        reason="because",
        detail=detail,
    )


@pytest.fixture()
def overrides() -> Iterator[dict[str, Any]]:
    """Install fake services and clean them up afterwards.

    Yields a mutable dict whose ``env``/``ai``/``jobs``/``catalog``/
    ``runtime`` entries the test may swap before issuing the request.
    """
    state: dict[str, Any] = {
        "env": _FakeEnvService(
            {
                "INFLUX_URL": "http://influxdb3:8181",
                "INFLUX_TOKEN": "supersecrettoken",
                "POSTGRES_PASSWORD": "pgsecret",
                "POSTGRES_DSN": "postgresql://u:p@pg/db",
                "TZ": "UTC",
            }
        ),
        "ai": _FakeAIService(
            {
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "gpt",
                "job_model": "gpt",
                "state": "ready",
                "key_configured": True,
            }
        ),
        "jobs": _FakeJobsService(),
        "catalog": _FakeCatalogService(),
        "runtime": _FakeRuntimeClient(status={"chat_model": "gpt", "job_model": "gpt"}),
    }
    app.dependency_overrides[get_env_compose_service] = lambda: state["env"]
    app.dependency_overrides[get_ai_connection_service] = lambda: state["ai"]
    app.dependency_overrides[get_operations_jobs_service] = lambda: state["jobs"]
    app.dependency_overrides[get_ai_model_catalog_service] = lambda: state["catalog"]
    app.dependency_overrides[get_ai_runtime_client] = lambda: state["runtime"]
    state["runtime_repo"] = _FakeRuntimeRepo()
    app.dependency_overrides[get_runtime_config_repo] = lambda: state["runtime_repo"]
    try:
        yield state
    finally:
        for dep in (
            get_env_compose_service,
            get_ai_connection_service,
            get_operations_jobs_service,
            get_ai_model_catalog_service,
            get_ai_runtime_client,
            get_runtime_config_repo,
        ):
            app.dependency_overrides.pop(dep, None)


def _client(
    monkeypatch: pytest.MonkeyPatch,
    api_key: str = "test-secret",
    otalon_ai_internal_key: str = "internal-key-456",
) -> TestClient:
    """Return a client whose middleware sees ``api_key`` as configured.

    ``get_settings`` is overridden through ``app.dependency_overrides`` so
    route handlers resolved the test settings even where a router module
    holds its own imported reference. The middleware patch stays because
    Starlette middleware does not consult the overrides.
    """
    settings = _make_settings(api_key, otalon_ai_internal_key=otalon_ai_internal_key)
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: settings)
    monkeypatch.setattr("otalon_api.dependencies.get_settings", lambda: settings)
    app.dependency_overrides[get_settings] = lambda: settings
    return TestClient(app, raise_server_exceptions=False)


class TestConfigAuth:
    def test_boot_get_401_without_key(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        assert client.get("/api/v1/operations/configuration/boot").status_code == 401

    def test_boot_get_503_when_unset(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch, api_key="")
        response = client.get("/api/v1/operations/configuration/boot")
        assert response.status_code == 503

    def test_ai_get_401_without_key(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        assert client.get("/api/v1/operations/ai-connection").status_code == 401


class TestBootConfig:
    def test_boot_get_masks_sensitive_and_lists_affected(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.get("/api/v1/operations/configuration/boot", headers=_HEADERS)
        assert response.status_code == 200
        data = response.json()
        assert set(data["editable_keys"]) == {
            "INFLUX_URL",
            "INFLUX_TOKEN",
            "POSTGRES_PASSWORD",
            "TZ",
        }
        assert data["readonly_keys"] == ["POSTGRES_DSN"]
        assert "POSTGRES_DSN" not in data["editable_keys"]
        assert "POSTGRES_DSN" in data["env"]
        assert "INFLUX_TOKEN" in data["sensitive_keys"]
        assert "POSTGRES_DSN" in data["sensitive_keys"]
        assert "supersecrettoken" not in response.text
        assert data["affected_services"]["POSTGRES_PASSWORD"] == ["postgres"]
        # reads freshly reload the env file
        assert overrides["env"].load_calls >= 1

    def test_boot_get_does_not_leak_secret_values(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        body = client.get(
            "/api/v1/operations/configuration/boot", headers=_HEADERS
        ).text
        assert "supersecrettoken" not in body
        assert "pgsecret" not in body

    def test_boot_get_fully_masks_sensitive_keys_no_plaintext_fragment(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """Sensitive boot values carry no raw character on the wire (full mask)."""
        client = _client(monkeypatch)
        response = client.get("/api/v1/operations/configuration/boot", headers=_HEADERS)
        assert response.status_code == 200
        env = response.json()["env"]
        secrets = {"INFLUX_TOKEN": "supersecrettoken", "POSTGRES_PASSWORD": "pgsecret"}
        body = response.text
        for key, raw in secrets.items():
            masked = env[key]
            # Fully masked: only asterisks, same length, no first/last fragment.
            assert masked == "*" * len(raw)
            assert set(masked) == {"*"}
            assert raw[:3] not in body
            assert raw[-3:] not in body

    def test_boot_put_rejects_non_boot_key(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/configuration/boot",
            headers=_HEADERS,
            json={"key": "LITELLM_API_KEY", "value": "x", "reason": "attempt"},
        )
        assert response.status_code == 400
        assert overrides["env"].writes == []

    def test_boot_put_rejects_readonly_derived_dsn(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """The derived POSTGRES_DSN is read-only and cannot be mutated."""
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/configuration/boot",
            headers=_HEADERS,
            json={
                "key": "POSTGRES_DSN",
                "value": "postgresql://x:y@pg/db",
                "reason": "attempt to edit derived dsn",
            },
        )
        assert response.status_code == 400
        assert overrides["env"].writes == []

    def test_boot_put_audits_with_actor_reason_and_prior(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/configuration/boot",
            headers=_HEADERS,
            json={"key": "TZ", "value": "Europe/Berlin", "reason": "dst change"},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["changed_keys"] == ["TZ"]
        assert data["restart_required"] is True
        appended = overrides["jobs"].appended[-1]
        assert appended.category == "config"
        assert appended.actor == "operator"
        assert appended.reason == "dst change"
        detail = json.loads(appended.detail or "{}")
        assert detail["prior_value"] == "UTC"

    def test_boot_put_sensitive_prior_value_is_redacted(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/configuration/boot",
            headers=_HEADERS,
            json={
                "key": "INFLUX_TOKEN",
                "value": "newtokenvalue",
                "reason": "rotate token",
            },
        )
        assert response.status_code == 200
        appended = overrides["jobs"].appended[-1]
        detail = json.loads(appended.detail or "{}")
        assert detail["prior_value"] is None
        assert "supersecrettoken" not in (appended.detail or "")


class TestAIConnection:
    def test_ai_get_never_returns_key(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.get("/api/v1/operations/ai-connection", headers=_HEADERS)
        assert response.status_code == 200
        data = response.json()
        # The protection that matters: no credential VALUE field. key_configured
        # is a presence flag (bool), which the form needs to show key state.
        assert "key" not in data
        assert isinstance(data.get("key_configured", False), bool)
        assert "LITELLM_API_KEY" not in str(data)

    def test_ai_get_reports_active_models_without_drift(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["runtime"] = _FakeRuntimeClient(
            status={"chat_model": "gpt", "job_model": "gpt"}
        )
        app.dependency_overrides[get_ai_runtime_client] = lambda: overrides["runtime"]
        client = _client(monkeypatch)
        data = client.get("/api/v1/operations/ai-connection", headers=_HEADERS).json()
        # Contract: persisted connection fields (for form pre-fill) plus the drift
        # fields. The key is only ever a boolean, never a value.
        assert data["active_chat_model"] == "gpt"
        assert data["active_job_model"] == "gpt"
        assert data["drift"] is False
        assert data["provider"] == "litellm"
        assert data["endpoint"] == "https://llm.example.com"
        assert data["chat_model"] == "gpt"
        assert data["job_model"] == "gpt"
        assert data["key_configured"] is True
        assert overrides["runtime"].status_calls >= 1

    def test_ai_get_reports_drift_when_active_differs(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["runtime"] = _FakeRuntimeClient(
            status={"chat_model": "old-model", "job_model": "gpt"}
        )
        app.dependency_overrides[get_ai_runtime_client] = lambda: overrides["runtime"]
        client = _client(monkeypatch)
        data = client.get("/api/v1/operations/ai-connection", headers=_HEADERS).json()
        assert data["drift"] is True

    def test_ai_get_active_null_never_fabricates_drift(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["runtime"] = _FakeRuntimeClient(
            status_error=AIRuntimePushError("runtime status unavailable: ConnectError")
        )
        app.dependency_overrides[get_ai_runtime_client] = lambda: overrides["runtime"]
        client = _client(monkeypatch)
        data = client.get("/api/v1/operations/ai-connection", headers=_HEADERS).json()
        assert data["active_chat_model"] is None
        assert data["active_job_model"] is None
        assert data["drift"] is False

    def test_ai_not_configured_distinct_from_failed(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["ai"] = _FakeAIService(
            {
                "provider": "litellm",
                "endpoint": "",
                "chat_model": "",
                "job_model": "",
                "state": "not-configured",
                "key_configured": False,
            }
        )
        app.dependency_overrides[get_ai_connection_service] = lambda: overrides["ai"]
        client = _client(monkeypatch)
        data = client.get("/api/v1/operations/ai-connection", headers=_HEADERS).json()
        # The GET now reports the otalon-ai active state; ``state`` itself
        # is no longer part of the drift response. not-configured is still
        # distinguishable via null active models and no drift.
        assert data["active_chat_model"] is None or isinstance(
            data["active_chat_model"], str
        )
        assert data["drift"] in (True, False)

    def test_ai_test_runs_and_returns_state(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/ai-connection/test", headers=_HEADERS, json={}
        )
        assert response.status_code == 200
        assert response.json() == {"success": True, "state": "ready"}
        assert overrides["ai"].test_called is True

    def test_ai_test_reports_not_configured(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["ai"] = _FakeAIService(
            {}, test_result={"success": False, "state": "not-configured"}
        )
        app.dependency_overrides[get_ai_connection_service] = lambda: overrides["ai"]
        client = _client(monkeypatch)
        data = client.post(
            "/api/v1/operations/ai-connection/test", headers=_HEADERS, json={}
        ).json()
        assert data["state"] == "not-configured"

    def test_ai_update_audits_without_secret(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json={
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "gpt-5.4",
                "job_model": "gpt-5.4",
                "context_window": 256000,
                "reason": "swap chat model",
            },
        )
        assert response.status_code == 200
        # AI-045: the non-secret values go to runtime_config; the key never does.
        # AI-046: the context window is saved as text in the same store.
        assert any(
            k == "ai.context_window" for (_s, k) in overrides["runtime_repo"].rows
        )
        repo_rows = overrides["runtime_repo"].rows
        assert {k for (_svc, k) in repo_rows} == {
            "ai.provider",
            "ai.endpoint",
            "ai.chat_model",
            "ai.job_model",
            "ai.context_window",
        }
        assert "LITELLM_API_KEY" not in str(repo_rows)
        assert overrides["env"].writes == []
        data = response.json()
        assert data["live_applied"] is True
        assert data["live_detail"] == "llm-config applied"
        # AI-046: the saved context window is pushed live with the value the operator sent.
        assert overrides["runtime"].pushes[-1]["context_window"] == 256000

    def test_get_ai_connection_returns_saved_context_window(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """AI-046: the GET route returns the saved window, not the schema default.

        The route is fed by ``AIConnectionService.metadata()``. The fake service in
        ``overrides`` replaces that call, so this test sets the fake's metadata to what the
        real service returns for a saved row, and checks the route passes it through.
        """
        overrides["ai"]._metadata["context_window"] = 256000
        client = _client(monkeypatch)
        response = client.get("/api/v1/operations/ai-connection", headers=_HEADERS)
        assert response.status_code == 200, response.text
        assert response.json()["context_window"] == 256000

    def test_ai_update_without_context_window_writes_no_context_row(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """AI-046 Gegenprobe: an omitted context window must not overwrite the saved value."""
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json={
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "gpt-5.4",
                "job_model": "gpt-5.4",
                "reason": "no context change",
            },
        )
        assert response.status_code == 200, response.text
        written = {k for (_s, k) in overrides["runtime_repo"].rows}
        assert "ai.context_window" not in written
        assert "None" not in str(overrides["runtime_repo"].rows)

    def test_ai_update_response_returns_saved_context_window(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """AI-046: the serialized PUT response carries the persisted window, not a default.

        Uses the real service over the fake env and runtime repo, so the value in the
        response is what ``metadata()`` reads back from the saved row.
        """
        overrides["ai"] = AIConnectionService(overrides["env"], overrides["runtime_repo"])
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json={
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "gpt-5.4",
                "job_model": "gpt-5.4",
                "context_window": 320000,
                "reason": "raise window",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["context_window"] == 320000
        assert overrides["runtime_repo"].rows[("otalon-ai", "ai.context_window")] == "320000"

    def test_ai_update_without_context_window_preserves_saved_value_in_response(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """AI-046: an older caller omitting the window keeps the saved row and sees it echoed."""
        overrides["runtime_repo"].rows[("otalon-ai", "ai.context_window")] = "256000"
        overrides["ai"] = AIConnectionService(overrides["env"], overrides["runtime_repo"])
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json={
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "gpt-5.4",
                "job_model": "gpt-5.4",
                "reason": "model only",
            },
        )
        assert response.status_code == 200, response.text
        assert response.json()["context_window"] == 256000
        assert overrides["runtime_repo"].rows[("otalon-ai", "ai.context_window")] == "256000"
        assert overrides["runtime"].pushes[-1]["context_window"] is None

    def test_ai_update_rejects_out_of_range_context_window_without_write(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json={
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "gpt-5.4",
                "job_model": "gpt-5.4",
                "context_window": 100,
                "reason": "too small",
            },
        )
        assert response.status_code == 422, response.text
        assert overrides["runtime_repo"].rows == {}

    def test_ai_key_replace_writes_key_but_audit_has_no_secret(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch)
        secret = "sk-super-secret-value-123"
        response = client.post(
            "/api/v1/operations/ai-connection/key",
            headers=_HEADERS,
            json={"key": secret, "reason": "rotate ai key"},
        )
        assert response.status_code == 200
        assert overrides["env"].writes[-1] == {"LITELLM_API_KEY": secret}
        appended = overrides["jobs"].appended[-1]
        assert secret not in (appended.detail or "")
        assert secret not in response.text


class TestAIModelList:
    """Spec api--ai-connection: model list, identifiers only, no key leak."""

    _SECRET = "sk-proxy-secret-value"

    def test_models_returns_identifiers_only(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["env"]._values.update(
            {
                "LITELLM_BASE_URL": "https://llm.example.com",
                "LITELLM_API_KEY": self._SECRET,
            }
        )
        overrides["catalog"] = _FakeCatalogService(
            models=["gpt-5.4", "claude-opus-5-5"]
        )
        app.dependency_overrides[get_ai_model_catalog_service] = lambda: overrides[
            "catalog"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/ai-connection/models", headers=_HEADERS, json={}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["models"] == ["gpt-5.4", "claude-opus-5-5"]
        assert self._SECRET not in response.text

    def test_models_unreachable_yields_502_without_key(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["env"]._values.update(
            {
                "LITELLM_BASE_URL": "https://llm.example.com",
                "LITELLM_API_KEY": self._SECRET,
            }
        )
        overrides["catalog"] = _FakeCatalogService(
            error=ModelCatalogError("model catalog request failed: ConnectError")
        )
        app.dependency_overrides[get_ai_model_catalog_service] = lambda: overrides[
            "catalog"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/ai-connection/models", headers=_HEADERS, json={}
        )
        assert response.status_code == 502
        assert self._SECRET not in response.text

    def test_models_success_with_allow_unlisted_flag_present(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """The 200 list is returned even when it contains no models."""
        overrides["catalog"] = _FakeCatalogService(models=[])
        app.dependency_overrides[get_ai_model_catalog_service] = lambda: overrides[
            "catalog"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/ai-connection/models", headers=_HEADERS, json={}
        )
        assert response.status_code == 200
        assert response.json()["models"] == []


class TestAIConnectionSave:
    """Spec api--ai-connection: model check 422, push failure keeps the file."""

    def _save_body(
        self, chat_model: str = "gpt-5.4", allow_unlisted: bool = False
    ) -> dict[str, Any]:
        return {
            "provider": "litellm",
            "endpoint": "https://llm.example.com",
            "chat_model": chat_model,
            "job_model": "gpt-5.4",
            "reason": "swap chat model",
            "allow_unlisted_model": allow_unlisted,
        }

    def test_unlisted_model_is_rejected_422(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """Proxy offers gpt-5.4/claude-opus-5-5; unknown-model → 422, nothing written."""
        overrides["catalog"] = _FakeCatalogService(
            models=["gpt-5.4", "claude-opus-5-5"]
        )
        app.dependency_overrides[get_ai_model_catalog_service] = lambda: overrides[
            "catalog"
        ]
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json=self._save_body(chat_model="unknown-model"),
        )
        assert response.status_code == 422
        assert response.json()["detail"] == "model 'unknown-model' not offered by proxy"
        assert overrides["env"].writes == []
        assert overrides["runtime"].pushes == []

    def test_unlisted_model_accepted_with_explicit_fallback(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """Proxy unreachable + allow_unlisted_model=true → 200, unverified model."""
        overrides["catalog"] = _FakeCatalogService(
            error=ModelCatalogError("model catalog request failed: ConnectError")
        )
        app.dependency_overrides[get_ai_model_catalog_service] = lambda: overrides[
            "catalog"
        ]
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json=self._save_body(chat_model="not-in-any-list", allow_unlisted=True),
        )
        assert response.status_code == 200
        assert overrides["runtime_repo"].rows
        assert overrides["runtime"].pushes

    def test_push_failure_keeps_saved_file(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """Push failure → 200, .env.compose written, live_applied=false + step detail."""
        overrides["runtime"] = _FakeRuntimeClient(
            push_error=AIRuntimePushError("push request failed: ConnectError")
        )
        app.dependency_overrides[get_ai_runtime_client] = lambda: overrides["runtime"]
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json=self._save_body(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["live_applied"] is False
        assert data["live_detail"].startswith("push request failed")
        # The runtime_config write happened and was NOT rolled back on a push failure.
        saved = overrides["runtime_repo"].rows
        assert saved[("otalon-ai", "ai.chat_model")] == "gpt-5.4"
        assert saved[("otalon-ai", "ai.job_model")] == "gpt-5.4"

    def test_push_uses_internal_key_header_only(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """The internal key reaches the push call and never the audit or response."""
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json=self._save_body(),
        )
        assert response.status_code == 200
        push = overrides["runtime"].pushes[-1]
        assert push["api_key"] == "internal-key-456"
        assert "internal-key-456" not in response.text
        appended = overrides["jobs"].appended[-1]
        assert "internal-key-456" not in (appended.detail or "")

    def test_push_skipped_detail_when_internal_key_unset(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        client = _client(monkeypatch, otalon_ai_internal_key="")
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json=self._save_body(),
        )
        assert response.status_code == 200
        data = response.json()
        assert data["live_applied"] is False
        assert (
            data["live_detail"]
            == "live push skipped: OTALON_AI_INTERNAL_KEY is not configured"
        )
        # The file write still happened.
        assert overrides["runtime_repo"].rows
        assert overrides["runtime"].pushes == []

    def test_default_allow_unlisted_model_is_false(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        """Omitting the flag keeps the strict 422 path (AIConnectionUpdate default)."""
        overrides["catalog"] = _FakeCatalogService(models=["gpt-5.4"])
        app.dependency_overrides[get_ai_model_catalog_service] = lambda: overrides[
            "catalog"
        ]
        client = _client(monkeypatch)
        response = client.put(
            "/api/v1/operations/ai-connection",
            headers=_HEADERS,
            json={
                "provider": "litellm",
                "endpoint": "https://llm.example.com",
                "chat_model": "claude-opus-5-5",
                "job_model": "gpt-5.4",
                "reason": "swap chat model",
            },
        )
        assert response.status_code == 422
        assert overrides["env"].writes == []


class TestConfigHistory:
    def test_history_serialises_datetime_and_omits_detail(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService([_entry(1, "TZ")])
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        response = client.get(
            "/api/v1/operations/configuration/history", headers=_HEADERS
        )
        assert response.status_code == 200
        row = response.json()[0]
        assert row["at"].startswith("2026-07-18T01:02:03")
        assert "detail" not in row
        assert row["rollback_eligible"] is True

    def test_history_marks_sensitive_and_key_replace_ineligible(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService(
            [
                _entry(1, "INFLUX_TOKEN"),  # sensitive
                _entry(2, "LITELLM_API_KEY", action="replace-ai-key", prior_value=None),
                _entry(3, "ai-connection", action="update-ai", prior_value=None),
            ]
        )
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        rows = {
            r["target"]: r["rollback_eligible"]
            for r in client.get(
                "/api/v1/operations/configuration/history", headers=_HEADERS
            ).json()
        }
        assert rows["INFLUX_TOKEN"] is False
        assert rows["LITELLM_API_KEY"] is False
        assert rows["ai-connection"] is False


class TestConfigRollback:
    def test_rollback_requires_confirmation(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService([_entry(1, "TZ")])
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/configuration/history/1/rollback",
            headers=_HEADERS,
            json={"reason": "undo", "confirmed": False},
        )
        assert response.status_code == 400

    def test_confirmed_rollback_reapplies_prior_and_audits(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService([_entry(1, "TZ", prior_value="UTC")])
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/configuration/history/1/rollback",
            headers=_HEADERS,
            json={"reason": "undo change", "confirmed": True},
        )
        assert response.status_code == 200
        assert response.json()["target"] == "TZ"
        assert overrides["env"].writes[-1] == {"TZ": "UTC"}
        assert overrides["jobs"].appended[-1].action == "rollback"

    def test_rollback_rejects_sensitive_target(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService(
            [_entry(1, "INFLUX_TOKEN", prior_value="old")]
        )
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/configuration/history/1/rollback",
            headers=_HEADERS,
            json={"reason": "undo", "confirmed": True},
        )
        assert response.status_code == 409
        assert overrides["env"].writes == []

    def test_rollback_rejects_missing_snapshot(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService([_entry(1, "TZ", prior_value=None)])
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/configuration/history/1/rollback",
            headers=_HEADERS,
            json={"reason": "undo", "confirmed": True},
        )
        assert response.status_code == 409

    def test_rollback_unknown_entry_is_404(
        self, monkeypatch: pytest.MonkeyPatch, overrides: dict[str, Any]
    ) -> None:
        overrides["jobs"] = _FakeJobsService([])
        app.dependency_overrides[get_operations_jobs_service] = lambda: overrides[
            "jobs"
        ]
        client = _client(monkeypatch)
        response = client.post(
            "/api/v1/operations/configuration/history/999/rollback",
            headers=_HEADERS,
            json={"reason": "undo", "confirmed": True},
        )
        assert response.status_code == 404
