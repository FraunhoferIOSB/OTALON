"""Endpoint tests for generic runtime configuration and seeder status."""

from __future__ import annotations

import json
from collections.abc import Generator
from datetime import datetime, timezone
from typing import Any

import pytest
from fastapi.testclient import TestClient
from otalon_common.runtime import MANIFEST

from otalon_api.dependencies import (
    get_operations_jobs_service,
    get_passive_seeder_status_repo,
    get_runtime_config_repo,
)
from otalon_api.main import app
from otalon_api.settings import Settings

# This module uses fake repositories throughout; collection needs no database.
pytestmark = pytest.mark.unit

_HEADERS = {"X-API-Key": "operator"}
_VIEWER_HEADERS = {"X-API-Key": "viewer"}


class _RuntimeRepo:
    def __init__(self) -> None:
        self.rows: dict[tuple[str, str], dict[str, Any]] = {}
        self.writes: list[tuple[str, str, str, str]] = []
        self.notifies: list[tuple[str, str]] = []
        self.notify_error: Exception | None = None

    def list_rows(self) -> list[dict[str, Any]]:
        return list(self.rows.values())

    def get(self, service: str, key: str) -> dict[str, Any] | None:
        return self.rows.get((service, key))

    def upsert(self, service: str, key: str, value: str, updated_by: str) -> None:
        old = self.rows.get((service, key))
        self.rows[(service, key)] = {
            "service": service,
            "key": key,
            "value": value,
            "value_prev": old["value"] if old else None,
            "updated_at": datetime.now(timezone.utc),
            "updated_by": updated_by,
        }
        self.writes.append((service, key, value, updated_by))

    class _Postgres:
        """Mimics the pooled SQL surface the NOTIFY helper targets."""

        def __init__(self, outer: "_RuntimeRepo") -> None:
            self._outer = outer

        def _execute_update(self, sql: str, params: dict[str, Any] | None = None) -> int:
            params = params or {}
            if "pg_notify" not in sql:
                return 0
            if self._outer.notify_error is not None:
                raise self._outer.notify_error
            self._outer.notifies.append((str(params.get("channel")), str(params.get("payload"))))
            return 0

    @property
    def _repo(
        self,
    ) -> "_RuntimeRepo._Postgres":  # noqa: SLF001 - test stand-in for the pooled PG repo
        return self._Postgres(self)


class _StatusRepo:
    def __init__(self, row: dict[str, Any] | None = None) -> None:
        self.row = row

    def get(self, service: str) -> dict[str, Any] | None:
        assert service == "otalon-scan"
        return self.row


class _Jobs:
    def __init__(self) -> None:
        self.entries: list[Any] = []

    async def append_audit(self, entry: Any) -> None:
        self.entries.append(entry)


def _settings() -> Settings:
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="token",
        influxdb_org="org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="user",
        postgres_password="password",
        postgres_database="db",
        admin_api_key="",
        otalon_api_allowed_keys="operator:operator:operator,viewer:viewer:viewer",
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


@pytest.fixture()
def endpoint_state(
    monkeypatch: pytest.MonkeyPatch,
) -> Generator[dict[str, Any], None, None]:
    """Install isolated repositories and role-aware auth for endpoint tests."""
    runtime = _RuntimeRepo()
    status = _StatusRepo()
    jobs = _Jobs()
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", _settings)
    monkeypatch.setattr("otalon_api.dependencies.get_settings", _settings)
    app.dependency_overrides[get_runtime_config_repo] = lambda: runtime
    app.dependency_overrides[get_passive_seeder_status_repo] = lambda: status
    app.dependency_overrides[get_operations_jobs_service] = lambda: jobs
    try:
        yield {"runtime": runtime, "status": status, "jobs": jobs}
    finally:
        app.dependency_overrides.clear()


def _client() -> TestClient:
    return TestClient(app, raise_server_exceptions=False)


def test_runtime_get_lists_manifest_and_boot_fallback(
    endpoint_state: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in (
        "SERIES_BLACKLIST",
        "TRAINING_CLASSIFICATION_ENABLED",
        "PREDICTION_CLASSIFICATION_ENABLED",
        "PASSIVE_SEEDER_ENABLED",
        "PASSIVE_SEEDER_POLL_INTERVAL_S",
        "PASSIVE_SEEDER_LOOKBACK_WINDOW_S",
        "PASSIVE_SEEDER_DROP_LAA",
    ):
        monkeypatch.delenv(name, raising=False)
    response = _client().get("/api/v1/operations/configuration/runtime", headers=_VIEWER_HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert {(item["service"], item["key"]) for item in body["items"]} == {
        (entry.service, entry.key) for entry in MANIFEST
    }
    assert all(isinstance(item["value"], str) for item in body["items"])
    values = {(item["service"], item["key"]): item["value"] for item in body["items"]}
    assert values == {
        ("otalon-clas", "classification.training_enabled"): "false",
        ("otalon-clas", "training.default_quantile"): "0.0001",
        ("otalon-clas", "training.retrain_paused"): "false",
        ("otalon-clas", "detection.conn.bounds_enabled"): "unknown",
        ("otalon-clas", "detection.conn.classification_enabled"): "false",
        ("otalon-clas", "detection.conn.frequency_enabled"): "true",
        ("otalon-clas", "detection.mac_traffic.bounds_enabled"): "unknown",
        ("otalon-clas", "detection.mac_traffic.classification_enabled"): "false",
        ("otalon-clas", "detection.mac_traffic.frequency_enabled"): "true",
        ("otalon-clas", "detection.proto_traffic.bounds_enabled"): "unknown",
        ("otalon-clas", "detection.proto_traffic.classification_enabled"): "false",
        ("otalon-clas", "detection.proto_traffic.frequency_enabled"): "true",
        ("otalon-clas", "detection.conn.port_rule_refresh.enabled"): "true",
        ("otalon-clas", "detection.conn.port_rule_refresh.interval_seconds"): "300",
        ("otalon-clas", "detection.conn.port_rule_refresh.lookback_hours"): "6",
        ("otalon-clas", "detection.conn.port_rule_refresh.confirm_cycles"): "2",
        ("otalon-clas", "detection.conn.port_rule_refresh.min_samples"): "2",
        ("otalon-clas", "detection.conn.port_rule_refresh.rotation_distinct_ports"): "3",
        ("otalon-clas", "detection.series_blacklist"): "[]",
        ("otalon-scan", "enabled"): "false",
        ("otalon-scan", "poll_interval_s"): "60",
        ("otalon-scan", "lookback_window_s"): "300",
        ("otalon-scan", "drop_laa"): "false",
        ("otalon-ai", "ai.provider"): "",
        ("otalon-ai", "ai.endpoint"): "",
        ("otalon-ai", "ai.chat_model"): "",
        ("otalon-ai", "ai.job_model"): "",
        ("otalon-ai", "ai.context_window"): "0",
    }


def test_runtime_get_lists_live_detection_boot_fallbacks(
    endpoint_state: dict[str, Any], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setenv("PREDICTION_CLASSIFICATION_ENABLED", "true")
    response = _client().get("/api/v1/operations/configuration/runtime", headers=_VIEWER_HEADERS)
    assert response.status_code == 200
    values = {
        item["key"]: item["value"]
        for item in response.json()["items"]
        if item["service"] == "otalon-clas" and item["key"].startswith("detection.")
    }
    assert values == {
        "detection.conn.bounds_enabled": "unknown",
        "detection.conn.classification_enabled": "true",
        "detection.mac_traffic.bounds_enabled": "unknown",
        "detection.mac_traffic.classification_enabled": "true",
        "detection.proto_traffic.bounds_enabled": "unknown",
        "detection.proto_traffic.classification_enabled": "true",
        "detection.conn.frequency_enabled": "true",
        "detection.mac_traffic.frequency_enabled": "true",
        "detection.proto_traffic.frequency_enabled": "true",
        # CLAS-033 port-collapse rule refresh boot fallbacks
        # (operations_config.py mirrors otalon_clas PortRuleRefreshConfig).
        "detection.conn.port_rule_refresh.enabled": "true",
        "detection.conn.port_rule_refresh.interval_seconds": "300",
        "detection.conn.port_rule_refresh.lookback_hours": "6",
        "detection.conn.port_rule_refresh.confirm_cycles": "2",
        "detection.conn.port_rule_refresh.min_samples": "2",
        "detection.conn.port_rule_refresh.rotation_distinct_ports": "3",
        # CLAS-071: conservative empty list before the first write (D12).
        "detection.series_blacklist": "[]",
    }


@pytest.mark.parametrize(
    "key",
    [
        "detection.conn.bounds_enabled",
        "detection.conn.classification_enabled",
        "detection.mac_traffic.bounds_enabled",
        "detection.mac_traffic.classification_enabled",
        "detection.proto_traffic.bounds_enabled",
        "detection.proto_traffic.classification_enabled",
        "detection.conn.frequency_enabled",
        "detection.mac_traffic.frequency_enabled",
        "detection.proto_traffic.frequency_enabled",
    ],
)
def test_runtime_put_accepts_live_detection_boolean(endpoint_state: dict[str, Any], key: str) -> None:
    response = _client().put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": "otalon-clas",
            "key": key,
            "value": "false",
            "reason": "test",
        },
    )
    assert response.status_code == 200
    assert endpoint_state["runtime"].writes == [("otalon-clas", key, "false", "operator")]
    assert len(endpoint_state["jobs"].entries) == 1


@pytest.mark.parametrize(
    "payload",
    [
        {
            "service": "otalon-scan",
            "key": "not_registered",
            "value": "true",
            "reason": "test",
        },
        {
            "service": "otalon-scan",
            "key": "influx_token",
            "value": "secret",
            "reason": "test",
        },
        {
            "service": "otalon-scan",
            "key": "poll_interval_s",
            "value": "1",
            "reason": "test",
        },
    ],
)
def test_runtime_put_rejects_invalid_values_without_side_effects(
    endpoint_state: dict[str, Any], payload: dict[str, str]
) -> None:
    response = _client().put("/api/v1/operations/configuration/runtime", headers=_HEADERS, json=payload)
    assert response.status_code == 400
    assert endpoint_state["runtime"].writes == []
    assert endpoint_state["jobs"].entries == []


def test_runtime_put_allows_missing_reason(
    endpoint_state: dict[str, Any],
) -> None:
    """Runtime writes accept an omitted reason under the optional contract."""
    response = _client().put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": "otalon-clas",
            "key": "detection.conn.bounds_enabled",
            "value": "false",
        },
    )
    assert response.status_code == 200
    assert endpoint_state["runtime"].writes == [("otalon-clas", "detection.conn.bounds_enabled", "false", "operator")]
    assert len(endpoint_state["jobs"].entries) == 1


def test_runtime_put_normalizes_boolean_literals(
    endpoint_state: dict[str, Any],
) -> None:
    """Accepted boolean aliases persist in canonical form."""
    response = _client().put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": "otalon-clas",
            "key": "detection.conn.bounds_enabled",
            "value": "0",
            "reason": "disable bounds",
        },
    )
    assert response.status_code == 200
    assert endpoint_state["runtime"].writes == [("otalon-clas", "detection.conn.bounds_enabled", "false", "operator")]


def test_runtime_put_persists_audits_and_requires_no_restart(
    endpoint_state: dict[str, Any],
) -> None:
    response = _client().put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": "otalon-scan",
            "key": "poll_interval_s",
            "value": "120",
            "reason": "tune",
        },
    )
    assert response.status_code == 200
    assert response.json()["restart_required"] is False
    assert endpoint_state["runtime"].writes == [("otalon-scan", "poll_interval_s", "120", "operator")]
    assert len(endpoint_state["jobs"].entries) == 1
    assert json.loads(endpoint_state["jobs"].entries[0].detail)["prior_value"] is None


def test_status_returns_row_and_unknown_state(endpoint_state: dict[str, Any]) -> None:
    client = _client()
    unknown = client.get("/api/v1/operations/passive-seeder/status", headers=_VIEWER_HEADERS)
    assert unknown.status_code == 200
    assert unknown.json()["state"] == "unknown"
    endpoint_state["status"].row = {
        "service": "otalon-scan",
        "state": "running",
        "last_cycle_at": None,
        "last_error": None,
        "rows_seeded": 4,
        "poll_interval_s": 60,
        "updated_at": None,
    }
    row = client.get("/api/v1/operations/passive-seeder/status", headers=_VIEWER_HEADERS)
    assert row.json()["rows_seeded"] == 4
    assert client.get("/api/v1/operations/passive-seeder/status").status_code == 401
    assert client.get("/api/v1/operations/passive-seeder/status", headers={"X-API-Key": "wrong"}).status_code == 401


def test_runtime_auth_rejects_missing_and_viewer_write(
    endpoint_state: dict[str, Any],
) -> None:
    client = _client()
    assert client.get("/api/v1/operations/configuration/runtime").status_code == 401
    assert (
        client.put(
            "/api/v1/operations/configuration/runtime",
            headers=_VIEWER_HEADERS,
            json={"service": "otalon-scan", "key": "enabled", "value": "true"},
        ).status_code
        == 403
    )


def test_api_manifest_view_matches_shared_manifest(
    endpoint_state: dict[str, Any],
) -> None:
    """Ensure API enumeration exposes exactly the shared manifest contract."""
    response = _client().get("/api/v1/operations/configuration/runtime", headers=_VIEWER_HEADERS)
    actual = {(item["service"], item["key"], item["type"], item["domain"]) for item in response.json()["items"]}
    expected = {(entry.service, entry.key, entry.value_type, entry.domain) for entry in MANIFEST}
    assert actual == expected


_BLACKLIST_KEY = "detection.series_blacklist"
_BLACKLIST_SERVICE = "otalon-clas"


def _put_blacklist(client: TestClient, value: str) -> Any:
    return client.put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": _BLACKLIST_SERVICE,
            "key": _BLACKLIST_KEY,
            "value": value,
            "reason": "test",
        },
    )


def test_series_blacklist_put_persists_canonical_text_audit_and_notify(
    endpoint_state: dict[str, Any],
) -> None:
    """A valid array PUT persists canonical text, one audit row, one NOTIFY."""
    response = _put_blacklist(_client(), ' [ "FF:FF:FF:FF:FF:FF" , " IPv6 " , "IPv6" ] ')
    assert response.status_code == 200
    runtime = endpoint_state["runtime"]
    assert runtime.writes == [(_BLACKLIST_SERVICE, _BLACKLIST_KEY, '["ff:ff:ff:ff:ff:ff","ipv6"]', "operator")]
    assert runtime.rows[(_BLACKLIST_SERVICE, _BLACKLIST_KEY)]["value_prev"] is None
    assert len(endpoint_state["jobs"].entries) == 1
    assert json.loads(endpoint_state["jobs"].entries[0].detail)["prior_value"] is None
    assert runtime.notifies == [
        (
            "cyberclas_runtime_invalidation",
            '{"service": "otalon-clas", "key": "detection.series_blacklist"}',
        )
    ]


def test_series_blacklist_put_invalid_entry_maps_to_422_naming_index(
    endpoint_state: dict[str, Any],
) -> None:
    """An invalid entry yields 422 with the entry index and no row written."""
    response = _put_blacklist(_client(), '["33:33:*", "bad!!"]')
    assert response.status_code == 422
    assert "entry[1]" in response.json()["detail"]
    assert endpoint_state["runtime"].writes == []
    assert endpoint_state["runtime"].notifies == []
    assert endpoint_state["jobs"].entries == []


def test_series_blacklist_put_non_array_stays_structural_400(
    endpoint_state: dict[str, Any],
) -> None:
    """Non-array JSON keeps the structural 400 semantics."""
    response = _put_blacklist(_client(), '"not-an-array"')
    assert response.status_code == 400
    assert "expected a JSON array" in response.json()["detail"]
    assert endpoint_state["runtime"].writes == []
    assert endpoint_state["jobs"].entries == []


def test_series_blacklist_put_unknown_key_still_rejected(
    endpoint_state: dict[str, Any],
) -> None:
    """The allow-list still rejects unregistered keys with 400."""
    response = _client().put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": _BLACKLIST_SERVICE,
            "key": "detection.series_typo",
            "value": "[]",
            "reason": "test",
        },
    )
    assert response.status_code == 400
    assert "allow-list" in response.json()["detail"]
    assert endpoint_state["runtime"].writes == []


def test_series_blacklist_put_secret_key_still_denied(
    endpoint_state: dict[str, Any],
) -> None:
    """Secret-deny semantics are unaffected by the list branch."""
    response = _client().put(
        "/api/v1/operations/configuration/runtime",
        headers=_HEADERS,
        json={
            "service": _BLACKLIST_SERVICE,
            "key": "detection.secret_token",
            "value": "[]",
            "reason": "test",
        },
    )
    assert response.status_code == 400
    assert "secret-looking" in response.json()["detail"]
    assert endpoint_state["runtime"].writes == []


def test_series_blacklist_get_shows_list_type_and_db_value(
    endpoint_state: dict[str, Any],
) -> None:
    """GET carries the list-typed item, showing the DB value after a write."""
    client = _client()
    before = _item_for(client.get("/api/v1/operations/configuration/runtime", headers=_VIEWER_HEADERS))
    assert before is not None
    assert before["type"] == "list"
    assert before["value"] == "[]"
    assert before["domain"] is not None
    assert before["description"].startswith("Series exclusion patterns")

    _put_blacklist(client, '["IPv6"]')
    after = _item_for(client.get("/api/v1/operations/configuration/runtime", headers=_VIEWER_HEADERS))
    assert after is not None
    assert after["value"] == '["ipv6"]'
    assert after["type"] == "list"


def _item_for(response: Any) -> dict[str, Any] | None:
    """Extract the series-blacklist item from a runtime-GET response."""
    assert response.status_code == 200
    for item in response.json()["items"]:
        if item["key"] == _BLACKLIST_KEY and item["service"] == _BLACKLIST_SERVICE:
            return item
    return None


def test_series_blacklist_put_survives_notify_failure(
    endpoint_state: dict[str, Any],
) -> None:
    """A NOTIFY failure is absorbed: the PUT stays successful and audited."""
    runtime = endpoint_state["runtime"]
    runtime.notify_error = RuntimeError("connection reset")
    response = _put_blacklist(_client(), '["IPv6"]')
    assert response.status_code == 200
    assert runtime.writes == [(_BLACKLIST_SERVICE, _BLACKLIST_KEY, '["ipv6"]', "operator")]
    assert len(endpoint_state["jobs"].entries) == 1


def test_series_blacklist_put_skips_notify_on_repo_without_pg_surface(
    endpoint_state: dict[str, Any],
) -> None:
    """A repository exposing no PostgreSQL surface logs and still succeeds."""

    class _BareRepo:
        """Proxy hiding the pooled-PG attribute from the NOTIFY helper."""

        def __init__(self, inner: Any) -> None:
            self._inner = inner
            self.notifies: list[tuple[str, str]] = []
            self.writes: list[tuple[str, str, str, str]] = []

        def __getattr__(self, name: str) -> Any:
            if name == "_repo":
                raise AttributeError(name)
            return getattr(self.__dict__["_inner"], name)

        def upsert(self, service: str, key: str, value: str, updated_by: str) -> None:
            self.__dict__["_inner"].upsert(service, key, value, updated_by)
            self.writes.append((service, key, value, updated_by))

    runtime = endpoint_state["runtime"]
    bare = _BareRepo(runtime)
    app.dependency_overrides[get_runtime_config_repo] = lambda: bare
    try:
        response = _put_blacklist(_client(), '["IPv6"]')
        assert response.status_code == 200
        assert bare.writes == [(_BLACKLIST_SERVICE, _BLACKLIST_KEY, '["ipv6"]', "operator")]
        assert runtime.notifies == []
        assert len(endpoint_state["jobs"].entries) == 1
    finally:
        app.dependency_overrides[get_runtime_config_repo] = lambda: runtime
