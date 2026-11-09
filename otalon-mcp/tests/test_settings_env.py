"""MCP-014: the typed settings model is the single configuration source.

These tests pin the behaviour the migration had to preserve:

* values that used to be read with raw ``os.environ`` at 20 scattered
  call sites now resolve through :class:`otalon_mcp.settings.Settings`;
* the two legacy alias pairs keep the precedence they had at runtime;
* a missing ``$ENV_VAR`` placeholder is a hard error, matching the
  ``RAISE`` policy otalon-mcp is declared with in ``backend.md``.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Iterator

import pytest
from pydantic import ValidationError

from otalon_mcp.settings import (
    InfluxConfig,
    PostgresConfig,
    Settings,
    parse_influx_fields,
)

ENV_VARS: tuple[str, ...] = (
    "OTALON_MCP_TRANSPORT",
    "OTALON_MCP_FORCE_TIMEOUT",
    "OTALON_MCP_INFLUX_DB",
    "INFLUX_DATABASE",
    "OTALON_MCP_INFLUX_MEASUREMENT",
    "OTALON_MCP_INFLUX_ID_TAG",
    "OTALON_MCP_INFLUX_FIELDS",
    "OTALON_MCP_API_TIMEOUT_SECONDS",
    "OTALON_MCP_CONFIRM_NONCE_TTL",
    "OTALON_API_URL",
    "OTALON_API_KEY",
    "AGENT_URL",
    "AI_URL",
    "AGENT_PROXY_TIMEOUT_SECONDS",
    "PCAP_BASELINE_DIR",
    "PCAP_RECORDER_API_KEY",
    "ADMIN_API_KEY",
    "POSTGRES_DSN",
    "INFLUX_URL",
    "INFLUX_TOKEN",
    "MCP_LOG_FILE",
    "PCAP_RECORDER_URL",
)
"""Every variable the settings layer consults, cleared between tests."""

CONFIG_TEMPLATE: dict[str, Any] = {
    "server": {"name": "otalon-mcp", "host": "0.0.0.0", "port": 9000, "transport": "streamable-http"},
    "postgres": {"dsn": "$POSTGRES_DSN"},
    "influx": {"url": "$INFLUX_URL", "token": "$INFLUX_TOKEN"},
    "logging": {"level": "DEBUG", "file": "$MCP_LOG_FILE"},
    "pcap_recorder": {"url": "$PCAP_RECORDER_URL", "timeout_seconds": 30},
}
"""Minimal config.json shaped like the real one, placeholders included."""


@pytest.fixture(autouse=True)
def clean_env(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    """Remove every settings-relevant variable from the environment.

    Yields:
        Control to the test with a known-empty environment.
    """
    for name in ENV_VARS:
        monkeypatch.delenv(name, raising=False)
    yield


def _write_config(tmp_path: Path, overrides: dict[str, Any] | None = None) -> Path:
    """Write a config.json for a test and return its path.

    Args:
        tmp_path: Per-test temporary directory.
        overrides: Sections merged over :data:`CONFIG_TEMPLATE`.

    Returns:
        The path of the written config file.
    """
    payload = json.loads(json.dumps(CONFIG_TEMPLATE))
    for section, values in (overrides or {}).items():
        payload.setdefault(section, {}).update(values)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(payload), encoding="utf-8")
    return path


def _set_required(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the variables the placeholders in the template demand.

    Args:
        monkeypatch: Fixture used to set the variables.
    """
    monkeypatch.setenv("POSTGRES_DSN", "postgresql://u:p@pg:5432/otalon")
    monkeypatch.setenv("INFLUX_URL", "http://influxdb3:8181")
    monkeypatch.setenv("INFLUX_TOKEN", "influx-token")
    monkeypatch.setenv("MCP_LOG_FILE", "otalon-mcp.log")
    monkeypatch.setenv("PCAP_RECORDER_URL", "http://pcap-recorder:9090")


def _bare_settings() -> Settings:
    """Build a settings instance without touching the filesystem.

    Returns:
        A settings object carrying only the two mandatory sections.
    """
    return Settings(
        postgres=PostgresConfig(dsn="postgresql://u@h/db"),
        influx=InfluxConfig(url="http://influx:8181"),
    )


# ── placeholders resolve into the typed model ──────────────────────────


def test_placeholders_resolve_into_typed_fields(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    _set_required(monkeypatch)
    settings = Settings.from_json(_write_config(tmp_path))
    assert settings.postgres.dsn == "postgresql://u:p@pg:5432/otalon"
    assert settings.influx.url == "http://influxdb3:8181"
    assert settings.pcap_recorder.url == "http://pcap-recorder:9090"


def test_postgres_dsn_has_exactly_one_source(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``POSTGRES_DSN`` is the config placeholder, never a second raw read."""
    _set_required(monkeypatch)
    monkeypatch.setenv("POSTGRES_DSN", "postgresql://only:source@pg:5432/otalon")
    settings = Settings.from_json(_write_config(tmp_path))
    assert settings.postgres.dsn == "postgresql://only:source@pg:5432/otalon"


def test_missing_required_variable_raises(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """The RAISE policy makes an unset placeholder a boot-time failure."""
    _set_required(monkeypatch)
    monkeypatch.delenv("POSTGRES_DSN", raising=False)
    with pytest.raises(RuntimeError, match="POSTGRES_DSN"):
        Settings.from_json(_write_config(tmp_path))


def test_unknown_config_key_is_ignored(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``extra="ignore"`` is re-declared; the shared base forbids extras."""
    _set_required(monkeypatch)
    path = _write_config(tmp_path)
    payload = json.loads(path.read_text(encoding="utf-8"))
    payload["a_section_no_model_knows"] = {"x": 1}
    path.write_text(json.dumps(payload), encoding="utf-8")
    settings = Settings.from_json(path)
    assert not hasattr(settings, "a_section_no_model_knows")


def test_missing_mandatory_section_is_a_validation_error() -> None:
    with pytest.raises(ValidationError):
        Settings(influx=InfluxConfig(url="http://influx:8181"))  # type: ignore[call-arg]


# ── server section ─────────────────────────────────────────────────────


def test_transport_override_replaces_the_config_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_TRANSPORT", "stdio")
    assert _bare_settings().with_env_overrides().server.transport == "stdio"


def test_unknown_transport_keeps_the_configured_value(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_TRANSPORT", "carrier-pigeon")
    assert _bare_settings().with_env_overrides().server.transport == "streamable-http"


def test_force_timeout_override_and_fallback(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_FORCE_TIMEOUT", "2.5")
    assert _bare_settings().with_env_overrides().server.force_timeout_seconds == 2.5
    monkeypatch.setenv("OTALON_MCP_FORCE_TIMEOUT", "not-a-number")
    assert _bare_settings().with_env_overrides().server.force_timeout_seconds == 8.0


# ── influx section, incl. the legacy alias pair ────────────────────────


def test_influx_db_alias_prefers_the_namespaced_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_INFLUX_DB", "primary")
    monkeypatch.setenv("INFLUX_DATABASE", "legacy")
    assert _bare_settings().with_env_overrides().influx.database == "primary"


def test_influx_db_alias_falls_back_to_the_legacy_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("INFLUX_DATABASE", "legacy")
    assert _bare_settings().with_env_overrides().influx.database == "legacy"


def test_influx_db_defaults_to_netcap() -> None:
    assert _bare_settings().with_env_overrides().influx.database == "netcap"


def test_influx_measurement_and_id_tag_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_INFLUX_MEASUREMENT", "other_metrics")
    monkeypatch.setenv("OTALON_MCP_INFLUX_ID_TAG", "device")
    influx = _bare_settings().with_env_overrides().influx
    assert influx.measurement == "other_metrics"
    assert influx.id_tag == "device"


def test_influx_fields_override_accepts_json_and_csv(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_INFLUX_FIELDS", '["a", "b"]')
    assert _bare_settings().with_env_overrides().influx.fields == ["a", "b"]
    monkeypatch.setenv("OTALON_MCP_INFLUX_FIELDS", "a, b ,c")
    assert _bare_settings().with_env_overrides().influx.fields == ["a", "b", "c"]


def test_influx_fields_keeps_defaults_on_unusable_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_INFLUX_FIELDS", "   ")
    fields = _bare_settings().with_env_overrides().influx.fields
    assert fields[0] == "packet_count" and len(fields) == 10


@pytest.mark.parametrize("raw", [None, "", "   ", "single-token", "{}"])
def test_parse_influx_fields_returns_none_when_unusable(raw: str | None) -> None:
    assert parse_influx_fields(raw) is None


# ── otalon-api: one field, one default, four former call sites ─────────


def test_otalon_api_url_and_key_resolve_once(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_API_URL", "http://api.test:8090")
    monkeypatch.setenv("OTALON_API_KEY", "operator-key")
    api = _bare_settings().with_env_overrides().otalon_api
    assert api.url == "http://api.test:8090"
    assert api.api_key == "operator-key"


def test_otalon_api_has_a_single_url_default() -> None:
    api = _bare_settings().with_env_overrides().otalon_api
    assert api.url == "http://otalon-api:8090"


def test_otalon_api_key_has_no_default() -> None:
    """A credential never carries a fallback value."""
    assert _bare_settings().with_env_overrides().otalon_api.api_key == ""


def test_otalon_api_timeout_and_nonce_ttl(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_API_TIMEOUT_SECONDS", "42")
    monkeypatch.setenv("OTALON_MCP_CONFIRM_NONCE_TTL", "600")
    api = _bare_settings().with_env_overrides().otalon_api
    assert api.timeout_seconds == 42.0
    assert api.confirm_nonce_ttl_seconds == 600.0


def test_nonce_ttl_is_clamped_to_one_second(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OTALON_MCP_CONFIRM_NONCE_TTL", "0")
    assert _bare_settings().with_env_overrides().otalon_api.confirm_nonce_ttl_seconds == 1.0


# ── agent: the AGENT_URL / AI_URL alias pair ───────────────────────────


def test_agent_url_prefers_the_legacy_alias(monkeypatch: pytest.MonkeyPatch) -> None:
    """``AGENT_URL`` won at runtime before MCP-014 and still does."""
    monkeypatch.setenv("AGENT_URL", "http://legacy:9100")
    monkeypatch.setenv("AI_URL", "http://otalon-ai:9100")
    assert _bare_settings().with_env_overrides().agent.url == "http://legacy:9100"


def test_agent_url_falls_back_to_ai_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AI_URL", "http://otalon-ai:9100")
    assert _bare_settings().with_env_overrides().agent.url == "http://otalon-ai:9100"


def test_agent_url_is_empty_when_neither_is_set() -> None:
    assert _bare_settings().with_env_overrides().agent.url == ""


def test_agent_timeout_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_PROXY_TIMEOUT_SECONDS", "1.5")
    assert _bare_settings().with_env_overrides().agent.timeout_seconds == 1.5


# ── pcap recorder credential + baseline directory ──────────────────────


def test_recorder_key_prefers_the_recorder_specific_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PCAP_RECORDER_API_KEY", "recorder-key")
    monkeypatch.setenv("ADMIN_API_KEY", "admin-key")
    assert _bare_settings().with_env_overrides().pcap_recorder.api_key == "recorder-key"


def test_recorder_key_falls_back_to_admin_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("ADMIN_API_KEY", "admin-key")
    assert _bare_settings().with_env_overrides().pcap_recorder.api_key == "admin-key"


def test_recorder_key_has_no_default() -> None:
    assert _bare_settings().with_env_overrides().pcap_recorder.api_key == ""


def test_baseline_directory_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("PCAP_BASELINE_DIR", "/data/baseline")
    assert _bare_settings().with_env_overrides().baseline.directory == "/data/baseline"


def test_baseline_directory_default() -> None:
    assert _bare_settings().with_env_overrides().baseline.directory == "/app/pcap/baseline"


# ── no raw configuration reads remain outside the settings module ──────


def test_only_the_settings_module_reads_the_environment() -> None:
    """Every ``os.environ`` hit under ``src/`` lives in ``settings.py``."""
    src = Path(__file__).resolve().parents[1] / "src" / "otalon_mcp"
    offenders = [
        path.relative_to(src).as_posix()
        for path in src.rglob("*.py")
        if path.name != "settings.py"
        and ("os.environ" in path.read_text(encoding="utf-8") or "os.getenv" in path.read_text(encoding="utf-8"))
    ]
    assert offenders == []


def test_the_shipped_config_declares_every_migrated_section() -> None:
    """``config/config.json`` carries the sections the model expects."""
    path = Path(__file__).resolve().parents[1] / "config" / "config.json"
    payload = json.loads(path.read_text(encoding="utf-8"))
    for section in (
        "server",
        "postgres",
        "influx",
        "logging",
        "pcap_recorder",
        "baseline",
        "agent",
        "otalon_api",
        "mitre",
    ):
        assert section in payload, section


def test_env_vars_list_matches_the_settings_module() -> None:
    """Guard against a new raw lookup being added without a test."""
    source = (Path(__file__).resolve().parents[1] / "src" / "otalon_mcp" / "settings.py").read_text(encoding="utf-8")
    assert source.count("os.environ") == 1, "settings.py must keep a single raw lookup helper"
    assert "PCAP_RECORDER_API_KEY" in source
    assert os.environ.get("OTALON_MCP_TRANSPORT") is None
