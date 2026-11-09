"""Unit tests for :mod:`src.settings`.

Coverage focus: Cluster d / B8 (fail-fast on missing LLM env). The
``LiteLLMConfig`` model SHALL reject empty / missing values for
``base_url`` and ``api_key`` rather than defaulting to the unsafe
localhost + ``sk-no-key`` pair that the previous implementation used,
and :meth:`Settings._apply_legacy_env_fallbacks` SHALL surface the
clearer ``RuntimeError`` BEFORE Pydantic validation runs.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

import pytest

from otalon_ai.settings import ChatConfig, LiteLLMConfig, Settings

# ── LiteLLMConfig validator ─────────────────────────────────────────────


def test_b8_litellm_config_requires_base_url() -> None:
    """An empty base_url MUST raise a ValueError at model validation."""
    with pytest.raises(ValueError) as exc_info:
        LiteLLMConfig(base_url="", api_key="sk-real")
    msg = str(exc_info.value)
    assert "base_url" in msg
    # The error message mentions the env var and the security rationale.
    assert "LITELLM_BASE_URL" in msg


def test_b8_litellm_config_requires_api_key() -> None:
    """An empty api_key MUST raise a ValueError at model validation."""
    with pytest.raises(ValueError) as exc_info:
        LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="")
    msg = str(exc_info.value)
    assert "api_key" in msg
    assert "LITELLM_API_KEY" in msg


def test_b8_litellm_config_rejects_whitespace_only() -> None:
    """Whitespace-only env (a common trap when an env file has a stray space)
    MUST be treated as missing, not as a valid override.
    """
    with pytest.raises(ValueError):
        LiteLLMConfig(base_url="   ", api_key="sk-real")
    with pytest.raises(ValueError):
        LiteLLMConfig(base_url="http://x/v1", api_key="\t\n")


def test_b8_litellm_config_no_longer_has_localhost_default() -> None:
    """Regression: instantiating without arguments MUST fail. The previous
    implementation accepted a default ``host.docker.internal:4000`` +
    ``sk-no-key`` pair which silently routed classifier traffic to the
    operator's localhost when the env was forgotten.
    """
    with pytest.raises(Exception):
        # Pydantic raises ``ValidationError`` (subclass of ValueError /
        # Exception) when required fields are missing.
        LiteLLMConfig()  # type: ignore[call-arg]


def test_b8_litellm_config_accepts_real_values() -> None:
    """Sanity: well-formed values MUST construct without error."""
    cfg = LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-real-token")
    assert cfg.base_url == "http://litellm:4000/v1"
    assert cfg.api_key == "sk-real-token"


# ── _apply_legacy_env_fallbacks fail-fast path ─────────────────────────


def _baseline_jobs_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set the AGENT/JOBS env vars so the JOBS_LLM_MODEL gate passes; we
    are only probing the LITELLM_* gate in these tests.
    """
    monkeypatch.setenv("JOBS_LLM_MODEL", "azure/gpt-5.4")


def test_b8_fail_fast_when_litellm_base_url_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _baseline_jobs_env(monkeypatch)
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.setenv("LITELLM_API_KEY", "sk-real")

    with pytest.raises(RuntimeError) as exc_info:
        Settings._apply_legacy_env_fallbacks()
    msg = str(exc_info.value)
    assert "LITELLM_BASE_URL" in msg
    # The error explains WHY it fails-fast.
    assert "fails fast" in msg.lower() or "default" in msg.lower()


def test_b8_fail_fast_when_litellm_api_key_missing(monkeypatch: pytest.MonkeyPatch) -> None:
    _baseline_jobs_env(monkeypatch)
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        Settings._apply_legacy_env_fallbacks()
    assert "LITELLM_API_KEY" in str(exc_info.value)


def test_b8_fail_fast_lists_all_missing_vars(monkeypatch: pytest.MonkeyPatch) -> None:
    _baseline_jobs_env(monkeypatch)
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)

    with pytest.raises(RuntimeError) as exc_info:
        Settings._apply_legacy_env_fallbacks()
    msg = str(exc_info.value)
    # Both names appear so the operator sees the full list in one shot.
    assert "LITELLM_BASE_URL" in msg
    assert "LITELLM_API_KEY" in msg


def test_b8_passes_when_both_litellm_vars_set(monkeypatch: pytest.MonkeyPatch) -> None:
    """Sanity check: the gate stays out of the way when env is well-formed."""
    _baseline_jobs_env(monkeypatch)
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "sk-real")
    # MUST NOT raise.
    Settings._apply_legacy_env_fallbacks()


# ── End-to-end via Settings.from_json ─────────────────────────────────


def _write_config(tmp_path: Path, overrides: Dict[str, Any] | None = None) -> Path:
    """Materialise a minimal config.json that exercises env-resolution."""
    cfg: Dict[str, Any] = {
        "server": {"name": "otalon-ai", "host": "0.0.0.0", "port": 9100},
        "litellm": {"base_url": "$LITELLM_BASE_URL", "api_key": "$LITELLM_API_KEY"},
        "mcp": {"servers": [{"name": "m", "url": "http://mcp:9000"}], "request_timeout_seconds": 60},
        "db": {"dsn": "postgresql://x:x@h/d"},
        "chat": {
            "llm_model": "azure/gpt-5.4",
            "history_window": 20,
            "retention_days": 30,
            "max_tool_rounds": 12,
            "model_context_window": 128000,
            "allowed_tools": [],
        },
        "jobs": {
            "llm_model": "azure/gpt-5.4",
            "default_prompt": "expert",
            "timeout_seconds": 600,
            "n_workers": 4,
            "log_level": "INFO",
            "allowed_tools": ["postgres.read_anomalies"],
        },
        "logging": {"level": "INFO", "file": None},
    }
    if overrides:
        cfg.update(overrides)
    path = tmp_path / "config.json"
    path.write_text(json.dumps(cfg), encoding="utf-8")
    return path


def test_b8_from_json_raises_runtime_error_when_env_missing(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end: ``Settings.from_json`` SHALL surface the clear
    ``RuntimeError`` from :meth:`_apply_legacy_env_fallbacks` rather
    than allowing a default localhost / sk-no-key fallback to slip
    through into the LLM provider.
    """
    monkeypatch.setenv("JOBS_LLM_MODEL", "azure/gpt-5.4")
    monkeypatch.delenv("LITELLM_BASE_URL", raising=False)
    monkeypatch.delenv("LITELLM_API_KEY", raising=False)
    path = _write_config(tmp_path)
    with pytest.raises(RuntimeError) as exc_info:
        Settings.from_json(path)
    assert "LITELLM_BASE_URL" in str(exc_info.value)


def test_b8_from_json_succeeds_with_real_env(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """End-to-end happy path: real env values yield a fully-validated Settings."""
    monkeypatch.setenv("JOBS_LLM_MODEL", "azure/gpt-5.4")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "sk-real")
    path = _write_config(tmp_path)
    settings = Settings.from_json(path)
    assert settings.litellm.base_url == "http://litellm:4000/v1"
    assert settings.litellm.api_key == "sk-real"


def test_chat_config_default_context_window() -> None:
    """``model_context_window`` defaults to 128000 when not specified."""
    cfg = ChatConfig()
    assert cfg.model_context_window == 128000


def test_chat_config_explicit_context_window() -> None:
    """``model_context_window`` accepts an explicit value."""
    cfg = ChatConfig(model_context_window=256000)
    assert cfg.model_context_window == 256000


def test_chat_allowed_tools_from_real_config(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Loading the real config.json yields a read-only allow-list.

    The single exception is the operator retrain namespace
    (``training.retrain_boundaries`` / ``training.retrain_classifier`` /
    ``training.get_retrain_status``):
    per the runtime-retraining spec these are chat-triggered
    operator actions and MUST be present, so the "no mutating tool"
    guard below whitelists them explicitly (AI-014).
    """
    monkeypatch.setenv("JOBS_LLM_MODEL", "azure/gpt-5.4")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "sk-real")
    import json as _json

    real = _json.loads(Path("config/config.json").read_text())
    # Stub env placeholders so Pydantic validation passes.
    real["server"]["port"] = 9100
    real["mcp"]["servers"][0]["url"] = "http://mcp:9000"
    real["mcp"]["servers"][0]["api_key"] = "fake-mcp-consumer-key"
    real["db"]["dsn"] = "postgresql://x:x@h/d"
    real["chat"]["llm_model"] = "azure/gpt-5.4"
    real["chat"]["history_window"] = 20
    real["chat"]["retention_days"] = 30
    real["chat"]["max_tool_rounds"] = 12
    real["chat"]["model_context_window"] = 128000
    real["jobs"]["default_prompt"] = "expert"
    real["jobs"]["timeout_seconds"] = 600
    real["jobs"]["n_workers"] = 4
    real["jobs"]["log_level"] = "INFO"
    real["logging"]["level"] = "INFO"
    cfg_path = tmp_path / "config.json"
    cfg_path.write_text(_json.dumps(real), encoding="utf-8")
    settings = Settings.from_json(cfg_path)
    tools = settings.chat.allowed_tools
    assert isinstance(tools, list)
    assert "postgres.read_alarm_details" in tools
    import re

    # The boundary-retrain tools are the deliberate, spec-required
    # exception to the read-only rule (AI-014): they are chat-triggered
    # operator actions gated by a confirmation-first system prompt and
    # an api-side single-flight lock, not autonomous mutations.
    retrain_allowlist = {
        "training.retrain_boundaries",
        "training.retrain_classifier",
        "training.get_retrain_status",
    }
    mutating = re.compile(
        r"write|add_|update_|delete_|remove_|replace_|expand_|flag_|retrain|update_stix|classify_alert"
    )
    for t in tools:
        if t in retrain_allowlist:
            continue
        assert not mutating.search(t), f"mutating tool {t} in allow-list"
    assert "chat" not in tools
    # Positive assertion: the retrain tools ARE reachable from chat.
    assert retrain_allowlist.issubset(set(tools))


# ── AI-017: forensic prompt variant in default_prompt ──────────────


def test_jobs_config_accepts_forensic_default_prompt(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """``JobsConfig.default_prompt`` accepts 'forensic' (AI-017)."""
    monkeypatch.setenv("JOBS_LLM_MODEL", "azure/gpt-5.4")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "sk-real")
    path = _write_config(tmp_path)
    real = json.loads(path.read_text())
    real["jobs"]["default_prompt"] = "forensic"
    path.write_text(json.dumps(real), encoding="utf-8")
    settings = Settings.from_json(path)
    assert settings.jobs.default_prompt == "forensic"


def test_jobs_config_rejects_unknown_prompt_variant() -> None:
    """An unknown default_prompt value is rejected by Pydantic."""
    from otalon_ai.settings import JobsConfig

    with pytest.raises(Exception):
        JobsConfig(
            llm_model="azure/gpt-5.4",
            default_prompt="not-a-variant",  # type: ignore[arg-type]
            timeout_seconds=60,
            n_workers=1,
            log_level="INFO",
            allowed_tools=[],
        )


# ── AI-045 Task 1.1: Settings.with_llm_overrides ──────────────────────


def _write_env_for_overrides(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> Path:
    """Write a minimal config.json and set the env vars for override tests."""
    monkeypatch.setenv("JOBS_LLM_MODEL", "azure/gpt-5.4")
    monkeypatch.setenv("LITELLM_BASE_URL", "http://litellm:4000/v1")
    monkeypatch.setenv("LITELLM_API_KEY", "sk-real")
    return _write_config(tmp_path)


def test_with_llm_overrides_returns_new_instance(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The original settings stay unchanged; the copy carries the overrides."""
    _write_env_for_overrides(monkeypatch, tmp_path)
    base = Settings.from_json(tmp_path / "config.json")
    new = base.with_llm_overrides(chat_model="claude-opus-5-5", job_model="gpt-5.5")
    assert new is not base
    assert new.chat.llm_model == "claude-opus-5-5"
    assert new.jobs.llm_model == "gpt-5.5"
    # The ORIGINAL instance is untouched (design.md D3).
    assert base.chat.llm_model == "azure/gpt-5.4"
    assert base.jobs.llm_model == "azure/gpt-5.4"


def test_with_llm_overrides_none_keeps_current_values(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """All-None kwargs yield a copy with identical LLM sections."""
    _write_env_for_overrides(monkeypatch, tmp_path)
    base = Settings.from_json(tmp_path / "config.json")
    new = base.with_llm_overrides()
    # Copy, not the same identity — the swap stays a reference change.
    assert new is not base
    assert new.litellm == base.litellm
    assert new.chat == base.chat
    assert new.jobs == base.jobs


def test_with_llm_overrides_base_url_swaps_and_revalidates(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """base_url override replaces the litellm section and keeps the key."""
    _write_env_for_overrides(monkeypatch, tmp_path)
    base = Settings.from_json(tmp_path / "config.json")
    new = base.with_llm_overrides(base_url="http://litellm2:4000/v1")
    assert new.litellm.base_url == "http://litellm2:4000/v1"
    assert new.litellm.api_key == base.litellm.api_key


def test_with_llm_overrides_reasoning_efforts(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Chat and jobs reasoning efforts override independently."""
    _write_env_for_overrides(monkeypatch, tmp_path)
    base = Settings.from_json(tmp_path / "config.json")
    new = base.with_llm_overrides(
        chat_reasoning_effort="low",
        job_reasoning_effort="high",
    )
    assert new.chat.llm_reasoning_effort == "low"
    assert new.jobs.llm_reasoning_effort == "high"
    # Original untouched.
    assert base.chat.llm_reasoning_effort is None
    assert base.jobs.llm_reasoning_effort is None


def test_with_llm_overrides_invalid_base_url_raises(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """An empty override fails validation BEFORE the callers swap anything."""
    _write_env_for_overrides(monkeypatch, tmp_path)
    base = Settings.from_json(tmp_path / "config.json")
    with pytest.raises(ValueError):
        base.with_llm_overrides(base_url="   ")
    # The original settings remain usable.
    assert base.litellm.base_url == "http://litellm:4000/v1"
