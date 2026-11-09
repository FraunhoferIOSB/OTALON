"""otalon-ai runtime keys: registrations must match the shared manifest (AI-045)."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from otalon_common.runtime import (
    OTALON_AI_SERVICE,
    manifest_for_service,
    validate_write,
)
from otalon_common.runtime.registry import all_specs, reset_registry

from otalon_ai.runtime_keys import register_runtime_keys


@pytest.fixture(autouse=True)
def _isolated_runtime_registry() -> Iterator[None]:
    """Reset the registry and register otalon-ai keys for each test."""
    reset_registry()
    register_runtime_keys()
    yield
    reset_registry()


@pytest.mark.unit
def test_registrations_match_manifest_slice() -> None:
    """Every otalon-ai registration mirrors its manifest declaration exactly."""
    registered = sorted(
        (spec.key, spec.value_type, spec.domain, spec.description)
        for spec in all_specs()
        if spec.service == OTALON_AI_SERVICE
    )
    expected = sorted(
        (entry.key, entry.value_type, entry.domain, entry.description)
        for entry in manifest_for_service(OTALON_AI_SERVICE)
    )
    assert registered == expected
    assert len(registered) == 5


@pytest.mark.unit
def test_secret_key_is_never_registered() -> None:
    """The API key is a secret: it must stay out of runtime_config entirely."""
    with pytest.raises(ValueError):
        validate_write(OTALON_AI_SERVICE, "LITELLM_API_KEY", "sk-test")


@pytest.mark.unit
def test_endpoint_rejects_non_http_scheme() -> None:
    """A non-http(s) endpoint is refused before it can reach the database."""
    with pytest.raises(ValueError):
        validate_write(OTALON_AI_SERVICE, "ai.endpoint", "ftp://example.com/v1")


@pytest.mark.unit
def test_model_rejects_blank_value() -> None:
    """A blank model name is refused."""
    with pytest.raises(ValueError):
        validate_write(OTALON_AI_SERVICE, "ai.chat_model", "   ")


class _FakeCursor:
    def __init__(self, rows):
        self._rows = rows

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params):
        self.sql = sql
        self.params = params

    def fetchall(self):
        return self._rows


class _FakeConn:
    def __init__(self, rows):
        self._rows = rows

    def cursor(self):
        return _FakeCursor(self._rows)


class _FakeDatabase:
    def __init__(self, rows=None, fail=False):
        self._rows = rows or []
        self._fail = fail

    def chat_connection(self):
        if self._fail:
            raise RuntimeError("db unreachable")
        from contextlib import contextmanager

        rows = self._rows

        @contextmanager
        def _cm():
            yield _FakeConn(rows)

        return _cm()


@pytest.mark.unit
def test_saved_ai_values_are_read_from_runtime_config() -> None:
    """AI-045: the saved model wins over the env bootstrap after a restart."""
    from otalon_ai.runtime_keys import load_saved_ai_values

    db = _FakeDatabase(
        rows=[("ai.chat_model", "gpt-6-astra"), ("ai.job_model", "FW-GLM-5.3-Flash")]
    )
    values = load_saved_ai_values(db)
    assert values == {
        "ai.chat_model": "gpt-6-astra",
        "ai.job_model": "FW-GLM-5.3-Flash",
    }


@pytest.mark.unit
def test_unreachable_database_keeps_env_value_and_does_not_raise() -> None:
    """Gegenprobe: a DB failure at startup must not stop the service; env stays in effect."""
    from otalon_ai.runtime_keys import load_saved_ai_values

    assert load_saved_ai_values(_FakeDatabase(fail=True)) == {}


@pytest.mark.unit
def test_empty_saved_value_is_ignored() -> None:
    """A row with an empty value must not overwrite the env bootstrap."""
    from otalon_ai.runtime_keys import load_saved_ai_values

    db = _FakeDatabase(rows=[("ai.chat_model", ""), ("ai.job_model", None)])
    assert load_saved_ai_values(db) == {}


@pytest.mark.unit
def test_saved_context_window_accepts_a_valid_value() -> None:
    """AI-046: a saved context window in range is applied at startup."""
    from otalon_ai.runtime_keys import saved_context_window

    assert saved_context_window("256000") == 256000
    assert saved_context_window(" 4096 ") == 4096
    assert saved_context_window("1000000") == 1000000


@pytest.mark.unit
@pytest.mark.parametrize("raw", [None, "", "abc", "100", "99999999", "4095", "1000001"])
def test_saved_context_window_rejects_absent_corrupt_or_out_of_range(
    raw: str | None,
) -> None:
    """Gegenprobe: anything unusable returns None so the env default stays in place."""
    from otalon_ai.runtime_keys import saved_context_window

    assert saved_context_window(raw) is None
