"""Unit tests for :class:`RuntimeConfigRepository`.

Covers precedence resolution, secret-key denial, the v1 allow-list +
typed/domain validation (audit B-09), and one-step rollback via
``value_prev``.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from otalon_common.runtime import reset_registry

from otalon_clas.common.postgres_connector import PostgresConnector, RuntimeConfig
from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository
from otalon_clas.runtime.runtime_keys import register_runtime_keys

_SERVICE = "otalon-clas"
_BOOL_KEY = "training.retrain_paused"
_QUANTILE_KEY = "training.default_quantile"


@pytest.fixture(autouse=True)
def _isolated_runtime_registry() -> Iterator[None]:
    """Reset and register otalon-clas keys around each repository test."""
    reset_registry()
    register_runtime_keys()
    yield
    reset_registry()


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    db_path = tmp_path / "runtime_config.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    RuntimeConfig.__table__.create(pg.engine, checkfirst=True)
    return pg


def test_get_returns_default_when_absent(tmp_path: Path) -> None:
    """Missing rows fall back to the env/config default (precedence)."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    assert repo.get(_SERVICE, _BOOL_KEY, default="fallback") == "fallback"


def test_persisted_value_wins_over_default(tmp_path: Path) -> None:
    """A persisted row wins over the env/config default at runtime."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    repo.upsert(_SERVICE, _BOOL_KEY, "true")
    assert repo.get(_SERVICE, _BOOL_KEY, default="false") == "true"


def test_get_bool_parses_stored_strings(tmp_path: Path) -> None:
    """Boolean values are parsed from stored strings."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    repo.upsert(_SERVICE, _BOOL_KEY, "true")
    assert repo.get_bool(_SERVICE, _BOOL_KEY, default=False) is True
    repo.upsert(_SERVICE, _BOOL_KEY, "0")
    assert repo.get_bool(_SERVICE, _BOOL_KEY, default=True) is False


def test_upsert_moves_prior_value_to_value_prev(tmp_path: Path) -> None:
    """Updating a row retains the previous value for rollback."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    repo.upsert(_SERVICE, _QUANTILE_KEY, "0.001", updated_by="op1")
    repo.upsert(_SERVICE, _QUANTILE_KEY, "0.01", updated_by="op2")

    with pg.session() as session:
        row = session.get(RuntimeConfig, {"service": _SERVICE, "key": _QUANTILE_KEY})
        assert row is not None
        assert row.value == "0.01"
        assert row.value_prev == "0.001"
        assert row.updated_by == "op2"


def test_secret_key_is_rejected(tmp_path: Path) -> None:
    """Keys matching secret patterns cannot be persisted."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    for bad in ("INFLUX_TOKEN", "POSTGRES_PASSWORD", "API_KEY", "CLIENT_SECRET"):
        with pytest.raises(ValueError, match="secret-looking"):
            repo.upsert(_SERVICE, bad, "leak")


def test_unknown_key_is_rejected(tmp_path: Path) -> None:
    """Keys outside the v1 allow-list are rejected (no arbitrary keys)."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    with pytest.raises(ValueError, match="allow-list"):
        repo.upsert(_SERVICE, "training.some_typo", "true")
    with pytest.raises(ValueError, match="allow-list"):
        repo.upsert("other-service", _BOOL_KEY, "true")


def test_typed_domain_validation(tmp_path: Path) -> None:
    """Allow-listed keys enforce their value domain."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    with pytest.raises(ValueError, match="boolean literal"):
        repo.upsert(_SERVICE, _BOOL_KEY, "sometimes")
    with pytest.raises(ValueError, match="float"):
        repo.upsert(_SERVICE, _QUANTILE_KEY, "not-a-number")
    with pytest.raises(ValueError, match="in .0, 0.5"):
        repo.upsert(_SERVICE, _QUANTILE_KEY, "0.9")
    # Valid values are accepted.
    repo.upsert(_SERVICE, _QUANTILE_KEY, "0.0001")
    assert repo.get_float(_SERVICE, _QUANTILE_KEY) == 0.0001
