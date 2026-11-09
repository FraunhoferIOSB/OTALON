"""Unit tests for :class:`PortRuleRefreshConfig` (CLAS-033 Wave C).

Covers the static spec defaults and the ``runtime_config`` hot-override
resolution path: persisted rows win over the static defaults while absent
keys keep their defaults.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import pytest
from otalon_common.runtime import reset_registry

from otalon_clas.common.postgres_connector import PostgresConnector, RuntimeConfig
from otalon_clas.common.settings import PortRuleRefreshConfig
from otalon_clas.runtime.runtime_config_repository import RuntimeConfigRepository
from otalon_clas.runtime.runtime_keys import register_runtime_keys

_SERVICE = "otalon-clas"
_PREFIX = "detection.conn.port_rule_refresh"


@pytest.fixture(autouse=True)
def _isolated_runtime_registry() -> Iterator[None]:
    """Reset and register otalon-clas keys around each test."""
    reset_registry()
    register_runtime_keys()
    yield
    reset_registry()


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    db_path = tmp_path / "port_rule_refresh.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    RuntimeConfig.__table__.create(pg.engine, checkfirst=True)
    return pg


def test_defaults_match_spec() -> None:
    """The static defaults match the CLAS-033 spec."""
    cfg = PortRuleRefreshConfig()
    assert cfg.enabled is True
    assert cfg.interval_seconds == 300
    assert cfg.lookback_hours == 6
    assert cfg.confirm_cycles == 2
    assert cfg.min_samples == 2
    assert cfg.rotation_distinct_ports == 3


def test_resolve_falls_back_to_defaults_when_no_overrides(tmp_path: Path) -> None:
    """With no runtime_config rows, resolve returns the static defaults."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)

    effective = PortRuleRefreshConfig().resolve(repo)

    assert effective == PortRuleRefreshConfig()


def test_resolve_applies_full_hot_override(tmp_path: Path) -> None:
    """Every persisted override wins over the static defaults."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    repo.upsert(_SERVICE, f"{_PREFIX}.enabled", "false")
    repo.upsert(_SERVICE, f"{_PREFIX}.interval_seconds", "600")
    repo.upsert(_SERVICE, f"{_PREFIX}.lookback_hours", "24")
    repo.upsert(_SERVICE, f"{_PREFIX}.confirm_cycles", "4")
    repo.upsert(_SERVICE, f"{_PREFIX}.min_samples", "10")
    repo.upsert(_SERVICE, f"{_PREFIX}.rotation_distinct_ports", "5")

    effective = PortRuleRefreshConfig().resolve(repo)

    assert effective.enabled is False
    assert effective.interval_seconds == 600
    assert effective.lookback_hours == 24
    assert effective.confirm_cycles == 4
    assert effective.min_samples == 10
    assert effective.rotation_distinct_ports == 5


def test_resolve_partial_override_keeps_other_defaults(tmp_path: Path) -> None:
    """A subset of overrides leaves the remaining keys at their defaults."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    repo.upsert(_SERVICE, f"{_PREFIX}.interval_seconds", "120")
    repo.upsert(_SERVICE, f"{_PREFIX}.confirm_cycles", "1")

    effective = PortRuleRefreshConfig().resolve(repo)

    assert effective.enabled is True
    assert effective.interval_seconds == 120
    assert effective.lookback_hours == 6
    assert effective.confirm_cycles == 1
    assert effective.min_samples == 2
    assert effective.rotation_distinct_ports == 3


def test_resolve_does_not_mutate_original_config(tmp_path: Path) -> None:
    """resolve returns a new instance; the source config is untouched."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RuntimeConfigRepository(pg)
    repo.upsert(_SERVICE, f"{_PREFIX}.enabled", "false")
    original = PortRuleRefreshConfig()

    effective = original.resolve(repo)

    assert effective is not original
    assert original.enabled is True
    assert original.rotation_distinct_ports == 3
    assert effective.enabled is False
