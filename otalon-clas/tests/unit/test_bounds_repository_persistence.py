"""Unit tests for :class:`BoundsRepository` persistence semantics.

Covers CLAS-010: a retrain must REPLACE a module's bounds atomically
(delete-then-insert in a single transaction), so no stale series from a
prior training survive. The tests seed a module, then re-save with a
different set of series and assert PostgreSQL ends up with EXACTLY the
freshly trained series, while other modules are untouched.

The tests run against an in-memory SQLite database. The ``bounds`` ORM
model uses only JSON/DateTime/String columns, so the SQLite dialect is
sufficient to verify the delete-then-insert transaction semantics.
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

import pytest

from otalon_clas.common.postgres_connector import Bound, PostgresConnector
from otalon_clas.detection.bounds_manager import BoundsManager, BoundsRepository
from otalon_clas.runtime.training_helpers import BoundsCandidate, publish_bounds_candidate


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file.

    Only the ``bounds`` table is created; the rest of the schema is not
    needed for these tests and some sibling ORM models use PG-specific
    column types that don't compile under SQLite.
    """
    db_path = tmp_path / "bounds.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    Bound.__table__.create(pg.engine, checkfirst=True)
    return pg


def _bounds(*series_ids: str) -> dict[str, dict[str, tuple[float, float]]]:
    """Build a bounds dict assigning a trivial (0.0, 1.0) bound per series."""
    return {sid: {"bytes": (0.0, 1.0)} for sid in series_ids}


def _series_for_module(pg: PostgresConnector, module: str) -> set[str]:
    """Return the set of series_ids persisted for a module."""
    with pg.session() as session:
        rows = session.query(Bound).filter(Bound.module == module).all()
        return {str(row.series_id) for row in rows}


def test_save_replace_removes_stale_series(tmp_path: Path) -> None:
    """Retrain with replace=True drops series absent from the new bounds."""
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    now = datetime.now(tz=timezone.utc)

    repo.save(module="M", bounds=_bounds("A", "B", "C"), last_ts=now)
    assert _series_for_module(pg, "M") == {"A", "B", "C"}

    repo.save(module="M", bounds=_bounds("A", "B"), last_ts=now, replace=True)
    assert _series_for_module(pg, "M") == {"A", "B"}


def test_save_replace_swaps_series(tmp_path: Path) -> None:
    """Retrain with a disjoint series set fully replaces the module bounds."""
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    now = datetime.now(tz=timezone.utc)

    repo.save(module="M", bounds=_bounds("A", "B", "C"), last_ts=now)
    repo.save(module="M", bounds=_bounds("A", "D"), last_ts=now, replace=True)
    assert _series_for_module(pg, "M") == {"A", "D"}


def test_save_replace_leaves_other_modules_untouched(tmp_path: Path) -> None:
    """replace=True on one module never deletes another module's bounds."""
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    now = datetime.now(tz=timezone.utc)

    repo.save(module="M", bounds=_bounds("A", "B", "C"), last_ts=now)
    repo.save(module="N", bounds=_bounds("X", "Y"), last_ts=now)

    repo.save(module="M", bounds=_bounds("A"), last_ts=now, replace=True)

    assert _series_for_module(pg, "M") == {"A"}
    assert _series_for_module(pg, "N") == {"X", "Y"}


def test_save_without_replace_keeps_legacy_upsert(tmp_path: Path) -> None:
    """Default replace=False preserves the per-series upsert behaviour."""
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    now = datetime.now(tz=timezone.utc)

    repo.save(module="M", bounds=_bounds("A", "B", "C"), last_ts=now)
    repo.save(module="M", bounds=_bounds("A", "B"), last_ts=now)
    assert _series_for_module(pg, "M") == {"A", "B", "C"}


def test_save_replace_empty_bounds_raises_and_keeps_series(
    tmp_path: Path,
) -> None:
    """replace=True with empty bounds refuses loudly, leaving DB untouched.

    Covers CLAS-011: an empty retrain window must not silently skip the
    delete (keeping stale series) nor silently wipe the module. The raise
    happens before the transaction, so previously trained series survive.
    """
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    now = datetime.now(tz=timezone.utc)

    repo.save(module="M", bounds=_bounds("A", "B", "C"), last_ts=now)

    with pytest.raises(ValueError, match="refusing replace=True with empty"):
        repo.save(module="M", bounds={}, last_ts=now, replace=True)

    assert _series_for_module(pg, "M") == {"A", "B", "C"}


def test_save_empty_bounds_without_replace_is_noop(tmp_path: Path) -> None:
    """replace=False with empty bounds is a harmless no-op returning 0."""
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    now = datetime.now(tz=timezone.utc)

    repo.save(module="M", bounds=_bounds("A", "B"), last_ts=now)

    assert repo.save(module="M", bounds={}, last_ts=now) == 0
    assert _series_for_module(pg, "M") == {"A", "B"}


def test_publish_bounds_save_failure_keeps_real_cache_and_rows(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Persist-first bounds publication exposes no candidate on save failure."""
    pg = _make_sqlite_connector(tmp_path)
    repo = BoundsRepository(connector=pg)
    prior = _bounds("prior")
    repo.save("M", prior)
    manager = BoundsManager("M", repository=repo)
    manager.load_bounds(prior)
    candidate = BoundsCandidate("M", _bounds("candidate"), None, None)

    def fail_save(*args: object, **kwargs: object) -> int:
        raise OSError("injected bounds persistence failure")

    monkeypatch.setattr(repo, "save", fail_save)
    with pytest.raises(OSError, match="injected bounds"):
        publish_bounds_candidate(
            type("Bundle", (), {"bounds_repository": repo, "bounds_manager": manager})(),
            candidate,
        )

    assert repo.load("M") == prior
    assert manager._cache is not None
    assert manager._cache.bounds == prior
