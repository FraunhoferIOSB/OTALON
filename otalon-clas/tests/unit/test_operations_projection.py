"""Direct worker Operations-projection regression for runtime retrain.

These tests drive the real outer runner path
(:meth:`JobRunner.try_run` -> claim -> stage -> publish -> terminal) and
inject only the inner training success/failure via the same helper
fakes used by :mod:`test_job_runner`. They never call
``_sync_operations_job``, terminal helpers, rollback, or exception
handlers directly, so the canonical ``operations_jobs`` projection is
proven end-to-end through the producer boundary.

A faithful SQLite mirror of the canonical ``operations_jobs`` table
(owned by otalon-api in ``operations_schema.py``) is created so the
dialect-aware projection SQL executes against a real linked row. The PG
JSONB statement and the SQLite ``json_insert`` statement share the same
projection semantics (append one structured log entry, preserve prior
result), verified here on SQLite while the PG SQL stays native.
"""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import polars as pl
import pytest
from sqlalchemy import text

from otalon_clas.common.postgres_connector import (
    PostgresConnector,
    RetrainJob,
    RuntimeConfig,
)
from otalon_clas.runtime.job_runner import JobRunner
from otalon_clas.runtime.retrain_job_repository import RetrainJobRepository

_OPERATIONS_JOBS_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS operations_jobs (
    id              INTEGER PRIMARY KEY,
    display_id      TEXT NOT NULL,
    type            TEXT NOT NULL,
    title           TEXT NOT NULL,
    state           TEXT NOT NULL DEFAULT 'queued',
    trigger         TEXT NOT NULL,
    actor           TEXT,
    started_at      TEXT,
    ended_at        TEXT,
    phase_current   INTEGER,
    phase_total     INTEGER,
    phase_label     TEXT,
    latest_event    TEXT,
    params          TEXT NOT NULL DEFAULT '{}',
    log             TEXT NOT NULL DEFAULT '[]',
    error           TEXT,
    result          TEXT,
    can_cancel      INTEGER NOT NULL DEFAULT 0,
    can_retry       INTEGER NOT NULL DEFAULT 0,
    retried_as_id   INTEGER,
    idempotency_key TEXT
)
"""


class _FakeInflux:
    """Influx stub returning a non-empty real Polars frame per interval."""

    def fetch(self, start: str, stop: str) -> Any:
        return pl.DataFrame({"value": [1, 2, 3, 4, 5]})


class _FakePreprocessor:
    def preprocess_for_training(self, df: Any) -> Any:
        return df


class _FakeModuleConfig:
    def __init__(self, name: str = "conn") -> None:
        self.name = name
        self.bounds_enabled = True
        self.tag_key = "uci"

        class _Freq:
            enabled = True

        class _Cls:
            enabled = True

        self.frequency_monitor = _Freq()
        self.classification = _Cls()


class _FakeBundle:
    """Duck-typed bundle sufficient for JobRunner bounds staging."""

    def __init__(self, name: str = "conn") -> None:
        self.config = _FakeModuleConfig(name)
        self.influx = _FakeInflux()
        self.preprocessor = _FakePreprocessor()


def _make_connector(tmp_path: Path) -> PostgresConnector:
    """Build a SQLite connector with retrain + faithful operations tables."""
    db = tmp_path / "ops_projection.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db}", pool_size=1, max_overflow=0)
    RetrainJob.__table__.create(pg.engine, checkfirst=True)
    RuntimeConfig.__table__.create(pg.engine, checkfirst=True)
    with pg.session() as session:
        session.execute(text(_OPERATIONS_JOBS_SQLITE_DDL))
    return pg


def _seed_linked_job(pg: PostgresConnector, job_ref: str, operations_job_id: int) -> None:
    """Insert a canonical queued operations row plus a linked retrain job."""
    with pg.session() as session:
        session.execute(
            text(
                """
                INSERT INTO operations_jobs
                    (id, display_id, type, title, state, trigger, actor)
                VALUES
                    (:id, :display_id, 'training', 'Runtime retrain', 'queued',
                     'chat', 'operator')
                """
            ),
            {"id": operations_job_id, "display_id": f"J-{operations_job_id}"},
        )
    RetrainJobRepository(pg).insert_queued(
        job_ref=job_ref,
        scope="bounds_frequency",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
        requested_by="operator",
    )
    with pg.session() as session:
        row = session.query(RetrainJob).filter_by(job_ref=job_ref).one()
        row.operations_job_id = operations_job_id


def _make_runner(pg: PostgresConnector, bundles: list[_FakeBundle]) -> JobRunner:
    return JobRunner(
        config=object(),
        pg=pg,
        model_store=object(),
        bundles=bundles,  # type: ignore[arg-type]
    )


def _wait_terminal(repo: RetrainJobRepository, job_ref: str, timeout: float = 5.0) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        dto = repo.get(job_ref)
        if dto is not None and dto.state in {"succeeded", "failed"}:
            return dto
        time.sleep(0.02)
    return repo.get(job_ref)


def _read_operation(pg: PostgresConnector, operations_job_id: int) -> dict[str, Any]:
    with pg.session() as session:
        row = session.execute(
            text("SELECT * FROM operations_jobs WHERE id = :id"),
            {"id": operations_job_id},
        ).mappings()
        return dict(next(iter(row)))


@pytest.fixture()
def patched_helpers(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace bounds/frequency compute+publish helpers with fakes."""
    import otalon_clas.runtime.job_runner as jr

    class _Cand:
        def __init__(self, module: str) -> None:
            self.module = module
            # A staged frequency candidate always carries computed profiles; the
            # runner only stages a candidate whose profiles dict is truthy.
            self.profiles = {f"{module}-s1": object()}

    monkeypatch.setattr(jr, "compute_bounds_candidate", lambda cfg, b, df: _Cand(b.config.name))
    monkeypatch.setattr(jr, "compute_frequency_candidate", lambda b, df: _Cand(b.config.name))
    monkeypatch.setattr(jr, "publish_bounds_candidate", lambda *a, **k: None)
    monkeypatch.setattr(jr, "publish_frequency_candidate", lambda *a, **k: None)


def test_success_projects_running_then_completed(tmp_path: Path, patched_helpers: None) -> None:
    """A real successful run drives the linked operation to completed."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_linked_job(pg, "job-ok", operations_job_id=101)
    runner = _make_runner(pg, [_FakeBundle("conn")])

    assert runner.try_run("job-ok") is True
    runner._thread.join(timeout=5.0)  # type: ignore[union-attr]

    dto = _wait_terminal(repo, "job-ok")
    assert dto is not None and dto.state == "succeeded"

    op = _read_operation(pg, 101)
    assert op["state"] == "completed"
    assert op["actor"] == "operator"  # canonical row link + actor preserved
    assert op["phase_label"]
    assert op["latest_event"]
    assert op["error"] is None
    assert op["result"] is not None and "metrics" in op["result"]
    assert bool(op["can_cancel"]) is False
    assert bool(op["can_retry"]) is False

    log = json.loads(op["log"])
    assert isinstance(log, list) and len(log) >= 2  # running + completed appended
    completed_entry = log[-1]
    assert completed_entry["state"] == "succeeded"
    assert "metrics" in completed_entry
    assert len(completed_entry["metrics"]) <= 12  # bounded structured log


def test_failure_projects_failed_and_retryable(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """A real training failure projects a failed, retryable operation."""
    import otalon_clas.runtime.job_runner as jr

    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _seed_linked_job(pg, "job-fail", operations_job_id=202)

    def _boom(cfg: Any, bundle: Any, df: Any) -> Any:
        raise RuntimeError("staging blew up")

    monkeypatch.setattr(jr, "compute_bounds_candidate", _boom)
    monkeypatch.setattr(jr, "compute_frequency_candidate", lambda b, df: None)
    published: list[str] = []
    monkeypatch.setattr(jr, "publish_bounds_candidate", lambda *a, **k: published.append("b"))
    monkeypatch.setattr(jr, "publish_frequency_candidate", lambda *a, **k: published.append("f"))

    runner = _make_runner(pg, [_FakeBundle("conn")])
    assert runner.try_run("job-fail") is True
    runner._thread.join(timeout=5.0)  # type: ignore[union-attr]

    dto = _wait_terminal(repo, "job-fail")
    assert dto is not None and dto.state == "failed"
    assert published == []  # no publish on staging failure

    op = _read_operation(pg, 202)
    assert op["state"] == "failed"
    assert op["error"] and "staging blew up" in op["error"]
    assert op["result"] is None
    assert bool(op["can_cancel"]) is False
    assert bool(op["can_retry"]) is True  # failed operations are retryable
    assert op["ended_at"] is not None

    log = json.loads(op["log"])
    assert isinstance(log, list) and log[-1]["state"] == "failed"


def test_no_orphan_projection_without_link(tmp_path: Path, patched_helpers: None) -> None:
    """An unlinked retrain job never mutates any operations row."""
    pg = _make_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    # Canonical row exists but retrain job carries no operations_job_id.
    with pg.session() as session:
        session.execute(
            text(
                """
                INSERT INTO operations_jobs
                    (id, display_id, type, title, state, trigger, actor)
                VALUES
                    (303, 'J-303', 'training', 'Unlinked', 'queued', 'chat', 'operator')
                """
            )
        )
    repo.insert_queued(
        job_ref="job-unlinked",
        scope="bounds_frequency",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
    )
    runner = _make_runner(pg, [_FakeBundle("conn")])

    assert runner.try_run("job-unlinked") is True
    runner._thread.join(timeout=5.0)  # type: ignore[union-attr]

    dto = _wait_terminal(repo, "job-unlinked")
    assert dto is not None and dto.state == "succeeded"

    op = _read_operation(pg, 303)
    assert op["state"] == "queued"  # untouched: no orphan projection
    assert json.loads(op["log"]) == []
