"""Unit tests for :class:`RetrainJobRepository`.

Covers single-flight atomic claiming, detached-safe DTO returns, and the
state+worker guarded transitions that prevent a reaped/terminal job from
being resurrected (audit A-04 / B-05 / B-11 / F1).
"""

from __future__ import annotations

from pathlib import Path

import pytest

from otalon_clas.common.postgres_connector import PostgresConnector, RetrainJob
from otalon_clas.runtime.job_dto import RetrainJobDTO
from otalon_clas.runtime.retrain_job_repository import (
    RetrainJobClaimError,
    RetrainJobRepository,
)

_WORKER = "worker-a"


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file."""
    db_path = tmp_path / "retrain_jobs.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    RetrainJob.__table__.create(pg.engine, checkfirst=True)
    return pg


def _insert_job(pg: PostgresConnector, job_ref: str, state: str = "queued") -> None:
    """Seed a minimal job row, claiming it when a non-queued state is asked for."""
    repo = RetrainJobRepository(pg)
    repo.insert_queued(
        job_ref=job_ref,
        scope="bounds_frequency",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
    )
    if state != "queued":
        claimed = repo.claim_next(job_ref, _WORKER)
        assert claimed is not None
        if state != "running":
            repo.set_state(
                job_ref,
                state,
                worker_id=_WORKER,
                expected_states=("running",),
                detail="seeded",
            )


def test_claim_next_is_atomic_single_flight(tmp_path: Path) -> None:
    """Two concurrent claim attempts on the same row yield exactly one winner."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    repo.insert_queued(
        job_ref="job-1",
        scope="bounds_frequency",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
    )

    winner1 = repo.claim_next("job-1", "worker-a")
    winner2 = repo.claim_next("job-1", "worker-b")

    assert winner1 is not None
    assert isinstance(winner1, RetrainJobDTO)
    assert winner1.state == "running"
    assert winner1.worker_id == "worker-a"
    assert winner2 is None


def test_claim_next_returns_detached_dto(tmp_path: Path) -> None:
    """The claimed row survives session close (no DetachedInstanceError)."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    repo.insert_queued(
        job_ref="job-dto",
        scope="classifier",
        window_start="2026-05-08 12:00:00",
        window_stop="2026-05-08 12:30:00",
        mitre_file="/labels/mitre.json",
    )
    dto = repo.claim_next("job-dto", _WORKER)
    assert dto is not None
    # Accessing every field after the session closed must not raise.
    assert dto.scope == "classifier"
    assert dto.window_start == "2026-05-08 12:00:00"
    assert dto.window_stop == "2026-05-08 12:30:00"
    assert dto.mitre_file == "/labels/mitre.json"
    assert dto.job_ref == "job-dto"


def test_fetch_queued_refs_sees_only_queued(tmp_path: Path) -> None:
    """Only queued rows are returned by the poll safety-net helper."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _insert_job(pg, "queued-job", "queued")
    _insert_job(pg, "running-job", "running")

    refs = repo.fetch_queued_refs()
    assert refs == ["queued-job"]


def test_set_terminal_marks_job_failed(tmp_path: Path) -> None:
    """Terminal update sets state, error and finished_at."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _insert_job(pg, "job-fail", "running")

    landed = repo.set_terminal(
        "job-fail",
        "failed",
        detail="training failed",
        worker_id=_WORKER,
        error="empty window",
    )
    assert landed is True
    final = repo.get("job-fail")
    assert final is not None
    assert final.state == "failed"
    assert final.error == "empty window"
    assert final.finished_at is not None


def test_set_state_guarded_by_worker(tmp_path: Path) -> None:
    """A worker that does not own the row cannot transition it."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _insert_job(pg, "job-owned", "running")

    with pytest.raises(RetrainJobClaimError):
        repo.set_state(
            "job-owned",
            "publishing",
            worker_id="other-worker",
            expected_states=("running",),
        )


def test_terminal_cannot_flap_after_reap(tmp_path: Path) -> None:
    """A job reaped to failed cannot later be set to succeeded (B-05)."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _insert_job(pg, "job-reaped", "running")

    # Simulate the api reaper flipping the row to failed out from under us.
    with pg.session() as session:
        row = session.query(RetrainJob).filter_by(job_ref="job-reaped").one()
        row.state = "failed"
        row.error = "heartbeat timeout"

    # The worker's late success must NOT overwrite the terminal failed row.
    landed = repo.set_terminal(
        "job-reaped",
        "succeeded",
        detail="training complete",
        worker_id=_WORKER,
        error=None,
    )
    assert landed is False
    final = repo.get("job-reaped")
    assert final is not None
    assert final.state == "failed"
    assert final.error == "heartbeat timeout"


def test_heartbeat_returns_false_when_ownership_lost(tmp_path: Path) -> None:
    """Heartbeat on a terminal/foreign row reports lost ownership."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _insert_job(pg, "job-hb", "running")

    assert repo.heartbeat("job-hb", _WORKER) is True
    assert repo.heartbeat("job-hb", "other-worker") is False

    repo.set_terminal("job-hb", "failed", detail="done", worker_id=_WORKER)
    assert repo.heartbeat("job-hb", _WORKER) is False


def test_list_non_terminal_returns_dtos(tmp_path: Path) -> None:
    """Non-terminal listing returns detached DTOs only for open jobs."""
    pg = _make_sqlite_connector(tmp_path)
    repo = RetrainJobRepository(pg)
    _insert_job(pg, "open-job", "running")
    _insert_job(pg, "closed-job", "running")
    repo.set_terminal("closed-job", "succeeded", detail="ok", worker_id=_WORKER)

    rows = repo.list_non_terminal()
    assert [r.job_ref for r in rows] == ["open-job"]
    assert all(isinstance(r, RetrainJobDTO) for r in rows)
