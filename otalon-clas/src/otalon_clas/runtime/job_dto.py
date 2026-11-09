"""Immutable, detached-safe data transfer objects for runtime retrain jobs.

The :class:`RetrainJobRepository` reads every scalar it needs *inside* an
open SQLAlchemy session and returns one of these frozen dataclasses. Live
worker threads therefore never touch a live ORM identity map, so a
``DetachedInstanceError`` cannot occur after the session closes (audit
A-04 / B-11 / F1).
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, cast

from otalon_clas.common.postgres_connector import RetrainJob


@dataclass(frozen=True)
class RetrainJobDTO:
    """Read-only snapshot of a ``retrain_jobs`` row.

    All fields are plain Python scalars copied out of the ORM row while
    the session was still open, so accessing them later never triggers a
    lazy DB refresh.
    """

    job_ref: str
    scope: str
    state: str
    window_start: str
    window_stop: str
    intervals: list[list[str]] | None
    mitre_file: str | None
    requested_by: str | None
    detail: str
    error: str | None
    worker_id: str | None
    metrics: dict[str, Any] | None
    history_snapshot_rows: int
    requested_at: datetime | None
    started_at: datetime | None
    finished_at: datetime | None
    heartbeat_at: datetime | None
    operations_job_id: int | None

    @classmethod
    def from_orm_row(cls, row: RetrainJob) -> RetrainJobDTO:
        """Build a detached snapshot from a live ORM row.

        Must be called while *row* is still bound to its session so all
        attribute reads resolve without a lazy refresh.

        Args:
            row: A live :class:`RetrainJob` ORM instance.

        Returns:
            A frozen :class:`RetrainJobDTO` copy.
        """
        raw_metrics = row.metrics
        metrics = dict(raw_metrics) if isinstance(raw_metrics, dict) else None
        return cls(
            job_ref=str(row.job_ref),
            scope=str(row.scope),
            state=str(row.state),
            window_start=str(row.window_start),
            window_stop=str(row.window_stop),
            intervals=cast("list[list[str]] | None", row.intervals),
            mitre_file=cast("str | None", row.mitre_file),
            requested_by=cast("str | None", row.requested_by),
            detail=str(row.detail or ""),
            error=cast("str | None", row.error),
            worker_id=cast("str | None", row.worker_id),
            metrics=metrics,
            history_snapshot_rows=int(row.history_snapshot_rows or 0),
            requested_at=cast("datetime | None", row.requested_at),
            started_at=cast("datetime | None", row.started_at),
            finished_at=cast("datetime | None", row.finished_at),
            heartbeat_at=cast("datetime | None", row.heartbeat_at),
            operations_job_id=cast("int | None", row.operations_job_id),
        )
