"""PostgreSQL repositories for OTALON-AI jobs.

- :class:`SubagentJobsRepo` — full CRUD + incremental trace append
- :class:`BaselineRepo` — read-only access to ``baselines`` (write goes
  through ``otalon-api``)
- :class:`AlarmsRepo` — read-only access to the existing ``alarms`` table
  so the worker can fetch the alarm record when the API hands us only an id
- :func:`ensure_schema` — idempotent DDL bootstrap reading the SQL files
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, TypeVar
from uuid import UUID, uuid4

from loguru import logger
from sqlalchemy import create_engine, text
from sqlalchemy.engine import Engine

from otalon_ai.jobs.domain.job import JobFilter, JobRecord, JobStatus, JobSummary, TraceEntry

_SQL_DIR = Path(__file__).resolve().parent / "sql"

_T = TypeVar("_T")


async def run_db(func: Callable[..., _T], *args: Any, **kwargs: Any) -> _T:
    """Run a blocking repository call on a worker thread (AI-03).

    The repositories in this module are synchronous SQLAlchemy; calling
    them directly inside an ``async def`` handler would stall the event
    loop for the full round-trip. Every call site in an async context
    routes through this helper (a thin ``asyncio.to_thread`` wrapper).
    """
    return await asyncio.to_thread(func, *args, **kwargs)


def build_engine(dsn: str) -> Engine:
    """Build a SQLAlchemy engine with sane defaults for an HTTP service."""
    return create_engine(dsn, pool_pre_ping=True, pool_size=10, max_overflow=20)


def ensure_schema(engine: Engine) -> None:
    """Apply ``baselines.sql`` and ``subagent_jobs.sql`` idempotently."""
    files = ["baselines.sql", "subagent_jobs.sql"]
    with engine.begin() as conn:
        for fname in files:
            path = _SQL_DIR / fname
            sql = path.read_text(encoding="utf-8")
            for stmt in [s.strip() for s in sql.split(";") if s.strip()]:
                conn.exec_driver_sql(stmt)
            logger.info("Applied DDL {}", fname)


class AlarmsRepo:
    """Read-only access to ``alarms`` in shared PostgreSQL schema."""

    def __init__(self, engine: Engine) -> None:
        """Bind the repo to a SQLAlchemy engine.

        Args:
            engine: SQLAlchemy engine pointing at the workspace
                PostgreSQL instance.
        """
        self._engine = engine

    def get_by_id(self, alarm_id: str) -> Optional[Dict[str, Any]]:
        """Return the alarm row as a dict, or ``None`` if missing."""
        with self._engine.connect() as conn:
            row = (
                conn.execute(
                    text("SELECT * FROM alarms WHERE id = :id"),
                    {"id": alarm_id},
                )
                .mappings()
                .first()
            )
        if not row:
            return None
        result = dict(row)
        # JSON columns are already python objects via psycopg2 default,
        # but in case they come back as strings, parse them.
        for key in ("primary_type", "series_ids", "anomaly_type_stats"):
            value = result.get(key)
            if isinstance(value, str):
                try:
                    result[key] = json.loads(value)
                except json.JSONDecodeError:
                    pass
        return result


class BaselineRepo:
    """Read-only access to ``baselines`` for the worker to resolve baseline_id."""

    def __init__(self, engine: Engine) -> None:
        """Bind the repo to a SQLAlchemy engine.

        Args:
            engine: SQLAlchemy engine pointing at the workspace
                PostgreSQL instance.
        """
        self._engine = engine

    def get_active(self) -> Optional[Dict[str, Any]]:
        """Return the currently active baseline row, or ``None`` if none is active."""
        with self._engine.connect() as conn:
            row = (
                conn.execute(
                    text(
                        "SELECT id, name, start_ts, end_ts, is_active " "FROM baselines WHERE is_active = TRUE LIMIT 1"
                    )
                )
                .mappings()
                .first()
            )
        return dict(row) if row else None

    def get_by_id(self, baseline_id: UUID) -> Optional[Dict[str, Any]]:
        """Return the baseline row matching ``baseline_id``, or ``None`` if missing."""
        with self._engine.connect() as conn:
            row = (
                conn.execute(
                    text("SELECT id, name, start_ts, end_ts, is_active " "FROM baselines WHERE id = :id"),
                    {"id": str(baseline_id)},
                )
                .mappings()
                .first()
            )
        return dict(row) if row else None


def _trace_to_jsonb(trace: List[Dict[str, Any]]) -> str:
    """Serialise a list of trace entries to a JSON string for ``::jsonb`` cast."""
    return json.dumps(trace, default=str)


class SubagentJobsRepo:
    """Full CRUD for subagent jobs."""

    def __init__(self, engine: Engine) -> None:
        """Bind the repo to a SQLAlchemy engine.

        Args:
            engine: SQLAlchemy engine pointing at the workspace
                PostgreSQL instance.
        """
        self._engine = engine

    # ── Insert/lifecycle ───────────────────────────────────────────

    def insert_pending(
        self,
        *,
        alarm_id: str,
        prompt_variant: str,
        prompt_hash: str,
        llm_provider: str,
        llm_model: str,
        llm_endpoint: Optional[str],
        reasoning_effort: Optional[str],
        baseline_id: Optional[UUID],
        timeout_seconds: int,
        trigger_source: str,
    ) -> UUID:
        """Insert a new job row in ``pending`` state and return its id.

        Args:
            alarm_id: Foreign key into ``alarms.id``.
            prompt_variant: Selected prompt variant (``open`` / ``expert``).
            prompt_hash: SHA-256 of the materialised system prompt.
            llm_provider: Legacy provider name kept for traceability;
                defaults to ``"litellm"`` post Phase 9 of
                ``replace-n8n-chat-orchestration``. The runtime no longer
                dispatches on this value — every job is served via the
                LiteLLM proxy.
            llm_model: Concrete model/deployment name resolved at enqueue.
            llm_endpoint: Endpoint snapshot recorded for traceability
                (never read back into the worker — see Cluster d).
            reasoning_effort: Optional provider-specific reasoning level.
            baseline_id: Optional baseline UUID, validated upstream.
            timeout_seconds: Hard per-job wall-clock budget.
            trigger_source: Origin tag (``ui`` / ``chat`` / ``api``).

        Returns:
            The freshly generated job ``UUID``.
        """
        job_id = uuid4()
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    INSERT INTO subagent_jobs (
                        id, alarm_id, status, prompt_variant, prompt_hash,
                        llm_provider, llm_model, llm_endpoint, reasoning_effort,
                        baseline_id, timeout_seconds, trigger_source
                    ) VALUES (
                        :id, :alarm_id, 'pending', :pv, :ph,
                        :lp, :lm, :le, :re,
                        :bid, :ts, :tsrc
                    )
                    """
                ),
                {
                    "id": str(job_id),
                    "alarm_id": alarm_id,
                    "pv": prompt_variant,
                    "ph": prompt_hash,
                    "lp": llm_provider,
                    "lm": llm_model,
                    "le": llm_endpoint,
                    "re": reasoning_effort,
                    "bid": str(baseline_id) if baseline_id else None,
                    "ts": timeout_seconds,
                    "tsrc": trigger_source,
                },
            )
        return job_id

    def reap_stranded(self, *, error_message: str = "reaped: service restarted") -> int:
        """Fail orphaned ``pending``/``running`` rows left by a previous process.

        Worker shutdown hard-cancels consumer tasks mid-flight, so rows can
        be stranded in a non-terminal state forever (AI-06). The jobs
        surface calls this once at startup, before the new pool accepts
        work. Returns the number of reaped rows.
        """
        with self._engine.begin() as conn:
            result = conn.execute(
                text(
                    "UPDATE subagent_jobs SET status='failed', error_message=:err, finished_at=NOW() "
                    "WHERE status IN ('pending','running')"
                ),
                {"err": error_message},
            )
            reaped = result.rowcount or 0
        if reaped:
            logger.warning("startup reaper: failed {} stranded pending/running job(s)", reaped)
        return reaped

    def mark_running(self, job_id: UUID) -> None:
        """Transition a job from ``pending`` to ``running`` and stamp ``started_at``."""
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE subagent_jobs SET status='running', started_at=NOW() " "WHERE id = :id"),
                {"id": str(job_id)},
            )

    def mark_terminal(
        self,
        job_id: UUID,
        *,
        status: str,
        duration_seconds: float,
        step1_technical: Optional[Dict[str, Any]],
        step2_classification: Optional[Dict[str, Any]],
        tool_trace: List[Dict[str, Any]],
        tokens_prompt: int,
        tokens_completion: int,
        error_message: Optional[str],
        verdict: Optional[Dict[str, Any]] = None,
    ) -> None:
        """Persist the terminal job state in one update."""
        with self._engine.begin() as conn:
            conn.execute(
                text(
                    """
                    UPDATE subagent_jobs SET
                        status = :status,
                        finished_at = NOW(),
                        duration_seconds = :dur,
                        step1_technical = CAST(:s1 AS jsonb),
                        step2_classification = CAST(:s2 AS jsonb),
                        verdict = CAST(:verdict AS jsonb),
                        tool_trace = CAST(:trace AS jsonb),
                        tokens_prompt = :tp,
                        tokens_completion = :tc,
                        error_message = :err
                    WHERE id = :id
                    """
                ),
                {
                    "id": str(job_id),
                    "status": status,
                    "dur": duration_seconds,
                    "s1": json.dumps(step1_technical) if step1_technical else None,
                    "s2": (json.dumps(step2_classification) if step2_classification else None),
                    "verdict": json.dumps(verdict) if verdict else None,
                    "trace": _trace_to_jsonb(tool_trace),
                    "tp": tokens_prompt,
                    "tc": tokens_completion,
                    "err": error_message,
                },
            )

    def append_trace_entry(self, job_id: UUID, entry: Dict[str, Any]) -> None:
        """Append one entry to the job's tool_trace jsonb array."""
        with self._engine.begin() as conn:
            conn.execute(
                text("UPDATE subagent_jobs " "SET tool_trace = tool_trace || CAST(:entry AS jsonb) " "WHERE id = :id"),
                {"id": str(job_id), "entry": json.dumps([entry], default=str)},
            )

    # ── Query ──────────────────────────────────────────────────────

    def get_by_id(self, job_id: UUID) -> Optional[JobRecord]:
        """Fetch one job row by id and inflate it into a :class:`JobRecord`.

        Args:
            job_id: UUID of the job.

        Returns:
            A :class:`JobRecord` or ``None`` if no row matches.
        """
        with self._engine.connect() as conn:
            row = (
                conn.execute(
                    text("SELECT * FROM subagent_jobs WHERE id = :id"),
                    {"id": str(job_id)},
                )
                .mappings()
                .first()
            )
        if not row:
            return None
        return self._row_to_record(dict(row))

    def list_jobs(self, flt: JobFilter) -> tuple[List[Any], int]:
        """Return (items, total_count) honoring the filter."""
        clauses: List[str] = []
        params: Dict[str, Any] = {}
        if flt.alarm_id:
            clauses.append("alarm_id = :alarm_id")
            params["alarm_id"] = flt.alarm_id
        if flt.status:
            clauses.append("status = :status")
            params["status"] = flt.status.value
        where = "WHERE " + " AND ".join(clauses) if clauses else ""
        params["lim"] = flt.limit
        params["off"] = flt.offset
        with self._engine.connect() as conn:
            total = conn.execute(text(f"SELECT COUNT(*) FROM subagent_jobs {where}"), params).scalar() or 0
            rows = (
                conn.execute(
                    text(f"SELECT * FROM subagent_jobs {where} " f"ORDER BY created_at DESC LIMIT :lim OFFSET :off"),
                    params,
                )
                .mappings()
                .all()
            )
        items: List[Any] = []
        for row in rows:
            full = self._row_to_record(dict(row))
            if flt.summary:
                items.append(self._record_to_summary(full))
            else:
                items.append(full)
        return items, int(total)

    def get_recent_durations(self, n: int = 20) -> List[float]:
        """Return durations of the last ``n`` finished jobs (newest first).

        ``degraded`` runs (AI-036) count too: they executed the full
        tool-loop and their wall-clock is as representative for the ETA
        estimate as a clean ``completed`` run.
        """
        with self._engine.connect() as conn:
            rows = conn.execute(
                text(
                    "SELECT duration_seconds FROM subagent_jobs "
                    "WHERE status IN ('completed', 'degraded') AND duration_seconds IS NOT NULL "
                    "ORDER BY finished_at DESC LIMIT :n"
                ),
                {"n": n},
            ).fetchall()
        return [float(r[0]) for r in rows if r[0] is not None]

    # ── Helpers ────────────────────────────────────────────────────

    @staticmethod
    def _row_to_record(row: Dict[str, Any]) -> JobRecord:
        # SQLAlchemy returns jsonb as already-parsed objects with psycopg2;
        # tool_trace is a list, the others are dicts or None.
        trace_raw = row.get("tool_trace") or []
        if isinstance(trace_raw, str):
            trace_raw = json.loads(trace_raw)
        trace_entries: List[TraceEntry] = []
        for entry in trace_raw:
            try:
                trace_entries.append(TraceEntry.model_validate(entry))
            except Exception:
                continue
        return JobRecord(
            id=row["id"],
            alarm_id=row["alarm_id"],
            status=JobStatus(row["status"]),
            prompt_variant=row["prompt_variant"],
            prompt_hash=row["prompt_hash"],
            llm_provider=row["llm_provider"],
            llm_model=row["llm_model"],
            llm_endpoint=row.get("llm_endpoint"),
            reasoning_effort=row.get("reasoning_effort"),
            baseline_id=row.get("baseline_id"),
            timeout_seconds=row["timeout_seconds"],
            trigger_source=row.get("trigger_source") or "api",
            started_at=row.get("started_at"),
            finished_at=row.get("finished_at"),
            duration_seconds=row.get("duration_seconds"),
            step1_technical=row.get("step1_technical"),
            step2_classification=row.get("step2_classification"),
            verdict=row.get("verdict"),
            tool_trace=trace_entries,
            tokens_prompt=row.get("tokens_prompt") or 0,
            tokens_completion=row.get("tokens_completion") or 0,
            error_message=row.get("error_message"),
            created_at=row["created_at"],
        )

    @staticmethod
    def _record_to_summary(rec: JobRecord) -> JobSummary:
        top = None
        method = None
        if rec.step2_classification:
            cls_list = rec.step2_classification.get("classifications", [])
            if cls_list:
                top = cls_list[0]
        if rec.step1_technical:
            method = rec.step1_technical.get("technical_method")
        verdict_outcome = rec.verdict.get("outcome") if rec.verdict else None
        return JobSummary(
            id=rec.id,
            alarm_id=rec.alarm_id,
            status=rec.status,
            prompt_variant=rec.prompt_variant,
            llm_provider=rec.llm_provider,
            llm_model=rec.llm_model,
            started_at=rec.started_at,
            finished_at=rec.finished_at,
            duration_seconds=rec.duration_seconds,
            tool_trace_count=len(rec.tool_trace),
            tokens_total=rec.tokens_prompt + rec.tokens_completion,
            top_step2=top,
            step1_method=method,
            verdict_outcome=verdict_outcome,
            created_at=rec.created_at,
        )
