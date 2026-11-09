"""Unit tests for :mod:`src.jobs.repositories.postgres_repo`.

Boundary-mocked: the SQLAlchemy ``Engine`` is replaced by a recording
double that captures SQL + params and returns scripted rows. This lets us
verify:

- CRUD round-trip for ``SubagentJobsRepo`` (insert/run/terminal/get/list).
- ``AlarmsRepo.get_by_id`` returns ``None`` for missing rows + parses
  stringified JSON columns.
- ``BaselineRepo.get_active`` / ``get_by_id`` shape.
- The pure helpers ``_row_to_record`` and ``_record_to_summary`` are
  exercised across all branches (completed-with-classifications, empty,
  legacy string-jsonb).
- ``append_trace_entry`` produces the JSON payload the SQL expects.
- Concurrent inserts (via ``asyncio.gather`` on a thread-pool wrapper)
  do not interleave row ids — every job_id is unique.
"""

from __future__ import annotations

import asyncio
import json
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Any, Dict, Iterator, List, Optional
from uuid import UUID, uuid4

import pytest

from otalon_ai.jobs.domain.job import JobFilter, JobRecord, JobStatus
from otalon_ai.jobs.repositories.postgres_repo import (
    AlarmsRepo,
    BaselineRepo,
    SubagentJobsRepo,
    _trace_to_jsonb,
)

# ── Recording fake engine ────────────────────────────────────────────


class _FakeResult:
    """Minimal stand-in for SQLAlchemy ``Result`` with the methods the repo uses."""

    def __init__(self, rows: Optional[List[Dict[str, Any]]] = None, scalar_value: Any = None) -> None:
        self._rows = rows or []
        self._scalar = scalar_value

    def mappings(self) -> "_FakeResult":
        return self

    def first(self) -> Optional[Dict[str, Any]]:
        return self._rows[0] if self._rows else None

    def all(self) -> List[Dict[str, Any]]:
        return list(self._rows)

    def fetchall(self) -> List[List[Any]]:
        # Mimic SQLAlchemy row tuples: assume single-column query.
        return [[row.get("duration_seconds")] for row in self._rows]

    def scalar(self) -> Any:
        return self._scalar


class _FakeConn:
    """Captures ``execute`` calls + returns scripted results in FIFO order."""

    def __init__(self, fake_engine: "_FakeEngine") -> None:
        self._fake_engine = fake_engine

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _FakeResult:
        sql = str(statement)
        self._fake_engine.calls.append({"sql": sql, "params": params or {}})
        # Pop a scripted result if available; otherwise empty.
        if self._fake_engine.results:
            return self._fake_engine.results.pop(0)
        return _FakeResult()

    # The repo uses ``conn.exec_driver_sql`` in ``ensure_schema``.
    def exec_driver_sql(self, sql: str) -> None:
        self._fake_engine.ddl.append(sql)


class _FakeEngine:
    """Pretends to be a ``sqlalchemy.engine.Engine``.

    - ``calls`` records every (sql, params) pair the repo issued.
    - ``results`` is a FIFO queue of :class:`_FakeResult` returned by
      ``connect().execute(...)`` / ``begin().execute(...)``.
    """

    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.results: List[_FakeResult] = []
        self.ddl: List[str] = []

    @contextmanager
    def connect(self) -> Iterator[_FakeConn]:
        yield _FakeConn(self)

    @contextmanager
    def begin(self) -> Iterator[_FakeConn]:
        yield _FakeConn(self)


# ── AlarmsRepo ───────────────────────────────────────────────────────


@pytest.mark.unit
def test_alarms_repo_get_by_id_returns_none_when_missing() -> None:
    engine = _FakeEngine()
    repo = AlarmsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id("missing-id")
    assert out is None
    assert engine.calls[0]["params"] == {"id": "missing-id"}


@pytest.mark.unit
def test_alarms_repo_get_by_id_returns_dict() -> None:
    engine = _FakeEngine()
    engine.results.append(
        _FakeResult(rows=[{"id": "a-1", "primary_type": "phish", "series_ids": [1, 2], "anomaly_type_stats": {"x": 1}}])
    )
    repo = AlarmsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id("a-1")
    assert out is not None
    assert out["id"] == "a-1"
    assert out["primary_type"] == "phish"


@pytest.mark.unit
def test_alarms_repo_parses_stringified_json_columns() -> None:
    engine = _FakeEngine()
    engine.results.append(
        _FakeResult(
            rows=[
                {
                    "id": "a-1",
                    "primary_type": '["a", "b"]',
                    "series_ids": "[1, 2]",
                    "anomaly_type_stats": '{"x": 1}',
                }
            ]
        )
    )
    repo = AlarmsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id("a-1")
    assert out is not None
    assert out["primary_type"] == ["a", "b"]
    assert out["series_ids"] == [1, 2]
    assert out["anomaly_type_stats"] == {"x": 1}


@pytest.mark.unit
def test_alarms_repo_passes_through_non_json_string() -> None:
    engine = _FakeEngine()
    engine.results.append(
        _FakeResult(rows=[{"id": "a", "primary_type": "not json", "series_ids": None, "anomaly_type_stats": None}])
    )
    repo = AlarmsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id("a")
    assert out is not None
    assert out["primary_type"] == "not json"


# ── BaselineRepo ─────────────────────────────────────────────────────


@pytest.mark.unit
def test_baseline_repo_get_active_none() -> None:
    engine = _FakeEngine()
    repo = BaselineRepo(engine)  # type: ignore[arg-type]
    assert repo.get_active() is None


@pytest.mark.unit
def test_baseline_repo_get_active_returns_row() -> None:
    engine = _FakeEngine()
    engine.results.append(
        _FakeResult(
            rows=[
                {
                    "id": uuid4(),
                    "name": "b1",
                    "start_ts": datetime.now(timezone.utc),
                    "end_ts": datetime.now(timezone.utc),
                    "is_active": True,
                }
            ]
        )
    )
    repo = BaselineRepo(engine)  # type: ignore[arg-type]
    out = repo.get_active()
    assert out is not None
    assert out["name"] == "b1"


@pytest.mark.unit
def test_baseline_repo_get_by_id_none_and_some() -> None:
    engine = _FakeEngine()
    repo = BaselineRepo(engine)  # type: ignore[arg-type]
    bid = uuid4()
    assert repo.get_by_id(bid) is None
    engine.results.append(
        _FakeResult(rows=[{"id": bid, "name": "x", "start_ts": None, "end_ts": None, "is_active": False}])
    )
    out = repo.get_by_id(bid)
    assert out is not None
    assert out["name"] == "x"


# ── SubagentJobsRepo: writes ─────────────────────────────────────────


@pytest.mark.unit
def test_insert_pending_emits_expected_sql_and_returns_uuid() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    job_id = repo.insert_pending(
        alarm_id="a-1",
        prompt_variant="open",
        prompt_hash="ph",
        llm_provider="azure_openai",
        llm_model="gpt-5.4",
        llm_endpoint=None,
        reasoning_effort="high",
        baseline_id=None,
        timeout_seconds=600,
        trigger_source="api",
    )
    assert isinstance(job_id, UUID)
    assert "INSERT INTO subagent_jobs" in engine.calls[0]["sql"]
    params = engine.calls[0]["params"]
    assert params["alarm_id"] == "a-1"
    assert params["pv"] == "open"
    assert params["tsrc"] == "api"
    assert params["ts"] == 600
    assert params["bid"] is None


@pytest.mark.unit
def test_insert_pending_with_baseline_id_serialises_to_str() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    bid = uuid4()
    repo.insert_pending(
        alarm_id="a",
        prompt_variant="expert",
        prompt_hash="h",
        llm_provider="openai_compat",
        llm_model="m",
        llm_endpoint="http://x",
        reasoning_effort=None,
        baseline_id=bid,
        timeout_seconds=60,
        trigger_source="ui",
    )
    assert engine.calls[0]["params"]["bid"] == str(bid)


@pytest.mark.unit
def test_mark_running_updates_status() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    jid = uuid4()
    repo.mark_running(jid)
    sql = engine.calls[0]["sql"]
    assert "UPDATE subagent_jobs" in sql
    assert "status='running'" in sql
    assert engine.calls[0]["params"] == {"id": str(jid)}


@pytest.mark.unit
def test_mark_terminal_serialises_jsonb_payloads() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    jid = uuid4()
    repo.mark_terminal(
        jid,
        status="completed",
        duration_seconds=12.3,
        step1_technical={"technical_method": "x"},
        step2_classification={"classifications": [{"technique_id": "T0846"}]},
        verdict={"outcome": "benign", "reasoning": "maintenance window"},
        tool_trace=[{"round": 1, "tool": "x", "args": {}, "result_chars": 0, "duration_ms": 0, "error": None}],
        tokens_prompt=100,
        tokens_completion=50,
        error_message=None,
    )
    p = engine.calls[0]["params"]
    assert p["status"] == "completed"
    assert p["dur"] == 12.3
    assert json.loads(p["s1"]) == {"technical_method": "x"}
    assert json.loads(p["s2"])["classifications"][0]["technique_id"] == "T0846"
    assert json.loads(p["verdict"]) == {"outcome": "benign", "reasoning": "maintenance window"}
    assert json.loads(p["trace"])[0]["tool"] == "x"
    assert p["tp"] == 100
    assert p["tc"] == 50
    assert p["err"] is None


@pytest.mark.unit
def test_mark_terminal_handles_none_payloads() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    repo.mark_terminal(
        uuid4(),
        status="failed",
        duration_seconds=0.0,
        step1_technical=None,
        step2_classification=None,
        tool_trace=[],
        tokens_prompt=0,
        tokens_completion=0,
        error_message="boom",
    )
    p = engine.calls[0]["params"]
    assert p["s1"] is None
    assert p["s2"] is None
    assert p["verdict"] is None
    assert json.loads(p["trace"]) == []
    assert p["err"] == "boom"


@pytest.mark.unit
def test_append_trace_entry_wraps_in_list_for_jsonb_concat() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    jid = uuid4()
    entry = {"round": 1, "tool": "t.x", "result_chars": 10, "duration_ms": 5}
    repo.append_trace_entry(jid, entry)
    p = engine.calls[0]["params"]
    assert "tool_trace || CAST(:entry AS jsonb)" in engine.calls[0]["sql"]
    parsed = json.loads(p["entry"])
    assert isinstance(parsed, list) and parsed[0]["tool"] == "t.x"


# ── SubagentJobsRepo: reads ──────────────────────────────────────────


def _full_row(job_id: UUID, alarm_id: str = "a-1", status: str = "completed") -> Dict[str, Any]:
    now = datetime.now(timezone.utc)
    return {
        "id": job_id,
        "alarm_id": alarm_id,
        "status": status,
        "prompt_variant": "open",
        "prompt_hash": "h",
        "llm_provider": "azure_openai",
        "llm_model": "gpt-5.4",
        "llm_endpoint": None,
        "reasoning_effort": None,
        "baseline_id": None,
        "timeout_seconds": 600,
        "trigger_source": "api",
        "started_at": now,
        "finished_at": now,
        "duration_seconds": 5.0,
        "step1_technical": {"technical_method": "tm"},
        "step2_classification": {"classifications": [{"technique_id": "T0846", "confidence": 0.9}]},
        "tool_trace": [{"round": 1, "tool": "t.x", "args": {}, "result_chars": 1, "duration_ms": 2, "error": None}],
        "tokens_prompt": 100,
        "tokens_completion": 50,
        "error_message": None,
        "created_at": now,
    }


@pytest.mark.unit
def test_get_by_id_none_when_missing() -> None:
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    assert repo.get_by_id(uuid4()) is None


@pytest.mark.unit
def test_get_by_id_returns_job_record() -> None:
    engine = _FakeEngine()
    jid = uuid4()
    engine.results.append(_FakeResult(rows=[_full_row(jid)]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id(jid)
    assert isinstance(out, JobRecord)
    assert out.id == jid
    assert out.status == JobStatus.COMPLETED
    assert len(out.tool_trace) == 1
    assert out.tool_trace[0].tool == "t.x"


@pytest.mark.unit
def test_get_by_id_parses_stringified_tool_trace() -> None:
    engine = _FakeEngine()
    jid = uuid4()
    row = _full_row(jid)
    row["tool_trace"] = json.dumps(row["tool_trace"], default=str)
    engine.results.append(_FakeResult(rows=[row]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id(jid)
    assert out is not None
    assert len(out.tool_trace) == 1


@pytest.mark.unit
def test_get_by_id_skips_invalid_trace_entries() -> None:
    engine = _FakeEngine()
    jid = uuid4()
    row = _full_row(jid)
    # Add a malformed entry alongside a valid one — only valid is kept.
    row["tool_trace"] = [
        {"round": 1, "tool": "t.x", "args": {}, "result_chars": 1, "duration_ms": 2},
        "not a dict",
    ]
    engine.results.append(_FakeResult(rows=[row]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_by_id(jid)
    assert out is not None
    assert len(out.tool_trace) == 1


@pytest.mark.unit
def test_list_jobs_returns_summary_by_default() -> None:
    engine = _FakeEngine()
    jid = uuid4()
    engine.results.append(_FakeResult(scalar_value=1))  # COUNT(*)
    engine.results.append(_FakeResult(rows=[_full_row(jid)]))  # SELECT *
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    items, total = repo.list_jobs(JobFilter())
    assert total == 1
    assert len(items) == 1
    assert items[0].id == jid
    # Summary has tool_trace_count + step1_method.
    assert items[0].tool_trace_count == 1
    assert items[0].step1_method == "tm"
    assert items[0].top_step2["technique_id"] == "T0846"


@pytest.mark.unit
def test_list_jobs_full_records_when_summary_false() -> None:
    engine = _FakeEngine()
    jid = uuid4()
    engine.results.append(_FakeResult(scalar_value=1))
    engine.results.append(_FakeResult(rows=[_full_row(jid)]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    items, total = repo.list_jobs(JobFilter(summary=False))
    assert total == 1
    assert isinstance(items[0], JobRecord)


@pytest.mark.unit
def test_list_jobs_filter_clauses_built() -> None:
    engine = _FakeEngine()
    engine.results.append(_FakeResult(scalar_value=0))
    engine.results.append(_FakeResult(rows=[]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    repo.list_jobs(JobFilter(alarm_id="a-1", status=JobStatus.RUNNING, limit=10, offset=5))
    count_call = engine.calls[0]
    assert "alarm_id = :alarm_id" in count_call["sql"]
    assert "status = :status" in count_call["sql"]
    assert count_call["params"]["alarm_id"] == "a-1"
    assert count_call["params"]["status"] == "running"
    select_call = engine.calls[1]
    assert "LIMIT :lim OFFSET :off" in select_call["sql"]
    assert select_call["params"]["lim"] == 10
    assert select_call["params"]["off"] == 5


@pytest.mark.unit
def test_get_recent_durations_returns_floats() -> None:
    engine = _FakeEngine()
    engine.results.append(_FakeResult(rows=[{"duration_seconds": 3.0}, {"duration_seconds": 5.5}]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_recent_durations(5)
    assert out == [3.0, 5.5]


@pytest.mark.unit
def test_get_recent_durations_skips_none() -> None:
    engine = _FakeEngine()
    engine.results.append(_FakeResult(rows=[{"duration_seconds": 3.0}, {"duration_seconds": None}]))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    out = repo.get_recent_durations(5)
    assert out == [3.0]


# ── Pure helpers ─────────────────────────────────────────────────────


@pytest.mark.unit
def test_trace_to_jsonb_serialises_datetimes() -> None:
    out = _trace_to_jsonb([{"ts": datetime.now(timezone.utc), "round": 1}])
    parsed = json.loads(out)
    assert isinstance(parsed[0]["ts"], str)
    assert parsed[0]["round"] == 1


@pytest.mark.unit
def test_record_to_summary_empty_step2() -> None:
    rec = JobRecord(
        id=uuid4(),
        alarm_id="a",
        status=JobStatus.FAILED,
        prompt_variant="open",
        prompt_hash="h",
        llm_provider="p",
        llm_model="m",
        timeout_seconds=60,
        created_at=datetime.now(timezone.utc),
    )
    summary = SubagentJobsRepo._record_to_summary(rec)
    assert summary.top_step2 is None
    assert summary.step1_method is None
    assert summary.tool_trace_count == 0
    assert summary.tokens_total == 0


# ── Concurrent writes ────────────────────────────────────────────────


@pytest.mark.unit
async def test_concurrent_insert_pending_produces_unique_ids() -> None:
    """Spawn many ``insert_pending`` calls in parallel — every ``job_id`` unique."""
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]

    def _do_insert(i: int) -> UUID:
        return repo.insert_pending(
            alarm_id=f"a-{i}",
            prompt_variant="open",
            prompt_hash="h",
            llm_provider="azure_openai",
            llm_model="m",
            llm_endpoint=None,
            reasoning_effort=None,
            baseline_id=None,
            timeout_seconds=60,
            trigger_source="api",
        )

    ids = await asyncio.gather(*(asyncio.to_thread(_do_insert, i) for i in range(20)))
    assert len(set(ids)) == 20
    # All 20 inserts hit the engine.
    inserts = [c for c in engine.calls if "INSERT INTO subagent_jobs" in c["sql"]]
    assert len(inserts) == 20


@pytest.mark.unit
async def test_concurrent_mark_terminal_does_not_corrupt_params() -> None:
    """Concurrent ``mark_terminal`` calls keep their own params unmixed."""
    engine = _FakeEngine()
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]
    ids = [uuid4() for _ in range(10)]

    def _do_mark(jid: UUID, idx: int) -> None:
        repo.mark_terminal(
            jid,
            status="completed",
            duration_seconds=float(idx),
            step1_technical={"i": idx},
            step2_classification={"classifications": []},
            tool_trace=[],
            tokens_prompt=idx,
            tokens_completion=idx,
            error_message=None,
        )

    await asyncio.gather(*(asyncio.to_thread(_do_mark, jid, i) for i, jid in enumerate(ids)))
    # Every call landed on the engine with a distinct ``dur`` value.
    durs = sorted(c["params"]["dur"] for c in engine.calls)
    assert durs == list(map(float, range(10)))
