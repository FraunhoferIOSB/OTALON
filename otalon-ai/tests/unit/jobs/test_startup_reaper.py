"""AI-06: startup reaper for stranded ``pending``/``running`` jobs.

Worker shutdown hard-cancels consumer tasks mid-flight; without a reaper,
the affected rows stay ``pending``/``running`` in PostgreSQL forever. The
jobs-surface startup MUST fail those orphans with
``error_message='reaped: service restarted'`` before the new pool starts
accepting work.

Covers:

- ``SubagentJobsRepo.reap_stranded`` issues the single bounded UPDATE and
  returns the affected row count.
- ``start_jobs_surface`` invokes the reaper exactly once, before the
  worker pool starts, and off the event-loop thread.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

import pytest
from fastapi import FastAPI

from otalon_ai.jobs.repositories.postgres_repo import SubagentJobsRepo
from otalon_ai.settings import (
    ChatConfig,
    DbConfig,
    JobsConfig,
    LiteLLMConfig,
    McpConfig,
    McpServerEntry,
    Settings,
)

# ── Recording fake engine (mirrors test_postgres_repo.py) ────────────


class _FakeResult:
    def __init__(self, rowcount: int = 0) -> None:
        self.rowcount = rowcount

    def mappings(self) -> "_FakeResult":
        return self


class _FakeConn:
    def __init__(self, engine: "_FakeEngine") -> None:
        self._engine = engine

    def execute(self, statement: Any, params: Optional[Dict[str, Any]] = None) -> _FakeResult:
        self._engine.calls.append({"sql": str(statement), "params": params or {}})
        if self._engine.results:
            return self._engine.results.pop(0)
        return _FakeResult()

    def exec_driver_sql(self, sql: str) -> None:
        self._engine.ddl.append(sql)


class _FakeEngine:
    def __init__(self) -> None:
        self.calls: List[Dict[str, Any]] = []
        self.results: List[_FakeResult] = []
        self.ddl: List[str] = []
        self.disposed = False
        self.execute_thread_ids: List[int] = []

    @contextmanager
    def connect(self) -> Iterator[_FakeConn]:
        self.execute_thread_ids.append(threading.get_ident())
        yield _FakeConn(self)

    @contextmanager
    def begin(self) -> Iterator[_FakeConn]:
        self.execute_thread_ids.append(threading.get_ident())
        yield _FakeConn(self)

    def dispose(self) -> None:
        self.disposed = True


# ── repo-level ───────────────────────────────────────────────────────


@pytest.mark.unit
def test_reap_stranded_issues_single_update_and_returns_rowcount() -> None:
    """The reaper fails every orphaned pending/running row in one UPDATE."""
    engine = _FakeEngine()
    engine.results.append(_FakeResult(rowcount=3))
    repo = SubagentJobsRepo(engine)  # type: ignore[arg-type]

    reaped = repo.reap_stranded()

    assert reaped == 3
    assert len(engine.calls) == 1
    sql = engine.calls[0]["sql"]
    assert "UPDATE subagent_jobs" in sql
    assert "status='failed'" in sql.replace(" ", "")
    assert "'pending'" in sql and "'running'" in sql
    assert engine.calls[0]["params"]["err"] == "reaped: service restarted"


# ── wiring-level ─────────────────────────────────────────────────────


def _settings() -> Settings:
    return Settings(
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        litellm=LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-x"),
        mcp=McpConfig(servers=[McpServerEntry(name="mcp", url="http://mcp-test:9000")]),
        chat=ChatConfig(llm_model="azure/gpt-5.4"),
        jobs=JobsConfig(llm_model="litellm/gpt-5.4", allowed_tools=["postgres.read_anomalies"], n_workers=1),
    )


class _FakePool:
    def __init__(self, **_kwargs: Any) -> None:
        self.started = False
        self.started_after_reaper = False

    async def start(self) -> None:
        self.started = True


@pytest.mark.unit
async def test_start_jobs_surface_reaps_stranded_jobs_before_pool_start(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``start_jobs_surface`` MUST run the reaper before the pool accepts
    work, and MUST NOT run the blocking UPDATE on the event-loop thread.
    """
    from otalon_ai.jobs import wiring

    loop_tid = threading.get_ident()
    engine = _FakeEngine()
    engine.results.append(_FakeResult(rowcount=2))

    events: List[str] = []

    class _OrderingPool(_FakePool):
        async def start(self) -> None:
            events.append("pool_start")
            self.started = True

    class _OrderingRepo(SubagentJobsRepo):
        def reap_stranded(self, *, error_message: str = "reaped: service restarted") -> int:
            events.append("reap")
            return super().reap_stranded(error_message=error_message)

    monkeypatch.setattr(wiring, "build_engine", lambda _dsn: engine)
    monkeypatch.setattr(wiring, "ensure_schema", lambda _engine: None)
    monkeypatch.setattr(wiring, "SubagentJobsRepo", _OrderingRepo)
    monkeypatch.setattr(wiring, "WorkerPool", _OrderingPool)

    app = FastAPI()
    await wiring.start_jobs_surface(app, _settings())

    assert events[:1] == ["reap"], f"reaper must run before pool.start; got {events}"
    assert "pool_start" in events
    assert any("UPDATE subagent_jobs" in c["sql"] for c in engine.calls)
    assert engine.execute_thread_ids, "reaper never hit the engine"
    assert all(
        tid != loop_tid for tid in engine.execute_thread_ids
    ), "startup reaper ran on the event-loop thread (blocking SQLAlchemy)"
