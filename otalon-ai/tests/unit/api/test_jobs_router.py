"""Unit tests for ``src.jobs.api.jobs`` (REST + SSE).

Boundary-mocked: builds a minimal FastAPI app with the jobs router and
fakes for ``alarms_repo`` / ``baseline_repo`` / ``jobs_repo`` / ``pool``
/ ``bus`` / ``prompts`` attached to ``app.state``.

Covers:

- POST /jobs — happy path → 202 + body shape.
- POST /jobs — alarm not found → 404.
- POST /jobs — baseline not found → 404.
- POST /jobs — request-body validation (alarm_id empty, bad enum).
- GET /jobs — pagination + filters (alarm_id + status).
- GET /jobs/{id} — happy + 404.
- POST /jobs/{id}/cancel — happy + 404 (not active).
- GET /jobs/{id}/events — replay terminal record, no live stream.
- GET /jobs/{id}/events — 404 when job not found.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from uuid import UUID, uuid4

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from otalon_ai.jobs.api.jobs import router as jobs_router
from otalon_ai.jobs.domain.events import SubagentEvent
from otalon_ai.jobs.domain.job import (
    JobFilter,
    JobRecord,
    JobStatus,
    JobSummary,
    TraceEntry,
)
from otalon_ai.jobs.worker_pool import JobSpec
from otalon_ai.settings import (
    ChatConfig,
    DbConfig,
    JobsConfig,
    LiteLLMConfig,
    Settings,
)

# ── Fakes ─────────────────────────────────────────────────────────────


def _tid() -> int:
    import threading

    return threading.get_ident()


class _FakeAlarmsRepo:
    def __init__(self, alarms: Optional[Dict[str, Dict[str, Any]]] = None) -> None:
        self.alarms = alarms or {"alarm-1": {"id": "alarm-1", "name": "test"}}
        self.call_thread_ids: List[int] = []

    def get_by_id(self, alarm_id: str) -> Optional[Dict[str, Any]]:
        self.call_thread_ids.append(_tid())
        return self.alarms.get(alarm_id)


class _FakeBaselineRepo:
    def __init__(self, baselines: Optional[Dict[UUID, Dict[str, Any]]] = None) -> None:
        self.baselines = baselines or {}
        self.call_thread_ids: List[int] = []

    def get_by_id(self, bid: UUID) -> Optional[Dict[str, Any]]:
        self.call_thread_ids.append(_tid())
        return self.baselines.get(bid)


class _FakeJobsRepo:
    def __init__(self) -> None:
        self.inserts: List[Dict[str, Any]] = []
        self.jobs: Dict[UUID, JobRecord] = {}
        self.list_pages: List[Tuple[List[Any], int]] = []
        self.call_thread_ids: List[int] = []

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
        jid = uuid4()
        self.call_thread_ids.append(_tid())
        self.inserts.append(
            {
                "id": jid,
                "alarm_id": alarm_id,
                "prompt_variant": prompt_variant,
                "prompt_hash": prompt_hash,
                "llm_provider": llm_provider,
                "llm_model": llm_model,
                "llm_endpoint": llm_endpoint,
                "reasoning_effort": reasoning_effort,
                "baseline_id": baseline_id,
                "timeout_seconds": timeout_seconds,
                "trigger_source": trigger_source,
            }
        )
        return jid

    def get_by_id(self, job_id: UUID) -> Optional[JobRecord]:
        self.call_thread_ids.append(_tid())
        return self.jobs.get(job_id)

    def list_jobs(self, flt: JobFilter) -> Tuple[List[Any], int]:
        self.call_thread_ids.append(_tid())
        if self.list_pages:
            return self.list_pages.pop(0)
        return [], 0

    def get_recent_durations(self, n: int = 20) -> List[float]:
        return [120.0]


class _FakePool:
    def __init__(self) -> None:
        self.enqueued: List[JobSpec] = []
        self.cancelled_ok: set[UUID] = set()
        self._eta = 42
        self.call_thread_ids: List[int] = []

    def enqueue(self, spec: JobSpec) -> int:
        self.enqueued.append(spec)
        return 0

    def estimate_eta_seconds(self) -> int:
        self.call_thread_ids.append(_tid())
        return self._eta

    def cancel(self, job_id: UUID) -> bool:
        return job_id in self.cancelled_ok

    def queue_size(self) -> int:
        return len(self.enqueued)

    def active_count(self) -> int:
        return 0


class _FakeBus:
    def __init__(self) -> None:
        self.subscribed: List[UUID] = []
        self.unsubscribed: List[UUID] = []

    async def subscribe(self, job_id: UUID) -> Any:
        import asyncio as _asyncio

        self.subscribed.append(job_id)
        q: _asyncio.Queue[Optional[SubagentEvent]] = _asyncio.Queue()
        return q

    async def unsubscribe(self, job_id: UUID, _q: Any) -> None:
        self.unsubscribed.append(job_id)


class _FakePrompts:
    def get_hash(self, _variant: str) -> str:
        return "h0"


# ── Helpers ───────────────────────────────────────────────────────────


def _make_settings() -> Settings:
    return Settings(
        db=DbConfig(dsn="postgresql://x:x@h/d"),
        litellm=LiteLLMConfig(base_url="http://litellm:4000/v1", api_key="sk-x"),
        chat=ChatConfig(llm_model="litellm/gpt-5.4"),
        jobs=JobsConfig(
            llm_model="litellm/gpt-5.4",
            llm_reasoning_effort="high",
            allowed_tools=["postgres.read_anomalies"],
        ),
    )


def _build_record(
    *,
    job_id: UUID,
    alarm_id: str = "alarm-1",
    status: JobStatus = JobStatus.COMPLETED,
    with_trace: bool = True,
) -> JobRecord:
    now = datetime.now(timezone.utc)
    trace = (
        [TraceEntry(round=1, tool="postgres.read_anomalies", args={}, result_chars=10, duration_ms=5)]
        if with_trace
        else []
    )
    return JobRecord(
        id=job_id,
        alarm_id=alarm_id,
        status=status,
        prompt_variant="expert",
        prompt_hash="h",
        llm_provider="litellm",
        llm_model="litellm/gpt-5.4",
        timeout_seconds=600,
        trigger_source="api",
        started_at=now,
        finished_at=now,
        duration_seconds=12.3,
        step1_technical={"technical_method": "tm"},
        step2_classification={"classifications": [{"technique_id": "T0846", "confidence": 0.9}]},
        tool_trace=trace,
        tokens_prompt=100,
        tokens_completion=50,
        created_at=now,
    )


@pytest.fixture
def app_with_jobs():  # type: ignore[no-untyped-def]
    app = FastAPI()
    app.include_router(jobs_router)
    app.state.settings = _make_settings()
    app.state.alarms_repo = _FakeAlarmsRepo()
    app.state.baseline_repo = _FakeBaselineRepo()
    app.state.jobs_repo = _FakeJobsRepo()
    app.state.worker_pool = _FakePool()
    app.state.bus = _FakeBus()
    app.state.prompts = _FakePrompts()
    return app


def test_create_job_uses_live_applied_job_model(app_with_jobs: FastAPI) -> None:
    """AI-045 regression: a live model switch must reach the NEW job row.

    The boot snapshot (app.state.settings) still says gpt-5.4; the live push writes
    the new Settings to app.state.llm_config. The job must record the live model.
    """
    live = _make_settings()
    live.jobs.llm_model = "litellm/claude-haiku-5-5"
    app_with_jobs.state.llm_config = {"settings": live, "source": "live"}
    with TestClient(app_with_jobs) as client:
        r = client.post("/jobs", json={"alarm_id": "alarm-1", "prompt_variant": "forensic"})
    assert r.status_code == 202
    recorded = app_with_jobs.state.jobs_repo.inserts[-1]["llm_model"]
    assert recorded == "litellm/claude-haiku-5-5", recorded


# ── POST /jobs ───────────────────────────────────────────────────────


def test_create_job_happy_path(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post(
            "/jobs",
            json={"alarm_id": "alarm-1", "prompt_variant": "expert"},
        )
    assert r.status_code == 202
    body = r.json()
    assert "job_id" in body
    assert body["status"] == "pending"
    assert body["eta_seconds"] == 42
    assert body["events_url"].endswith("/events")
    # Pool received the spec.
    pool: _FakePool = app_with_jobs.state.worker_pool
    assert len(pool.enqueued) == 1
    assert pool.enqueued[0].alarm_id == "alarm-1"
    assert pool.enqueued[0].prompt_variant == "expert"
    # Repo recorded the insert. Post-Phase-9 the default provider is
    # "litellm" (legacy field, no longer used to dispatch backends).
    repo: _FakeJobsRepo = app_with_jobs.state.jobs_repo
    assert len(repo.inserts) == 1
    assert repo.inserts[0]["llm_provider"] == "litellm"
    # The model resolved to the configured LiteLLM identifier from settings.
    assert repo.inserts[0]["llm_model"] == "litellm/gpt-5.4"


def test_create_job_alarm_not_found(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post("/jobs", json={"alarm_id": "missing"})
    assert r.status_code == 404
    body = r.json()
    assert body["detail"]["detail"] == "alarm not found"


def test_create_job_baseline_not_found(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post(
            "/jobs",
            json={"alarm_id": "alarm-1", "baseline_id": str(uuid4())},
        )
    assert r.status_code == 404
    assert r.json()["detail"]["detail"] == "baseline not found"


def test_create_job_validation_error_empty_alarm_id(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post("/jobs", json={"alarm_id": ""})
    assert r.status_code == 422


def test_create_job_validation_error_bad_enum(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post("/jobs", json={"alarm_id": "alarm-1", "prompt_variant": "not-a-variant"})
    assert r.status_code == 422


def test_create_job_validation_error_timeout_out_of_range(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post("/jobs", json={"alarm_id": "alarm-1", "timeout_seconds": 99999})
    assert r.status_code == 422


def test_create_job_with_legacy_provider_name_is_accepted(app_with_jobs: FastAPI) -> None:
    """Post-Phase-9: ``llm_provider`` is legacy/optional but still accepted.

    Older chat-MCP callers may pass ``llm_provider="openai_compat"`` or
    ``"azure_openai"``; the server records the value verbatim on the job
    row for traceability but routes every classification through the
    LiteLLM proxy regardless. The persisted ``llm_endpoint`` always
    reflects ``settings.litellm.base_url``.
    """
    with TestClient(app_with_jobs) as client:
        r = client.post(
            "/jobs",
            json={
                "alarm_id": "alarm-1",
                "llm_provider": "openai_compat",
                "llm_model": "litellm/mistral",
                # Caller attempts to override the endpoint. The field is
                # not part of the schema; Pydantic drops it silently
                # (Cluster d / B1 SSRF close — still enforced).
                "llm_endpoint": "http://attacker.example/v1",
            },
        )
    assert r.status_code == 202
    pool: _FakePool = app_with_jobs.state.worker_pool
    assert pool.enqueued[0].llm_provider == "openai_compat"
    # Endpoint always comes from settings.litellm.base_url now, never the caller.
    assert pool.enqueued[0].llm_endpoint == "http://litellm:4000/v1"
    assert pool.enqueued[0].llm_endpoint != "http://attacker.example/v1"


def test_create_job_silently_ignores_caller_supplied_llm_endpoint(app_with_jobs: FastAPI) -> None:
    """Regression for Cluster d / B1: ``llm_endpoint`` in the request body
    is silently dropped at schema validation; the server-side endpoint
    (post Phase 9: ``settings.litellm.base_url``) is the one persisted
    on the job spec.
    """
    with TestClient(app_with_jobs) as client:
        r = client.post(
            "/jobs",
            json={
                "alarm_id": "alarm-1",
                "llm_provider": "azure_openai",
                "llm_endpoint": "http://169.254.169.254/latest/meta-data/",
            },
        )
    assert r.status_code == 202
    pool: _FakePool = app_with_jobs.state.worker_pool
    repo: _FakeJobsRepo = app_with_jobs.state.jobs_repo
    # The endpoint forwarded to the worker is the configured LiteLLM proxy URL.
    assert pool.enqueued[0].llm_endpoint == "http://litellm:4000/v1"
    # The persisted job record likewise reflects the configured endpoint.
    assert repo.inserts[0]["llm_endpoint"] == "http://litellm:4000/v1"


def test_create_job_resolves_default_prompt_when_omitted(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post("/jobs", json={"alarm_id": "alarm-1"})
    assert r.status_code == 202
    pool: _FakePool = app_with_jobs.state.worker_pool
    # default_prompt in JobsConfig is "expert"
    assert pool.enqueued[0].prompt_variant == "expert"


def test_create_job_accepts_forensic_variant(app_with_jobs: FastAPI) -> None:
    """AI-017: the API accepts prompt_variant='forensic' and forwards it."""
    with TestClient(app_with_jobs) as client:
        r = client.post(
            "/jobs",
            json={"alarm_id": "alarm-1", "prompt_variant": "forensic"},
        )
    assert r.status_code == 202
    pool: _FakePool = app_with_jobs.state.worker_pool
    assert pool.enqueued[0].prompt_variant == "forensic"


# ── GET /jobs ────────────────────────────────────────────────────────


def test_list_jobs_empty(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.get("/jobs")
    assert r.status_code == 200
    body = r.json()
    assert body["items"] == []
    assert body["total"] == 0
    assert body["limit"] == 50
    assert body["offset"] == 0


def test_list_jobs_with_pagination_and_filters(app_with_jobs: FastAPI) -> None:
    repo: _FakeJobsRepo = app_with_jobs.state.jobs_repo
    rec = _build_record(job_id=uuid4(), status=JobStatus.RUNNING)
    summary = JobSummary(
        id=rec.id,
        alarm_id=rec.alarm_id,
        status=rec.status,
        prompt_variant=rec.prompt_variant,
        llm_provider=rec.llm_provider,
        llm_model=rec.llm_model,
        tool_trace_count=1,
        tokens_total=150,
        step1_method="tm",
        top_step2={"technique_id": "T0846"},
        created_at=rec.created_at,
    )
    repo.list_pages.append(([summary], 1))

    with TestClient(app_with_jobs) as client:
        r = client.get("/jobs", params={"alarm_id": "alarm-1", "status": "running", "limit": 10, "offset": 5})
    assert r.status_code == 200
    body = r.json()
    assert body["limit"] == 10
    assert body["offset"] == 5
    assert body["total"] == 1
    assert len(body["items"]) == 1
    assert body["items"][0]["alarm_id"] == "alarm-1"


def test_list_jobs_rejects_invalid_status(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.get("/jobs", params={"status": "nonsense"})
    assert r.status_code == 422


def test_list_jobs_rejects_invalid_limit(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.get("/jobs", params={"limit": 500})  # > 200
    assert r.status_code == 422


# ── GET /jobs/{id} ───────────────────────────────────────────────────


def test_get_job_happy(app_with_jobs: FastAPI) -> None:
    repo: _FakeJobsRepo = app_with_jobs.state.jobs_repo
    jid = uuid4()
    repo.jobs[jid] = _build_record(job_id=jid)

    with TestClient(app_with_jobs) as client:
        r = client.get(f"/jobs/{jid}")
    assert r.status_code == 200
    body = r.json()
    assert body["id"] == str(jid)
    assert body["status"] == "completed"
    assert body["step1_technical"]["technical_method"] == "tm"


def test_get_job_404(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.get(f"/jobs/{uuid4()}")
    assert r.status_code == 404
    assert r.json()["detail"] == "job not found"


def test_get_job_invalid_uuid(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.get("/jobs/not-a-uuid")
    assert r.status_code == 422


# ── POST /jobs/{id}/cancel ───────────────────────────────────────────


def test_cancel_job_happy(app_with_jobs: FastAPI) -> None:
    pool: _FakePool = app_with_jobs.state.worker_pool
    jid = uuid4()
    pool.cancelled_ok.add(jid)
    with TestClient(app_with_jobs) as client:
        r = client.post(f"/jobs/{jid}/cancel")
    assert r.status_code == 200
    body = r.json()
    assert body["job_id"] == str(jid)
    assert body["cancellation_requested"] is True


def test_cancel_job_not_active_404(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.post(f"/jobs/{uuid4()}/cancel")
    assert r.status_code == 404
    assert r.json()["detail"] == "job not active"


# ── GET /jobs/{id}/events ────────────────────────────────────────────


def test_stream_events_404_when_job_missing(app_with_jobs: FastAPI) -> None:
    with TestClient(app_with_jobs) as client:
        r = client.get(f"/jobs/{uuid4()}/events")
    assert r.status_code == 404


def test_stream_events_terminal_replay(app_with_jobs: FastAPI) -> None:
    """A completed job replays its tool_trace + a synthetic 'final' event, then ends."""
    repo: _FakeJobsRepo = app_with_jobs.state.jobs_repo
    jid = uuid4()
    repo.jobs[jid] = _build_record(job_id=jid, status=JobStatus.COMPLETED, with_trace=True)

    with TestClient(app_with_jobs) as client:
        r = client.get(f"/jobs/{jid}/events", headers={"accept": "text/event-stream"})
    assert r.status_code == 200
    body = r.text
    # Trace was replayed.
    assert "event: tool_call_completed" in body
    assert "postgres.read_anomalies" in body
    # Final synthetic event present.
    assert "event: final" in body
    assert '"status": "completed"' in body


# ── AI-03: blocking SQLAlchemy repo calls must run off the loop ──────


def _repo_thread_ids(app: FastAPI) -> List[int]:
    out: List[int] = []
    for attr in ("alarms_repo", "baseline_repo", "jobs_repo", "worker_pool"):
        out.extend(getattr(app.state, attr).call_thread_ids)
    return out


def test_repo_calls_run_off_the_event_loop_thread(app_with_jobs: FastAPI) -> None:
    """AI-03: every blocking repo/pool-DB call from the REST handlers
    MUST be dispatched via ``asyncio.to_thread`` — never executed on the
    event-loop thread.
    """
    import threading

    handler_thread_ids: List[int] = []

    @app_with_jobs.get("/_probe_thread")
    async def _probe() -> Dict[str, int]:
        handler_thread_ids.append(threading.get_ident())
        return {"tid": threading.get_ident()}

    repo: _FakeJobsRepo = app_with_jobs.state.jobs_repo
    jid = uuid4()
    repo.jobs[jid] = _build_record(job_id=jid)

    with TestClient(app_with_jobs) as client:
        assert client.get("/_probe_thread").status_code == 200
        assert client.post("/jobs", json={"alarm_id": "alarm-1"}).status_code == 202
        assert client.get("/jobs").status_code == 200
        assert client.get(f"/jobs/{jid}").status_code == 200

    assert handler_thread_ids, "probe endpoint never ran"
    loop_tid = handler_thread_ids[0]
    offending = _repo_thread_ids(app_with_jobs)
    assert offending, "no repo/pool DB call was recorded"
    assert all(
        tid != loop_tid for tid in offending
    ), f"blocking repo calls ran on the event-loop thread {loop_tid}: {offending}"
