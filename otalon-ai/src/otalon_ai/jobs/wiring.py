"""Lifespan wiring for the jobs surface.

The inherited agent server built engine + repositories + worker
pool inside its lifespan. We re-wire the same setup here so
:mod:`otalon_ai.main`
can opt in / out cleanly (the chat surface may want to start without the jobs
worker pool during local development).

Per design.md § "Module layout" the jobs sub-package is a self-contained
re-host of the inherited code; only the import paths changed. Phase 9 of
tasks.md will swap the LLM factory call to LiteLLM without touching the
wiring sketched here.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

from fastapi import FastAPI
from loguru import logger

from otalon_ai.jobs.events_bus import EventsBus
from otalon_ai.jobs.repositories.postgres_repo import (
    AlarmsRepo,
    BaselineRepo,
    SubagentJobsRepo,
    build_engine,
    ensure_schema,
)
from otalon_ai.jobs.worker_pool import WorkerPool
from otalon_ai.prompts.loader import PromptLoader
from otalon_ai.settings import Settings


def _prompts_dir() -> Path:
    """Resolve the bundled jobs prompts directory.

    The two markdowns (``system_prompt_expert.md`` / ``system_prompt_open.md``)
    live next to the jobs sub-package under
    ``otalon_ai/jobs/prompts_data/``.
    """
    return Path(__file__).resolve().parent / "prompts_data"


async def start_jobs_surface(app: FastAPI, settings: Settings) -> None:
    """Initialise repositories + worker pool and attach them to app.state.

    Raises any exception encountered — the caller decides whether to abort
    startup (production) or log + continue (chat-only dev).
    """
    logger.info(
        "jobs surface: starting (n_workers={}, default_prompt={})",
        settings.jobs.n_workers,
        settings.jobs.default_prompt,
    )

    engine = build_engine(settings.db.dsn)
    ensure_schema(engine)

    jobs_repo = SubagentJobsRepo(engine)
    # AI-06: fail jobs stranded in pending/running by a previous process
    # BEFORE the new pool starts (blocking SQLAlchemy off the loop).
    await asyncio.to_thread(jobs_repo.reap_stranded)
    baseline_repo = BaselineRepo(engine)
    alarms_repo = AlarmsRepo(engine)
    prompts = PromptLoader(_prompts_dir())
    bus = EventsBus()

    pool = WorkerPool(
        settings=settings,
        prompts=prompts,
        bus=bus,
        jobs_repo=jobs_repo,
        alarms_repo=alarms_repo,
        baseline_repo=baseline_repo,
    )
    await pool.start()

    app.state.jobs_engine = engine
    app.state.jobs_repo = jobs_repo
    app.state.baseline_repo = baseline_repo
    app.state.alarms_repo = alarms_repo
    app.state.prompts = prompts
    app.state.bus = bus
    app.state.worker_pool = pool


async def stop_jobs_surface(app: FastAPI) -> None:
    """Drain the worker pool and release the SQLAlchemy engine."""
    pool: Any = getattr(app.state, "worker_pool", None)
    if pool is not None:
        await pool.stop()
    engine = getattr(app.state, "jobs_engine", None)
    if engine is not None:
        engine.dispose()
    logger.info("jobs surface: stopped")
