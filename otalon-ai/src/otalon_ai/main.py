"""FastAPI entry point for OTALON-AI.

Hosts both the chat surface (`/api/v1/chat/*`) and the jobs surface
(`/jobs/*`, contract-preserved from the standalone ``otalon-agent``)
in the same app, on port 9100. See design.md § "Module layout" for the
full rationale.

The lifespan does, in order:

1. Load settings (env-var resolution).
2. Configure loguru sinks (stderr + optional file).
3. Apply SQL migrations (creates ``chat_sessions``).
4. Build the shared :class:`Database` handle.
5. Connect the shared :class:`McpRegistry` (chat + jobs).
6. Load the system prompt from disk.
7. Build the jobs ``WorkerPool`` (inherited).
8. Mount routers.

On shutdown the worker pool is drained and DB handles are closed.
"""

from __future__ import annotations

import os
import sys
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, AsyncIterator, Dict

from fastapi import FastAPI, Response
from loguru import logger
from otalon_common.auth.api_key import KeyRegistry
from otalon_common.auth.fastapi import make_api_key_middleware
from otalon_common.logging import configure_logging


def _default_config_path() -> str:
    """Return the absolute path to ``config/config.json``."""
    root = Path(__file__).resolve().parents[2]
    return str(root / "config" / "config.json")


def _configure_logging(level: str, file: str | None) -> None:
    """Reset loguru sinks. Used at process startup."""
    console_format = (
        "<green>{time:YYYY-MM-DD HH:mm:ss}</green> | "
        "<level>{level: <8}</level> | "
        "<cyan>{name}:{line}</cyan> | {message}"
    )
    upper = level.upper()
    if not file:
        configure_logging(
            console_level=upper, stream=sys.stderr, console_format=console_format
        )
        return
    try:
        os.makedirs(os.path.dirname(file), exist_ok=True)
        configure_logging(
            log_file=file,
            console_level=upper,
            file_level=upper,
            rotation="20 MB",
            retention=5,
            stream=sys.stderr,
            console_format=console_format,
            enqueue=True,
        )
    except Exception as exc:  # pragma: no cover - file sink optional
        configure_logging(
            console_level=upper, stream=sys.stderr, console_format=console_format
        )
        logger.warning("Could not attach file sink for {}: {}", file, exc)


@asynccontextmanager
async def _lifespan(app: FastAPI) -> AsyncIterator[None]:
    # Imports here so module import does not eagerly require psycopg2 / mcp etc.
    # in environments that only need the FastAPI object (e.g. test collection).
    from otalon_ai import migrations
    from otalon_ai.db import Database
    from otalon_ai.jobs.wiring import start_jobs_surface, stop_jobs_surface
    from otalon_ai.settings import Settings

    settings = Settings.from_json(_default_config_path())
    _configure_logging(settings.logging.level, settings.logging.file)
    logger.info(
        "otalon-ai starting (host={}, port={}, chat_history_window={}, jobs_n_workers={})",
        settings.server.host,
        settings.server.port,
        settings.chat.history_window,
        settings.jobs.n_workers,
    )

    database = Database(settings.db.dsn)
    try:
        migrations.run(database)
    except Exception as exc:
        logger.exception("migrations failed: {}", exc)
        raise

    app.state.settings = settings
    app.state.database = database
    # AI-045: register the otalon-ai runtime keys so the runtime-config write path
    # accepts them. Lazy import keeps module import light (same as the lines above).
    from otalon_ai.runtime_keys import register_runtime_keys

    register_runtime_keys()
    # AI-045: a saved configuration survives a restart. Values in runtime_config win over
    # the env bootstrap; a missing row or an unreachable database keeps the env value.
    from otalon_ai.runtime_keys import load_saved_ai_values, saved_context_window

    saved = load_saved_ai_values(database)
    if saved.get("ai.chat_model"):
        settings.chat.llm_model = saved["ai.chat_model"]
    if saved.get("ai.job_model"):
        settings.jobs.llm_model = saved["ai.job_model"]
    if saved.get("ai.endpoint"):
        settings.litellm.base_url = saved["ai.endpoint"]
    # AI-046: the saved context window replaces the env default after a restart too.
    context_window = saved_context_window(saved.get("ai.context_window"))
    if context_window is not None:
        settings.chat.model_context_window = context_window
    if saved:
        logger.info(
            "AI runtime values loaded from runtime_config: keys={}", sorted(saved)
        )
    # AI-045 live-config state: the authoritative ``Settings`` reference
    # used by /internal/v1/llm-config. ``applied_at`` marks the env
    # bootstrap; a successful live push flips ``source`` to ``live``.
    app.state.llm_config = {
        "settings": settings,
        "source": "env",
        "applied_at": datetime.now(tz=timezone.utc),
    }

    # Chat surface: session store + retention prune. Per spec
    # `chat--postgres-schema` § "chat_sessions SHALL be pruned" the
    # startup query removes stale rows. The store itself stays attached
    # to app.state for the chat router (Phase 8 of tasks.md).
    from otalon_ai.chat.pruner import ChatSessionPruner
    from otalon_ai.chat.session_store import ChatSessionStore
    from otalon_ai.mcp.registry import McpRegistry

    chat_store = ChatSessionStore(database, history_window=settings.chat.history_window)
    chat_store.prune(settings.chat.retention_days)
    app.state.chat_store = chat_store

    # Long-running asyncio task that re-runs ``ChatSessionStore.prune``
    # hourly so retention is enforced for long-uptime processes (not
    # only at startup). Cancelled cleanly on lifespan shutdown.
    chat_pruner = ChatSessionPruner(
        chat_store,
        retention_days=settings.chat.retention_days,
    )
    chat_pruner.start()
    app.state.chat_pruner = chat_pruner

    # Shared MCP registry. Discovery is lazy on the first
    # `list_openai_tools()` call so a slow / unreachable MCP server does
    # not block startup; per spec chat--orchestration § "MCP server is
    # unreachable at startup" the registry simply caches an empty list
    # and rediscovers on the next request.
    mcp_registry = McpRegistry(
        settings.mcp.servers,
        request_timeout_seconds=settings.mcp.request_timeout_seconds,
    )
    app.state.mcp_registry = mcp_registry

    # Chat system prompt — loaded eagerly so startup fails loudly when
    # the canonical mount is missing (per spec chat--orchestration §
    # "Missing prompt file" → startup error).
    from otalon_ai.chat.agent_loop import ChatAgentLoop
    from otalon_ai.llm.factory import build_chat_provider
    from otalon_ai.prompts.loader import load_system_prompt

    chat_system_prompt = load_system_prompt()
    app.state.chat_system_prompt = chat_system_prompt

    # Chat agent loop — substantive core, constructed once, reused by both
    # /api/v1/chat (sync) and /api/v1/chat/stream/{id} (SSE) in Phase 8.
    # Per Cluster d / B5: forward ``settings.chat.allowed_tools`` so the
    # agent loop applies a default-deny allow-list to BOTH discovery
    # and execution. An empty list (the config default) means "no
    # tools" — the LLM sees no callable surface — until the operator
    # opts in explicitly.
    app.state.chat_loop = ChatAgentLoop(
        llm=build_chat_provider(settings),
        mcp_registry=mcp_registry,
        session_store=chat_store,
        system_prompt=chat_system_prompt,
        max_tool_rounds=settings.chat.max_tool_rounds,
        allowed_tools=settings.chat.allowed_tools,
    )

    # Jobs surface: full wiring (engine, repos, worker pool). The
    # inherited otalon-agent code lives under otalon_ai/jobs/ unchanged in
    # behaviour. Failure here is fatal because the public jobs API would
    # otherwise return 500s.
    await start_jobs_surface(app, settings)

    yield

    await stop_jobs_surface(app)
    await chat_pruner.stop()
    database.close()
    logger.info("otalon-ai shut down")


def create_app() -> FastAPI:
    """Build the FastAPI app for the otalon-ai service.

    Mounts the jobs router (root paths ``/jobs/*``), the chat router
    (``/api/v1/chat``), and the chat SSE router. Registers a ``/health``
    endpoint that surfaces worker-pool readiness. The async lifespan
    (:func:`_lifespan`) takes care of settings loading, logging setup,
    migrations, MCP registry, prompt loading, and worker-pool start /
    stop.

    Returns:
        A configured :class:`FastAPI` instance ready to be served by
        uvicorn (or to be imported by tests as ``otalon_ai.main:app``).
    """
    from otalon_ai.api.llm_config import router as llm_config_router
    from otalon_ai.chat.router import router as chat_router
    from otalon_ai.chat.sse import router as chat_sse_router
    from otalon_ai.jobs.api.jobs import router as jobs_router

    app = FastAPI(
        title="otalon-ai",
        description="Consolidated chat orchestration + subagent classification jobs service.",
        version="0.1.0",
        lifespan=_lifespan,
    )

    app.add_middleware(
        make_api_key_middleware(
            registry=KeyRegistry.from_env("OTALON_AI_ALLOWED_KEYS"),
            # AI-045 Task 1.4: ``/internal`` hosts the live LLM-config
            # push from otalon-api; it is protected by the same
            # X-API-Key registry (internal key carries role ``operator``).
            protected_prefixes=("/api/v1/chat", "/jobs", "/internal"),
        )
    )

    # Jobs router: paths `/jobs`, `/jobs/{id}`, `/jobs/{id}/cancel`,
    # `/jobs/{id}/events` — unchanged contract from otalon-agent. The
    # consuming otalon-api hits these as `<AI_URL>/jobs/...`.
    app.include_router(jobs_router)

    # Chat surface routers: /api/v1/chat (sync) + /api/v1/chat/stream/{id}
    # (SSE). Mounted under the /api/v1/chat/* prefix per spec
    # `chat--orchestration` § "Chat routes SHALL be mounted ...".
    app.include_router(chat_router)
    app.include_router(chat_sse_router)

    # Internal surface (AI-045): /internal/v1/llm-config — live LLM
    # configuration push + status. Protected by the middleware above.
    app.include_router(llm_config_router)

    @app.get("/metrics")
    async def metrics() -> Response:
        """Expose Prometheus counters (token usage, etc.).

        Wires ``src.metrics.render_metrics`` so any module that imports
        ``src.metrics`` and increments a Counter is automatically
        surfaced. Currently advertises:

        - ``otalon_ai_chat_tokens_total{type="prompt|completion"}``
        - ``otalon_ai_jobs_tokens_total{type="prompt|completion"}``
        """
        from otalon_ai.metrics import render_metrics

        body, content_type = render_metrics()
        return Response(content=body, media_type=content_type)

    @app.get("/health")
    async def health() -> Dict[str, Any]:
        settings = getattr(app.state, "settings", None)
        pool = getattr(app.state, "worker_pool", None)
        jobs_ready = pool is not None
        return {
            "ok": True,
            "name": settings.server.name if settings else "otalon-ai",
            "version": app.version,
            "chat": {"ready": True},
            "jobs": {
                "ready": jobs_ready,
                "active_jobs": pool.active_count() if pool else 0,
                "queued_jobs": pool.queue_size() if pool else 0,
            },
        }

    return app


app = create_app()
