"""MCP server initialization for OTALON.

This server:
- Loads runtime settings exclusively from config/config.json (no CLI arguments).
- Constructs repository instances (Postgres, Influx) in-process.
- Provides defaults to the unified tool module (mcp_tools.py).
- Uses transport configured via Settings.server.transport (streamable-http or stdio).
- Installs a robust shutdown handler with force-quit on second signal and a timed kill
  to avoid hangs if open HTTP connections prevent graceful shutdown.
- Exposes a GET /health endpoint for external monitoring probes (HTTP transports only).
"""

from __future__ import annotations

import os
import signal
import sys
import threading
import time
from pathlib import Path
from typing import Literal

import uvicorn
from loguru import logger
from mcp.server.fastmcp import FastMCP
from otalon_common.auth.api_key import KeyRegistry
from otalon_common.auth.fastapi import make_api_key_middleware
from otalon_common.logging import configure_logging
from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Mount, Route

from otalon_mcp.mcp_tools import Defaults, init_mcp_tools
from otalon_mcp.repositories.influx_repo import InfluxRepo
from otalon_mcp.repositories.postgres_repo import PostgresRepo
from otalon_mcp.settings import InfluxConfig, LoggingConfig, Settings


def _configure_logging(log_config: LoggingConfig) -> None:
    """Configure loguru loggers for file and stdout."""
    level = log_config.level.upper()
    configure_logging(
        log_file=log_config.file,
        console_level=level,
        file_level=level,
        rotation="10 MB",
        retention="14 days",
        stream=sys.stdout,
        console_format="<green>{time:YYYY-MM-DD HH:mm:ss}</green> | <white>{file}:{line}</white> | "
        "<level>{level: <8}</level> | <level>{message}</level>",
        colorize=True,
    )


def _build_defaults(influx: InfluxConfig) -> Defaults:
    """Build the tool defaults from the typed influx settings section.

    Args:
        influx: The resolved influx configuration.

    Returns:
        Defaults carrying measurement, id tag and field list.
    """
    return Defaults(
        measurement=influx.measurement,
        id_tag=influx.id_tag,
        fields=list(influx.fields),
    )


def _default_config_path() -> str:
    """Return absolute path to otalon-mcp/config/config.json regardless of CWD.

    Three levels up from ``src/otalon_mcp/server.py`` is the subproject root
    locally and ``/app`` in the container, where ``config/`` sits next to
    ``src/`` in both layouts.
    """
    root = Path(__file__).resolve().parents[2]
    return str(root / "config" / "config.json")


def create_server(settings: Settings) -> FastMCP:
    """Create and configure a FastMCP server instance.

    This function constructs repositories and registers all tools from mcp_tools.py.
    """
    server_name = settings.server.name
    host = settings.server.host
    port = settings.server.port

    influx_database = settings.influx.database
    defaults = _build_defaults(settings.influx)

    logger.debug(
        "Creating MCP server",
        name=server_name,
        host=host,
        port=port,
        influx_url=settings.influx.url,
        influx_database=influx_database,
        measurement=defaults.measurement,
        id_tag=defaults.id_tag,
    )

    # Initialize repositories with settings from config
    pg_repo = PostgresRepo(settings.postgres.dsn)
    influx_repo = InfluxRepo(
        host=settings.influx.url,
        token=settings.influx.token or "",
        database=influx_database,
    )

    # Build server
    mcp = FastMCP(server_name, host=host, port=port)

    # Extract pcap_recorder configuration
    pcap_url = settings.pcap_recorder.url
    pcap_timeout = settings.pcap_recorder.timeout_seconds

    stix_path = str((Path(__file__).resolve().parents[2] / settings.mitre.stix_bundle_path).resolve())

    # Register unified tools. Every value comes from the typed settings
    # model, which is the single resolution point for them (MCP-014).
    init_mcp_tools(
        mcp,
        pg_repo=pg_repo,
        influx_repo=influx_repo,
        defaults=defaults,
        pcap_url=pcap_url,
        pcap_timeout=pcap_timeout,
        pcap_api_key=settings.pcap_recorder.api_key,
        stix_path=stix_path,
        agent_url=settings.agent.url,
        agent_timeout=settings.agent.timeout_seconds,
        pg_dsn=settings.postgres.dsn,
        baseline_dir=settings.baseline.directory,
        api_url=settings.otalon_api.url,
        api_key=settings.otalon_api.api_key,
        api_timeout=settings.otalon_api.timeout_seconds,
        confirm_nonce_ttl=settings.otalon_api.confirm_nonce_ttl_seconds,
    )

    return mcp


def _install_shutdown_handlers(force_timeout_s: float = 8.0) -> None:
    """Install shutdown handlers with timed forced exit to avoid hangs.

    Behavior:
    - On first SIGINT/SIGTERM:
        * Log intent for graceful shutdown.
        * Start a timer thread that will forcefully exit the process after a timeout
          (``settings.server.force_timeout_seconds``, default 8 seconds).
        * Do NOT raise SystemExit immediately; let uvicorn begin graceful shutdown.
    - On second SIGINT/SIGTERM:
        * Force immediate exit via os._exit(130).

    Args:
        force_timeout_s: Seconds to wait before the hard exit.
    """
    counter = {"n": 0}

    def _force_kill_after_timeout() -> None:
        # Last resort: hard exit to avoid getting stuck while "waiting for connections to close".
        time.sleep(max(1.0, force_timeout_s))
        logger.warning(
            "Force quitting MCP server after timeout ({}s) due to hanging shutdown.",
            force_timeout_s,
        )
        os._exit(130)

    def _handler(signum: int, frame) -> None:  # type: ignore[override]
        counter["n"] += 1
        if counter["n"] == 1:
            logger.info(
                "Received signal {sign}. Attempting graceful shutdown. A forced quit will trigger after timeout.",
                sign=signum,
            )
            # Start a kill timer; do not interrupt uvicorn's own graceful shutdown handler.
            t = threading.Thread(
                target=_force_kill_after_timeout,
                name="otalon-mcp-force-kill",
                daemon=True,
            )
            t.start()
            # No SystemExit here: allow uvicorn/FastMCP handlers to proceed gracefully.
        else:
            logger.warning("Second interrupt received. Forcing immediate shutdown.")
            os._exit(130)

    # Let our handler run alongside uvicorn's own signal handling.
    signal.signal(signal.SIGINT, _handler)
    signal.signal(signal.SIGTERM, _handler)


async def _health_check(_request: Request) -> JSONResponse:
    """Health check endpoint for external monitoring probes.

    Returns a JSON ``{"status": "ok"}`` response with HTTP 200.
    This is only available when the server uses an HTTP transport
    (streamable-http or sse).
    """
    return JSONResponse({"status": "ok"})


def _build_http_app(
    mcp: FastMCP,
    transport: Literal["sse", "streamable-http"],
) -> Starlette:
    """Wrap the FastMCP Starlette app with a ``/health`` route.

    Parameters:
        mcp: The configured FastMCP server instance.
        transport: The HTTP transport type (``sse`` or ``streamable-http``).

    Returns:
        A Starlette application that serves ``/health`` and delegates all
        other routes to the underlying MCP application.
    """
    if transport == "sse":
        mcp_app = mcp.sse_app()
    else:
        mcp_app = mcp.streamable_http_app()

    app = Starlette(
        routes=[
            Route("/health", _health_check, methods=["GET"]),
            Mount("/", app=mcp_app),
        ],
        lifespan=mcp_app.router.lifespan_context,
    )
    registry = KeyRegistry.from_env("OTALON_MCP_ALLOWED_KEYS")
    app.add_middleware(
        make_api_key_middleware(
            registry=registry,
            protected_prefixes=("/",),
            open_paths=("/health",),
        )
    )
    return app


def main() -> int:
    """Entry point for running the MCP server (no CLI args)."""
    cfg = Settings.from_json(_default_config_path())
    _configure_logging(cfg.logging)

    transport: Literal["stdio", "sse", "streamable-http"] = cfg.server.transport  # type: ignore[assignment]

    logger.info(
        "Starting OTALON MCP server",
        host=cfg.server.host,
        port=cfg.server.port,
        transport=transport,
    )

    mcp = create_server(settings=cfg)

    _install_shutdown_handlers(cfg.server.force_timeout_seconds)

    if transport == "stdio":
        return _run_stdio(mcp)

    return _run_http(mcp, cfg, transport)


def _run_stdio(mcp: FastMCP) -> int:
    """Run the MCP server with stdio transport.

    Parameters:
        mcp: The configured FastMCP server instance.

    Returns:
        Process exit code.
    """
    try:
        mcp.run(transport="stdio")
    except SystemExit as ex:
        logger.info(
            "OTALON MCP server terminating with code {code}.",
            code=int(ex.code or 0),
        )
        return int(ex.code or 0)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, stopping MCP server.")
        return 130
    finally:
        logger.info("OTALON MCP server stopped.")
    return 0


def _run_http(
    mcp: FastMCP,
    cfg: Settings,
    transport: Literal["sse", "streamable-http"],
) -> int:
    """Run the MCP server with an HTTP transport, adding a /health endpoint.

    Parameters:
        mcp: The configured FastMCP server instance.
        cfg: Application settings (used for host/port).
        transport: The HTTP transport type.

    Returns:
        Process exit code.
    """
    app = _build_http_app(mcp, transport)
    logger.info("Registered GET /health endpoint for monitoring probes.")

    try:
        uvicorn.run(app, host=cfg.server.host, port=cfg.server.port)
    except SystemExit as ex:
        logger.info(
            "OTALON MCP server terminating with code {code}.",
            code=int(ex.code or 0),
        )
        return int(ex.code or 0)
    except KeyboardInterrupt:
        logger.info("KeyboardInterrupt received, stopping MCP server.")
        return 130
    finally:
        logger.info("OTALON MCP server stopped.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
