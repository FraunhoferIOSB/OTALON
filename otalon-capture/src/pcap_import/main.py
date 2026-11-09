"""Entry point for the PCAP import worker service."""

from __future__ import annotations

import asyncio
import os
import signal
import sys
from pathlib import Path
from typing import Optional

import uvicorn
from dotenv import load_dotenv
from loguru import logger
from otalon_common.logging import configure_logging

from .api import create_app
from .reporter import create_reporter
from .runner import PipelineImportRunner
from .service import ImportService
from .settings import LogConfig, PcapImportSettings

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"

DEFAULT_CONFIG_FILE = "config/config_import.json"


class RuntimeState:
    """Track the running server for signal handling."""

    def __init__(self) -> None:
        self.running = True
        self.uvicorn_server: Optional[uvicorn.Server] = None

    async def stop(self) -> None:
        """Shut the HTTP server down gracefully."""

        self.running = False
        if self.uvicorn_server is not None and getattr(self.uvicorn_server, "started", False):
            await self.uvicorn_server.shutdown()


def _configure_logging(log_config: LogConfig) -> None:
    """Configure Loguru sinks for the worker."""

    log_path = Path(log_config.file)
    log_path.parent.mkdir(parents=True, exist_ok=True)
    level = log_config.level.upper()

    configure_logging(
        log_file=log_path,
        console_level=level,
        file_level=level,
        rotation="10 MB",
        retention="14 days",
        stream=sys.stdout,
        console_format=(
            "<green>{time:YYYY-MM-DD at HH:mm:ss}</green> | "
            "<level>{level: <8}</level> | "
            "<cyan>{name}:{line}</cyan> | "
            "<white>{message}</white>"
        ),
        colorize=True,
    )


def build_service(settings: PcapImportSettings) -> ImportService:
    """Assemble the import service from ``settings``.

    Args:
        settings: Resolved worker configuration.

    Returns:
        A service wired to a pipeline runner and an HTTP progress reporter.
    """

    runner = PipelineImportRunner(
        adapter_config_file=settings.adapter_config_file,
        progress_interval_records=int(settings.progress_interval_records),
        import_dir=settings.import_dir,
    )
    return ImportService(runner=runner, reporter=create_reporter(settings.reporter))


async def _serve(app: uvicorn.Config, state: RuntimeState) -> None:
    """Run the uvicorn server, reporting bind failures instead of crashing."""

    server = uvicorn.Server(config=app)
    state.uvicorn_server = server
    try:
        await server.serve()
    except SystemExit as exc:
        logger.error("Uvicorn exited with code {code} (port likely in use).", code=exc.code)
        state.running = False


def main() -> None:
    """Load configuration and serve the import worker."""

    logger.info("Loading environment variables from: {path}", path=ENV_PATH)
    load_dotenv(dotenv_path=str(ENV_PATH), override=True)

    # Raw by necessity (PCAP-007): this selects WHICH config file is loaded,
    # so it cannot itself come from that file. Sanctioned by the raw
    # os.environ rule in .kilo/agent/backend.md.
    config_path = Path(os.environ.get("PCAP_IMPORT_CONFIG_FILE", DEFAULT_CONFIG_FILE))
    settings = PcapImportSettings.from_json(config_path)
    _configure_logging(settings.log)

    service = build_service(settings)
    app = create_app(service)

    runtime_state = RuntimeState()
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def handle_signal(*_args: object) -> None:
        logger.info("Shutdown signal received.")
        loop.create_task(runtime_state.stop())

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    config = uvicorn.Config(
        app=app,
        host=settings.api.host,
        port=int(settings.api.port),
        log_config=None,
        loop="asyncio",
    )
    logger.info(
        "PCAP import worker listening on {host}:{port}.",
        host=settings.api.host,
        port=settings.api.port,
    )
    try:
        loop.run_until_complete(_serve(config, runtime_state))
    finally:
        loop.run_until_complete(runtime_state.stop())
        loop.close()


if __name__ == "__main__":
    main()
