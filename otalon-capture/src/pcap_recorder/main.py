"""Entry point for the netcap_pcap_recorder service."""

from __future__ import annotations

import asyncio
import contextlib
import os
import signal
import sys
from datetime import timedelta
from pathlib import Path
from typing import Optional

import uvicorn
from dotenv import load_dotenv
from loguru import logger
from otalon_common.logging import configure_logging

from .api import CaptureStatusProvider, PcapService, create_app
from .capture_stats import CaptureLossMonitor
from .index import PcapIndex
from .recorder import TcpdumpRecorder
from .ringbuffer import RingbufferManager
from .settings import LogConfig, PcapRecorderSettings

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"

CAPTURE_STATS_INTERVAL_S = 30


class RuntimeState:
    """Track running components for signal handling."""

    def __init__(self) -> None:
        self.running = True
        self.recorder: Optional[TcpdumpRecorder] = None
        self.uvicorn_server: Optional[uvicorn.Server] = None
        self.ringbuffer_task: Optional[asyncio.Task[None]] = None
        self.capture_stats_task: Optional[asyncio.Task[None]] = None

    async def stop(self) -> None:
        """Gracefully shut down all managed components."""
        self.running = False
        if self.recorder:
            self.recorder.stop()
        if self.uvicorn_server:
            if getattr(self.uvicorn_server, "started", False):
                await self.uvicorn_server.shutdown()
            else:
                logger.warning("Uvicorn server was never fully started; skipping shutdown().")
        if self.ringbuffer_task:
            self.ringbuffer_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.ringbuffer_task
        if self.capture_stats_task:
            self.capture_stats_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.capture_stats_task


async def _run_uvicorn(app, host: str, port: int, state: RuntimeState) -> None:
    """Start the uvicorn ASGI server and propagate bind errors gracefully."""
    config = uvicorn.Config(app=app, host=host, port=port, log_config=None, loop="asyncio")
    server = uvicorn.Server(config=config)
    state.uvicorn_server = server
    try:
        await server.serve()
    except SystemExit as exc:
        logger.error("Uvicorn exited with code {code} (port {port} likely in use).", code=exc.code, port=port)
        state.running = False


async def _ringbuffer_loop(state: RuntimeState, ringbuffer: RingbufferManager) -> None:
    """Tick the ringbuffer every 5 s until the recorder stops.

    PCAP-018: a failing tick used to end this task silently (no handler), and
    the index then stopped growing while the buffer kept filling. A failed tick
    is now logged with its traceback and the loop keeps running.
    """
    try:
        while state.running:
            try:
                ringbuffer.tick()
            except Exception:  # noqa: BLE001 - keep the loop alive, make the failure visible
                logger.exception("Ringbuffer tick failed; retrying in 5 s")
            await asyncio.sleep(5)
    except asyncio.CancelledError:
        logger.info("Ringbuffer loop cancelled.")
        raise


async def _capture_stats_loop(
    state: RuntimeState,
    monitor: CaptureLossMonitor,
    interval_s: int = CAPTURE_STATS_INTERVAL_S,
) -> None:
    """Periodically log kernel capture-loss counters (PCAP-005 observability).

    The loop only reads procfs counters; it never interacts with the capture
    process. Polling failures are logged and never abort the recorder.
    """

    try:
        while state.running:
            try:
                monitor.poll_and_log()
            except Exception as error:  # noqa: BLE001 - observability must never kill the recorder
                logger.warning("Capture-loss poll failed: {error}", error=error)
            await asyncio.sleep(interval_s)
    except asyncio.CancelledError:
        logger.info("Capture stats loop cancelled.")
        raise


def _configure_logging(log_config: LogConfig) -> None:
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


def main() -> None:
    logger.info("Loading environment variables from: {path}", path=ENV_PATH)
    load_dotenv(dotenv_path=str(ENV_PATH), override=True)

    # Raw by necessity (PCAP-007): this selects WHICH config file is loaded,
    # so it cannot itself come from that file. Sanctioned by the raw
    # os.environ rule in .kilo/agent/backend.md.
    config_path = Path(os.environ.get("PCAP_CONFIG_FILE", "config/config_pcap.json"))
    settings = PcapRecorderSettings.from_json(config_path)
    _configure_logging(settings.log)

    recorder = TcpdumpRecorder(settings.pcap)
    index_file = Path(settings.pcap.ringbuffer.directory) / "pcap_index.json"
    chunk_duration = timedelta(seconds=settings.pcap.chunk_duration_sec)
    index = PcapIndex(index_file, chunk_duration=chunk_duration)
    ringbuffer = RingbufferManager(settings.pcap.ringbuffer, settings.pcap.archive, index)
    service = PcapService(index, ringbuffer, api_config=settings.api)
    status_provider = CaptureStatusProvider(recorder)
    app = create_app(service, status_provider=status_provider)

    runtime_state = RuntimeState()
    runtime_state.recorder = recorder

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def handle_signal(*_args: object) -> None:
        logger.info("Shutdown signal received.")
        loop.create_task(runtime_state.stop())

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    capture_monitor = CaptureLossMonitor(settings.pcap.interface)

    async def runner() -> None:
        recorder.start()
        runtime_state.ringbuffer_task = asyncio.create_task(_ringbuffer_loop(runtime_state, ringbuffer))
        runtime_state.capture_stats_task = asyncio.create_task(_capture_stats_loop(runtime_state, capture_monitor))
        await _run_uvicorn(app, settings.api.host, settings.api.port, runtime_state)

    try:
        loop.run_until_complete(runner())
    finally:
        loop.run_until_complete(runtime_state.stop())
        loop.close()


if __name__ == "__main__":
    main()
