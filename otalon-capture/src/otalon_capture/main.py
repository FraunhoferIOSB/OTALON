"""Entry point for the Netcap-to-Influx adapter."""

from __future__ import annotations

import argparse
import json
import os
import signal
import tempfile
import threading
import time
from dataclasses import asdict
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from loguru import logger

from capture_runtime import ADAPTER_SNAPSHOT_PATH, AdapterSnapshot, CaptureIntent, SourceState, resolve_capture_intent

from .helper import configure_logger, wait_for_influx_health
from .pipeline import CapturePipeline
from .settings import Settings
from .write_failure import TerminalWriteError

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


class RuntimeState:
    """Hold runtime state for signal handlers."""

    def __init__(self) -> None:
        self.running = True
        self.pipeline: Optional[CapturePipeline] = None
        self.stop_event = threading.Event()

    def stop(self) -> None:
        """Signal the capture pipeline to stop."""
        if not self.running:
            return
        self.running = False
        self.stop_event.set()
        if self.pipeline is not None:
            self.pipeline.stop()


def _shutdown(state: RuntimeState) -> None:
    logger.info("Shutdown signal received.")
    state.stop()


def _construct_pipeline(settings: Settings) -> CapturePipeline:
    """Retain partial construction solely to close acquired resources on failure.

    The pipeline's run/finalization and writer/aggregation semantics are unchanged.
    """
    pipeline = CapturePipeline.__new__(CapturePipeline)
    try:
        CapturePipeline.__init__(pipeline, settings)
    except BaseException:
        capture = getattr(pipeline, "_capture", None)
        writer = getattr(pipeline, "_writer", None)
        if capture is not None:
            try:
                capture.stop()
            except Exception:
                logger.warning("Partial adapter reader cleanup failed.")
        if writer is not None:
            try:
                writer.close()
            except Exception:
                logger.warning("Partial adapter writer cleanup failed.")
        raise
    return pipeline


def _write_snapshot(generation: str, state: SourceState, reason=None) -> None:
    snapshot = AdapterSnapshot(state, generation, os.getpid(), time.monotonic(), reason)
    path = Path(ADAPTER_SNAPSHOT_PATH)
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=path.name + ".", suffix=".tmp")
    temporary = Path(name)
    try:
        # mkstemp creates a same-directory exclusive 0600 file, without xattrs.
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(asdict(snapshot), handle)
        temporary.replace(path)
    finally:
        temporary.unlink(missing_ok=True)


def main() -> None:
    """Application entry point for the adapter."""

    logger.info("Loading environment variables from: {path}", path=ENV_PATH)
    load_dotenv(dotenv_path=str(ENV_PATH), override=True)

    if resolve_capture_intent() is not CaptureIntent.LIVE:
        raise ValueError("CAPTURE_TYPE must be LIVE for the acquisition adapter.")
    parser = argparse.ArgumentParser()
    parser.add_argument("--_capture-generation", help=argparse.SUPPRESS)
    generation = parser.parse_args()._capture_generation
    # Validate narrowly internal child context before loading metric settings.
    if generation is not None:
        AdapterSnapshot(SourceState.WAITING, generation, os.getpid(), time.monotonic(), None)
    settings = Settings.from_json(Path("config/config.json"))
    configure_logger(settings.log)

    runtime_state = RuntimeState()

    def handle_signal(*_args: object) -> None:
        _shutdown(runtime_state)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    heartbeat = None
    failed = False
    auth_status: int | None = None
    terminal = SourceState.DEGRADED
    reason = "dependency_unavailable"
    try:
        wait_for_influx_health(
            str(settings.influx.host),
            settings.influx.token.get_secret_value(),
            timeout_s=2.0,
            max_wait_s=2.0,
            backoff_s=0.25,
            stop_event=runtime_state.stop_event,
        )
        if not runtime_state.running:
            return
        runtime_state.pipeline = _construct_pipeline(settings)
        if not runtime_state.running:
            runtime_state.pipeline.stop()
        elif generation is not None:
            _write_snapshot(generation, SourceState.RECORDING)

            def refresh() -> None:
                while not runtime_state.stop_event.wait(1.0):
                    try:
                        _write_snapshot(generation, SourceState.RECORDING)
                    except Exception:
                        logger.warning("Adapter readiness heartbeat failed.")
                        runtime_state.stop()
                        return

            heartbeat = threading.Thread(target=refresh, name="capture-adapter-heartbeat", daemon=True)
            heartbeat.start()
        logger.info("Adapter started; acquisition readiness is not metric publication proof.")
        runtime_state.pipeline.run()
    except TerminalWriteError as error:
        failed = True
        terminal = SourceState.BLOCKED
        reason = "upstream_unavailable"
        auth_status = error.status
        logger.warning("Adapter metric publication refused; acquisition blocked.")
        try:
            raise TerminalWriteError(auth_status) from None
        except TerminalWriteError as failure:
            failure.__context__ = None
            raise
    except Exception as error:
        failed = True
        terminal = SourceState.BLOCKED
        if isinstance(error, PermissionError):
            reason = "privilege_denied"
        logger.warning("Adapter startup/run failed; acquisition blocked.")
        raise
    finally:
        runtime_state.stop()
        if heartbeat is not None:
            heartbeat.join(timeout=1.0)
            if heartbeat.is_alive():
                # The final snapshot must follow the last readiness write.
                heartbeat.join()
        if generation is not None:
            try:
                _write_snapshot(generation, terminal, reason)
            except Exception:
                if auth_status is None:
                    raise
                logger.warning("Adapter terminal snapshot write failed after publication refusal.")
        if failed:
            logger.warning("Adapter terminated after failure.")
        else:
            logger.info("Adapter terminated cleanly.")


if __name__ == "__main__":
    main()
