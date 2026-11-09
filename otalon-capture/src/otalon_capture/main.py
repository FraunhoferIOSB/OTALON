"""Entry point for the Netcap-to-Influx adapter."""

from __future__ import annotations

import signal
from pathlib import Path
from typing import Optional

from dotenv import load_dotenv
from loguru import logger

from .helper import configure_logger, wait_for_influx_health
from .pipeline import CapturePipeline
from .settings import Settings

ENV_PATH = Path(__file__).resolve().parents[2] / ".env"


class RuntimeState:
    """Hold runtime state for signal handlers."""

    def __init__(self) -> None:
        self.running = True
        self.pipeline: Optional[CapturePipeline] = None

    def stop(self) -> None:
        """Signal the capture pipeline to stop."""
        self.running = False
        if self.pipeline is not None:
            self.pipeline.stop()


def _shutdown(state: RuntimeState) -> None:
    logger.info("Shutdown signal received.")
    state.stop()


def main() -> None:
    """Application entry point for the adapter."""

    logger.info("Loading environment variables from: {path}", path=ENV_PATH)
    load_dotenv(dotenv_path=str(ENV_PATH), override=True)

    settings = Settings.from_json(Path("config/config.json"))
    configure_logger(settings.log)

    runtime_state = RuntimeState()

    def handle_signal(*_args: object) -> None:
        _shutdown(runtime_state)

    signal.signal(signal.SIGINT, handle_signal)
    signal.signal(signal.SIGTERM, handle_signal)

    try:
        wait_for_influx_health(
            str(settings.influx.host),
            settings.influx.token.get_secret_value(),
            timeout_s=5.0,
            max_wait_s=10.0,
            backoff_s=2.0,
        )
    except Exception as error:
        logger.warning("Healthcheck wrapper exception: {error}. Continuing.", error=error)

    runtime_state.pipeline = CapturePipeline(settings)

    logger.info("Adapter started.")
    try:
        runtime_state.pipeline.run()
    except Exception as error:
        logger.exception("Unhandled exception: {error}", error=error)
    finally:
        logger.info("Adapter terminated cleanly.")


if __name__ == "__main__":
    main()
