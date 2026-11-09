"""Wrapper around the Netcap++ capture interface with graceful shutdown."""

from __future__ import annotations

from threading import Event
from typing import Generator

import network_capture as nc
from loguru import logger

from .settings import CaptureConfig, CaptureType


class Netcap:
    """Thin wrapper around :mod:`network_capture` with structured error handling."""

    def __init__(self, config: CaptureConfig) -> None:
        self.stop_event = Event()
        self.nc = self._create_capture(config)

    def capture_loop(self) -> Generator[object, None, None]:
        """Yield capture results until :meth:`stop` is invoked."""

        logger.debug("Capture loop started.")
        try:
            while not self.stop_event.is_set():
                value = self.nc.get_next()
                if value is None:
                    continue
                yield value
        except RuntimeError:
            logger.warning(
                "Capture loop terminated due to RuntimeError (possibly empty queue)."
            )
        except Exception as error:  # noqa: BLE001 - forwarding unexpected exceptions
            logger.exception("Unexpected error in capture loop: {error}", error=error)
        finally:
            logger.info("Exiting capture loop.")

    def stop(self) -> None:
        """Signal the capture loop to stop."""

        logger.info("Stop event received. Stopping capture...")
        self.stop_event.set()

    @staticmethod
    def _create_capture(config: CaptureConfig) -> nc.NetworkCapture:
        capture_type = Netcap._map_capture_type(config.type)
        try:
            return nc.NetworkCapture(str(config.source), capture_type, config.interval)
        except RuntimeError as error:  # noqa: BLE001 - propagate with context
            logger.exception("Exception capturing on {source}: {error}", source=config.source, error=error)
            raise

    @staticmethod
    def _map_capture_type(capture_type: CaptureType) -> nc.CaptureType:
        type_map = {
            CaptureType.PCAP: nc.CaptureType.PCAP,
            CaptureType.LIVE: nc.CaptureType.LIVE,
        }
        try:
            return type_map[capture_type]
        except KeyError as error:
            raise ValueError(f"Unsupported capture type: {capture_type}") from error
