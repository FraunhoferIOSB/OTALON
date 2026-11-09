"""Utility helpers for logging and InfluxDB health checks."""

from __future__ import annotations

import sys
import time
from typing import Dict
from urllib import error, request

from loguru import logger
from otalon_common.logging import configure_logging

from .settings import LogConfig


def configure_logger(log_config: LogConfig) -> None:
    """Configure global Loguru sinks based on ``log_config``."""

    level = log_config.level.upper()
    configure_logging(
        log_file=log_config.file,
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


def wait_for_influx_health(
    base_url: str,
    token: str = "",
    timeout_s: float = 5.0,
    max_wait_s: float = 30.0,
    backoff_s: float = 2.0,
) -> bool:
    """Poll the InfluxDB health endpoint until available or timeout expires."""

    if not base_url:
        logger.warning("Influx base URL is empty; skipping healthcheck.")
        return False

    health_url = base_url.rstrip("/") + "/health"
    start = time.time()
    attempt = 0
    while (time.time() - start) < max_wait_s:
        attempt += 1
        try:
            headers = _build_auth_header(token)
            logger.debug("Checking InfluxDB health (attempt {attempt}): {url}", attempt=attempt, url=health_url)
            req = request.Request(health_url, headers=headers)
            with request.urlopen(req, timeout=timeout_s) as response:
                status = getattr(response, "status", 200)
                if 200 <= status < 300:
                    logger.info("InfluxDB health OK (HTTP {status}). Proceeding.", status=status)
                    return True
                if status == 401:
                    logger.info(
                        "InfluxDB health endpoint responded 401 Unauthorized; treating as UP and proceeding."
                    )
                    return True
                logger.warning(
                    "InfluxDB health not OK (HTTP {status}). Retrying in {backoff}s...",
                    status=status,
                    backoff=backoff_s,
                )
        except error.HTTPError as http_error:
            if http_error.code == 401:
                logger.info(
                    "InfluxDB health endpoint responded 401 Unauthorized; treating as UP and proceeding."
                )
                return True
            logger.warning(
                "InfluxDB health HTTP error: {error}. Retrying in {backoff}s...",
                error=http_error,
                backoff=backoff_s,
            )
        except error.URLError as url_error:
            logger.warning(
                "InfluxDB healthcheck failed: {error}. Retrying in {backoff}s...",
                error=url_error,
                backoff=backoff_s,
            )
        except Exception as unexpected_error:  # noqa: BLE001 - defensive logging
            logger.warning(
                "Unexpected error during InfluxDB healthcheck: {error}. Retrying in {backoff}s...",
                error=unexpected_error,
                backoff=backoff_s,
            )
        time.sleep(backoff_s)

    logger.error("InfluxDB healthcheck timed out after {timeout}s. Continuing startup, writes may retry.", timeout=max_wait_s)
    return False


def _build_auth_header(token: str) -> Dict[str, str]:
    """Return an authorization header dictionary if ``token`` is provided."""

    token = (token or "").strip()
    if not token:
        return {}
    return {"Authorization": f"Bearer {token}"}
