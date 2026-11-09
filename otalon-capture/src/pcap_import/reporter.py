"""Outbound progress reporting from the import worker to the job's owner.

The worker never writes PostgreSQL. It reports over HTTP to the owner, which
remains the single writer of job records. The owner endpoint belongs to a later
wave, so an unreachable or unconfigured target is a logged, bounded-retry
condition — never a crash and never a reason to abandon a running import.

Only the standard library is used (``urllib.request``), so this adds no
dependency to the subproject.
"""

from __future__ import annotations

import json
import time
from typing import Optional, Protocol
from urllib import error, request

from loguru import logger

from .models import JobUpdate
from .settings import ReporterConfig


class JobReporter(Protocol):
    """Structural type of a progress sink, so tests can substitute a double."""

    def report(self, display_id: str, update: JobUpdate) -> bool:
        """Deliver ``update`` for the job identified by ``display_id``."""
        ...


class NullJobReporter:
    """Reporter that discards updates, used when no owner URL is configured."""

    def report(self, display_id: str, update: JobUpdate) -> bool:
        """Log the update at debug level and report success.

        Args:
            display_id: Identifier of the job the update belongs to.
            update: The update that would have been delivered.

        Returns:
            Always ``True`` — discarding is the configured behaviour.
        """

        logger.debug(
            "No job-owner URL configured; dropping update for job {display_id}: {update}",
            display_id=display_id,
            update=update.model_dump(exclude_none=True),
        )
        return True


class HttpJobReporter:
    """Deliver job updates via ``PATCH`` to the job owner's internal endpoint."""

    def __init__(self, config: ReporterConfig) -> None:
        """Store the reporting configuration.

        Args:
            config: Base URL, path template, credentials and retry bounds.
        """

        self._config = config

    def report(self, display_id: str, update: JobUpdate) -> bool:
        """Send ``update`` for ``display_id``, retrying a bounded number of times.

        Args:
            display_id: Identifier of the owning job record.
            update: Progress or terminal-state payload.

        Returns:
            ``True`` when the owner acknowledged the update, ``False`` when all
            attempts failed. A ``False`` result is logged and otherwise ignored:
            the import itself is unaffected by a reporting outage.
        """

        url = self._build_url(display_id)
        body = json.dumps(update.model_dump(exclude_none=True, mode="json")).encode("utf-8")
        attempts = int(self._config.max_attempts)
        for attempt in range(1, attempts + 1):
            if self._attempt(url, body, attempt, attempts):
                return True
            if attempt < attempts:
                time.sleep(max(0.0, self._config.retry_backoff_s))
        logger.warning(
            "Giving up reporting job {display_id} after {attempts} attempt(s); import continues.",
            display_id=display_id,
            attempts=attempts,
        )
        return False

    def _attempt(self, url: str, body: bytes, attempt: int, attempts: int) -> bool:
        """Perform one delivery attempt and classify the outcome."""

        try:
            with request.urlopen(self._build_request(url, body), timeout=self._config.timeout_s) as response:
                status = int(getattr(response, "status", 200))
            if 200 <= status < 300:
                return True
            logger.warning(
                "Job owner returned HTTP {status} for {url} (attempt {attempt}/{attempts}).",
                status=status,
                url=url,
                attempt=attempt,
                attempts=attempts,
            )
        except error.HTTPError as http_error:
            logger.warning(
                "Job owner rejected update at {url}: HTTP {code} (attempt {attempt}/{attempts}).",
                url=url,
                code=http_error.code,
                attempt=attempt,
                attempts=attempts,
            )
        except (error.URLError, OSError) as transport_error:
            logger.warning(
                "Job owner unreachable at {url}: {error} (attempt {attempt}/{attempts}).",
                url=url,
                error=transport_error,
                attempt=attempt,
                attempts=attempts,
            )
        return False

    def _build_request(self, url: str, body: bytes) -> request.Request:
        """Build the authenticated ``PATCH`` request carrying ``body``."""

        headers = {"Content-Type": "application/json"}
        token = (self._config.token or "").strip()
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return request.Request(url, data=body, headers=headers, method="PATCH")

    def _build_url(self, display_id: str) -> str:
        """Compose the absolute job URL from base URL and path template."""

        path = self._config.job_path_template.format(display_id=display_id)
        return self._config.base_url.rstrip("/") + "/" + path.lstrip("/")


def create_reporter(config: Optional[ReporterConfig]) -> JobReporter:
    """Return an HTTP reporter, or a null reporter when no owner is configured.

    Args:
        config: Reporting configuration, or ``None``.

    Returns:
        A :class:`JobReporter` implementation that never raises on delivery.
    """

    if config is None or not (config.base_url or "").strip():
        return NullJobReporter()
    return HttpJobReporter(config)
