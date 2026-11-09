"""Fire-and-forget HTTP client for PCAP anomaly flagging.

Sends anomaly flag requests to the PCAP recorder service. All errors
are logged but never propagated to the caller.
"""

from __future__ import annotations

import os
from datetime import datetime
from typing import Any

import httpx
from loguru import logger

DEFAULT_TIMEOUT_SECONDS: int = 10

API_KEY_ENV_VAR = "ADMIN_API_KEY"
"""Environment variable holding the operator credential for the recorder."""

API_KEY_HEADER = "X-API-Key"
"""Header the PCAP recorder's operator dependency reads (``require_operator_api_key``)."""


class PcapFlagClient:
    """HTTP client for flagging anomalies in the PCAP recorder.

    Provides fire-and-forget semantics: errors are logged and swallowed
    so that flagging failures never interrupt the detection pipeline.

    Args:
        base_url: Base URL of the PCAP recorder service (e.g., ``http://localhost:9090``).
        timeout_seconds: Request timeout in seconds.
    """

    def __init__(
        self,
        base_url: str,
        timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        """Initialize the PCAP flag client.

        Args:
            base_url: PCAP recorder base URL.
            timeout_seconds: HTTP request timeout.
        """
        self._base_url = base_url.rstrip("/")
        self._timeout = timeout_seconds

    def _auth_headers(self) -> dict[str, str] | None:
        """Return the operator credential header for the PCAP recorder.

        The recorder gates ``POST /anomalies/flag`` on the suite
        ``X-API-Key`` operator credential (``require_operator_api_key``),
        so an unauthenticated call always answered HTTP 401 and produced no
        PCAP evidence (CLAS-059). The value is read from the process
        environment on every call and is never logged or persisted.

        Returns:
            A single-entry header mapping, or ``None`` when the credential
            is unset. Callers must then skip the request rather than send
            an unauthenticated one.
        """

        key = os.environ.get(API_KEY_ENV_VAR, "")
        if not key:
            logger.warning(
                "PCAP flagging skipped: environment variable {} is not set, "
                "so the recorder would reject the request with HTTP 401",
                API_KEY_ENV_VAR,
            )
            return None
        return {API_KEY_HEADER: key}

    def flag_anomaly(self, payload: dict[str, Any]) -> None:
        """Send a fire-and-forget anomaly flag to the PCAP recorder.

        Posts the payload to ``/anomalies/flag``. Errors are logged but
        never raised to the caller.

        .. note::
           Prefer :meth:`flag_alarm` for the canonical post-grouping
           workflow. ``flag_anomaly`` flags individual anomaly samples
           and therefore cannot carry an ``alarm_id`` label, which makes
           the resulting chunks unreachable via ``pcap.get_chunks_by_alarm_id``.

        Args:
            payload: Anomaly data to send as JSON body.
        """
        url = f"{self._base_url}/anomalies/flag"
        headers = self._auth_headers()
        if headers is None:
            return
        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=self._timeout)
            if response.status_code >= 400:
                logger.warning(
                    "PCAP flag request returned HTTP {}: {}",
                    response.status_code,
                    response.text[:200],
                )
            else:
                logger.debug("PCAP anomaly flagged successfully: HTTP {}", response.status_code)
        except httpx.TimeoutException:
            logger.warning("PCAP flag request timed out after {}s to {}", self._timeout, url)
        except Exception as exc:
            logger.warning("PCAP flag request failed: {}: {}", type(exc).__name__, exc)

    def flag_alarm(
        self,
        start_ts: datetime,
        end_ts: datetime,
        labels: dict[str, str] | None = None,
    ) -> list[str]:
        """Flag every PCAP chunk overlapping the alarm time window.

        This is the canonical post-grouping API: after the grouping cycle
        has materialised an alarm row (with a stable ``alarm_id``), this
        method asks the PCAP recorder to mark every chunk that overlaps
        ``[start_ts, end_ts]`` as an anomaly. The supplied ``labels``
        (``alarm_id``, ``module``, ``primary_type``, ``series_ids``)
        are attached to each flagged chunk so the subagent's
        ``pcap.get_chunks_by_alarm_id`` tool can resolve them later.

        Mirrors the legacy ``otalon-clas`` flow byte-for-byte so the
        downstream PCAP-Recorder endpoint behaves identically.

        Args:
            start_ts: Inclusive UTC start of the alarm window.
            end_ts: Inclusive UTC end of the alarm window.
            labels: Optional metadata propagated into every flagged chunk's
                ``labels`` dictionary.

        Returns:
            List of chunk IDs that were flagged, or an empty list on
            error / disabled flagging.
        """
        url = f"{self._base_url}/anomalies/flag"
        payload: dict[str, Any] = {
            "start_ts": start_ts.isoformat(),
            "end_ts": end_ts.isoformat(),
            "labels": labels or {},
        }
        headers = self._auth_headers()
        if headers is None:
            return []
        try:
            response = httpx.post(url, json=payload, headers=headers, timeout=self._timeout)
            if response.status_code >= 400:
                logger.warning(
                    "PCAP alarm flag returned HTTP {} for alarm_id={}: {}",
                    response.status_code,
                    (labels or {}).get("alarm_id", "?"),
                    response.text[:200],
                )
                return []
            data = response.json()
            chunk_ids: list[str] = data.get("chunk_ids", [])
            logger.info(
                "PCAP flagging: {} chunks flagged for alarm_id={}",
                len(chunk_ids),
                (labels or {}).get("alarm_id", "?"),
            )
            return chunk_ids
        except httpx.TimeoutException:
            logger.warning(
                "PCAP alarm flag timed out after {}s to {}",
                self._timeout,
                url,
            )
        except Exception as exc:
            logger.warning(
                "PCAP alarm flag failed: {}: {}",
                type(exc).__name__,
                exc,
            )
        return []

    def health_check(self) -> bool:
        """Check if the PCAP recorder service is reachable.

        Sends a GET request to ``/health``.

        Returns:
            True if the service responds with HTTP 2xx, False otherwise.
        """
        url = f"{self._base_url}/health"
        try:
            response = httpx.get(url, timeout=self._timeout)
            healthy = 200 <= response.status_code < 300
            if not healthy:
                logger.warning("PCAP recorder health check returned HTTP {}", response.status_code)
            return healthy
        except Exception as exc:
            logger.warning("PCAP recorder health check failed: {}: {}", type(exc).__name__, exc)
            return False
