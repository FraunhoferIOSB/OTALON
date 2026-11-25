"""Read-only capture status service.

This service is a thin, bounded HTTP proxy to the pcap_recorder
``GET /status`` endpoint (owned by the recorder, UI-075 Wave C). It never
inspects host processes, host network interfaces or recorder config files:
``recording``, ``interface`` and ``link_up`` are truthful facts sourced by
the recorder itself inside its own network namespace. On timeout, transport
failure or an unexpected upstream shape, the service returns unknown facts
with degraded source state rather than fabricating acquisition evidence.
"""

from __future__ import annotations

from dataclasses import dataclass
from math import isfinite
from typing import TYPE_CHECKING, Any, Literal, get_args

import httpx
from loguru import logger

if TYPE_CHECKING:
    from otalon_api.settings import Settings

_STATUS_PATH = "/status"

CaptureType = Literal["NONE", "LIVE"]
CaptureBackend = Literal["native", "wsl"]
CaptureSourceState = Literal["disabled", "waiting", "recording", "degraded", "blocked"]
CaptureReasonCode = Literal[
    "none_selected",
    "source_absent",
    "collector_stale",
    "retry_exhausted",
    "privilege_denied",
    "dependency_unavailable",
    "custody_invalid",
    "checkpoint_incompatible",
    "upstream_unavailable",
]


@dataclass(frozen=True)
class CaptureStatusResult:
    """Truthful capture status snapshot.

    ``None`` means the value could not be sourced from the recorder without
    fabricating it.
    """

    interface: str | None
    link_up: bool | None
    recording: bool | None
    drops_24h_pct: float | None
    overflows: int | None

    capture_type: CaptureType | None = None
    backend: CaptureBackend | None = None
    source_state: CaptureSourceState = "degraded"
    reason_code: CaptureReasonCode | None = None
    retry_attempt: int | None = None
    retry_limit: int | None = None
    retry_in_seconds: float | None = None
    retry_exhausted: bool | None = None
    observation_age_seconds: float | None = None

    @classmethod
    def degraded(cls) -> "CaptureStatusResult":
        """Return unknown facts and an explicit upstream-unavailable diagnosis."""
        return cls(
            interface=None,
            link_up=None,
            recording=None,
            drops_24h_pct=None,
            overflows=None,
            reason_code="upstream_unavailable",
        )


def _coerce_bool(value: Any) -> bool | None:
    """Return ``value`` as a bool only when it truly is one; else ``None``."""
    return value if isinstance(value, bool) else None


def _coerce_float(value: Any) -> float | None:
    """Return ``value`` as a float only for real numbers (not bools)."""
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        return float(value)
    return None


def _coerce_int(value: Any) -> int | None:
    """Return ``value`` as an int only for real integers (not bools)."""
    if isinstance(value, bool):
        return None
    return value if isinstance(value, int) else None


def _coerce_str(value: Any) -> str | None:
    """Return ``value`` as a non-empty string, else ``None``."""
    if isinstance(value, str) and value:
        return value
    return None


def _bounded_number(value: Any, *, maximum: float | None = None) -> float | None:
    """Reject external coercion, nonfinite values, and unrepresentable integers."""
    if type(value) not in (int, float):
        return None
    try:
        if isfinite(value) and value >= 0 and (maximum is None or value <= maximum):
            return float(value)
    except OverflowError:
        pass
    return None


class CaptureStatusService:
    """Proxy the recorder's read-only capture status to the API.

    The service performs a single bounded ``GET`` against the recorder's
    ``/status`` endpoint and maps the response into a
    :class:`CaptureStatusResult`. It is strictly non-mutating and holds no
    host-level inspection logic.
    """

    def __init__(self, settings: "Settings", *, timeout: float | None = None) -> None:
        """Initialize with application settings.

        Args:
            settings: Application settings containing recorder host/port and
                the outbound HTTP timeout.
            timeout: Optional probe timeout override in seconds.
        """
        self._settings = settings
        self._timeout = timeout if timeout is not None else settings.pcap_recorder_timeout_s

    def _recorder_url(self, path: str) -> str:
        host = self._settings.pcap_recorder_host or "localhost"
        port = self._settings.pcap_recorder_port or 9090
        return f"http://{host}:{port}{path}"

    def _headers(self) -> dict[str, str]:
        """Build outbound headers, forwarding the recorder key if configured."""
        api_key = getattr(self._settings, "pcap_recorder_api_key", "") or ""
        return {"X-API-Key": api_key} if api_key else {}

    async def get_status(self) -> CaptureStatusResult:
        """Fetch and map the recorder's capture status.

        Returns:
            A :class:`CaptureStatusResult` with unknown facts and degraded
            source state when upstream is unavailable. No mode is inferred.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self._recorder_url(_STATUS_PATH), headers=self._headers())
        except httpx.TimeoutException:
            logger.debug("capture-status: recorder /status timed out")
            return CaptureStatusResult.degraded()
        except httpx.TransportError:
            logger.debug("capture-status: recorder unreachable")
            return CaptureStatusResult.degraded()

        if resp.status_code != 200:
            logger.debug("capture-status: recorder /status returned HTTP {}", resp.status_code)
            return CaptureStatusResult.degraded()

        try:
            body = resp.json()
        except ValueError:
            logger.debug("capture-status: recorder /status returned non-JSON body")
            return CaptureStatusResult.degraded()
        if not isinstance(body, dict):
            return CaptureStatusResult.degraded()

        return CaptureStatusResult(
            interface=_coerce_str(body.get("interface")),
            link_up=_coerce_bool(body.get("link_up")),
            recording=_coerce_bool(body.get("recording")),
            drops_24h_pct=_coerce_float(body.get("drops_24h_pct")),
            overflows=_coerce_int(body.get("overflows")),
            capture_type=body.get("capture_type") if body.get("capture_type") in get_args(CaptureType) else None,
            backend=body.get("backend") if body.get("backend") in get_args(CaptureBackend) else None,
            source_state=(
                body["source_state"] if body.get("source_state") in get_args(CaptureSourceState) else "degraded"
            ),
            reason_code=body.get("reason_code") if body.get("reason_code") in get_args(CaptureReasonCode) else None,
            retry_attempt=(
                body["retry_attempt"]
                if type(body.get("retry_attempt")) is int and 0 <= body["retry_attempt"] <= 5
                else None
            ),
            retry_limit=(
                body["retry_limit"] if type(body.get("retry_limit")) is int and body["retry_limit"] == 5 else None
            ),
            retry_in_seconds=_bounded_number(body.get("retry_in_seconds"), maximum=16),
            retry_exhausted=_coerce_bool(body.get("retry_exhausted")),
            observation_age_seconds=_bounded_number(body.get("observation_age_seconds")),
        )
