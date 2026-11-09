"""Read-only capture status service.

This service is a thin, bounded HTTP proxy to the pcap_recorder
``GET /status`` endpoint (owned by the recorder, UI-075 Wave C). It never
inspects host processes, host network interfaces or recorder config files:
``recording``, ``interface`` and ``link_up`` are truthful facts sourced by
the recorder itself inside its own network namespace. On timeout, transport
failure or an unexpected upstream shape, the service returns a fully-null
degraded snapshot rather than fabricating any value.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import httpx
from loguru import logger

if TYPE_CHECKING:
    from otalon_api.settings import Settings

_STATUS_PATH = "/status"


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

    @classmethod
    def degraded(cls) -> "CaptureStatusResult":
        """Return an all-null snapshot used when the recorder is unavailable."""
        return cls(
            interface=None,
            link_up=None,
            recording=None,
            drops_24h_pct=None,
            overflows=None,
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
            A :class:`CaptureStatusResult`. Every field falls back to
            ``None`` when the recorder is unreachable, times out or returns
            an unexpected payload; no value is ever invented.
        """
        try:
            async with httpx.AsyncClient(timeout=self._timeout) as client:
                resp = await client.get(self._recorder_url(_STATUS_PATH), headers=self._headers())
        except httpx.TimeoutException as exc:
            logger.debug("capture-status: recorder /status timed out: {}", exc)
            return CaptureStatusResult.degraded()
        except httpx.TransportError as exc:
            logger.debug("capture-status: recorder unreachable ({}): {}", type(exc).__name__, exc)
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
        )
