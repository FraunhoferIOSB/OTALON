"""Boundary-retraining proxy tool (OpenSpec ``add-chat-triggered-boundary-retraining``).

Thin HTTP proxy in front of otalon-api's
``POST /api/v1/training/retrain-boundaries`` and ``GET .../status``
endpoints. The MCP tool layer enforces the same ISO-8601 + ``start <
stop`` guard as the api orchestrator does — a first-line check so a
malformed call from the chat never reaches the api and therefore never
mutates ``.env.compose``.

The api base URL, the operator key and the confirmation-nonce lifetime
are injected through :func:`init` from ``otalon_mcp.settings`` — the one
place that resolves them (MCP-014). When a key is configured, every
request carries an ``X-API-Key`` header.
"""

from __future__ import annotations

import re
import time
import uuid
from datetime import datetime
from typing import Any, Dict

import httpx
from loguru import logger

# Mirror of the pattern in otalon-api so the MCP-side rejection
# message lines up with the api's. Date + space/T + 24h time.
_WINDOW_RE = re.compile(r"^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}$")

DEFAULT_API_URL: str = "http://otalon-api:8090"
"""Fallback base URL, used when the caller injects an empty value."""

DEFAULT_CONFIRM_NONCE_TTL_SECONDS: float = 300.0
"""Fallback confirmation-nonce lifetime in seconds."""

_state: Dict[str, Any] = {
    "url": "",
    "timeout": 10.0,
    "api_key": "",
    "confirm_nonce_ttl": DEFAULT_CONFIRM_NONCE_TTL_SECONDS,
    "confirm_nonce": None,
    "confirm_nonce_expires_at": 0.0,
}


def init(
    api_url: str = "",
    api_key: str = "",
    timeout: float = 10.0,
    confirm_nonce_ttl: float = DEFAULT_CONFIRM_NONCE_TTL_SECONDS,
) -> None:
    """Initialise the proxy tool with the api base URL and operator key.

    Args:
        api_url: Base URL of otalon-api; falls back to
            :data:`DEFAULT_API_URL` when empty.
        api_key: Operator key forwarded as ``X-API-Key``; may be empty.
        timeout: Outbound request timeout in seconds.
        confirm_nonce_ttl: Lifetime of a retrain confirmation nonce.
    """
    resolved_url = api_url or DEFAULT_API_URL
    _state["url"] = resolved_url.rstrip("/")
    _state["api_key"] = api_key
    _state["timeout"] = float(timeout) if timeout else 10.0
    _state["confirm_nonce_ttl"] = max(1.0, float(confirm_nonce_ttl or DEFAULT_CONFIRM_NONCE_TTL_SECONDS))
    _state["confirm_nonce"] = None
    _state["confirm_nonce_expires_at"] = 0.0
    logger.info(
        "tools.training.init: url={} api_key={} timeout={}s",
        _state["url"],
        "<set>" if api_key else "<unset>",
        _state["timeout"],
    )


def _headers() -> Dict[str, str]:
    """Return the auth headers for outbound requests."""
    headers = {"Accept": "application/json"}
    if _state["api_key"]:
        headers["X-API-Key"] = str(_state["api_key"])
    return headers


def _validate_window(window_start: str, window_stop: str) -> Dict[str, Any] | None:
    """Return an error dict if the window is invalid, otherwise ``None``."""
    for label, value in (
        ("window_start", window_start),
        ("window_stop", window_stop),
    ):
        if not isinstance(value, str) or not value.strip():
            return {
                "ok": False,
                "error": (
                    f"{label} must be a non-empty ISO-8601 string " "'YYYY-MM-DD HH:MM:SS' / 'YYYY-MM-DDTHH:MM:SS'"
                ),
            }
        if not _WINDOW_RE.match(value):
            return {
                "ok": False,
                "error": (f"{label}={value!r} is not ISO-8601 " "'YYYY-MM-DD HH:MM:SS' / 'YYYY-MM-DDTHH:MM:SS'"),
            }
    try:
        start_dt = datetime.fromisoformat(window_start.replace(" ", "T"))
        stop_dt = datetime.fromisoformat(window_stop.replace(" ", "T"))
    except ValueError as exc:
        return {
            "ok": False,
            "error": f"Could not parse retrain window: {exc}",
        }
    if start_dt >= stop_dt:
        return {
            "ok": False,
            "error": (f"window_start ({window_start}) must be strictly less than " f"window_stop ({window_stop})"),
        }
    return None


def _validate_intervals(intervals: list[list[str]] | None) -> Dict[str, Any] | None:
    """Return an error dict when any supplied training interval is invalid."""
    if intervals is None:
        return None
    if not intervals:
        return {"ok": False, "error": "intervals must contain at least one [start, stop] pair"}
    for index, interval in enumerate(intervals):
        if not isinstance(interval, list) or len(interval) != 2:
            return {"ok": False, "error": f"intervals[{index}] must be [start, stop]"}
        invalid = _validate_window(interval[0], interval[1])
        if invalid is not None:
            return invalid
    return None


def retrain_boundaries(
    window_start: str,
    window_stop: str,
    nonce: str = "",
    intervals: list[list[str]] | None = None,
) -> Dict[str, Any]:
    """Trigger a chat-driven boundary retraining run on otalon-clas.

    Proxies to ``POST /api/v1/training/retrain-boundaries`` on the
    otalon-api service after a first-line ISO-8601 + ``start < stop``
    guard. The api writes a ``retrain_jobs`` row and notifies the running
    otalon-clas process, which executes the retrain in-process. The
    container is NOT restarted or recreated and detection stays online.

    Returns immediately with a ``job_ref`` and the initial orchestrator
    ``state``; the run takes minutes (compute only, no detection
    downtime). Poll :func:`get_retrain_status` for progress.

    Args:
        window_start: ISO-8601 retrain-window start
            (``"YYYY-MM-DD HH:MM:SS"`` — same shape as the otalon-clas
            ``TRAINING_BOUNDARY_TRAIN_WINDOW_START`` env value).
        window_stop: ISO-8601 retrain-window stop. Must be strictly
            after *window_start*.
        intervals: Optional one-or-more disjoint ``[start, stop]`` pairs.
            The api normalizes Europe/Berlin wall time and merges overlaps.

    Returns:
        On success: ``{"ok": True, "state": str, "detail": str,
        "job_ref": str, "started_at": str | None, "window_start": str,
        "window_stop": str, "hint": str}``.

        On validation failure (handled locally — no network call):
        ``{"ok": False, "error": "..."}``.

        On api 409 (another run already in progress): ``{"ok": False,
        "error": "boundary retrain already in progress …", "status": "busy"}``.

        On any other api error: ``{"ok": False, "error": "...",
        "detail": "..."}``.
    """
    invalid = _validate_window(window_start, window_stop)
    if invalid is not None:
        return invalid
    invalid = _validate_intervals(intervals)
    if invalid is not None:
        return invalid

    now = time.monotonic()
    expected = _state["confirm_nonce"]
    expires_at = float(_state["confirm_nonce_expires_at"])
    if not nonce or nonce != expected or now >= expires_at:
        issued = str(uuid.uuid4())
        _state["confirm_nonce"] = issued
        _state["confirm_nonce_expires_at"] = now + _nonce_ttl_seconds()
        return {"ok": False, "nonce": issued, "requires": "confirm"}
    _state["confirm_nonce"] = None
    _state["confirm_nonce_expires_at"] = 0.0

    base = _state["url"]
    if not base:
        return {
            "ok": False,
            "error": "otalon-api URL is not configured (OTALON_API_URL)",
        }

    body: Dict[str, Any] = {"window_start": window_start, "window_stop": window_stop}
    if intervals is not None:
        body["intervals"] = intervals
    try:
        with httpx.Client(timeout=_state["timeout"]) as client:
            resp = client.post(
                f"{base}/api/v1/training/retrain-boundaries",
                json=body,
                headers=_headers(),
            )
    except httpx.HTTPError as exc:
        logger.error("training.retrain_boundaries: api unreachable: {}", exc)
        return {
            "ok": False,
            "error": "otalon-api unreachable",
            "detail": str(exc),
        }

    if resp.status_code == 409:
        data: Dict[str, Any] = {}
        try:
            data = resp.json() or {}
        except Exception:
            pass
        return {
            "ok": False,
            "status": "busy",
            "error": (data.get("detail") or "boundary retrain already in progress (state != idle)"),
        }
    if resp.status_code == 400:
        try:
            data = resp.json() or {}
        except Exception:
            data = {}
        return {
            "ok": False,
            "error": data.get("detail") or "validation rejected by api",
        }
    if resp.status_code >= 400:
        return {
            "ok": False,
            "error": f"api returned {resp.status_code}",
            "detail": resp.text[:500],
        }

    data = resp.json()
    return {
        "ok": True,
        "state": data.get("state"),
        "detail": data.get("detail"),
        "job_ref": data.get("job_ref"),
        "started_at": data.get("started_at"),
        "window_start": data.get("window_start"),
        "window_stop": data.get("window_stop"),
        "intervals": data.get("intervals", []),
        "hint": (
            "Boundary retraining is now in progress. otalon-clas stays "
            "online; the retrain runs in-process without restarting the "
            "container. Poll training.get_retrain_status until the state is "
            "'succeeded' or 'failed'. The snapshot of the productive bounds "
            "was already written to bounds_history before training started — "
            "bounds are recoverable on failure."
        ),
    }


def _nonce_ttl_seconds() -> float:
    """Return the configured confirmation nonce lifetime.

    Returns:
        The lifetime in seconds, never below one second.
    """
    return max(1.0, float(_state["confirm_nonce_ttl"]))


def retrain_classifier(
    window_start: str,
    window_stop: str,
    mitre_file: str,
    intervals: list[list[str]] | None = None,
) -> Dict[str, Any]:
    """Trigger a chat-driven CLASSIFIER retraining of otalon-clas.

    Proxies to ``POST /api/v1/training/retrain-classifier`` on
    otalon-api. Runtime classifier retraining does NOT restart or
    recreate the otalon-clas container; the new model is published
    atomically and reloaded in-process.

    ALWAYS warn the operator that this is a heavy compute operation
    before calling it. Refuse vague phrasings like "retrain everything".

    Args:
        window_start: ISO-8601 classifier-training-window start.
        window_stop: ISO-8601 classifier-training-window stop. Must be
            strictly after *window_start*.
        mitre_file: Path to the MITRE-technique JSON file used to label
            the ML training data. Required and must be non-empty.
        intervals: Optional one-or-more disjoint ``[start, stop]`` pairs.

    Returns:
        Same shape as :func:`retrain_boundaries`, with ``scope='ml'``.
    """
    invalid = _validate_window(window_start, window_stop)
    if invalid is not None:
        return invalid
    invalid = _validate_intervals(intervals)
    if invalid is not None:
        return invalid
    if not isinstance(mitre_file, str) or not mitre_file.strip():
        return {
            "ok": False,
            "error": "mitre_file is required for classifier retrain",
        }

    base = _state["url"]
    if not base:
        return {
            "ok": False,
            "error": "otalon-api URL is not configured (OTALON_API_URL)",
        }

    body: Dict[str, Any] = {
        "window_start": window_start,
        "window_stop": window_stop,
        "mitre_file": mitre_file.strip(),
    }
    if intervals is not None:
        body["intervals"] = intervals
    try:
        with httpx.Client(timeout=_state["timeout"]) as client:
            resp = client.post(
                f"{base}/api/v1/training/retrain-classifier",
                json=body,
                headers=_headers(),
            )
    except httpx.HTTPError as exc:
        logger.error("training.retrain_classifier: api unreachable: {}", exc)
        return {
            "ok": False,
            "error": "otalon-api unreachable",
            "detail": str(exc),
        }

    if resp.status_code == 409:
        data: Dict[str, Any] = {}
        try:
            data = resp.json() or {}
        except Exception:
            pass
        return {
            "ok": False,
            "status": "busy",
            "error": (data.get("detail") or "classifier retrain already in progress"),
        }
    if resp.status_code == 400:
        try:
            data = resp.json() or {}
        except Exception:
            data = {}
        return {
            "ok": False,
            "error": data.get("detail") or "validation rejected by api",
        }
    if resp.status_code >= 400:
        return {
            "ok": False,
            "error": f"api returned {resp.status_code}",
            "detail": resp.text[:500],
        }

    data = resp.json()
    return {
        "ok": True,
        "state": data.get("state"),
        "detail": data.get("detail"),
        "job_ref": data.get("job_ref"),
        "scope": data.get("scope"),
        "started_at": data.get("started_at"),
        "window_start": data.get("window_start"),
        "window_stop": data.get("window_stop"),
        "intervals": data.get("intervals", []),
        "mitre_file": data.get("mitre_file"),
        "hint": (
            "Classifier retraining is in progress. Detection stays online; "
            "the model is atomically published and reloaded in-process. "
            "Poll training.get_retrain_status until state is 'succeeded' or "
            "'failed'."
        ),
    }


def get_retrain_status() -> Dict[str, Any]:
    """Return the current orchestrator status.

    Side-effect free; safe to poll. Mirrors ``GET
    /api/v1/training/retrain-boundaries/status`` on otalon-api.
    """
    base = _state["url"]
    if not base:
        return {
            "ok": False,
            "error": "otalon-api URL is not configured (OTALON_API_URL)",
        }
    try:
        with httpx.Client(timeout=_state["timeout"]) as client:
            resp = client.get(
                f"{base}/api/v1/training/retrain-boundaries/status",
                headers=_headers(),
            )
    except httpx.HTTPError as exc:
        logger.error("training.get_retrain_status: api unreachable: {}", exc)
        return {
            "ok": False,
            "error": "otalon-api unreachable",
            "detail": str(exc),
        }

    if resp.status_code >= 400:
        return {
            "ok": False,
            "error": f"api returned {resp.status_code}",
            "detail": resp.text[:500],
        }
    return {"ok": True, **resp.json()}
