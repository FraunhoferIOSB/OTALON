"""HTTP proxy for audited rhythm-profile corrections."""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

import httpx
from loguru import logger

_state: dict[str, Any] = {"url": "", "api_key": "", "timeout": 10.0}


def init(api_url: str = "", api_key: str = "", timeout: float = 10.0) -> None:
    """Initialize the frequency API proxy with injected connection values.

    Args:
        api_url: Base URL of otalon-api; an empty value disables the proxy.
        api_key: Operator key forwarded as ``X-API-Key``; may be empty.
        timeout: Outbound request timeout in seconds.
    """
    _state["url"] = api_url.rstrip("/")
    _state["api_key"] = api_key
    _state["timeout"] = float(timeout) if timeout else 10.0


def _headers() -> dict[str, str]:
    """Build outbound API headers."""
    headers = {"Accept": "application/json"}
    if _state["api_key"]:
        headers["X-API-Key"] = str(_state["api_key"])
    return headers


def _error(response: httpx.Response) -> dict[str, Any]:
    """Convert an API error into a chat-readable result."""
    try:
        detail = response.json().get("detail", response.text[:500])
    except (ValueError, AttributeError):
        detail = response.text[:500]
    result: dict[str, Any] = {
        "ok": False,
        "status": response.status_code,
        "error": f"rhythm profile correction rejected by api ({response.status_code}): {detail}",
    }
    if response.status_code == 409:
        result["error"] = f"stale rhythm profile snapshot (409): {detail}"
    return result


def correct_rhythm_profile(
    series_id: str,
    tolerance_factor_override: float | None = None,
    absence_factor_override: float | None = None,
    reason: str = "",
    module: str = "conn",
) -> dict[str, Any]:
    """Preview then apply an audited rhythm-profile override.

    ``reason`` is optional, matching ``FrequencyOverrideApplyRequest``.
    At least one override value must be supplied. The API owns the single
    audit-row write, snapshot conflict check, and detector notification.
    """
    if not series_id.strip():
        return {"ok": False, "error": "series_id must not be empty"}
    requested: dict[str, Any] = {"series_id": series_id}
    if tolerance_factor_override is not None:
        requested["tolerance_factor_override"] = tolerance_factor_override
    if absence_factor_override is not None:
        requested["absence_factor_override"] = absence_factor_override
    if len(requested) == 1:
        return {"ok": False, "error": "at least one rhythm override must be supplied"}
    base = _state["url"]
    if not base:
        return {"ok": False, "error": "otalon-api URL is not configured (OTALON_API_URL)"}
    # The API's `_resolve_series` decodes the path segment once before
    # route matching (Starlette itself already decodes `%2F` -> `/`), so a
    # UCI containing `/` only survives as a *route-matching* path segment
    # if it is percent-encoded twice. `series_id` in the request body is
    # authoritative for the actual value used; this mirrors the UI's
    # `seriesPathSegment()` contract in rhythmReviewStore.ts.
    path_id = quote(quote(series_id, safe=""), safe="")
    try:
        with httpx.Client(timeout=_state["timeout"]) as client:
            preview = client.post(
                f"{base}/api/v1/frequency/{path_id}/override/preview",
                params={"module": module},
                json=requested,
                headers=_headers(),
            )
            if preview.status_code >= 400:
                return _error(preview)
            preview_data = preview.json()
            apply_body = {**requested, "before_snapshot": preview_data["before_snapshot"], "reason": reason}
            applied = client.post(
                f"{base}/api/v1/frequency/{path_id}/override/apply",
                params={"module": module},
                json=apply_body,
                headers=_headers(),
            )
    except httpx.HTTPError as exc:
        logger.error("frequency.correct_rhythm_profile: api unreachable: {}", exc)
        return {"ok": False, "error": "otalon-api unreachable", "detail": str(exc)}
    if applied.status_code >= 400:
        return _error(applied)
    return {"ok": True, "preview": preview_data, "apply": applied.json()}
