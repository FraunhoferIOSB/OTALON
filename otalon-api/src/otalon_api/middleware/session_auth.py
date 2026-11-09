"""Cookie-session authentication middleware for product-user routes."""

from __future__ import annotations

import asyncio
from collections.abc import Awaitable, Callable
from typing import Any

from fastapi import HTTPException
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import JSONResponse, Response

from otalon_api.dependencies import get_session_repo
from otalon_api.repositories.identity_repo import UserEntry

SESSION_COOKIE_NAME = "otalon_session"
SESSION_PROTECTED_PATH_PREFIXES: tuple[str, ...] = ("/api/v1/admin/users",)
SESSION_LIFECYCLE_PATHS: tuple[str, ...] = (
    "/api/v1/auth/logout",
    "/api/v1/auth/me",
    "/api/v1/auth/change-password",
)
SESSION_PROTECTED_REQUESTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("POST", "/api/v1/operations/reset"),
        ("POST", "/api/v1/operations/restore"),
        ("POST", "/api/v1/operations/services/action"),
        ("PUT", "/api/v1/dashboard/layout"),
        ("PUT", "/api/v1/dashboard/tour"),
    }
)
SESSION_READ_EXEMPT_PATHS: frozenset[str] = frozenset(
    {"/health", "/livez", "/readyz", "/api/v1/status/health", "/api/v1/auth/login"}
)
# /api/v1/status/health is exempt from session handling ONLY for the plain
# probe (no ``detail=true``). With ``detail=true`` it exposes per-service
# health and is protected in ApiKeyAuthMiddleware's own PUBLIC_PROBE_PATHS
# check (`src/otalon_api/middleware/auth.py`) the same way. If this middleware treated
# it as unconditionally exempt, `request.state.user_entry` would never be
# attached for the detailed call and the admin UI's session-based request
# would be rejected with 401 even though a valid product session exists
# (UI-154 regression: the dashboard's Service Health widget silently failed
# authentication for every browser request).
DETAIL_GATED_PATHS: frozenset[str] = frozenset({"/api/v1/status/health"})


def _session_required(method: str, path: str) -> bool:
    """Return whether product-session authentication is required for path."""
    return (
        (method, path) in SESSION_PROTECTED_REQUESTS
        or path in SESSION_LIFECYCLE_PATHS
        or any(path.startswith(prefix) for prefix in SESSION_PROTECTED_PATH_PREFIXES)
    )


def _session_optional_read(method: str, path: str, detail_requested: bool) -> bool:
    """Return whether a protected read may use a session when present."""
    if method not in {"GET", "HEAD"}:
        return False
    if path in DETAIL_GATED_PATHS:
        return detail_requested
    return path not in SESSION_READ_EXEMPT_PATHS


def _forced_change_allowed(path: str) -> bool:
    """Return whether forced-change sessions may access path."""
    return path in SESSION_LIFECYCLE_PATHS


class SessionAuthMiddleware(BaseHTTPMiddleware):
    """Validate product cookies before protected handlers run."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Attach current user or reject missing and invalid sessions."""
        path = request.url.path
        detail_requested = request.query_params.get("detail") == "true"
        if _session_optional_read(request.method, path, detail_requested) and not _session_required(
            request.method, path
        ):
            session_id = request.cookies.get(SESSION_COOKIE_NAME)
            if not session_id:
                return await call_next(request)
            try:
                user_entry = await asyncio.to_thread(get_session_repo().validate_and_touch, session_id)
            except Exception:
                return await call_next(request)
            if user_entry is not None and not user_entry.must_change_password:
                request.state.user_entry = user_entry
            return await call_next(request)
        if not _session_required(request.method, path):
            return await call_next(request)
        session_id = request.cookies.get(SESSION_COOKIE_NAME)
        if not session_id:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        try:
            user_entry = await asyncio.to_thread(get_session_repo().validate_and_touch, session_id)
        except Exception:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        if user_entry is None:
            return JSONResponse({"detail": "Authentication required"}, status_code=401)
        request.state.user_entry = user_entry
        if user_entry.must_change_password and not _forced_change_allowed(request.url.path):
            return JSONResponse({"detail": "Password change required"}, status_code=403)
        return await call_next(request)


async def require_session(request: Request) -> UserEntry:
    """Return middleware-attached user identity or raise HTTP 401."""
    entry: Any = getattr(request.state, "user_entry", None)
    if not isinstance(entry, UserEntry):
        raise HTTPException(status_code=401, detail="Authentication required")
    return entry


def require_minimum_role(minimum: str) -> Callable[[Request], Awaitable[UserEntry]]:
    """Build dependency requiring an attached user at or above ``minimum``."""
    order = {"viewer": 0, "operator": 1, "admin": 2}
    if minimum not in order:
        raise ValueError(f"Unknown minimum user role: {minimum}")

    async def dependency(request: Request) -> UserEntry:
        """Validate session and minimum role for one request."""
        entry = await require_session(request)
        if order[entry.role.value] < order[minimum]:
            raise HTTPException(status_code=403, detail="Insufficient role")
        return entry

    return dependency
