"""Deny-by-default API-key authentication for the API surface."""

from __future__ import annotations

from typing import Any

from loguru import logger
from otalon_common.auth import KeyRegistry, KeyRole, OnMissing, parse_allowed_keys
from otalon_common.auth.fastapi import require_api_key
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

from otalon_api.dependencies import get_settings

PROTECTED_PATH_PREFIXES: tuple[str, ...] = ("/",)
PUBLIC_PROBE_PATHS: frozenset[str] = frozenset(
    {"/health", "/livez", "/readyz", "/api/v1/status/health", "/api/v1/auth/login"}
)
SESSION_OWNED_PATH_PREFIXES: tuple[str, ...] = (
    "/api/v1/auth",
    "/api/v1/admin/users",
)
SESSION_OWNED_REQUESTS: frozenset[tuple[str, str]] = frozenset(
    {
        ("PUT", "/api/v1/dashboard/layout"),
        ("PUT", "/api/v1/dashboard/tour"),
    }
)
# The dashboard state PUTs above are session-owned per the dashboard-user-state
# operator decisions (supersede auth-hardening-suite Δ6 for exactly these two
# method+path pairs): SessionAuthMiddleware (outermost) has already validated
# the cookie and attached ``user_entry`` before this middleware runs, and the
# handlers authorize via ``require_session``. Method+path scoped on purpose —
# a ``/api/v1/dashboard`` prefix would exempt anonymous dashboard GETs and
# weaken the deny-by-default surface.
# Worker-token channels authenticate themselves against their own shared
# secret (e.g. PCAP_IMPORT_WORKER_TOKEN) and are not part of the operator
# key surface. The generic X-API-Key middleware must stay out of their way
# entirely, including when no operator key is configured, or the wrong
# status code (503 instead of the endpoint's own 401) leaks through.
WORKER_TOKEN_PATH_PREFIXES: tuple[str, ...] = ("/internal/jobs",)


def _is_read_request(request: Request) -> bool:
    """Return whether request is a browser-safe read eligible for sessions."""
    return request.method in {"GET", "HEAD"}


def _has_authenticated_session(request: Request) -> bool:
    """Return whether SessionAuthMiddleware attached a validated user."""
    return getattr(request.state, "user_entry", None) is not None


def get_api_key_registry() -> KeyRegistry:
    """Build API registry from service settings, with legacy key compatibility."""
    settings = get_settings()
    raw = settings.otalon_api_allowed_keys
    if not raw and settings.admin_api_key:
        raw = f"admin:operator:{settings.admin_api_key}"
    return KeyRegistry(tuple(parse_allowed_keys(raw)), OnMissing.FAIL_CLOSED)


async def require_operator_api_key(request: Request) -> Any:
    """Require an operator key using a registry resolved for the current request."""
    return await require_api_key(get_api_key_registry(), KeyRole.OPERATOR)(request)


def _audit(request: Request, decision: str, entry: Any = None) -> None:
    """Emit structured auth decision without accepting or logging key material."""
    actor = getattr(entry, "name", "anonymous")
    role = getattr(entry, "role", "none")
    logger.info(
        "AUTH_AUDIT actor={} role={} decision={} path={} method={}",
        actor,
        role,
        decision,
        request.url.path,
        request.method,
    )


class ApiKeyAuthMiddleware(BaseHTTPMiddleware):
    """Delegate protected-prefix authentication to shared FastAPI adapter."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Authenticate protected paths and record key-free decisions.

        Authorization is enforced here as well: non-GET/HEAD requests
        require an operator-role key. Sessions only ever pass reads, and
        session-owned or worker-token paths are exempted above before the
        registry is consulted, so no legitimate non-operator mutation path
        remains behind this middleware.
        """
        path = request.url.path
        if any(path.startswith(prefix) for prefix in SESSION_OWNED_PATH_PREFIXES):
            return await call_next(request)
        if (request.method, path) in SESSION_OWNED_REQUESTS:
            return await call_next(request)
        if any(path.startswith(prefix) for prefix in WORKER_TOKEN_PATH_PREFIXES):
            return await call_next(request)
        if path in PUBLIC_PROBE_PATHS and request.query_params.get("detail") != "true":
            return await call_next(request)

        registry = get_api_key_registry()
        if _is_read_request(request) and _has_authenticated_session(request):
            _audit(request, "accept_session", None)
            return await call_next(request)
        if not registry.configured:
            response = Response(
                content='{"detail":"API key authentication unavailable"}',
                status_code=503,
                media_type="application/json",
            )
            _audit(request, "reject_503", None)
            return response
        entry = registry.verify(request.headers.get("X-API-Key", ""))
        if entry is None:
            response = Response(
                content='{"detail":"Invalid or missing API key"}',
                status_code=401,
                media_type="application/json",
            )
        elif not _is_read_request(request) and entry.role != KeyRole.OPERATOR:
            response = Response(
                content='{"detail":"Insufficient API key role"}',
                status_code=403,
                media_type="application/json",
            )
        else:
            request.state.api_key_entry = entry
            response = await call_next(request)
        entry = getattr(request.state, "api_key_entry", None)
        _audit(
            request,
            "accept" if entry is not None else f"reject_{response.status_code}",
            entry,
        )
        return response
