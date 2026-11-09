"""Optional FastAPI adapter for the shared API-key registry."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import TYPE_CHECKING, Any

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import JSONResponse, Response

from otalon_common.auth.api_key import KeyRegistry, KeyRole, OnMissing

if TYPE_CHECKING:
    from starlette.requests import Request


def _role_allows(actual: KeyRole, minimum: KeyRole) -> bool:
    """Return whether actual role satisfies minimum role."""
    return actual == KeyRole.OPERATOR or minimum == KeyRole.VIEWER


def require_api_key(
    registry: KeyRegistry, min_role: KeyRole = KeyRole.VIEWER
) -> Callable[["Request"], Any]:
    """Create a FastAPI dependency requiring a key with the requested role."""
    from fastapi import HTTPException, status

    async def dependency(request: "Request") -> Any:
        """Validate request header and return its redacted-safe registry entry."""
        if not registry.configured:
            if registry.on_missing == OnMissing.WARN_OPEN:
                return None
            raise HTTPException(
                status_code=503, detail="API key authentication unavailable"
            )
        entry = registry.verify(request.headers.get("X-API-Key", ""))
        if entry is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or missing API key",
            )
        if not _role_allows(entry.role, min_role):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Insufficient API key role",
            )
        return entry

    return dependency


def make_api_key_middleware(
    *,
    registry: KeyRegistry,
    protected_prefixes: Sequence[str],
    open_paths: Sequence[str] = ("/health",),
    on_missing: OnMissing = OnMissing.FAIL_CLOSED,
) -> type[BaseHTTPMiddleware]:
    """Create middleware protecting selected path prefixes."""

    class ApiKeyMiddleware(BaseHTTPMiddleware):
        """Authenticate requests matching configured protected prefixes."""

        async def dispatch(
            self, request: Request, call_next: RequestResponseEndpoint
        ) -> Response:
            path = request.url.path
            if path in open_paths or not any(
                path.startswith(prefix) for prefix in protected_prefixes
            ):
                return await call_next(request)
            missing_mode = (
                on_missing if not registry.configured else registry.on_missing
            )
            if not registry.configured:
                if missing_mode == OnMissing.WARN_OPEN:
                    return await call_next(request)
                return JSONResponse(
                    status_code=503,
                    content={"detail": "API key authentication unavailable"},
                )
            entry = registry.verify(request.headers.get("X-API-Key", ""))
            if entry is None:
                return JSONResponse(
                    status_code=401, content={"detail": "Invalid or missing API key"}
                )
            request.state.api_key_entry = entry
            return await call_next(request)

    return ApiKeyMiddleware
