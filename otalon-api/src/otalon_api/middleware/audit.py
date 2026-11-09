"""Audit-logging middleware for admin endpoints.

Logs all requests to admin paths with method, path, status code,
client IP, user agent, and duration for security auditing.
"""

from __future__ import annotations

import time

from loguru import logger
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response

AUDIT_PATH_PREFIXES: tuple[str, ...] = ("/api/v1/admin",)


class AuditLoggingMiddleware(BaseHTTPMiddleware):
    """Log requests to sensitive / admin endpoints for auditing purposes."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Log admin requests with timing and status information.

        Non-admin paths pass through without logging. Admin requests are
        logged after the response is generated so that the status code
        and duration are included.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware / route handler.

        Returns:
            The HTTP response.
        """
        path = request.url.path
        if not any(path.startswith(prefix) for prefix in AUDIT_PATH_PREFIXES):
            return await call_next(request)

        client_ip = request.client.host if request.client else "unknown"
        user_agent = request.headers.get("user-agent", "")

        t0 = time.perf_counter()
        response = await call_next(request)
        duration_ms = round((time.perf_counter() - t0) * 1000, 1)

        logger.info(
            "AUDIT | {} {} | status={} | ip={} | {:.1f}ms | ua={}",
            request.method,
            path,
            response.status_code,
            client_ip,
            duration_ms,
            user_agent[:100],
        )

        return response
