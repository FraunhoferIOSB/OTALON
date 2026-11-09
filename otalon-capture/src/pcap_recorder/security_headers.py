"""Security headers applied to every pcap_recorder response."""

from __future__ import annotations

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Add browser hardening headers and suppress technology disclosure.

    Mirrors ``otalon-api/src/middleware/security_headers.py`` so all suite
    HTTP services send the same header set (SUITE-023). TLS/HSTS/Cookie-Secure
    are deliberately out of scope (tracked as SUITE-025).
    """

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Add security headers to downstream response."""
        response = await call_next(request)
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Content-Security-Policy"] = "frame-ancestors 'none'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        if "X-Process-Time" in response.headers:
            del response.headers["X-Process-Time"]
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        return response
