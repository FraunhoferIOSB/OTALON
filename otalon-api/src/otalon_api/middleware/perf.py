"""Request-timing middleware without client-facing timing disclosure."""

from __future__ import annotations

import time

from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.requests import Request
from starlette.responses import Response


class RequestTimingMiddleware(BaseHTTPMiddleware):
    """Measure and expose request processing time via X-Process-Time header."""

    async def dispatch(self, request: Request, call_next: RequestResponseEndpoint) -> Response:
        """Time the request and add X-Process-Time to the response.

        Args:
            request: The incoming HTTP request.
            call_next: The next middleware / route handler.

        Returns:
            The HTTP response with the X-Process-Time header added.
        """
        t0 = time.perf_counter()
        response = await call_next(request)
        _ = time.perf_counter() - t0
        return response
