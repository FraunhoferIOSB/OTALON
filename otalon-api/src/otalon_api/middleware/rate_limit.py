"""Small process-local rate limiter for expensive API operations."""

from __future__ import annotations

import time
from collections import defaultdict, deque
from threading import Lock

from fastapi import HTTPException, Request


class FixedWindowRateLimiter:
    """Limit requests per client in a rolling in-memory window."""

    def __init__(self, limit: int, window_seconds: float) -> None:
        self.limit = limit
        self.window_seconds = window_seconds
        self._requests: defaultdict[str, deque[float]] = defaultdict(deque)
        self._lock = Lock()

    def check(self, client_id: str) -> None:
        """Accept request or raise HTTP 429 when client exceeds its quota."""
        now = time.monotonic()
        with self._lock:
            bucket = self._requests[client_id]
            while bucket and now - bucket[0] >= self.window_seconds:
                bucket.popleft()
            if len(bucket) >= self.limit:
                raise HTTPException(status_code=429, detail="Rate limit exceeded")
            bucket.append(now)


lookup_rate_limiter = FixedWindowRateLimiter(limit=5, window_seconds=60.0)


async def enforce_lookup_rate_limit(request: Request) -> None:
    """Rate-limit vulnerability lookup submissions by source IP."""
    client_id = request.client.host if request.client else "unknown"
    lookup_rate_limiter.check(client_id)
