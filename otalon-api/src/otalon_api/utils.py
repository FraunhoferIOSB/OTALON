"""Shared utility helpers for the OTALON API.

Provides concurrency helpers for mixing synchronous blocking code
(e.g. psycopg2, InfluxDB client) with asyncio-based FastAPI handlers.
"""

from __future__ import annotations

import asyncio
from functools import wraps
from typing import Any, Callable, Coroutine, TypeVar

T = TypeVar("T")


def run_in_thread(func: Callable[..., T]) -> Callable[..., Coroutine[Any, Any, T]]:
    """Decorate a synchronous function to run in an asyncio thread pool.

    Wraps a sync function so it becomes an async coroutine that offloads
    the blocking call to :func:`asyncio.to_thread`, preventing
    event-loop stalls when calling blocking I/O such as psycopg2 or
    the InfluxDB client.

    Usage::

        class MyService:
            @run_in_thread
            def heavy_query(self, param: str) -> list[dict]:
                return self._repo.execute(param)

        result = await service.heavy_query("test")

    Args:
        func: A synchronous callable (regular function or method).

    Returns:
        An async wrapper that delegates to the default thread-pool
        executor via :func:`asyncio.to_thread`.
    """

    @wraps(func)
    async def wrapper(*args: Any, **kwargs: Any) -> T:
        return await asyncio.to_thread(func, *args, **kwargs)

    return wrapper
