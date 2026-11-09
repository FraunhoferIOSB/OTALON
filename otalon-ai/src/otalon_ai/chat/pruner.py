"""Periodic background pruning of stale chat sessions.

The chat surface already prunes ``chat_sessions`` once at service startup
(see ``otalon_ai/main.py`` lifespan), which is sufficient for short-lived
processes but lets the table grow unboundedly on long uptime. This
module adds a long-running asyncio task that calls
:meth:`ChatSessionStore.prune` on a fixed cadence so retention is
enforced continuously.

The pruner is intentionally minimal:

- it is driven by ``asyncio.sleep`` so it cancels cleanly when the
  FastAPI lifespan exits;
- it runs the synchronous ``ChatSessionStore.prune`` call inside
  ``asyncio.to_thread`` so the event loop is never blocked by the
  PostgreSQL ``DELETE`` (per AGENTS.md § "Async-first guidelines");
- if a single iteration raises, the error is logged and the loop
  continues — a transient DB outage MUST NOT take down the service.
"""

from __future__ import annotations

import asyncio
from typing import Optional

from loguru import logger

from otalon_ai.chat.session_store import ChatSessionStore

# Module-level constant so tests can monkeypatch a tiny value instead of
# spinning real wall-clock hours.
DEFAULT_PRUNE_INTERVAL_SECONDS: int = 3600  # 1 h


class ChatSessionPruner:
    """Run :meth:`ChatSessionStore.prune` on a fixed interval.

    The pruner does not own the store; it borrows it for the lifetime of
    the FastAPI lifespan. Cancelling the returned task is the only
    supported shutdown path.

    Attributes:
        store: The session store to prune.
        retention_days: Passed to :meth:`ChatSessionStore.prune`. Values
            ``<= 0`` are tolerated (the underlying store treats them as
            "pruning disabled" and the pruner skips the call).
        interval_seconds: Time between two prune attempts. Must be ``>= 1``.
    """

    def __init__(
        self,
        store: ChatSessionStore,
        *,
        retention_days: int,
        interval_seconds: int = DEFAULT_PRUNE_INTERVAL_SECONDS,
    ) -> None:
        if interval_seconds < 1:
            raise ValueError("interval_seconds must be >= 1")
        self._store = store
        self._retention_days = retention_days
        self._interval_seconds = interval_seconds
        self._task: Optional[asyncio.Task[None]] = None

    @property
    def is_running(self) -> bool:
        """Whether the background task is currently scheduled."""
        return self._task is not None and not self._task.done()

    async def _run(self) -> None:
        """Sleep ``interval_seconds``, then prune, in a loop until cancelled."""
        logger.info(
            "ChatSessionPruner: started (interval_seconds={}, retention_days={})",
            self._interval_seconds,
            self._retention_days,
        )
        try:
            while True:
                await asyncio.sleep(self._interval_seconds)
                if self._retention_days <= 0:
                    # The store would log "retention disabled" on every
                    # tick — skip the call entirely to keep the log quiet.
                    continue
                try:
                    deleted = await asyncio.to_thread(self._store.prune, self._retention_days)
                    logger.debug("ChatSessionPruner: prune cycle removed {} row(s)", deleted)
                except Exception as exc:  # noqa: BLE001 - log and continue
                    # A transient DB error MUST NOT crash the loop.
                    logger.warning("ChatSessionPruner: prune cycle failed: {}", exc)
        except asyncio.CancelledError:
            logger.info("ChatSessionPruner: cancelled, exiting cleanly")
            raise

    def start(self) -> asyncio.Task[None]:
        """Schedule the background task. Idempotent.

        Returns:
            The asyncio task; callers typically just discard the handle
            because :meth:`stop` is the only supported shutdown path.
        """
        if self.is_running:
            return self._task  # type: ignore[return-value]
        self._task = asyncio.create_task(self._run(), name="chat-session-pruner")
        return self._task

    async def stop(self) -> None:
        """Cancel the background task and wait for it to finish."""
        if self._task is None:
            return
        self._task.cancel()
        try:
            await self._task
        except asyncio.CancelledError:
            pass
        self._task = None
