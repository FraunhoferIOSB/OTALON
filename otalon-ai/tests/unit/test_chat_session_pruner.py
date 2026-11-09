"""Unit tests for :class:`src.chat.pruner.ChatSessionPruner`.

The pruner is intentionally simple — sleep, then call
``ChatSessionStore.prune``. These tests verify:

- the background task does call ``prune`` repeatedly with the configured
  retention;
- ``retention_days <= 0`` short-circuits the prune call without raising;
- a single failing prune cycle does NOT crash the task — the next tick
  still executes;
- :meth:`stop` cancels and awaits the task cleanly.

A real ``ChatSessionStore`` is replaced by a lightweight spy so no DB is
required.
"""

from __future__ import annotations

import asyncio
from typing import List

import pytest

from otalon_ai.chat.pruner import ChatSessionPruner


class _SpyStore:
    """Records every ``prune`` call and can optionally raise on demand."""

    def __init__(self, *, raise_on: List[int] | None = None) -> None:
        self.calls: List[int] = []
        self._raise_on = set(raise_on or [])
        self._next_call = 0

    def prune(self, retention_days: int) -> int:
        self._next_call += 1
        self.calls.append(retention_days)
        if self._next_call in self._raise_on:
            raise RuntimeError(f"synthetic prune failure on call {self._next_call}")
        return 0


def test_constructor_rejects_zero_interval() -> None:
    """``interval_seconds <= 0`` is a configuration error."""
    store = _SpyStore()
    with pytest.raises(ValueError):
        ChatSessionPruner(store, retention_days=30, interval_seconds=0)  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_pruner_runs_at_least_twice_and_forwards_retention() -> None:
    """With a 1s tick the task SHOULD prune at least twice in ~2.3s."""
    store = _SpyStore()
    pruner = ChatSessionPruner(store, retention_days=7, interval_seconds=1)
    pruner.start()
    try:
        await asyncio.sleep(2.3)
    finally:
        await pruner.stop()

    assert len(store.calls) >= 2, f"expected at least 2 prune calls, got {store.calls}"
    assert all(arg == 7 for arg in store.calls)


@pytest.mark.asyncio
async def test_pruner_skips_call_when_retention_disabled() -> None:
    """``retention_days <= 0`` MUST NOT invoke ``ChatSessionStore.prune``."""
    store = _SpyStore()
    pruner = ChatSessionPruner(store, retention_days=0, interval_seconds=1)
    pruner.start()
    try:
        await asyncio.sleep(2.3)
    finally:
        await pruner.stop()

    assert store.calls == [], "prune must not be called when retention is disabled"


@pytest.mark.asyncio
async def test_pruner_keeps_running_after_store_error() -> None:
    """A raising prune cycle MUST be logged-and-continued, not crash the loop."""
    # Raise on the first call; subsequent calls should still happen.
    store = _SpyStore(raise_on=[1])
    pruner = ChatSessionPruner(store, retention_days=14, interval_seconds=1)
    pruner.start()
    try:
        await asyncio.sleep(2.3)
    finally:
        await pruner.stop()

    # 1st call raised, but the 2nd MUST have happened.
    assert len(store.calls) >= 2, f"loop must survive a failing cycle; got {store.calls}"


@pytest.mark.asyncio
async def test_pruner_stop_is_idempotent_and_safe_without_start() -> None:
    """``stop`` on a never-started pruner is a no-op."""
    store = _SpyStore()
    pruner = ChatSessionPruner(store, retention_days=30, interval_seconds=1)
    # No start() call.
    await pruner.stop()  # MUST NOT raise.
    assert pruner.is_running is False


@pytest.mark.asyncio
async def test_pruner_start_is_idempotent() -> None:
    """Calling ``start`` twice returns the same task."""
    store = _SpyStore()
    pruner = ChatSessionPruner(store, retention_days=30, interval_seconds=1)
    task_a = pruner.start()
    task_b = pruner.start()
    try:
        assert task_a is task_b
    finally:
        await pruner.stop()
