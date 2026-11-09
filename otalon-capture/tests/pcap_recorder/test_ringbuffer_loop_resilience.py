"""PCAP-018 regression: a failing ringbuffer tick must not kill the loop silently.

Before the fix ``_ringbuffer_loop`` had no handler for ordinary exceptions, so
one failing ``tick()`` ended the task without a log line. The index then stopped
growing while the buffer kept filling past its limit.
"""

from __future__ import annotations

import asyncio

import pytest
from pcap_recorder import main as recorder_main


class _FlakyRingbuffer:
    def __init__(self, failures: int) -> None:
        self.calls = 0
        self._failures = failures

    def tick(self) -> None:
        self.calls += 1
        if self.calls <= self._failures:
            raise RuntimeError("simulated tick failure")


class _State:
    running = True


@pytest.mark.asyncio
async def test_ringbuffer_loop_survives_tick_exception(monkeypatch: pytest.MonkeyPatch) -> None:
    state = _State()
    ringbuffer = _FlakyRingbuffer(failures=2)

    async def fast_sleep(_: float) -> None:
        if ringbuffer.calls >= 4:
            state.running = False

    monkeypatch.setattr(recorder_main.asyncio, "sleep", fast_sleep)

    await asyncio.wait_for(recorder_main._ringbuffer_loop(state, ringbuffer), timeout=5)

    assert ringbuffer.calls >= 3, "loop must keep ticking after a failed tick"
