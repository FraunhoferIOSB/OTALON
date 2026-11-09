"""Regression tests for SC-03 (SUITE-031 audit): ``stop_module`` return
semantics.

Root causes fixed:

1. The monitor thread and ``_clean_up_finished_modules`` retire the
   ``running_modules`` entry as soon as the child process exits. An operator
   ``stop`` racing that retirement looked the run up on a stale map, found
   nothing, and returned ``False`` — even though the process was already
   terminated (the desired end state). A run known to be finished now reports
   ``True``.
2. The termination path ended in ``set.remove(...)``; when the monitor thread
   had concurrently removed the same entry, ``remove`` raised ``KeyError``
   which the outer ``except`` turned into ``False`` — after the process had
   already been terminated successfully. The removal is now a ``discard``
   under the manager lock.
3. A generic termination failure (e.g. ``psutil.AccessDenied``) previously
   fell through to ``return True`` even though the process may still be
   running. It now reports ``False`` honestly.

Pure unit tests; only the happy-path case spawns a real (trivial) child
process.
"""

from __future__ import annotations

import multiprocessing
import time
from typing import Any

import psutil
import pytest

from otalon_scan.core import module_manager as mm
from otalon_scan.core.module_manager import ModuleManager


@pytest.fixture()
def manager(tmp_path: Any) -> Any:
    """A ModuleManager over an empty modules dir; shuts its mp Manager down."""
    empty_modules = tmp_path / "modules"
    empty_modules.mkdir()
    mgr = ModuleManager(modules_path=str(empty_modules), batch_size=3)
    yield mgr
    mgr.manager.shutdown()


def test_stop_reports_true_when_monitor_already_retired_the_run(manager: ModuleManager) -> None:
    """A run whose process already ended (monitor removed the registry entry
    and finalised it) IS stopped — the endpoint must not claim otherwise."""
    uid = "run-retired"
    manager._finalised_runs.add(uid)  # monitor thread already finalised it

    assert manager.stop_module(uid) is True
    # The cancellation marker is still recorded so a deferred finalisation
    # reports the operator-requested abort semantics (D4).
    assert uid in manager._cancelled_runs


def test_stop_reports_true_when_finalisation_is_pending(manager: ModuleManager) -> None:
    """A run whose finalisation was deferred (B-E3) has an exited process —
    stopping it succeeds at the process level already."""
    uid = "run-pending"
    manager._pending_finalize[uid] = "arp_scan"

    assert manager.stop_module(uid) is True
    assert uid in manager._cancelled_runs


def test_stop_unknown_run_still_reports_false(manager: ModuleManager) -> None:
    """A uid the manager never saw is genuinely not stoppable."""
    assert manager.stop_module("run-never-seen") is False


def test_stop_survives_stale_registry_entry(manager: ModuleManager, monkeypatch: pytest.MonkeyPatch) -> None:
    """The registry removal must not turn a successful termination into a
    ``False`` result when the monitor thread concurrently retired the entry
    (``set.remove`` → ``KeyError`` on the stale map)."""

    uid = "run-stale"

    def _sleep() -> None:
        time.sleep(30)

    proc = multiprocessing.Process(target=_sleep, daemon=True)
    proc.start()
    assert proc.pid is not None

    entry = (uid, "arp_scan", proc)
    manager.running_modules.add(entry)

    # Simulate the monitor thread winning the retirement race: the entry is
    # gone from the registry by the time ``stop_module`` removes it.
    original_wait = psutil.Process.wait

    def _wait_and_retire(self: psutil.Process, timeout: Any = None) -> Any:
        manager.running_modules.discard(entry)
        return original_wait(self, timeout)

    monkeypatch.setattr(psutil.Process, "wait", _wait_and_retire)
    try:
        assert manager.stop_module(uid) is True
        assert entry not in manager.running_modules
    finally:
        if proc.is_alive():
            proc.kill()
        proc.join(timeout=5)


def test_stop_reports_false_when_termination_fails(manager: ModuleManager, monkeypatch: pytest.MonkeyPatch) -> None:
    """A termination error (e.g. insufficient privileges) must NOT be
    reported as a successful stop."""

    uid = "run-denied"

    class _LiveProcess:
        pid = 2**22

        def is_alive(self) -> bool:
            return True

    class _DeniedProcess:
        def __init__(self, pid: int) -> None:
            self.pid = pid

        def terminate(self) -> None:
            raise psutil.AccessDenied(pid=self.pid)

    monkeypatch.setattr(mm.psutil, "Process", _DeniedProcess)
    manager.running_modules.add((uid, "arp_scan", _LiveProcess()))

    assert manager.stop_module(uid) is False


def test_stop_happy_path_terminates_real_process(manager: ModuleManager) -> None:
    """A live child process is terminated and reported as stopped."""

    def _sleep() -> None:
        time.sleep(30)

    proc = multiprocessing.Process(target=_sleep, daemon=True)
    proc.start()
    assert proc.pid is not None

    uid = "run-real"
    manager.running_modules.add((uid, "arp_scan", proc))
    try:
        assert manager.stop_module(uid) is True
        assert all(entry[0] != uid for entry in manager.running_modules)
        # stop_module reaps via psutil, so multiprocessing's own exitcode
        # bookkeeping is unreliable here — check the PID at OS level.
        assert not psutil.pid_exists(proc.pid)
    finally:
        if proc.is_alive():
            proc.kill()
            proc.join(timeout=5)
