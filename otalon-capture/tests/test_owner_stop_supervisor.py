"""Existing EntryPoint owns real held modules through TERM, KILL and reap."""

import asyncio
import os
import signal
from pathlib import Path
from unittest.mock import Mock

import pytest

import entrypoint


class Child:
    def __init__(self, code=0):
        self.returncode = None
        self.code = code
        self.terms = self.waits = 0
        self.exited = asyncio.Event()

    def terminate(self):
        self.terms += 1
        self.returncode = self.code
        self.exited.set()

    async def wait(self):
        self.waits += 1
        await self.exited.wait()
        return self.returncode


@pytest.mark.asyncio
async def test_repeated_stop_has_one_shutdown_and_wait(monkeypatch):
    handlers = {}
    monkeypatch.setattr(entrypoint.signal, "signal", lambda sig, handler: handlers.setdefault(sig, handler))
    monkeypatch.setattr(entrypoint, "_resolve_modules", lambda: ["desktop_ingest.main"])
    child = Child()
    entered = asyncio.Event()

    async def spawn(module):
        entered.set()
        return entrypoint.RuntimeProcess(module, child)

    owner = entrypoint.EntryPoint([])
    monkeypatch.setattr(owner, "_start_module", spawn)
    task = asyncio.create_task(owner._run())
    await entered.wait()
    await asyncio.sleep(0)
    handlers[signal.SIGTERM](signal.SIGTERM, None)
    handlers[signal.SIGTERM](signal.SIGTERM, None)
    assert await task == 0
    await asyncio.gather(owner._shutdown(), owner._shutdown())
    assert child.terms == child.waits == 1


@pytest.mark.asyncio
async def test_stop_before_spawn_and_during_spawn_retains_only_returned_child(monkeypatch):
    handlers = {}
    monkeypatch.setattr(entrypoint.signal, "signal", lambda sig, handler: handlers.setdefault(sig, handler))
    monkeypatch.setattr(entrypoint, "_resolve_modules", lambda: ["desktop_ingest.main", "unused.module"])
    entered, release = asyncio.Event(), asyncio.Event()
    child = Child()
    calls = []

    async def spawn(module):
        calls.append(module)
        entered.set()
        await release.wait()
        return entrypoint.RuntimeProcess(module, child)

    owner = entrypoint.EntryPoint([])
    monkeypatch.setattr(owner, "_start_module", spawn)
    task = asyncio.create_task(owner._run())
    await entered.wait()
    try:
        assert signal.SIGTERM in handlers, "handler must precede spawn await"
        handlers[signal.SIGTERM](signal.SIGTERM, None)
        stopping = asyncio.create_task(owner._shutdown())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        assert not stopping.done(), "shutdown must join and retain the pending spawn"
    finally:
        release.set()
    await task
    await stopping
    assert calls == ["desktop_ingest.main"]
    assert child.terms == child.waits == 1
    other = entrypoint.EntryPoint([])
    spawn_mock = Mock(side_effect=AssertionError("spawn after stop"))
    monkeypatch.setattr(other, "_start_module", spawn_mock)
    await other._shutdown()
    assert await other._run() == 0
    spawn_mock.assert_not_called()


@pytest.mark.asyncio
@pytest.mark.parametrize("code", [-9, 7])
async def test_failed_sibling_never_becomes_clean_disposition(monkeypatch, code):
    monkeypatch.setattr(entrypoint.signal, "signal", lambda *args: None)
    monkeypatch.setattr(entrypoint, "_resolve_modules", lambda: ["desktop_ingest.main", "second.module"])
    children = [Child(0), Child(code)]
    children[0].terminate()

    async def spawn(module):
        return entrypoint.RuntimeProcess(module, children.pop(0))

    owner = entrypoint.EntryPoint([])
    monkeypatch.setattr(owner, "_start_module", spawn)
    result = await owner._run()
    assert 0 < result <= 255
    assert all(proc.process.waits == 1 for proc in owner.processes)


@pytest.mark.asyncio
async def test_real_indefinite_owned_seams_term_kill_reap_and_exact_custody(tmp_path, monkeypatch):
    import importlib.util

    boundary_path = Path(__file__).parent / "desktop_ingest" / "test_owner_stop_boundaries.py"
    spec = importlib.util.spec_from_file_location("stop_boundaries", boundary_path)
    boundaries = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(boundaries)
    phases = ["constructor", "process", "publish", "query", "close", "gil"]
    before = {}
    modules = []
    for phase in phases:
        root = tmp_path / phase
        root.mkdir()
        ledger, _ = boundaries.custody(root / "custody", prepared=phase in {"publish", "query", "close"})
        before[phase] = boundaries.snapshot(ledger)
        ledger.close()
        name = "held_" + phase
        modules.append(name)
        (tmp_path / (name + ".py")).write_text(
            "import runpy\n"
            f"boundary = runpy.run_path({str(boundary_path)!r})\n"
            f"boundary['held_child']({str(root)!r}, {phase!r})\n"
        )
    monkeypatch.setenv("PYTHONPATH", str(tmp_path) + os.pathsep + os.environ.get("PYTHONPATH", ""))
    monkeypatch.setattr(entrypoint, "_resolve_modules", lambda: modules)
    handlers = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
    owner = entrypoint.EntryPoint([])
    task = asyncio.create_task(owner._run())
    try:

        async def ready():
            while not all((tmp_path / phase / "held").exists() for phase in phases):
                assert not task.done(), "owned child failed before hold"
                await asyncio.sleep(0.02)

        await asyncio.wait_for(ready(), timeout=10)
        pids = {phase: int((tmp_path / phase / "held").read_text()) for phase in phases}
        assert {proc.process.pid for proc in owner.processes} == set(pids.values())
        began = asyncio.get_running_loop().time()
        os.kill(os.getpid(), signal.SIGTERM)
        os.kill(os.getpid(), signal.SIGTERM)
        result = await asyncio.wait_for(asyncio.shield(task), timeout=15)
        elapsed = asyncio.get_running_loop().time() - began
        assert elapsed >= 10, "real source-derived TERM grace was bypassed"
        assert 0 < result <= 255, "forced child kill must never report clean success"
        assert all(proc.process.returncode == -signal.SIGKILL for proc in owner.processes)
        for phase, pid in pids.items():
            with pytest.raises(ProcessLookupError):
                os.kill(pid, 0)
            with pytest.raises(ChildProcessError):
                os.waitpid(pid, os.WNOHANG)
            assert not (tmp_path / phase / "late-success").exists()
            if phase != "gil":
                assert (tmp_path / phase / "terms").read_text() == "TERM\n"
            ledger = boundaries.Ledger(tmp_path / phase / "custody")
            try:
                assert boundaries.snapshot(ledger) == before[phase]
            finally:
                ledger.close()
    finally:
        for runtime in owner.processes:
            if runtime.process.returncode is None:
                runtime.process.kill()
                await runtime.process.wait()
        await asyncio.gather(task, return_exceptions=True)
        for sig, handler in handlers.items():
            signal.signal(sig, handler)
