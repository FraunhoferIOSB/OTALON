import asyncio
import os
import signal
import sys
from asyncio.subprocess import Process
from dataclasses import dataclass
from typing import List

from capture_runtime import CaptureIntent, resolve_capture_intent

DEFAULT_MODULES = ("pcap_recorder.main",)

MODULES_ENV_VAR = "NETCAP_ENTRYPOINT_MODULES"


def _resolve_modules() -> List[str]:
    """Return the modules to supervise, honouring an environment override.

    The native container runs the recorder coordinator, which owns LIVE children.
    The PCAP import worker is a separate container that shares this image, so it
    sets ``NETCAP_ENTRYPOINT_MODULES=pcap_import.main`` to run only itself.

    Returns:
        Module names to start, in order.
    """

    raw = os.environ.get(MODULES_ENV_VAR, "").strip()
    if not raw:
        return list(DEFAULT_MODULES)
    return [module.strip() for module in raw.split(",") if module.strip()]


@dataclass
class RuntimeProcess:
    module: str
    process: Process
    wait_task: asyncio.Task[int] | None = None


class EntryPoint:
    def __init__(self, args: List[str]):
        self.args = args
        self.processes: List[RuntimeProcess] = []
        self.loop = asyncio.get_event_loop()
        self.stopping = asyncio.Event()
        self._shutdown_task: asyncio.Task[int] | None = None
        self._spawn_task: asyncio.Task[RuntimeProcess] | None = None

    async def _start_module(self, module: str) -> RuntimeProcess:
        cmd = [sys.executable, "-u", "-m", module, *self.args]
        process = await asyncio.create_subprocess_exec(*cmd)
        return RuntimeProcess(module=module, process=process)

    def _wait_task(self, runtime_proc: RuntimeProcess) -> asyncio.Task[int]:
        if runtime_proc.wait_task is None:
            runtime_proc.wait_task = asyncio.create_task(runtime_proc.process.wait())
        return runtime_proc.wait_task

    async def _stop_process(self, runtime_proc: RuntimeProcess) -> int:
        proc = runtime_proc.process
        waiting = self._wait_task(runtime_proc)
        failed = False
        if proc.returncode is None:
            try:
                proc.terminate()
            except ProcessLookupError:
                pass  # An exit racing TERM still belongs to this owner's wait.
            except Exception:
                failed = True
                proc.kill()
            try:
                await asyncio.wait_for(asyncio.shield(waiting), timeout=10)
            except asyncio.TimeoutError:
                failed = True
                try:
                    proc.kill()
                except ProcessLookupError:
                    pass
        code = await waiting
        return 1 if failed else min(255, code if code >= 0 else 128 - code)

    async def _run(self) -> int:
        def _handle_signal(signum: int, _frame) -> None:
            self.stopping.set()

        previous = {sig: signal.getsignal(sig) for sig in (signal.SIGINT, signal.SIGTERM)}
        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)
        stopped = asyncio.create_task(self.stopping.wait())
        try:
            modules = _resolve_modules()
            # Worker and unrelated explicit overrides stay independent of boot intent.
            if any(module in {"pcap_recorder.main", "otalon_capture.main"} for module in modules):
                intent = resolve_capture_intent()
                if "otalon_capture.main" in modules and intent is not CaptureIntent.LIVE:
                    raise ValueError("CAPTURE_TYPE must be LIVE for the acquisition adapter.")
            for module in modules:
                if self.stopping.is_set():
                    break

                async def spawn_owned() -> RuntimeProcess:
                    runtime_proc = await self._start_module(module)
                    self.processes.append(runtime_proc)
                    self._wait_task(runtime_proc)
                    return runtime_proc

                self._spawn_task = asyncio.create_task(spawn_owned())
                await asyncio.shield(self._spawn_task)
                self._spawn_task = None
            if self.processes and not self.stopping.is_set():
                await asyncio.wait(
                    [stopped, *(self._wait_task(proc) for proc in self.processes)],
                    return_when=asyncio.FIRST_COMPLETED,
                )
        finally:
            exit_code = await self._shutdown()
            stopped.cancel()
            await asyncio.gather(stopped, return_exceptions=True)
            for sig, handler in previous.items():
                signal.signal(sig, handler)
        return exit_code

    async def _stop_all(self) -> int:
        spawn_failed = False
        if self._spawn_task is not None:
            try:
                await asyncio.shield(self._spawn_task)
            except Exception:
                spawn_failed = True
        codes = await asyncio.gather(*(self._stop_process(proc) for proc in self.processes), return_exceptions=True)
        return next((1 if isinstance(code, BaseException) else code for code in codes if code != 0), int(spawn_failed))

    async def _shutdown(self) -> int:
        self.stopping.set()
        if self._shutdown_task is None:
            self._shutdown_task = asyncio.create_task(self._stop_all())
        return await asyncio.shield(self._shutdown_task)

    def run(self) -> int:
        try:
            return self.loop.run_until_complete(self._run())
        finally:
            self.loop.close()


def main() -> int:
    entrypoint = EntryPoint(sys.argv[1:])
    return entrypoint.run()


if __name__ == "__main__":
    raise SystemExit(main())
