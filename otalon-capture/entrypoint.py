import asyncio
import os
import signal
import sys
from asyncio.subprocess import Process
from dataclasses import dataclass
from typing import List

DEFAULT_MODULES = (
    "otalon_capture.main",
    "pcap_recorder.main",
)

MODULES_ENV_VAR = "NETCAP_ENTRYPOINT_MODULES"


def _resolve_modules() -> List[str]:
    """Return the modules to supervise, honouring an environment override.

    The live adapter container runs the capture adapter plus the PCAP recorder.
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


class EntryPoint:
    def __init__(self, args: List[str]):
        self.args = args
        self.processes: List[RuntimeProcess] = []
        self.loop = asyncio.get_event_loop()

    async def _start_module(self, module: str) -> RuntimeProcess:
        cmd = [sys.executable, "-u", "-m", module, *self.args]
        process = await asyncio.create_subprocess_exec(*cmd)
        return RuntimeProcess(module=module, process=process)

    async def _stop_process(self, runtime_proc: RuntimeProcess) -> None:
        proc = runtime_proc.process
        if proc.returncode is None:
            proc.terminate()
            try:
                await asyncio.wait_for(proc.wait(), timeout=10)
            except asyncio.TimeoutError:
                proc.kill()
                await proc.wait()

    async def _run(self) -> int:
        for module in _resolve_modules():
            runtime_proc = await self._start_module(module)
            self.processes.append(runtime_proc)

        pending = {asyncio.create_task(proc.process.wait()): proc for proc in self.processes}

        def _handle_signal(signum: int, _frame) -> None:
            for task in pending:
                task.cancel()
            self.loop.create_task(self._shutdown())

        signal.signal(signal.SIGINT, _handle_signal)
        signal.signal(signal.SIGTERM, _handle_signal)

        done, _ = await asyncio.wait(pending.keys(), return_when=asyncio.FIRST_COMPLETED)
        exit_code = 0
        for task in done:
            try:
                exit_code = task.result()
            except asyncio.CancelledError:
                continue
        await self._shutdown()
        return exit_code

    async def _shutdown(self) -> None:
        await asyncio.gather(*(self._stop_process(proc) for proc in self.processes), return_exceptions=True)

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
