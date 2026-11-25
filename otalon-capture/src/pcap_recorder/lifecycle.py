"""One native acquisition owner. A2 makes one bounded initial attempt only."""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import stat
import time
import uuid
from pathlib import Path

from loguru import logger

from capture_runtime import (
    ADAPTER_SNAPSHOT_MAX_BYTES,
    ADAPTER_SNAPSHOT_PATH,
    AdapterSnapshot,
    CaptureBackend,
    CaptureIntent,
    CaptureSnapshot,
    SourceState,
)

from .recorder import TcpdumpRecorder
from .settings import PcapConfig


def _interface_exists(interface: str) -> bool:
    """Inspect only the configured kernel name, without scanning or raw access."""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", interface):
        raise ValueError("CAPTURE_SOURCE must be a syntactically safe native interface name.")
    return (Path("/sys/class/net") / interface).is_dir()


class AcquisitionPair:
    def __init__(self, config: PcapConfig) -> None:
        self.config = config
        self.adapter: asyncio.subprocess.Process | None = None
        self.recorder: TcpdumpRecorder | None = None
        self.generation = uuid.uuid4().hex
        self._stopped = asyncio.Event()
        self._stop_task: asyncio.Task | None = None
        self._launch_lock = asyncio.Lock()
        self._attempted = False
        self._ready = False
        self.snapshot = CaptureSnapshot(
            capture_type=CaptureIntent.LIVE, backend=CaptureBackend.NATIVE, source_state=SourceState.WAITING
        )

    def _status(self, state: SourceState, reason=None) -> None:
        self.snapshot = CaptureSnapshot(
            capture_type=CaptureIntent.LIVE,
            backend=CaptureBackend.NATIVE,
            source_state=state,
            reason_code=reason,
            retry_attempt=1,
            retry_limit=5,
        )

    def _read_snapshot(self) -> AdapterSnapshot | None:
        if self.adapter is None:
            return None
        try:
            # A same-UID path replacement must not turn a readiness read into
            # an unbounded FIFO read or redirect it through a symlink.
            fd = os.open(ADAPTER_SNAPSHOT_PATH, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
            with os.fdopen(fd, "rb") as handle:
                if not stat.S_ISREG(os.fstat(handle.fileno()).st_mode):
                    return None
                data = handle.read(ADAPTER_SNAPSHOT_MAX_BYTES + 1)
        except OSError:
            return None
        return AdapterSnapshot.from_bytes(
            data, generation=self.generation, child_pid=self.adapter.pid, now=time.monotonic()
        )

    async def _pause(self, seconds: float) -> None:
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self._stopped.wait(), timeout=seconds)

    async def start(self) -> bool:
        if self._attempted or self._stopped.is_set():
            return self._ready and not self._stopped.is_set()
        self._attempted = True
        deadline = time.monotonic() + 5.0
        try:
            if not _interface_exists(self.config.interface):
                self._status(SourceState.WAITING, "source_absent")
                logger.warning("Capture source {interface} unavailable: source_absent", interface=self.config.interface)
                return False
            Path(ADAPTER_SNAPSHOT_PATH).unlink(missing_ok=True)
            async with self._launch_lock:
                if self._stopped.is_set():
                    return False
                self.adapter = await asyncio.wait_for(
                    asyncio.create_subprocess_exec(
                        "/usr/local/bin/python3-cap",
                        "-u",
                        "-m",
                        "otalon_capture.main",
                        "--_capture-generation",
                        self.generation,
                    ),
                    timeout=max(0.0, deadline - time.monotonic()),
                )
                if self._stopped.is_set():
                    return False
                self.recorder = TcpdumpRecorder(self.config)
                self.recorder.start()
            while not self._stopped.is_set() and time.monotonic() < deadline:
                if self.adapter.returncode is not None or not self.recorder.is_running:
                    break
                snapshot = self._read_snapshot()
                if snapshot is not None:
                    if snapshot.state is SourceState.RECORDING:
                        self._ready = True
                        self._status(SourceState.RECORDING)
                        return True
                    if snapshot.state is SourceState.BLOCKED:
                        self._status(SourceState.BLOCKED, snapshot.reason_code or "dependency_unavailable")
                        break
                await self._pause(min(0.1, max(0.0, deadline - time.monotonic())))
            if self.snapshot.source_state is not SourceState.BLOCKED:
                self._status(SourceState.BLOCKED, "dependency_unavailable")
            logger.warning("Capture source {interface} blocked: readiness unverified", interface=self.config.interface)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            reason = "privilege_denied" if isinstance(error, PermissionError) else "dependency_unavailable"
            self._status(SourceState.BLOCKED, reason)
            logger.warning(
                "Capture source {interface} blocked: {reason}", interface=self.config.interface, reason=reason
            )
        finally:
            if not self._ready:
                await self.stop()
        return False

    async def run(self) -> None:
        try:
            if not await self.start():
                return
            while not self._stopped.is_set():
                snapshot = self._read_snapshot()
                if (
                    self.adapter is None
                    or self.adapter.returncode is not None
                    or self.recorder is None
                    or not self.recorder.is_running
                    or snapshot is None
                    or snapshot.state is not SourceState.RECORDING
                ):
                    self._status(SourceState.DEGRADED, "dependency_unavailable")
                    logger.warning(
                        "Capture source {interface} degraded: producer readiness lost", interface=self.config.interface
                    )
                    break
                await self._pause(0.25)
        finally:
            await self.stop()

    async def stop(self) -> None:
        self._stopped.set()
        if self._stop_task is None:
            self._stop_task = asyncio.create_task(self._reap())
        await asyncio.shield(self._stop_task)

    async def _reap(self) -> None:
        deadline = time.monotonic() + 6.0
        # A stop concurrent with spawn must reap the just-created handle too.
        async with self._launch_lock:
            child = self.adapter
            recorder = self.recorder

        async def adapter_stop() -> None:
            if child is None:
                return
            if child.returncode is None:
                with contextlib.suppress(ProcessLookupError):
                    child.terminate()
            try:
                await asyncio.wait_for(child.wait(), timeout=min(5.0, max(0.0, deadline - time.monotonic() - 1.0)))
            except asyncio.TimeoutError:
                with contextlib.suppress(ProcessLookupError):
                    child.kill()
                await asyncio.wait_for(child.wait(), timeout=min(1.0, max(0.0, deadline - time.monotonic())))

        async def recorder_stop() -> None:
            if recorder is not None:
                # Existing wait/kill/drain bounds sum to at most six seconds.
                timeout = min(2.0, max(0.0, (deadline - time.monotonic() - 2.0) / 2.0))
                await asyncio.to_thread(recorder.stop, timeout_s=timeout)

        try:
            results = await asyncio.gather(adapter_stop(), recorder_stop(), return_exceptions=True)
            if any(isinstance(result, BaseException) for result in results):
                logger.warning("Capture child cleanup did not complete normally.")
        finally:
            self.adapter = None
            self.recorder = None
            self._ready = False
            Path(ADAPTER_SNAPSHOT_PATH).unlink(missing_ok=True)
