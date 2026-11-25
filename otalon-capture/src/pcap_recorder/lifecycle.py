"""One native acquisition owner with finite, shared source-loss episodes."""

from __future__ import annotations

import asyncio
import contextlib
import os
import re
import stat
import time
import uuid
from dataclasses import replace
from pathlib import Path

from loguru import logger

from capture_runtime import (
    ADAPTER_SNAPSHOT_MAX_BYTES,
    ADAPTER_SNAPSHOT_PATH,
    AdapterSnapshot,
    CaptureBackend,
    CaptureIntent,
    CaptureSnapshot,
    RetryBudget,
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
        self._reap_task: asyncio.Task | None = None
        self._launch_lock = asyncio.Lock()
        self._start_lock = asyncio.Lock()
        self._budget = RetryBudget()
        self._attempts = 0
        self._had_success = False
        self._recording_since: float | None = None
        self._retry_at: float | None = None
        self._ready = False
        self._status(SourceState.WAITING)

    @property
    def snapshot(self) -> CaptureSnapshot:
        remaining = None if self._retry_at is None else min(16.0, max(0.0, self._retry_at - time.monotonic()))
        return replace(self._snapshot, retry_in_seconds=remaining)

    def _status(self, state: SourceState, reason=None, *, exhausted=False) -> None:
        self._snapshot = CaptureSnapshot(
            capture_type=CaptureIntent.LIVE,
            backend=CaptureBackend.NATIVE,
            source_state=state,
            reason_code=reason,
            retry_attempt=self._attempts,
            retry_limit=self._budget.retry_limit,
            retry_exhausted=exhausted,
        )

    def _source_loss(self) -> None:
        self._status(SourceState.DEGRADED if self._had_success else SourceState.WAITING, "source_absent")

    def _lost_readiness(self, snapshot: AdapterSnapshot | None, *, source_absent=False) -> None:
        # Explicit child failures take precedence even if the interface also vanished.
        if snapshot is not None and snapshot.state is SourceState.BLOCKED:
            self._status(SourceState.BLOCKED, snapshot.reason_code or "dependency_unavailable")
        elif source_absent or not _interface_exists(self.config.interface):
            self._source_loss()
        elif snapshot is not None and snapshot.reason_code == "source_absent":
            self._source_loss()
        else:
            self._status(SourceState.BLOCKED, "dependency_unavailable")

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
        """Acquire a current pair, consuming the same budget across short flaps."""
        async with self._start_lock:
            if self._ready or self._stopped.is_set():
                return self._ready and not self._stopped.is_set()
            if self.snapshot.source_state is SourceState.BLOCKED or self.snapshot.retry_exhausted:
                return False
            try:
                while not self._stopped.is_set() and self._attempts < self._budget.retry_limit:
                    attempt = self._attempts + 1
                    delay = self._budget.delay_before(attempt)
                    logger.warning(
                        "Capture source {interface} attempt {attempt}/5 scheduled in {delay}s; acquisition only",
                        interface=self.config.interface,
                        attempt=attempt,
                        delay=delay,
                    )
                    if delay:
                        self._retry_at = time.monotonic() + delay
                        await self._pause(delay)
                        self._retry_at = None
                    if self._stopped.is_set():
                        return False
                    self._attempts = attempt
                    self._status(SourceState.DEGRADED if self._had_success else SourceState.WAITING)
                    self.generation = uuid.uuid4().hex
                    self._reap_task = None
                    if await self._attempt():
                        self._had_success = True
                        self._recording_since = time.monotonic()
                        return True
                    if self._stopped.is_set() or self.snapshot.source_state is SourceState.BLOCKED:
                        return False
                if not self._stopped.is_set():
                    self._status(
                        SourceState.DEGRADED if self._had_success else SourceState.WAITING,
                        "retry_exhausted",
                        exhausted=True,
                    )
                    logger.warning(
                        "Capture source {interface} retry_exhausted; explicit recreation required",
                        interface=self.config.interface,
                    )
                return False
            finally:
                self._retry_at = None

    async def _attempt(self) -> bool:
        deadline = time.monotonic() + self._budget.readiness_timeout_seconds
        try:
            Path(ADAPTER_SNAPSHOT_PATH).unlink(missing_ok=True)
            if not _interface_exists(self.config.interface):
                self._source_loss()
                logger.warning("Capture source {interface} unavailable: source_absent", interface=self.config.interface)
                return False
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
                snapshot = self._read_snapshot()
                if snapshot is not None and snapshot.state is SourceState.BLOCKED:
                    self._lost_readiness(snapshot)
                    break
                if self.adapter.returncode is not None or not self.recorder.is_running:
                    self._lost_readiness(snapshot)
                    break
                if snapshot is not None:
                    if snapshot.state is SourceState.RECORDING:
                        self._ready = True
                        self._status(SourceState.RECORDING)
                        return True
                    if snapshot.reason_code == "source_absent":
                        self._source_loss()
                        break
                await self._pause(min(0.1, max(0.0, deadline - time.monotonic())))
            else:
                if not self._stopped.is_set():
                    self._lost_readiness(self._read_snapshot())
            logger.warning(
                "Capture source {interface} not ready: {reason}",
                interface=self.config.interface,
                reason=self.snapshot.reason_code,
            )
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
                await self._reap_once()
        return False

    async def run(self) -> None:
        try:
            if not await self.start():
                return
            while not self._stopped.is_set():
                snapshot = self._read_snapshot()
                source_absent = not _interface_exists(self.config.interface)
                if (
                    self.adapter is None
                    or self.adapter.returncode is not None
                    or self.recorder is None
                    or not self.recorder.is_running
                    or snapshot is None
                    or snapshot.state is not SourceState.RECORDING
                    or source_absent
                ):
                    self._lost_readiness(snapshot, source_absent=source_absent)
                    if (
                        self.snapshot.source_state is not SourceState.BLOCKED
                        and self._recording_since is not None
                        and time.monotonic() >= self._recording_since + self._budget.stable_reset_seconds
                    ):
                        self._attempts = 0
                        self._source_loss()
                    logger.warning(
                        "Capture source {interface} {state}: producer readiness lost ({reason})",
                        interface=self.config.interface,
                        state=self.snapshot.source_state.value,
                        reason=self.snapshot.reason_code,
                    )
                    break
                await self._pause(0.25)
        except asyncio.CancelledError:
            raise
        except Exception as error:
            reason = "privilege_denied" if isinstance(error, PermissionError) else "dependency_unavailable"
            self._status(SourceState.BLOCKED, reason)
            logger.warning(
                "Capture source {interface} blocked: {reason}", interface=self.config.interface, reason=reason
            )
        finally:
            self._recording_since = None
            await self._reap_once()

    async def stop(self) -> None:
        self._stopped.set()
        self._retry_at = None
        if self._stop_task is None:
            self._stop_task = asyncio.create_task(self._reap_once())
        await asyncio.shield(self._stop_task)

    async def _reap_once(self) -> None:
        if self._reap_task is None:
            self._reap_task = asyncio.create_task(self._reap())
        await asyncio.shield(self._reap_task)

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
                self._status(SourceState.BLOCKED, "dependency_unavailable")
                logger.warning("Capture child cleanup did not complete normally.")
        finally:
            self.adapter = None
            self.recorder = None
            self._ready = False
            Path(ADAPTER_SNAPSHOT_PATH).unlink(missing_ok=True)
