"""Bounded local owners. Collector receipt is not authenticated publication proof."""

from __future__ import annotations

import asyncio
import errno
import socket
import ssl
from time import monotonic

from loguru import logger
from urllib3.exceptions import MaxRetryError, NewConnectionError, ReadTimeoutError, SSLError

from capture_runtime import CaptureBackend, CaptureIntent, CaptureSnapshot, RetryBudget, SourceState


def classify_failure(error):
    """Only explicit transport unavailability is retryable, never generic IO errors."""
    cause = error.reason if isinstance(error, MaxRetryError) else error
    nested = cause
    for _ in range(8):
        if nested is None:
            break
        if isinstance(nested, (PermissionError, ssl.SSLError, SSLError)):
            return False, "privilege_denied" if isinstance(nested, PermissionError) else "upstream_unavailable"
        if isinstance(nested, socket.gaierror) and nested.errno != socket.EAI_AGAIN:
            return False, "upstream_unavailable"
        if (
            isinstance(nested, OSError)
            and not isinstance(nested, socket.gaierror)
            and nested.errno
            not in {
                errno.ECONNREFUSED,
                errno.ECONNRESET,
                errno.ETIMEDOUT,
                errno.EHOSTUNREACH,
                errno.ENETUNREACH,
            }
        ):
            return False, "upstream_unavailable"
        if nested is not cause and not isinstance(nested, (OSError, NewConnectionError, ReadTimeoutError)):
            return False, "upstream_unavailable"
        nested = getattr(nested, "__cause__", None)
    else:
        return False, "upstream_unavailable"
    if isinstance(cause, (NewConnectionError, ReadTimeoutError)):
        return True, "dependency_unavailable"
    if isinstance(error, PermissionError):
        return False, "privilege_denied"
    if type(error) is ValueError:
        if str(error) in {
            "checkpoint configuration mismatch",
            "checkpoint timestamp contract mismatch; legacy carry requires explicit reconciliation",
        }:
            return False, "checkpoint_incompatible"
        if str(error) in {"custody bytes changed", "point identity conflict", "preparation cursor conflict"}:
            return False, "custody_invalid"
    return False, "upstream_unavailable"


class CollectorFreshness:
    """Five local checks per loss episode; only accepted observations wake idle."""

    def __init__(self, ledger):
        self.ledger = ledger
        self.policy = RetryBudget()
        self.changed = asyncio.Event()
        self.stopping = False
        self.attempts = 0
        self.retry_exhausted = False
        self.retry_at = None
        self.present = False
        self.ever_present = False
        self.stable_since = None
        self.last_receipt = None

    @property
    def snapshot(self):
        age = self.ledger.observation_age_seconds()
        fresh = age is not None and age < 6
        return CaptureSnapshot(
            CaptureIntent.LIVE,
            CaptureBackend.WSL,
            SourceState.DEGRADED if self.ever_present else SourceState.WAITING,
            None if fresh else "collector_stale",
            self.attempts,
            5,
            max(0.0, self.retry_at - monotonic()) if self.retry_at is not None else None,
            self.retry_exhausted if not fresh else False,
            age,
        )

    async def _wait(self, delay):
        try:
            if delay is None:
                await self.changed.wait()
            else:
                await asyncio.wait_for(self.changed.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    async def stop(self):
        self.stopping = True
        self.changed.set()

    async def run(self):
        loop = asyncio.get_running_loop()

        def accepted():
            now = monotonic()
            if self.last_receipt is not None and now - self.last_receipt >= 6:
                self.stable_since = now
            self.last_receipt = now
            loop.call_soon_threadsafe(self.changed.set)

        with self.ledger.lock:
            self.ledger._observation_listener = accepted
        try:
            while not self.stopping:
                self.changed.clear()
                age = self.ledger.observation_age_seconds()
                if age is not None and age < 6:
                    self.last_receipt = monotonic() - age
                    if not self.present:
                        self.present = self.ever_present = True
                        self.stable_since = monotonic()
                        logger.warning("Collector restored reason=collector_stale")
                    if self.stable_since is not None and monotonic() - self.stable_since >= 60:
                        self.attempts = 0
                        self.retry_exhausted = False
                        self.stable_since = None
                        logger.warning("Collector reset reason=collector_stale")
                    self.retry_at = None
                    await self._wait(6 - age)
                    continue
                if self.present:
                    self.present = False
                    self.stable_since = None
                    if self.attempts:
                        logger.warning("Collector first_failure reason=collector_stale")
                if self.attempts == 0:
                    self.attempts = 1
                    logger.warning("Collector first_failure reason=collector_stale attempt=1")
                if self.attempts >= self.policy.retry_limit:
                    if not self.retry_exhausted:
                        self.retry_exhausted = True
                        logger.warning("Collector exhausted reason=retry_exhausted attempt=5")
                    self.retry_at = None
                    await self._wait(None)
                    continue
                delay = self.policy.delay_before(self.attempts + 1)
                self.retry_at = monotonic() + delay
                logger.warning(
                    "Collector scheduled reason=collector_stale attempt={} delay={}", self.attempts + 1, delay
                )
                await self._wait(delay)
                self.retry_at = None
                if not self.stopping and not self.changed.is_set():
                    self.attempts += 1
        finally:
            self.retry_at = None
            with self.ledger.lock:
                if self.ledger._observation_listener is accepted:
                    self.ledger._observation_listener = None


class ProcessorOwner:
    """One returned instance and one joined thread operation at a time.

    Thread cancellation cannot stop a native constructor or client call. We join
    its result before cleanup, rather than race close or abandon returned owners.
    The read-only pipeline must supply any stronger native-call/cleanup bounds.
    """

    def __init__(self, settings, ledger, refresh_index):
        self.settings, self.ledger, self.refresh_index = settings, ledger, refresh_index
        self.policy = RetryBudget()
        self.collector = None
        self.stop_event = asyncio.Event()
        self.attempts = 0
        self.retry_exhausted = False
        self.retry_at = None
        self.processor_state = "waiting"
        self.reason = None
        self.error_class = None
        self.usable = False
        self.ever_usable = False
        self.stable_since = None
        self.last_usable = None
        self.pipeline = None
        self._work_task = None

    @property
    def snapshot(self):
        observation = self.ledger.observation()
        age = self.ledger.observation_age_seconds()
        state = SourceState.DEGRADED if self.ever_usable else SourceState.WAITING
        reason = self.reason
        if self.processor_state == "blocked":
            state = SourceState.BLOCKED
        elif self.usable and observation and observation.get("recording") is True:
            state, reason = SourceState.RECORDING, None
        elif self.usable:
            reason = "collector_stale" if observation is None else None
        return CaptureSnapshot(
            CaptureIntent.LIVE,
            CaptureBackend.WSL,
            state,
            reason,
            self.attempts,
            5,
            max(0.0, self.retry_at - monotonic()) if self.retry_at is not None else None,
            self.retry_exhausted,
            age,
        )

    async def _pause(self, delay):
        try:
            if delay is None:
                await self.stop_event.wait()
            else:
                await asyncio.wait_for(self.stop_event.wait(), timeout=delay)
        except asyncio.TimeoutError:
            pass

    async def _work(self, function, *args):
        task = self._work_task = asyncio.create_task(asyncio.to_thread(function, *args))
        cancelled = False
        try:
            while True:
                try:
                    result = await asyncio.shield(task)
                    break
                except asyncio.CancelledError:
                    if task.cancelled():
                        raise
                    cancelled = True
                    self.stop_event.set()
            # A returned constructor is retained even if cancellation arrived.
            if cancelled:
                self.stop_event.set()
            return result
        finally:
            self._work_task = None

    def _failure(self, error, *, dependency=True):
        retry, reason = classify_failure(error)
        self.reason = reason if dependency else "custody_invalid"
        name = type(error).__name__
        self.error_class = (
            name
            if name
            in {
                "NewConnectionError",
                "NameResolutionError",
                "ReadTimeoutError",
                "MaxRetryError",
                "PermissionError",
                "OSError",
                "ValueError",
                "RuntimeError",
                "HTTPStatusError",
                "ApiException",
                "IntegrityError",
                "OperationalError",
                "JSONDecodeError",
            }
            else "Exception"
        )
        self.usable = False
        if self.stable_since is not None and self.last_usable - self.stable_since >= 60:
            self.attempts = 0
            logger.warning("Processor reset reason=dependency_unavailable")
        self.stable_since = None
        self.last_usable = None
        self.processor_state = ("degraded" if self.ever_usable else "waiting") if retry and dependency else "blocked"
        logger.warning(
            "Processor {} reason={} exception={} attempt={}",
            "first_failure" if self.attempts <= 1 else "failure",
            self.reason,
            self.error_class,
            self.attempts,
        )
        if self.processor_state == "blocked":
            logger.warning("Processor blocked reason={} exception={}", self.reason, self.error_class)

    def _schedule(self):
        delay = self.policy.delay_before(self.attempts + 1)
        self.retry_at = monotonic() + delay
        logger.warning("Processor scheduled reason={} attempt={} delay={}", self.reason, self.attempts + 1, delay)
        return delay

    async def _close(self):
        pipeline, self.pipeline = self.pipeline, None
        self.usable = False
        if pipeline is not None:
            try:
                await self._work(pipeline.close)
            except Exception as error:
                self._failure(error, dependency=False)

    async def run(self):
        try:
            from .pipeline import ContinuousPipeline

            while not self.stop_event.is_set():
                if self.processor_state == "blocked" or self.retry_exhausted:
                    await self._pause(None)
                    continue
                if self.pipeline is None:
                    if self.attempts:
                        await self._pause(self._schedule())
                        self.retry_at = None
                        if self.stop_event.is_set():
                            break
                    self.attempts += 1
                    try:
                        began = monotonic()
                        self.pipeline = await self._work(ContinuousPipeline, self.settings, self.ledger)
                        if monotonic() - began >= self.policy.readiness_timeout_seconds:
                            self._failure(RuntimeError("readiness deadline"))
                            await self._close()
                            continue
                    except Exception as error:
                        self._failure(error)
                        if self.attempts >= 5 and self.processor_state != "blocked":
                            self.retry_exhausted = True
                            self.reason = "retry_exhausted"
                            logger.warning("Processor exhausted reason=retry_exhausted attempt=5")
                        continue
                if self.stop_event.is_set():
                    break
                try:
                    await self._work(self.refresh_index)
                except Exception as error:
                    self._failure(error, dependency=False)
                    await self._close()
                    continue
                if self.stop_event.is_set():
                    break
                try:
                    worked = await self._work(self.pipeline.process_one)
                except Exception as error:
                    self._failure(error)
                    await self._close()
                    if self.attempts >= 5 and self.processor_state != "blocked":
                        self.retry_exhausted = True
                        self.reason = "retry_exhausted"
                        logger.warning("Processor exhausted reason=retry_exhausted attempt=5")
                    continue
                self.usable = self.ever_usable = True
                self.processor_state = "usable"
                self.error_class = self.reason = None
                if self.stable_since is None:
                    self.stable_since = monotonic()
                self.last_usable = monotonic()
                await self._pause(0.1 if worked else 1.0)
        except asyncio.CancelledError:
            self.stop_event.set()
            raise
        except Exception as error:
            self._failure(error, dependency=False)
            await self._pause(None)
        finally:
            self.retry_at = None
            await self._close()
