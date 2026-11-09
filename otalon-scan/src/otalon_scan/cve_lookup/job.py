"""Async job wrapper + task registry around ``run_lookup`` (SCAN-026 WA.3).

The CVE lookup is promoted from a synchronous proxy call into a tracked
async **job** (design.md § D2, Fork 2b). This module owns the in-process
machinery that mirrors the scan ``ModuleManager`` pattern — a running
:class:`asyncio.Task` plus a per-``job_id`` progress bus — **without**
reaching for FastAPI ``BackgroundTasks`` (which offers neither a progress
stream nor a registry lookup for the List/Detail/SSE surface).

The pure, stateless :func:`~otalon_scan.cve_lookup.core.run_lookup` is the
**unchanged** job body. The wrapper around it:

1. transitions the already-created ``cve_lookups`` record to ``running``
   (the record is created by the API layer via ``start_lookup`` so the
   ``job_id`` is known before the task is registered);
2. registers a tracked :class:`asyncio.Task` under ``job_id``;
3. calls ``run_lookup`` **exactly once** over the eligible asset set and
   publishes one ``progress`` event per asset onto the progress bus;
4. upserts the hits via the existing Feature-3 upsert
   (:class:`~otalon_scan.repositories.vulnerability_observation_repo.VulnerabilityObservationRepo`);
5. finalizes the record (``completed`` / ``failed`` + ``summary`` /
   ``error``) via ``finish_lookup`` and publishes the terminal
   ``done`` / ``failed`` event before closing the bus.

A forced error anywhere in steps 3-4 is caught: the job is finalized as
``failed`` with the error text and a terminal ``failed`` event — **no
exception leaks** out of the task (design.md § D3, CONCEPT §10.3).
"""

from __future__ import annotations

import asyncio
from typing import Any, AsyncIterator, Awaitable, Callable, Dict, List, Optional, Protocol
from uuid import UUID

from loguru import logger

from ..repositories.models import CveLookupStatus
from .core import AssetCves, LookupCancelled, LookupResult, run_lookup
from .sources.base import CveSource, LookupAsset

# SSE event kinds that terminate a lookup stream. ``aborted`` (R-02) is a
# terminal frame alongside ``done`` / ``failed`` so an operator-cancelled
# lookup closes the stream and is retained for late-subscriber replay.
_TERMINAL_EVENTS = ("done", "failed", "aborted")


class _LookupRepo(Protocol):
    """Structural type of the repo methods the job wrapper depends on.

    Lets the wrapper be unit-tested against a fake repo without importing
    the concrete :class:`ScannerPostgresRepo` (which would pull in the
    asyncpg engine).
    """

    async def finish_lookup(
        self,
        lookup_id: Any,
        status: CveLookupStatus,
        summary: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Finalize the job-header record (status/summary/error)."""
        ...


# Callback that persists a finished :class:`LookupResult` and returns the
# number of hits written. The API layer injects the Feature-3 upsert
# (``VulnerabilityObservationRepo.persist_lookup_result``); tests inject a
# fake. Kept as a callable so the wrapper does not import the upsert repo.
PersistCallback = Callable[[str, LookupResult], Awaitable[int]]

# Callback that finalizes the synthetic ``scans`` row that owns the FK for
# the lookup's vulnerability hits. The API layer injects a closure over the
# ``scan_id`` + ``ScannerPostgresRepo.finish_scan``; tests inject a fake.
# The job body invokes it on EVERY terminal branch (done / failed /
# aborted) so the synthetic scan never strands ``running`` — E2E-B1 (the
# success-only ``finish_scan`` left an operator-cancelled scan row stuck
# ``RUNNING``/``finished_at NULL`` forever). Arguments: the terminal status
# string (``"completed"`` / ``"failed"`` / ``"aborted"``) and an optional
# error text. Kept as a callable so the wrapper does not import the scan
# status enum or the concrete repo.
FinalizeScanCallback = Callable[[str, Optional[str]], Awaitable[None]]


class _ProgressBus:
    """Per-job async pub/sub for lookup ``progress`` / terminal events.

    Mirrors :class:`otalon_scan.core.module_manager._ProgressBus` but stays fully
    in-process and event-loop-native (the lookup runs as an asyncio task,
    not a child process, so no multiprocessing forwarder thread is
    needed). One :class:`asyncio.Queue` per ``job_id``; the SSE endpoint
    (Welle B) subscribes and consumes until the terminal sentinel
    (``None``) arrives.
    """

    def __init__(self) -> None:
        self._queues: Dict[str, "asyncio.Queue[Optional[Dict[str, Any]]]"] = {}
        # Last terminal (``done`` / ``failed``) event per ``job_id``,
        # retained after the queue closes so a late SSE subscriber (one
        # that connects after the job already finished) can still be
        # handed the terminal event by replay (D5 — the global
        # notification layer must never miss a completion).
        self._terminal: Dict[str, Dict[str, Any]] = {}

    def register(self, job_id: str) -> "asyncio.Queue[Optional[Dict[str, Any]]]":
        """Create or return the async queue backing ``job_id``."""
        q = self._queues.get(job_id)
        if q is None:
            q = asyncio.Queue()
            self._queues[job_id] = q
        return q

    def emit(self, job_id: str, event: Dict[str, Any]) -> None:
        """Publish one event dict onto ``job_id``'s queue (non-blocking).

        Terminal (``done`` / ``failed`` / ``aborted``) events are
        additionally retained in :attr:`_terminal` so they survive the
        queue close and can be replayed to a late subscriber.
        """
        if event.get("event") in _TERMINAL_EVENTS:
            self._terminal[job_id] = event
        self.register(job_id).put_nowait(event)

    def terminal_event(self, job_id: str) -> Optional[Dict[str, Any]]:
        """Return the retained terminal event for ``job_id`` (or ``None``)."""
        return self._terminal.get(job_id)

    def has_live_queue(self, job_id: str) -> bool:
        """Whether an open (not-yet-closed) queue exists for ``job_id``."""
        return job_id in self._queues

    def close(self, job_id: str) -> None:
        """Emit the terminal sentinel and forget the subscription."""
        q = self._queues.pop(job_id, None)
        if q is not None:
            q.put_nowait(None)

    async def subscribe(self, job_id: str) -> AsyncIterator[Dict[str, Any]]:
        """Yield event dicts for ``job_id`` until the sentinel arrives."""
        q = self.register(job_id)
        while True:
            item = await q.get()
            if item is None:
                return
            yield item


class LookupJobRegistry:
    """In-process registry of running CVE-lookup jobs (WA.3, Fork 2b).

    Owns the running :class:`asyncio.Task` per ``job_id`` and the
    :class:`_ProgressBus` the SSE endpoint subscribes to. Analogous to the
    scan ``ModuleManager`` task/progress-bus split, but for the
    single-call ``run_lookup`` job body.
    """

    def __init__(self) -> None:
        self._tasks: Dict[str, "asyncio.Task[None]"] = {}
        # Per-job cancellation flags (R-02). A flag is set by
        # :meth:`request_cancel` and polled cooperatively by the lookup
        # core between assets, so an in-flight sweep stops issuing further
        # NVD queries at the next iteration boundary.
        self._cancelled: set[str] = set()
        self.progress_bus = _ProgressBus()

    def active_job_ids(self) -> List[str]:
        """Return the ids of jobs with a live (not-yet-done) task."""
        return [jid for jid, task in self._tasks.items() if not task.done()]

    def is_active(self, job_id: UUID | str) -> bool:
        """Whether ``job_id`` has a live (not-yet-done) task in flight."""
        task = self._tasks.get(str(job_id))
        return task is not None and not task.done()

    def request_cancel(self, job_id: UUID | str) -> bool:
        """Flag ``job_id`` for cooperative cancellation (R-02).

        Sets the per-job cancel flag the lookup core polls between assets
        AND hard-cancels the in-flight :class:`asyncio.Task`. The flag
        alone covers a multi-asset sweep (the next iteration boundary
        raises :class:`LookupCancelled`); ``task.cancel()`` additionally
        interrupts a long single in-flight NVD ``await`` — a single-asset
        lookup whose one query is slow (NVD rate-limit) has no further
        iteration boundary, so without the task-cancel Stop would block
        until the query returns on its own. The job body catches both the
        flag-driven :class:`LookupCancelled` and the
        :class:`asyncio.CancelledError` and finalizes the job as
        ``aborted``.

        Returns ``True`` when a live task was flagged, ``False`` when the
        job is unknown or already finished (nothing to cancel).

        Args:
            job_id: The lookup job id to cancel.

        Returns:
            ``True`` if a live task was flagged for cancellation.
        """
        jid = str(job_id)
        task = self._tasks.get(jid)
        if task is None or task.done():
            return False
        self._cancelled.add(jid)
        task.cancel()
        return True

    async def await_cancelled(self, job_id: UUID | str, *, timeout: float = 5.0) -> bool:
        """Await the cancelled task's terminal finalization (E2E-B1).

        After :meth:`request_cancel` issues ``task.cancel()`` the abort path
        still has to run its shielded DB finalization (``cve_lookups`` +
        synthetic ``scans`` row → ``aborted``) and release its DB
        session/connection back to the pool. The ``/stop`` endpoint awaits
        this so it returns only once the task has actually finished — the
        terminal state is durably persisted and no connection lingers
        checked out (the previous fire-and-forget cancel left the row
        ``running`` and could strand a connection, the event-loop-block
        symptom).

        Never re-raises the task's ``CancelledError`` (the job body already
        catches it and finalizes as ``aborted``); a timeout is swallowed so
        a pathologically slow finalization cannot wedge the endpoint.

        Args:
            job_id: The lookup job id whose cancelled task to await.
            timeout: Max seconds to wait for finalization (default 5.0).

        Returns:
            ``True`` when the task finished within ``timeout``; ``False`` on
            timeout (or when there was no task to await).
        """
        task = self._tasks.get(str(job_id))
        if task is None or task.done():
            return task is not None
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=timeout)
        except asyncio.CancelledError:
            return True
        except asyncio.TimeoutError:
            return False
        except Exception:  # noqa: BLE001 — job body owns its terminal status
            return True
        return True

    async def stream_events(self, job_id: UUID | str) -> AsyncIterator[Dict[str, Any]]:
        """Yield SSE events for ``job_id``, replaying the terminal on a miss.

        The SSE endpoint (WB.2) consumes this. While the job is live the
        progress bus drives the stream (``progress`` events followed by
        the terminal ``done`` / ``failed`` event). If the client connects
        **after** the job already finished — the queue is gone — the
        retained terminal event is replayed once so the global
        notification layer (UI-051) never misses a completion (design.md
        § D5). A job id that was never seen yields nothing (the endpoint
        has already 404'd on the unknown id).

        Args:
            job_id: The lookup job id to stream events for.

        Yields:
            Event dicts in the ``{"event": ..., "data": ...}`` shape the
            scan SSE endpoint also emits.
        """
        jid = str(job_id)
        if self.progress_bus.has_live_queue(jid):
            saw_terminal = False
            async for event in self.progress_bus.subscribe(jid):
                if event.get("event") in _TERMINAL_EVENTS:
                    saw_terminal = True
                yield event
            if saw_terminal:
                return
        # No live queue (job already finished before connect) OR the live
        # stream closed without a terminal frame (a tight close-vs-connect
        # race) — replay the retained terminal once so the notification
        # layer never misses the completion (design.md § D5).
        terminal = self.progress_bus.terminal_event(jid)
        if terminal is not None:
            yield terminal

    def start(
        self,
        *,
        job_id: UUID | str,
        assets: List[LookupAsset],
        source: CveSource,
        repo: _LookupRepo,
        persist: PersistCallback,
        finalize_scan: FinalizeScanCallback,
        api_key_used: bool,
    ) -> "asyncio.Task[None]":
        """Register and start the async lookup job task for ``job_id``.

        The ``cve_lookups`` record already exists (``running``) — the API
        layer created it so the ``job_id`` is known before registration.
        Returns the tracked task so callers (and tests) can await it.

        Args:
            job_id: The lookup job UUID (already persisted as ``running``).
            assets: The eligible assets to look up (already scoped).
            source: The CVE provider passed verbatim to ``run_lookup``.
            repo: Repo exposing ``finish_lookup`` for finalization.
            persist: Callback that upserts the result and returns the
                number of hits written.
            finalize_scan: Callback that finalizes the synthetic ``scans``
                row on every terminal branch (E2E-B1).
            api_key_used: Whether the source carried an API key — copied
                into the job ``summary`` for the V2 rate-limit box.
        """
        jid = str(job_id)
        # Eagerly register the progress queue so a subscriber connecting
        # between dispatch and the first emit still sees a live queue
        # (otherwise it would wrongly take the terminal-replay path).
        self.progress_bus.register(jid)
        task = asyncio.ensure_future(
            self._run(
                job_id=jid,
                assets=assets,
                source=source,
                repo=repo,
                persist=persist,
                finalize_scan=finalize_scan,
                api_key_used=api_key_used,
            )
        )
        self._tasks[jid] = task

        def _forget(_task: "asyncio.Task[None]") -> None:
            self._tasks.pop(jid, None)

        task.add_done_callback(_forget)
        return task

    async def _run(
        self,
        *,
        job_id: str,
        assets: List[LookupAsset],
        source: CveSource,
        repo: _LookupRepo,
        persist: PersistCallback,
        finalize_scan: FinalizeScanCallback,
        api_key_used: bool,
    ) -> None:
        """Job body: run the lookup once, persist, finalize — no leak.

        Calls :func:`run_lookup` exactly once, publishes one ``progress``
        event per asset, upserts the hits, and finalizes BOTH the
        ``cve_lookups`` job-header AND the synthetic ``scans`` row with a
        terminal ``done`` / ``failed`` / ``aborted`` event. Any exception
        is caught and turned into a ``failed`` finalization so the task
        never raises (design.md § D3); an operator Stop is finalized as
        ``aborted`` (E2E-B1) so neither row strands ``running``.
        """
        bound = logger.bind(op="cve_lookup_job", job_id=job_id)
        try:
            result = await run_lookup(
                assets,
                source,
                should_cancel=lambda: job_id in self._cancelled,
                on_asset=lambda index, total, asset: self._publish_asset(job_id, index, total, asset),
            )
            written = await persist(job_id, result)
            summary = _build_summary(
                assets=assets,
                result=result,
                api_key_used=api_key_used,
                hits_written=written,
            )
            await repo.finish_lookup(job_id, CveLookupStatus.COMPLETED, summary=summary)
            await finalize_scan(CveLookupStatus.COMPLETED.value, None)
            self.progress_bus.emit(
                job_id,
                {
                    "event": "done",
                    "data": {
                        "job_id": job_id,
                        "status": CveLookupStatus.COMPLETED.value,
                        "cves_found": result.total_hits,
                        "critical": summary["critical"],
                    },
                },
            )
            bound.info(
                "cve_lookup job completed assets={} hits={} written={}",
                result.assets_checked,
                result.total_hits,
                written,
            )
        except (LookupCancelled, asyncio.CancelledError):
            # R-02: operator-requested Stop. Two cancellation paths converge
            # here — the flag-driven ``LookupCancelled`` (multi-asset, raised
            # at an iteration boundary) and ``asyncio.CancelledError`` from
            # ``task.cancel()`` interrupting a single long in-flight NVD
            # ``await``. Only treat the latter as an abort when the operator
            # actually requested it; an unexpected cancel (e.g. event-loop
            # shutdown) is re-raised so it is not silently swallowed.
            if job_id not in self._cancelled:
                raise
            bound.info("cve_lookup job aborted by operator request")
            await self._finalize_aborted(job_id, repo, finalize_scan, bound)
        except Exception as exc:  # noqa: BLE001 — failure becomes job status, never a leak
            error_text = f"{type(exc).__name__}: {exc}"
            bound.error("cve_lookup job failed: {}", error_text)
            await repo.finish_lookup(job_id, CveLookupStatus.FAILED, error=error_text)
            await finalize_scan(CveLookupStatus.FAILED.value, error_text)
            self.progress_bus.emit(
                job_id,
                {
                    "event": "failed",
                    "data": {
                        "job_id": job_id,
                        "status": CveLookupStatus.FAILED.value,
                        "error": error_text,
                    },
                },
            )
        finally:
            self._cancelled.discard(job_id)
            self.progress_bus.close(job_id)

    async def _finalize_aborted(
        self,
        job_id: str,
        repo: _LookupRepo,
        finalize_scan: FinalizeScanCallback,
        bound: Any,
    ) -> None:
        """Finalize a cancelled job as ``aborted`` + emit the terminal event.

        Finalizes BOTH the ``cve_lookups`` job-header AND the synthetic
        ``scans`` row to ``aborted`` (E2E-B1: the scan row previously
        stranded ``running`` because the success-only ``finish_scan`` was
        never reached on the cancel path).

        Both DB writes are wrapped in :func:`asyncio.shield` because this
        runs on the abort path where the task was ``task.cancel()``-ed:
        without the shield a write could itself be interrupted by a second
        ``CancelledError``, leaving a row stuck ``running`` AND a connection
        checked out of the pool (the event-loop-block symptom). The shield
        lets each write run to completion so its DB session/connection is
        always released back to the pool.
        """
        try:
            await asyncio.shield(
                repo.finish_lookup(
                    job_id,
                    CveLookupStatus.ABORTED,
                    error="Cancelled by operator",
                )
            )
        except Exception as exc:  # noqa: BLE001 — never let finalization leak
            bound.error("cve_lookup abort finalization failed: {}", exc)
        try:
            await asyncio.shield(finalize_scan(CveLookupStatus.ABORTED.value, "Cancelled by operator"))
        except Exception as exc:  # noqa: BLE001 — never let finalization leak
            bound.error("cve_lookup abort scan finalization failed: {}", exc)
        self.progress_bus.emit(
            job_id,
            {
                "event": "aborted",
                "data": {
                    "job_id": job_id,
                    "status": CveLookupStatus.ABORTED.value,
                },
            },
        )

    def _publish_asset(self, job_id: str, index: int, total: int, asset: AssetCves) -> None:
        """Emit one ``progress`` event for a freshly looked-up asset.

        Invoked from :func:`run_lookup` via the ``on_asset`` callback as
        each asset resolves, so progress is streamed **live** during the
        NVD sweep (rather than as a post-hoc burst). This also gives the
        cooperative-cancellation path (R-02) meaningful per-asset
        progress up to the point Stop was pressed.
        """
        self.progress_bus.emit(
            job_id,
            {
                "event": "progress",
                "data": {
                    "job_id": job_id,
                    "device_id": asset.device_id,
                    "cve_count": len(asset.hits),
                    "index": index,
                    "total": total,
                },
            },
        )


def _build_summary(
    *,
    assets: List[LookupAsset],
    result: LookupResult,
    api_key_used: bool,
    hits_written: int,
) -> Dict[str, Any]:
    """Assemble the CONCEPT §6 job ``summary`` jsonb payload.

    Shape: ``{assets_scanned, cves_found, critical, per_asset:[{device_id,
    ip, cve_count}], rate_limit_hits}``. ``ip`` is not carried by
    :class:`LookupAsset`, so it is emitted as ``None`` here (the SSE/UI
    layer enriches it from the device record). ``rate_limit_hits`` is 0
    when an API key was supplied; it stays a best-effort placeholder until
    the source surfaces real backoff counters.
    """
    critical = sum(1 for a in result.per_asset for h in a.hits if h.severity.lower() == "critical")
    per_asset = [{"device_id": asset.device_id, "ip": None, "cve_count": len(asset.hits)} for asset in result.per_asset]
    return {
        "assets_scanned": result.assets_checked,
        "cves_found": result.total_hits,
        "critical": critical,
        "hits_written": hits_written,
        "per_asset": per_asset,
        "rate_limit_hits": 0 if api_key_used else None,
    }
