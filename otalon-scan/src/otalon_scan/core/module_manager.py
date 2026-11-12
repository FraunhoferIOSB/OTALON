"""Module manager for CyberScan-ICS — orchestrator that owns persistence.

Responsibilities:

- Discovering available :class:`~otalon_scan.core.protocols.ScanModule` implementations on disk
- Validating module conformance at load time (D2: runtime ``isinstance`` against
  the ``@runtime_checkable`` Protocol)
- Spawning each scan in a separate process for isolation
- Iterating the module's ``scan(config)`` async generator and accumulating
  :class:`~otalon_scan.core.models.ScanResult` / :class:`~otalon_scan.core.models.ScanProgress`
  events
- Routing the terminal :class:`~otalon_scan.core.models.ScanResult` back to the parent
  process via a shared dict and invoking ``_persist_batch`` (the single commit
  boundary — HC6 / HC16 seam)

Modules MUST NOT open database connections themselves; this class is the
sole writer to the scan-result tables.
"""

from __future__ import annotations

import asyncio
import importlib
import importlib.util
import multiprocessing
import os
import queue
import signal
import sys
import threading
from dataclasses import dataclass
from pathlib import Path
from typing import Any, AsyncIterator, Callable, Dict, List, Optional, Tuple, Union
from uuid import uuid4

import psutil
from loguru import logger
from pydantic import ValidationError

from .config_utils import load_json, merge_configurations
from .log_config import setup_logging
from .models import DeviceFinding, ScanConfig, ScanProgress, ScanResult
from .module_config import config_schema_for_module
from .protocols import ScanModule, ScanModuleError

# Default commit batch size (decision D3, default 100). Configurable via the
# ``SCAN_PERSIST_BATCH_SIZE`` env var — Phase 2 keeps the seam ready for
# Phase 5 (HC16) batched-commit measurement.
DEFAULT_BATCH_SIZE = 100

# Sentinel placed on the IPC queue by the child once iteration ends, so the
# parent-side forwarder thread can complete its scan-bound subscription.
_PROGRESS_DONE: Dict[str, Any] = {"__type__": "__done__"}

# L-01: bound on the per-scan SSE replay buffer (see :class:`_ProgressBus`).
# A late-joining subscriber replays at most this many recent events; the
# terminal sentinel is always retained. Generous enough for a /24 ARP sweep
# (~254 host events) without unbounded growth on a pathological flood.
_REPLAY_BUFFER_MAX = 512


@dataclass(frozen=True)
class ModuleInfo:
    """Metadata for a discovered module."""

    start_path: str
    config_path: str


def _is_scan_module_class(cls: Any) -> bool:
    """Return True if ``cls`` is a class whose instance conforms to :class:`ScanModule`.

    Equivalent to ``isinstance(cls(), ScanModule)`` but without instantiating —
    we check for the presence of the ``name`` attribute and the ``scan``
    method on the class itself.
    """
    if not isinstance(cls, type):
        return False
    return hasattr(cls, "name") and hasattr(cls, "scan") and callable(getattr(cls, "scan", None))


def _get_scan_module_class(mod: Any) -> Optional[type]:
    """Return the first class in ``mod`` that looks like a :class:`ScanModule`."""
    for attr_name in dir(mod):
        if attr_name.startswith("_"):
            continue
        attr = getattr(mod, attr_name)
        if isinstance(attr, type) and _is_scan_module_class(attr):
            return attr
    return None


class _ProgressBus:
    """Per-scan async pub/sub for :class:`ScanProgress` events.

    The bus is owned by the parent process. Scan modules run in child
    processes and emit progress events into a :class:`multiprocessing.Queue`
    that a parent-side daemon forwarder thread drains and fans out onto the
    per-subscriber :class:`asyncio.Queue` instances registered against the
    FastAPI event loop.

    Subscribers (e.g. the SSE endpoint ``GET /scans/{scan_id}/events``)
    call :meth:`subscribe` and consume the async iterator until the
    terminal sentinel arrives.

    The bus is **multi-subscriber** per scan (L-01 fix): every concurrent
    SSE client for the same ``scan_id`` receives every event independently.
    The UI opens two streams for a running scan — the run-modal's
    :func:`useJobStream` and the global ``JobNotificationListener`` — so a
    single-subscriber queue would split events between them and strand the
    modal in "Running" forever (the terminal ``result`` frame going to only
    one of the two consumers). A bounded per-scan replay buffer additionally
    lets a late-joining subscriber catch up on events emitted before it
    connected (e.g. a fast ``pn_discovery`` that finishes within a few
    hundred ms of the modal opening its stream).
    """

    def __init__(self) -> None:
        self._loop: Optional[asyncio.AbstractEventLoop] = None
        # scan_id -> list of live per-subscriber queues (fan-out targets).
        self._subscribers: Dict[str, List[asyncio.Queue[Optional[Dict[str, Any]]]]] = {}
        # scan_id -> ordered replay buffer of items already published, so a
        # late subscriber can be brought up to date. ``None`` marks a
        # terminal sentinel already seen for the scan.
        self._replay: Dict[str, List[Optional[Dict[str, Any]]]] = {}
        # scan_ids whose forwarder/stream has reached the terminal sentinel.
        self._terminated: set[str] = set()
        self._lock = threading.Lock()

    def attach_loop(self, loop: asyncio.AbstractEventLoop) -> None:
        """Capture the FastAPI event loop reference at lifespan startup."""
        self._loop = loop

    def has_loop(self) -> bool:
        """True once :meth:`attach_loop` has been called."""
        return self._loop is not None

    def _fanout(self, scan_id: str, item: Optional[Dict[str, Any]]) -> None:
        """Append ``item`` to the replay buffer and push it to all subscribers.

        ``None`` is the terminal sentinel: it is delivered to every live
        subscriber and recorded so any subsequent subscriber terminates
        immediately after replay. Must run on the event-loop thread (callers
        marshal via ``call_soon_threadsafe``).
        """
        with self._lock:
            buf = self._replay.setdefault(scan_id, [])
            buf.append(item)
            # Cap the replay buffer so a pathological flood cannot grow it
            # unbounded; the terminal sentinel is always retained.
            if len(buf) > _REPLAY_BUFFER_MAX:
                del buf[0 : len(buf) - _REPLAY_BUFFER_MAX]
            if item is None:
                self._terminated.add(scan_id)
            subscribers = list(self._subscribers.get(scan_id, ()))
        for q in subscribers:
            q.put_nowait(item)

    def register(self, scan_id: str) -> asyncio.Queue[Optional[Dict[str, Any]]]:
        """Register a fresh per-subscriber async queue for ``scan_id``.

        Each call returns a distinct queue (fan-out). The new queue is
        primed with the current replay buffer so a late subscriber sees the
        events it missed. Must be called from the event loop thread.
        """
        q: asyncio.Queue[Optional[Dict[str, Any]]] = asyncio.Queue()
        with self._lock:
            for past in self._replay.get(scan_id, ()):  # replay history
                q.put_nowait(past)
            self._subscribers.setdefault(scan_id, []).append(q)
        return q

    def unsubscribe(self, scan_id: str, q: "asyncio.Queue[Optional[Dict[str, Any]]]") -> None:
        """Drop a subscriber queue obtained from :meth:`register`.

        Public counterpart to :meth:`register` for consumers that drive the
        queue directly (e.g. the SSE endpoint's idle-timeout loop, SC-04)
        instead of iterating :meth:`subscribe`.
        """
        self._unregister(scan_id, q)

    def _unregister(self, scan_id: str, q: "asyncio.Queue[Optional[Dict[str, Any]]]") -> None:
        """Drop a subscriber queue once its iterator is exhausted/cancelled."""
        with self._lock:
            queues = self._subscribers.get(scan_id)
            if queues is not None:
                try:
                    queues.remove(q)
                except ValueError:
                    pass
                if not queues:
                    self._subscribers.pop(scan_id, None)
                    # Once no subscribers remain AND the scan terminated,
                    # drop its replay buffer to bound memory.
                    if scan_id in self._terminated:
                        self._replay.pop(scan_id, None)
                        self._terminated.discard(scan_id)

    def start_forwarder(
        self,
        scan_id: str,
        mp_queue: "multiprocessing.Queue[Any]",
        on_item: Optional[Callable[[Dict[str, Any]], None]] = None,
    ) -> None:
        """Spawn a daemon thread that drains ``mp_queue`` into the per-scan
        async queue. Called from the FastAPI request handler (event-loop
        thread).

        Args:
            scan_id: Persistence scan UUID this stream addresses.
            mp_queue: The child-side multiprocessing queue.
            on_item: Optional side-channel callback invoked with every item
                drained from the queue before it is re-published onto the
                async queue. Used by :class:`ModuleManager` to feed the
                parent-side finding accumulator for HC16 batched commits.
                Callback errors are logged and swallowed; SSE delivery
                continues unaffected.
        """
        if self._loop is None:
            logger.warning(
                "_ProgressBus.start_forwarder: no event loop attached; " "SSE for scan_id={scan_id} will be silent",
                scan_id=scan_id,
            )
            return
        loop = self._loop

        def _drain() -> None:
            try:
                while True:
                    try:
                        item = mp_queue.get(timeout=1.0)
                    except queue.Empty:
                        continue
                    except (OSError, EOFError):
                        # mp manager has shut down — emit terminal sentinel
                        loop.call_soon_threadsafe(self._fanout, scan_id, None)
                        return
                    if item is None or (isinstance(item, dict) and item.get("__type__") == "__done__"):
                        # UI-173: the child's terminal sentinel only marks
                        # end-of-progress-stream. Do NOT fan out ``None`` here
                        # — the stream-close finish signal must wait until
                        # ``_finalize_run`` commits ``last_scan_at`` and then
                        # emits the deferred ``result`` event followed by
                        # ``progress_bus.close``. Closing now would let the UI
                        # treat the scan as finished before the commit.
                        return
                    if on_item is not None:
                        try:
                            on_item(item)
                        except Exception as exc_cb:
                            logger.debug("_ProgressBus._drain on_item callback failed: {exc_cb}", exc_cb=exc_cb)
                    loop.call_soon_threadsafe(self._fanout, scan_id, item)
            except Exception as exc:
                logger.error("_ProgressBus._drain failed for scan_id={scan_id}: {exc}", scan_id=scan_id, exc=exc)
                try:
                    loop.call_soon_threadsafe(self._fanout, scan_id, None)
                except Exception:
                    pass

        t = threading.Thread(target=_drain, name=f"cs-ics-sse-fwd-{scan_id[:8]}", daemon=True)
        t.start()

    async def subscribe(self, scan_id: str) -> AsyncIterator[Dict[str, Any]]:
        """Yield progress event dicts until the terminal sentinel arrives.

        Each call registers an independent fan-out queue, so concurrent SSE
        clients for the same ``scan_id`` (the run-modal stream and the global
        notification listener) each receive every event including the
        terminal ``result``/``final`` frame. The queue is primed with the
        replay buffer so a late subscriber catches up on missed events.

        Args:
            scan_id: Scan identifier returned by ``POST /scans/start``.

        Yields:
            Dicts shaped as ``{"event": "progress"|"result", "data": {...}}``.
        """
        q = self.register(scan_id)
        try:
            while True:
                item = await q.get()
                if item is None:
                    return
                yield item
        finally:
            self._unregister(scan_id, q)

    def emit(self, scan_id: str, event: Dict[str, Any]) -> None:
        """Push a synthesized event onto the bus from the parent process.

        Used to forward the terminal :class:`ScanResult` after persistence
        completes — child-side mp queue may have already been drained by
        the time the SSE consumer connects. Fans out to every subscriber.
        """
        if self._loop is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._fanout, scan_id, event)
        except RuntimeError:
            # Loop closed during shutdown — best effort
            pass

    def close(self, scan_id: str) -> None:
        """Emit the terminal sentinel to every subscriber of ``scan_id``."""
        if self._loop is None:
            return
        try:
            self._loop.call_soon_threadsafe(self._fanout, scan_id, None)
        except RuntimeError:
            pass


class ModuleManager:
    """Manage lifecycle of scanner modules and own all persistence."""

    def __init__(
        self,
        modules_path: str,
        callback: Optional[Callable[[str, str, Any], None]] = None,
        batch_size: Optional[int] = None,
    ) -> None:
        """Initialize the manager.

        Args:
            modules_path: Root directory where modules live. The manager
                looks for subfolders that contain both ``start.py`` and
                ``config.json``.
            callback: Optional callback invoked as ``callback(uid, module_name, raw_results)``
                after a module finishes. Receives the legacy
                ``raw_results`` payload for API-serializer compatibility.
            batch_size: Persistence batch size. Defaults to
                ``SCAN_PERSIST_BATCH_SIZE`` env var or :data:`DEFAULT_BATCH_SIZE`.
        """
        setup_logging()
        self.modules_path = modules_path
        self.modules: Dict[str, ModuleInfo] = self._detect_modules()
        self.running_modules: set[Tuple[str, str, multiprocessing.Process]] = set()
        self.manager = multiprocessing.Manager()
        self.module_results = self.manager.dict()
        self.callback = callback
        self._lock = threading.Lock()

        self.batch_size = batch_size or int(os.environ.get("SCAN_PERSIST_BATCH_SIZE", DEFAULT_BATCH_SIZE))
        # Persistence sink injected by the API layer. Phase 4 (HC5): the sink
        # is invoked synchronously from the monitor thread and dispatches the
        # underlying ``async`` repo call onto the FastAPI event loop via
        # ``asyncio.run_coroutine_threadsafe`` — see ``src/otalon_scan/api/server.py``.
        # None disables persistence (used by tests).
        self._persist_sink: Optional[Callable[[str, List[DeviceFinding], ScanResult], None]] = None
        # F-02 / scan--observability: optional callback fired with the
        # module slug whenever a persistence-related failure happens
        # inside the orchestrator (e.g. ``module_type`` discriminator
        # mismatch in :meth:`_finalize_run`). The API layer wires this
        # to ``PERSISTENCE_ERRORS.labels(module=...).inc()``. ``None``
        # disables the counter (used by tests).
        self._on_persistence_error: Optional[Callable[[str], None]] = None
        # Terminal-status sink (Phase 5 / HC16 / D4). Invoked by
        # :meth:`_finalize_run` to mark the owning :class:`Scan` row with the
        # correct status (``COMPLETED`` / ``FAILED`` / ``ABORTED`` /
        # ``CANCELLED_PARTIAL``). ``None`` disables status updates.
        self._finish_sink: Optional[Callable[[str, str, Optional[str]], None]] = None
        # L-02 findings-snapshot sink. Invoked once by :meth:`_finalize_run`
        # with ``(scan_id, findings)`` — a list of serialised DeviceFinding
        # dicts — so the owning :class:`Scan` row keeps a point-in-time record
        # of what the scan reported (surfaced by the history detail view).
        # ``None`` disables the snapshot (used by tests).
        self._findings_sink: Optional[Callable[[str, List[Dict[str, Any]]], None]] = None

        # SSE progress bus (Mission Q9 prerequisite). One mp queue per scan;
        # the parent-side forwarder is started by ``register_scan_id``.
        self.progress_bus = _ProgressBus()
        # ``run_id`` → ``multiprocessing.Queue`` used by the child to send
        # progress events. Populated in :meth:`start_module`.
        self._progress_mp_queues: Dict[str, "multiprocessing.Queue[Any]"] = {}

        # Phase 5 (HC16) — parent-side finding accumulator for batched
        # commits. The SSE forwarder feeds each progress event with a
        # ``finding`` payload into the buffer for the owning ``run_id``;
        # once the buffer reaches :attr:`batch_size`, ``_persist_batch``
        # flushes it via the registered sink. ``_finalize_run`` drains the
        # remainder (or, per D4, the cancellation handler).
        #
        # Invariant: when the forwarder is wired (i.e. ``register_scan_id``
        # was called for the run) the forwarder is the sole source of
        # findings into the persistence buffer; the terminal
        # ``ScanResult.findings`` payload is ignored in that case to avoid
        # double-writes. When the forwarder is not wired (tests, or when
        # the run completed before the SSE forwarder started), the legacy
        # path falls back to draining ``findings_payload`` directly.
        self._run_buffers: Dict[str, List[DeviceFinding]] = {}
        # Per-run flag: True once the SSE forwarder has been started, so
        # ``_finalize_run`` knows to read findings from ``_run_buffers``
        # rather than from the child's terminal payload.
        self._forwarder_wired: set[str] = set()
        # ``run_id`` set of runs that received an explicit stop request or
        # detected cancellation. Drives the ``CANCELLED_PARTIAL`` vs
        # ``ABORTED`` decision in :meth:`_finalize_run`.
        self._cancelled_runs: set[str] = set()
        # ``run_id`` set of runs that flushed at least one partial batch
        # via the SSE-forwarder accumulator. Combined with cancellation,
        # this picks ``CANCELLED_PARTIAL`` over plain ``ABORTED`` (D4).
        self._partial_flushed_runs: set[str] = set()
        self._buffer_lock = threading.Lock()
        # HC12 (2026-05-18): idempotency set for ``_finalize_run``.
        # The monitor thread and an explicit ``stop_module`` request can
        # race; the contract is "first finalisation wins". A run id added
        # to this set must NOT be finalised again — re-entry logs a
        # warning and returns early, so the persistence sink and the
        # finish sink fire exactly once per run.
        self._finalised_runs: set[str] = set()
        self._finalise_lock = threading.Lock()
        # Module name per run_id, captured at start so the synthetic
        # interim :class:`ScanResult` payloads carry the right metadata.
        self._run_module_name: Dict[str, str] = {}
        # B-E3 (2026-06-04): a fast scan can finish — and the monitor
        # thread can fire :meth:`_finalize_run` — *before* the API handler
        # has called :meth:`register_scan_id` to write the persistence
        # ``scan_id`` into ``module_results``. When that happens the
        # terminal-status sink would address the run UUID instead of the
        # DB scan UUID, the ``finish_scan`` UPDATE no-ops on a missing row,
        # and the scan is stranded at ``status=RUNNING`` even though
        # ``finished_at`` was stamped elsewhere (the ~46 % stuck-RUNNING
        # symptom). To close the race we DEFER finalisation when the
        # scan_id is not yet known: the run is recorded here and
        # :meth:`register_scan_id` re-drives :meth:`_finalize_run` as soon
        # as the DB UUID lands, guaranteeing a terminal transition on the
        # correct row. ``_pending_finalize`` maps run_id → module name.
        self._pending_finalize: Dict[str, str] = {}
        self._pending_finalize_lock = threading.Lock()
        # SCAN-005 (2026-06-13): keep the persistence ``scan_id`` OUT of the
        # ``module_results`` Manager dict. The child module process owns the
        # terminal payload for ``module_results[uid]`` and writes it as a
        # FULL dict replacement (see :meth:`_run_module_proc`), which would
        # clobber a parent-written ``scan_id`` key — stranding the scan at
        # ``status=RUNNING`` because :meth:`_finalize_run` then re-defers
        # forever. We instead hold the mapping in this parent-only dict the
        # child never references, so the terminal payload cannot overwrite
        # it. Guarded by ``_pending_finalize_lock`` so the
        # "scan_id becomes visible" / "pending entry recorded" interleaving
        # with :meth:`_finalize_run` stays mutually exclusive (B-E3).
        self._scan_id_by_uid: Dict[str, str] = {}

    # ---- Persistence wiring ----

    def set_persist_sink(
        self,
        sink: Optional[Callable[[str, List[DeviceFinding], ScanResult], None]],
    ) -> None:
        """Register the persistence callback invoked from ``_persist_batch``.

        The sink receives ``(scan_id, batch, result)`` where ``batch`` is the
        drained device-finding buffer for the current ``_persist_batch`` call
        and ``result`` is the terminal :class:`ScanResult`. The sink owns
        all DB writes; modules MUST NOT.
        """
        self._persist_sink = sink

    def set_persistence_error_callback(
        self,
        callback: Optional[Callable[[str], None]],
    ) -> None:
        """Register the F-02 persistence-error callback.

        Invoked with the module-slug whenever the orchestrator detects a
        persistence-class failure (currently: ``module_type``
        discriminator mismatch). The API layer wires this to the
        ``cyberscan_persistence_errors_total`` Prometheus counter.
        """
        self._on_persistence_error = callback

    def set_finish_sink(
        self,
        sink: Optional[Callable[[str, str, Optional[str]], None]],
    ) -> None:
        """Register the terminal-status callback (Phase 5 / HC16 / D4).

        The sink is called as ``sink(scan_id, status, error_message)`` exactly
        once per scan, from :meth:`_finalize_run`, after the final buffer
        flush. ``status`` is one of ``"completed"``, ``"failed"``,
        ``"aborted"``, ``"cancelled_partial"`` — keep the strings stable;
        the API-layer sink maps them onto the :class:`ScanStatus` enum.
        ``None`` disables terminal-status updates (used by tests).
        """
        self._finish_sink = sink

    def set_findings_sink(
        self,
        sink: Optional[Callable[[str, List[Dict[str, Any]]], None]],
    ) -> None:
        """Register the L-02 findings-snapshot sink.

        Called as ``sink(scan_id, findings)`` once per scan from
        :meth:`_finalize_run`, where ``findings`` is the list of serialised
        ``DeviceFinding`` dicts the run reported. The API layer wires this to
        persist the snapshot onto the :class:`Scan` row so the history detail
        view can replay past results. ``None`` disables the snapshot.
        """
        self._findings_sink = sink

    def _persist_batch(
        self,
        scan_id: str,
        batch: List[DeviceFinding],
        result: ScanResult,
    ) -> None:
        """Commit boundary for HC16 batched persistence.

        Slices ``batch`` into chunks of :attr:`batch_size` (D3 default 100,
        configurable via ``SCAN_PERSIST_BATCH_SIZE``) and invokes the
        registered sink once per chunk. Each sink invocation is the single
        DB-commit boundary; chunking caps WAL growth at one commit per
        ``batch_size`` findings rather than one commit per finding (the
        pre-refactor shape).

        Args:
            scan_id: Persistence scan UUID.
            batch: Device findings to persist. May be empty (no-op).
            result: Terminal :class:`ScanResult` for the run. Forwarded to
                the sink alongside each chunk so the sink can decide whether
                to also persist the legacy ``raw_results`` payload (only
                for the final, terminal chunk in practice — but the sink is
                responsible for that contract, not this method).
        """
        if not batch:
            logger.debug("_persist_batch: nothing to persist for scan_id={scan_id}", scan_id=scan_id)
            return
        if self._persist_sink is None:
            logger.debug(
                "_persist_batch: no persistence sink configured; dropping batch of {len_batch} findings",
                len_batch=len(batch),
            )
            return

        size = max(1, int(self.batch_size))
        total = len(batch)
        chunks = (total + size - 1) // size
        persisted = 0
        try:
            for idx in range(chunks):
                start = idx * size
                chunk = batch[start : start + size]
                self._persist_sink(scan_id, chunk, result)
                persisted += len(chunk)
            logger.info(
                "_persist_batch: persisted {total} findings for scan_id={scan_id} " "in {chunks} chunk(s) of <= {size}",
                total=total,
                scan_id=scan_id,
                chunks=chunks,
                size=size,
            )
        except asyncio.CancelledError:
            # D4 (resolved 2026-05-17): drain whatever remains of the
            # buffer one final time, tag the scan ``cancelled_partial``,
            # then re-raise so the caller's cancellation chain completes.
            # The sink that just raised may have left the current chunk
            # half-applied at the DB layer; any further chunks are best-
            # effort and may themselves raise — we still re-raise the
            # original CancelledError, not the secondary failure.
            logger.warning(
                "_persist_batch: CancelledError mid-flight for scan_id={scan_id}; "
                "persisted {persisted}/{total} findings; flushing remainder + "
                "marking scan_status='cancelled_partial'",
                scan_id=scan_id,
                persisted=persisted,
                total=total,
            )
            remaining = batch[persisted:]
            if remaining and self._persist_sink is not None:
                try:
                    self._persist_sink(scan_id, remaining, result)
                except Exception as exc_drain:
                    logger.error(
                        "_persist_batch: final-drain on cancellation failed for " "scan_id={scan_id}: {exc_drain}",
                        scan_id=scan_id,
                        exc_drain=exc_drain,
                    )
            if self._finish_sink is not None:
                try:
                    self._finish_sink(scan_id, "cancelled_partial", "scan_cancelled_mid_persist")
                except Exception as exc_fs:
                    logger.error(
                        "_persist_batch: finish sink failed during cancellation " "for scan_id={scan_id}: {exc_fs}",
                        scan_id=scan_id,
                        exc_fs=exc_fs,
                    )
            raise
        except Exception as exc:
            logger.error(
                "_persist_batch: persistence sink failed for scan_id={scan_id}: {exc}", scan_id=scan_id, exc=exc
            )

    # ---- Phase 5 interim-flush plumbing ----

    def _on_forwarder_item(self, run_id: str, item: Dict[str, Any]) -> None:
        """SSE-forwarder side-channel hook: accumulate findings, trigger flush.

        Called from the per-scan forwarder thread (parent process) for every
        item drained out of the child's ``multiprocessing.Queue``. Items with
        ``event == "progress"`` and a non-null ``finding`` get appended to the
        per-run buffer. When the buffer reaches :attr:`batch_size`, the
        accumulator drains it via :meth:`_persist_batch` (an intermediate
        flush) — implements task 6.1.

        Best-effort: any failure is logged and swallowed so SSE delivery
        continues uninterrupted.
        """
        try:
            if not isinstance(item, dict):
                return
            ev = item.get("event")
            data = item.get("data") or {}
            if ev != "progress":
                return
            finding_payload = data.get("finding") if isinstance(data, dict) else None
            if not finding_payload:
                return
            try:
                finding = DeviceFinding.model_validate(finding_payload)
            except Exception as exc_v:
                logger.debug(
                    "_on_forwarder_item: invalid finding payload for run_id={run_id}: {exc_v}",
                    run_id=run_id,
                    exc_v=exc_v,
                )
                return

            to_flush: List[DeviceFinding] = []
            with self._buffer_lock:
                buf = self._run_buffers.setdefault(run_id, [])
                buf.append(finding)
                if len(buf) >= self.batch_size:
                    to_flush = buf[:]
                    buf.clear()

            if to_flush:
                scan_id = self._lookup_scan_id(run_id)
                module_name = self._run_module_name.get(run_id, "")
                synthetic = ScanResult(module_name=module_name, findings=[])
                self._persist_batch(scan_id, to_flush, synthetic)
                self._partial_flushed_runs.add(run_id)
        except Exception as exc:
            logger.debug("_on_forwarder_item failed for run_id={run_id}: {exc}", run_id=run_id, exc=exc)

    def _lookup_scan_id(self, run_id: str) -> str:
        """Return the persistence ``scan_id`` for ``run_id``, falling back to ``run_id``.

        SCAN-005: the authoritative source is the parent-only
        ``_scan_id_by_uid`` mapping (the child terminal payload cannot
        clobber it). A legacy fallback reads ``module_results[uid]["scan_id"]``
        for callers that seed the scan_id directly into the shared dict — in
        production the child never writes that key, so the fallback yields
        ``None`` and cannot reintroduce the clobber.
        """
        with self._pending_finalize_lock:
            scan_id = self._scan_id_by_uid.get(run_id)
        if scan_id:
            return scan_id
        info = self.module_results.get(run_id)
        if info and info.get("scan_id"):
            return str(info["scan_id"])
        return run_id

    def cancel_run(self, run_id: str) -> None:
        """Mark ``run_id`` as cancelled; :meth:`_finalize_run` reports the
        appropriate terminal status (D4: ``CANCELLED_PARTIAL`` if any
        findings were drained from the buffer, else ``ABORTED``).
        """
        self._cancelled_runs.add(run_id)

    # ---- Discovery ----

    def _detect_modules(self) -> Dict[str, ModuleInfo]:
        """Discover modules recursively under ``self.modules_path``."""
        modules: Dict[str, ModuleInfo] = {}
        root_path = Path(self.modules_path)
        if not root_path.exists():
            logger.warning("Modules path does not exist: {self_modules_path}", self_modules_path=self.modules_path)
            return {}

        for root, _, files in os.walk(self.modules_path):
            if "start.py" in files and "config.json" in files:
                module_folder = os.path.basename(root)
                modules[module_folder] = ModuleInfo(
                    start_path=os.path.join(root, "start.py"),
                    config_path=os.path.join(root, "config.json"),
                )
        logger.debug("Detected modules: {list_modules_keys}", list_modules_keys=list(modules.keys()))
        return modules

    def refresh(self) -> None:
        """Re-scan the modules directory and update the internal registry."""
        self.modules = self._detect_modules()

    # ---- Introspection ----

    def get_modules(self) -> Dict[str, Dict[str, str]]:
        """Return shallow module info as a serializable dict."""
        return {k: {"start_path": v.start_path, "config_path": v.config_path} for k, v in self.modules.items()}

    def get_module_names(self) -> List[str]:
        """Return the list of discovered module names."""
        return list(self.modules.keys())

    def get_module_info(self, module_name: str) -> Dict[str, str]:
        """Return info for a module or ``{}`` if not found."""
        normalized = (module_name or "").split("/")[-1]
        info = self.modules.get(normalized)
        if not info:
            logger.error("Module {module_name} not found.", module_name=module_name)
            return {}
        return {"start_path": info.start_path, "config_path": info.config_path}

    # ---- Import & Run ----

    def _import_module_class(self, start_path: str) -> Optional[type]:
        """Dynamically import the ScanModule class from ``start.py``.

        Loads the module as ``otalon_scan.modules.<name>.start`` using
        :func:`importlib.util.spec_from_file_location` with proper
        ``submodule_search_locations`` so relative imports inside the
        module (e.g. ``from .walker import walker``) resolve correctly
        without mutating :data:`sys.path`.

        Conformance enforcement (decision D2): the imported class MUST
        pass an ``isinstance`` check against the ``@runtime_checkable``
        :class:`ScanModule` Protocol; non-conforming classes raise
        :class:`ScanModuleError`.
        """
        try:
            logger.debug("Importing module class from {start_path}", start_path=start_path)
            module_dir = os.path.dirname(start_path)
            leaf_folder = os.path.basename(module_dir)
            dotted_name = f"otalon_scan.modules.{leaf_folder}.start"
            pkg_name = f"otalon_scan.modules.{leaf_folder}"

            if pkg_name not in sys.modules:
                importlib.import_module(pkg_name)

            spec = importlib.util.spec_from_file_location(
                dotted_name,
                start_path,
                submodule_search_locations=[module_dir],
            )
            if spec is None or spec.loader is None:
                raise ImportError(f"Cannot load spec for {start_path}")

            module = importlib.util.module_from_spec(spec)
            sys.modules[dotted_name] = module
            spec.loader.exec_module(module)

            mod_cls = _get_scan_module_class(module)
            if mod_cls is None:
                raise ScanModuleError(
                    f"No ScanModule-compatible class found in {start_path}. "
                    "Expected a class with a 'name: str' attribute and an "
                    "async 'scan(self, config: ScanConfig)' method."
                )

            # D2 enforcement: runtime isinstance against @runtime_checkable Protocol.
            instance = mod_cls()
            if not isinstance(instance, ScanModule):
                raise ScanModuleError(
                    f"Class {mod_cls.__name__} in {start_path} does not conform "
                    "to the ScanModule Protocol (missing 'name' or 'scan')."
                )
            if not hasattr(instance, "scan"):
                raise ScanModuleError(f"Class {mod_cls.__name__} is missing required 'scan' method.")

            logger.debug("Loaded ScanModule class {mod_cls___name}", mod_cls___name=mod_cls.__name__)
            return mod_cls
        except ScanModuleError:
            raise
        except ImportError as exc:
            logger.error("Failed to import module: {exc}", exc=exc)
            return None
        except Exception as exc:
            logger.error("Unexpected error importing module: {exc}", exc=exc)
            return None

    def start_module(
        self,
        module_name: str,
        module_config: Optional[Dict[str, Any]] = None,
    ) -> Optional[str]:
        """Start a module in a separate process and return its run UUID.

        HC15 / scan--api-auth (2026-05-18): ``module_config`` is an
        already-validated override dict. The HTTP layer
        (:class:`~otalon_scan.api.server.StartScanRequest`) runs each per-module
        Pydantic schema (see :data:`otalon_scan.core.module_config.MODULE_SCHEMA_REGISTRY`)
        and normalises the payload before calling this method, so the
        dict that lands here is by contract free of unknown keys,
        malformed CIDRs, illegal timing templates, etc. The internal
        ``Dict[str, Any]`` typing reflects the post-validation shape,
        not "anything goes" — downstream code may rely on the schema
        contract documented by the per-module Pydantic models.
        """
        normalized = (module_name or "").split("/")[-1]
        if os.environ.get("OTALON_PLATFORM", "native").lower() == "desktop" and normalized in {
            "arp_scan",
            "pn_discovery",
        }:
            raise ValueError("Docker Desktop cannot run physical raw-L2 discovery; use routed protocol scans only")
        self._clean_up_finished_modules()
        try:
            normalized = (module_name or "").split("/")[-1]
            if normalized not in self.modules:
                logger.error("Module {module_name} not found.", module_name=module_name)
                return None

            info = self.modules[normalized]
            uid = str(uuid4())
            self._run_module_name[uid] = normalized
            # F-02 / scan--structured-logging Requirement "run_id Bound
            # on Every Log Line in Persist Path": bind a per-run logger
            # for the orchestrator-side persist + monitor paths so every
            # emitted line carries the correlation fields.
            run_logger = logger.bind(run_id=uid, module=normalized)
            run_logger.debug("Starting module: {normalized}", normalized=normalized)

            # ``full_conf`` is either a merged config dict (when the
            # caller supplied overrides) or the on-disk path to the
            # module's default config.json — the child process loads
            # the path lazily if it sees a string.
            full_conf: Union[Dict[str, Any], str]
            if module_config:
                full_conf = merge_configurations(module_config, info.config_path)
            else:
                full_conf = info.config_path

            # F-02 / scan--module-config-schemas Requirement
            # "Config Defaults Loaded From config.json" + Requirement
            # "Override merge". After merging defaults with the
            # caller-supplied overrides, re-validate the merged payload
            # against the module's *Config schema so the orchestrator
            # never dispatches a module with a config that violates the
            # schema invariants. Validation failure raises
            # ``ScanModuleError`` which the API layer surfaces as HTTP
            # 422.
            full_schema = config_schema_for_module(normalized)
            if full_schema is not None and isinstance(full_conf, dict):
                merged_for_validation = dict(full_conf)
                # The schema's ``module_type`` discriminator defaults to
                # the slug; the JSON shape on disk does not carry it.
                # Inject it here so strict validation is symmetric with
                # how the future MCP ``start_scan`` tool will call us.
                merged_for_validation.setdefault("module_type", normalized)
                try:
                    full_schema.model_validate(merged_for_validation)
                except ValidationError as exc:
                    raise ScanModuleError(
                        f"merged config for module {normalized!r} failed "
                        f"validation against {full_schema.__name__}: {exc}"
                    ) from exc

            # SSE progress channel (per-scan). Capacity is bounded to avoid
            # unbounded memory growth if no subscriber is connected.
            progress_q: "multiprocessing.Queue[Any]" = multiprocessing.Queue(maxsize=10_000)
            self._progress_mp_queues[uid] = progress_q

            process = multiprocessing.Process(
                target=self._run_module_proc,
                args=(
                    info.start_path,
                    full_conf,
                    self.module_results,
                    uid,
                    normalized,
                    progress_q,
                ),
                daemon=True,
            )
            process.start()
            self.running_modules.add((uid, normalized, process))
            self._spawn_monitor(uid, normalized, process)
            return uid
        except Exception as exc:
            logger.error("Failed to start module {module_name}: {exc}", module_name=module_name, exc=exc)
            return None

    def _spawn_monitor(self, uid: str, module: str, process: multiprocessing.Process) -> None:
        """Spawn a daemon thread that fires the callback as soon as the process ends."""

        def _run() -> None:
            try:
                process.join()
            except Exception:
                pass
            finally:
                try:
                    with self._lock:
                        for entry in list(self.running_modules):
                            if entry[0] == uid:
                                self.running_modules.remove(entry)
                                break
                except Exception as exc_rm:
                    logger.debug(
                        "Monitor cleanup error for {module} (uid={uid}): {exc_rm}",
                        module=module,
                        uid=uid,
                        exc_rm=exc_rm,
                    )
                self._finalize_run(uid, module)

        t = threading.Thread(target=_run, name=f"cs-ics-monitor-{module}-{uid[:8]}", daemon=True)
        try:
            t.start()
        except Exception as exc:
            logger.debug(
                "Failed to start monitor thread for {module} (uid={uid}): {exc}", module=module, uid=uid, exc=exc
            )

    @staticmethod
    def _build_findings_snapshot(
        result_obj: Optional[ScanResult],
        findings_payload: List[Any],
    ) -> List[Dict[str, Any]]:
        """Build the L-02 per-scan findings snapshot for persistence.

        Prefers the terminal :class:`ScanResult`'s authoritative findings
        list; falls back to the child's serialised ``findings_payload`` when
        no typed result was produced. Returns JSON-serialisable dicts so the
        caller can write them straight into the ``scans.findings`` JSONB
        column.
        """
        if result_obj is not None and result_obj.findings:
            return [f.model_dump(mode="json") for f in result_obj.findings]
        snapshot: List[Dict[str, Any]] = []
        for item in findings_payload or []:
            if isinstance(item, DeviceFinding):
                snapshot.append(item.model_dump(mode="json"))
            elif isinstance(item, dict):
                snapshot.append(item)
        return snapshot

    def _finalize_run(self, uid: str, module: str) -> None:
        """Persist accumulated findings, set terminal status, invoke user callback.

        This is the orchestrator-side persistence boundary (HC6 / HC16). The
        child process has serialized the terminal :class:`ScanResult` (and
        the full findings list it accumulated) into the shared dict. The
        parent-side per-run buffer (fed by the SSE forwarder during the
        run) may also contain findings that were not yet flushed in an
        interim ``_persist_batch`` (i.e. fewer than :attr:`batch_size`
        findings have accumulated since the last flush). Both sources are
        reconciled — the terminal full findings list takes precedence over
        the per-run buffer because it represents the module's authoritative
        view — and the remainder is drained via a final ``_persist_batch``.

        After persistence the terminal :class:`ScanStatus` is reported via
        the registered finish sink:

        - ``CANCELLED_PARTIAL`` if the run was cancelled (D4) and at least
          one finding was flushed at any point.
        - ``ABORTED`` if the run was cancelled and no findings were flushed.
        - ``FAILED`` if the shared-dict payload carries an ``error`` key.
        - ``COMPLETED`` otherwise.

        HC12 (2026-05-18): idempotency guard. The monitor thread (which
        spawns this via ``_spawn_monitor``) and an explicit operator
        ``stop_module`` call can race — both may want to finalise the
        same run. The contract is "first finalisation wins"; a second
        call for the same ``uid`` logs a warning and returns immediately
        without invoking the persistence or finish sinks again. Without
        this guard we observed (a) duplicate ``Scan`` row updates that
        clobbered the terminal status from the first call, and (b)
        double-insert constraint violations on the legacy ARP-scan
        results path.
        """
        # B-E3 (2026-06-04): defer finalisation until the persistence
        # ``scan_id`` is known. If the run completed before the API layer
        # registered the DB UUID, finalising now would address the run
        # UUID and the ``finish_scan`` UPDATE would silently no-op on a
        # non-existent row — stranding the scan at ``status=RUNNING``.
        # We record the run as pending and return WITHOUT claiming the
        # HC12 token, so :meth:`register_scan_id` can re-drive a real
        # finalisation against the correct row. This check is outside the
        # idempotency guard on purpose: a deferral is not a finalisation.
        #
        # The readiness re-check and the pending-set write happen under
        # ``_pending_finalize_lock`` — the same lock ``register_scan_id``
        # takes around its scan_id write + pending drain — to close the
        # lost-wakeup race: either we see the scan_id (and finalise now)
        # or ``register_scan_id`` sees our pending entry (and re-drives).
        with self._pending_finalize_lock:
            scan_id_known = bool(self._scan_id_by_uid.get(uid))
            if not scan_id_known:
                legacy = self.module_results.get(uid)
                scan_id_known = bool(legacy and legacy.get("scan_id"))
            if not scan_id_known:
                self._pending_finalize[uid] = module
                logger.debug(
                    "_finalize_run: scan_id not yet registered for uid={uid} module={module}; "
                    "deferring to register_scan_id (B-E3)",
                    uid=uid,
                    module=module,
                )
                return

        # HC12 idempotency check — set lookup + insert under a single
        # lock so two threads cannot both win the race. The lock is
        # held only for the membership check, not for the heavyweight
        # persistence work that follows.
        with self._finalise_lock:
            if uid in self._finalised_runs:
                logger.warning(
                    "_finalize_run: duplicate finalise for uid={uid} module={module}; "
                    "ignored (HC12 idempotency guard)",
                    uid=uid,
                    module=module,
                )
                return
            self._finalised_runs.add(uid)
        scan_id: Optional[str] = None  # resolved in the try block; used by the SC-04 bus close below
        try:
            # SCAN-005: the scan_id lives in ``_scan_id_by_uid``, not in
            # ``module_results``, so a run whose child wrote no terminal
            # payload (e.g. fatal import error) must still finalise to a
            # terminal status rather than bail here and strand at RUNNING.
            # Fall back to an empty payload; the registered scan_id below
            # still addresses the right row.
            info = dict(self.module_results.get(uid) or {})

            result_payload = info.get("scan_result")
            findings_payload = info.get("findings") or []
            scan_id = self._lookup_scan_id(uid)
            error_message = info.get("error")
            module_name = info.get("module_name", module)

            result_obj: Optional[ScanResult] = None
            if result_payload is not None:
                try:
                    result_obj = ScanResult.model_validate(result_payload)
                except Exception as exc:
                    logger.error(
                        "_finalize_run: invalid ScanResult payload for {module} (uid={uid}): {exc}",
                        module=module,
                        uid=uid,
                        exc=exc,
                    )
                    result_obj = None

            # F-02 / scan--module-contract Requirement "Wrong discriminator
            # value rejected": if the child yielded a typed
            # ``*ScanResult`` whose ``module_type`` does not match the
            # dispatching module's directory-name slug, refuse to
            # persist the result and mark the scan failed. The
            # persistence-error counter increment is wired in section 6
            # (capability ``scan--observability``).
            if result_obj is not None:
                claimed = (
                    getattr(result_obj, "module_type", None)
                    if isinstance(result_payload, dict) and "module_type" in result_payload
                    else None
                )
                if claimed is not None and claimed != module:
                    logger.error(
                        "_finalize_run: module_type discriminator mismatch for "
                        "uid={uid} dispatched_as={module} claimed={claimed}; "
                        "refusing to persist",
                        uid=uid,
                        module=module,
                        claimed=claimed,
                    )
                    info["error"] = info.get("error") or (
                        f"module_type discriminator mismatch: expected={module!r}, claimed={claimed!r}"
                    )
                    error_message = info["error"]
                    result_obj = None
                    if self._on_persistence_error is not None:
                        try:
                            self._on_persistence_error(module)
                        except Exception as exc_cb:
                            logger.debug(
                                "_finalize_run: persistence-error callback failed: {exc_cb}",
                                exc_cb=exc_cb,
                            )

            # Drain the parent-side buffer. When the SSE forwarder is wired
            # for this run, this is the authoritative finding source — the
            # forwarder has been streaming findings into the buffer all along
            # and we have already issued zero or more interim flushes; this
            # final drain catches the trailing remainder. When the forwarder
            # is NOT wired (no scan_id registered, the run completed before
            # the bus attached, or running in unit tests), fall back to the
            # child's terminal ``findings_payload``.
            with self._buffer_lock:
                buffered = self._run_buffers.pop(uid, [])
            forwarder_used = uid in self._forwarder_wired

            had_partial_flush = uid in self._partial_flushed_runs

            if forwarder_used:
                if buffered:
                    final_result_for_flush = result_obj or ScanResult(module_name=module_name, findings=[])
                    self._persist_batch(scan_id, buffered, final_result_for_flush)
                # Always invoke the sink at least once with the terminal
                # result so the sink can persist scan-level metadata (e.g.
                # raw_results → save_port_scan_results) — pass an empty
                # batch when nothing trailing remains. The sink itself
                # skips empty work and handles scan-level finalisation.
                elif result_obj is not None and self._persist_sink is not None:
                    try:
                        self._persist_sink(scan_id, [], result_obj)
                    except Exception as exc_sink:
                        logger.error(
                            "_finalize_run: terminal sink call failed for {module} (uid={uid}): {exc_sink}",
                            module=module,
                            uid=uid,
                            exc_sink=exc_sink,
                        )
            else:
                # Legacy / no-forwarder path: persist directly from terminal payload.
                if result_obj is not None:
                    findings = [DeviceFinding.model_validate(f) for f in findings_payload]
                    if findings:
                        self._persist_batch(scan_id, findings, result_obj)
                elif findings_payload:
                    findings = [DeviceFinding.model_validate(f) for f in findings_payload]
                    synthetic = ScanResult(module_name=module_name, findings=findings)
                    self._persist_batch(scan_id, findings, synthetic)

            # Decide terminal status (Phase 5 / 6.3).
            was_cancelled = uid in self._cancelled_runs
            findings_persisted = had_partial_flush or bool(buffered) or bool(findings_payload)

            if error_message:
                status = "failed"
            elif was_cancelled and findings_persisted:
                status = "cancelled_partial"
            elif was_cancelled:
                status = "aborted"
            else:
                status = "completed"

            if self._finish_sink is not None:
                try:
                    self._finish_sink(scan_id, status, error_message)
                except Exception as exc_fs:
                    logger.error(
                        "_finalize_run: finish sink failed for {module} (uid={uid}): {exc_fs}",
                        module=module,
                        uid=uid,
                        exc_fs=exc_fs,
                    )

            # L-02: persist a point-in-time findings snapshot onto the Scan
            # row so the history detail view can replay what the run reported.
            # The terminal ScanResult's findings list is the module's
            # authoritative view; fall back to the child's serialised
            # findings payload when no typed result was produced.
            if self._findings_sink is not None:
                snapshot = self._build_findings_snapshot(result_obj, findings_payload)
                try:
                    self._findings_sink(scan_id, snapshot)
                except Exception as exc_snap:
                    logger.error(
                        "_finalize_run: findings sink failed for {module} (uid={uid}): {exc_snap}",
                        module=module,
                        uid=uid,
                        exc_snap=exc_snap,
                    )

            if self.callback:
                try:
                    self.callback(uid, module_name, info.get("results"))
                except Exception as exc_cb:
                    logger.error(
                        "Callback error for {module} (uid={uid}): {exc_cb}", module=module, uid=uid, exc_cb=exc_cb
                    )

            # UI-173: emit the deferred terminal ``result`` SSE event ONLY
            # after persist + finish + findings + callback have all run, so
            # the UI finish signal cannot precede the ``last_scan_at`` commit.
            # The child no longer pushes this event (see ``_run_module_proc``);
            # ``_finalize_run`` is the single authoritative source. The
            # ``finally`` block below then calls ``progress_bus.close`` which
            # fans out the ``None`` stream-close sentinel, ordering finish
            # signal strictly after the commit. Emit only when a typed
            # ScanResult was produced; error/no-result runs rely on the
            # terminal watchdog (DB-poll fallback) for their finish signal.
            result_payload = info.get("scan_result")
            if result_payload is not None and scan_id is not None:
                try:
                    self.progress_bus.emit(scan_id, {"event": "result", "data": result_payload})
                except Exception as exc_emit:
                    logger.debug(
                        "_finalize_run: deferred result emit failed for {module} (uid={uid}): {exc_emit}",
                        module=module,
                        uid=uid,
                        exc_emit=exc_emit,
                    )
        except Exception as exc:
            logger.error("_finalize_run: error for {module} (uid={uid}): {exc}", module=module, uid=uid, exc=exc)
        finally:
            # Drop the per-run mp queue reference; the child's terminal
            # sentinel already triggered the forwarder to close the async
            # queue, so no further events are expected on this run.
            self._progress_mp_queues.pop(uid, None)
            self._cancelled_runs.discard(uid)
            self._partial_flushed_runs.discard(uid)
            self._run_module_name.pop(uid, None)
            self._forwarder_wired.discard(uid)
            with self._pending_finalize_lock:
                self._scan_id_by_uid.pop(uid, None)
            # SC-04: publish the terminal sentinel for the scan even when no
            # SSE forwarder was ever wired for the run (e.g. the run finished
            # before registration). Without this, subscribers of
            # ``GET /scans/{scan_id}/events`` block forever in ``q.get()``.
            # Idempotent for the wired case — the forwarder already fanned
            # out a sentinel and a duplicate ``None`` is a no-op.
            if scan_id:
                self.progress_bus.close(scan_id)

    def _run_module_proc(
        self,
        start_path: str,
        config: Any,
        shared_results: Any,
        uid: str,
        module_name: str,
        progress_q: Optional["multiprocessing.Queue[Any]"] = None,
    ) -> None:
        """Child-process entry: import the ScanModule, iterate its async generator.

        Buffers all :class:`DeviceFinding` events plus the terminal
        :class:`ScanResult` and writes them to ``shared_results[uid]``.
        Per-event :class:`ScanProgress` payloads are also published onto
        ``progress_q`` for the parent-side SSE forwarder (Mission Q9).
        The parent's monitor thread drains the shared dict via
        :meth:`_finalize_run` and calls :meth:`_persist_batch`.
        """
        try:
            # F-02 / scan--structured-logging Requirement "run_id Bound
            # on Module Subprocess Output": bind run_id + module on the
            # child-process logger so every emitted line carries the
            # correlation fields. We use ``logger.configure(extra=...)``
            # because the loguru ``logger`` singleton in the child has
            # no inherited ``extra`` after the fork-and-init reset.
            os.environ["OTALON_SCAN_RUN_ID"] = uid
            logger.configure(extra={"run_id": uid, "module": module_name})
            logger.debug("Module process started for uid={uid}", uid=uid)
            module_class = self._import_module_class(start_path)
            if module_class is None:
                return
            module_instance = module_class()

            raw_cfg: Dict[str, Any]
            if isinstance(config, dict):
                raw_cfg = dict(config)
            else:
                raw_cfg = load_json(str(config)) or {}

            scan_config = ScanConfig(
                module_name=getattr(module_instance, "name", module_name),
                network_interface=raw_cfg.get("network_interface"),
                target_ip=raw_cfg.get("target_ip"),
                target_mac=raw_cfg.get("target_mac"),
                target_subnet=raw_cfg.get("target_subnet"),
                target_port=raw_cfg.get("target_port"),
                parameters=raw_cfg,
            )

            abort_event = threading.Event()

            def graceful_exit(signum: int, _frame: Any) -> None:
                logger.warning("Signal {signum} received for uid={uid}; requesting abort", signum=signum, uid=uid)
                abort_event.set()
                # Terminate any spawned subprocess children (nmap, pysnmp, ...)
                try:
                    parent = psutil.Process(os.getpid())
                    for child in parent.children(recursive=True):
                        try:
                            child.terminate()
                        except Exception:
                            pass
                except psutil.NoSuchProcess:
                    pass

            signal.signal(signal.SIGTERM, graceful_exit)
            signal.signal(signal.SIGINT, graceful_exit)

            def _push_progress(payload: Dict[str, Any]) -> None:
                """Best-effort publish onto the SSE mp queue (drops on full)."""
                if progress_q is None:
                    return
                try:
                    progress_q.put_nowait(payload)
                except queue.Full:
                    # Slow subscriber — drop oldest, then enqueue
                    try:
                        progress_q.get_nowait()
                        progress_q.put_nowait(payload)
                    except Exception:
                        pass
                except Exception as exc_push:
                    logger.debug("progress_q push failed for uid={uid}: {exc_push}", uid=uid, exc_push=exc_push)

            async def _iterate() -> Tuple[Optional[ScanResult], List[ScanProgress], List[DeviceFinding]]:
                """Drive the module's async generator to completion."""
                progress_events: List[ScanProgress] = []
                findings: List[DeviceFinding] = []
                final_result: Optional[ScanResult] = None
                async for event in module_instance.scan(scan_config):
                    if abort_event.is_set():
                        logger.warning("Abort requested for uid={uid}; stopping iteration", uid=uid)
                        break
                    if isinstance(event, ScanProgress):
                        progress_events.append(event)
                        if event.finding is not None:
                            findings.append(event.finding)
                        _push_progress({"event": "progress", "data": event.model_dump(mode="json")})
                    elif isinstance(event, ScanResult):
                        final_result = event
                        # Prefer the terminal result's full findings list if provided
                        if event.findings:
                            findings = list(event.findings)
                        # UI-173: the terminal ``result`` event is NOT pushed
                        # here. The child yields it at scan-completion time,
                        # but the parent has not yet committed ``last_scan_at``
                        # to PostgreSQL (that happens in ``_finalize_run`` via
                        # ``_persist_batch``). Pushing it now lets the SSE
                        # ``result``/``final`` frame — the UI finish signal —
                        # reach the browser before the commit, so device
                        # badges flap grey→green on the next poll. The parent
                        # re-emits the deferred ``result`` event from
                        # ``_finalize_run`` AFTER persist + finish + findings
                        # sinks, guaranteeing commit-before-finish-signal.
                return final_result, progress_events, findings

            # HC8: do NOT use ``asyncio.run`` from library code. The child
            # process owns its own event loop; create it explicitly, drive
            # the module's async generator, and close cleanly. This is the
            # idiomatic equivalent of ``asyncio.run`` but keeps the grep
            # gate ``grep -rn "asyncio.run" src/`` clean and makes the
            # ownership of the loop explicit.
            loop = asyncio.new_event_loop()
            try:
                try:
                    final_result, _progress, findings = loop.run_until_complete(_iterate())
                except ScanModuleError as exc:
                    logger.error("Module {module_name} failed: {exc}", module_name=module_name, exc=exc)
                    shared_results[uid] = {
                        "module_name": getattr(module_instance, "name", module_name),
                        "results": None,
                        "scan_result": None,
                        "findings": [],
                        "error": str(exc),
                    }
                    return

                raw_results = final_result.raw_results if final_result is not None else None
                shared_results[uid] = {
                    "module_name": getattr(module_instance, "name", module_name),
                    "results": raw_results,
                    "scan_result": (final_result.model_dump(mode="json") if final_result is not None else None),
                    "findings": [f.model_dump(mode="json") for f in findings],
                }
            finally:
                try:
                    loop.close()
                except Exception as exc_close:
                    logger.debug("Loop close error for uid={uid}: {exc_close}", uid=uid, exc_close=exc_close)
                # Terminal sentinel for the SSE forwarder. Best-effort; the
                # parent-side _drain handles a missing sentinel via EOF.
                if progress_q is not None:
                    try:
                        progress_q.put_nowait(_PROGRESS_DONE)
                    except Exception:
                        pass
        except Exception as exc:
            logger.error("Failed to run module: {exc}", exc=exc)

    # ---- Control ----

    def stop_module(self, uid: str) -> bool:
        """Stop a running module process by UUID.

        Marks the run as cancelled (D4) so :meth:`_finalize_run` reports
        ``CANCELLED_PARTIAL`` if any findings made it through the
        forwarder before termination, or ``ABORTED`` if the buffer was
        empty at cancellation time.

        Returns ``True`` when the module is terminated after the call —
        either because this call terminated it, or because the monitor
        thread / cleanup already retired the finished run from the
        registry (SC-03: a stale ``running_modules`` map must not report
        ``stopped: false`` for a process that is already gone). Returns
        ``False`` only for an unknown run id or when the termination
        itself failed.
        """
        self._cancelled_runs.add(uid)
        try:
            with self._lock:
                entry = next((e for e in self.running_modules if e[0] == uid), None)
            if entry is None:
                # SC-03: the monitor thread (or a cleanup pass) retires the
                # registry entry as soon as the child exits. A run that is
                # already finalised — or whose finalisation is deferred
                # (B-E3) — has no live process left: the stop request's end
                # state is already reached, so report success.
                if uid in self._finalised_runs or uid in self._pending_finalize:
                    logger.debug(
                        "stop_module: run {uid} already retired by monitor/cleanup; reporting stopped",
                        uid=uid,
                    )
                    return True
                logger.error("No module running with id: {uid}", uid=uid)
                return False
            id_, module, process = entry
            logger.debug("Stopping module: {module}", module=module)
            terminated = False
            try:
                parent = psutil.Process(process.pid)
                parent.terminate()
                try:
                    parent.wait(timeout=5)
                    terminated = True
                except psutil.TimeoutExpired:
                    logger.warning("Module {module} did not terminate gracefully, killing", module=module)
                    for child in parent.children(recursive=True):
                        try:
                            child.kill()
                        except Exception:
                            pass
                    try:
                        parent.kill()
                        parent.wait()
                        terminated = True
                    except Exception:
                        pass
            except psutil.NoSuchProcess:
                # Process already gone — the desired end state is reached.
                logger.debug("stop_module: process for module {module} already gone", module=module)
                terminated = True
            except Exception as exc:
                logger.exception("Error while stopping module {module}: {exc}", module=module, exc=exc)
            if terminated:
                # ``discard`` (not ``remove``) under the manager lock: the
                # monitor thread may have concurrently retired the same
                # entry (SC-03) — a successful termination must never be
                # turned into a ``False`` result by a stale-map KeyError.
                with self._lock:
                    self.running_modules.discard(entry)
            return terminated
        except Exception as exc:
            logger.error("Failed to stop module {uid}: {exc}", uid=uid, exc=exc)
            return False

    # ---- Status & Results ----

    def get_all_running_modules_status(self) -> Dict[str, str]:
        """Return mapping of run UUID to module name for live processes."""
        self._clean_up_finished_modules()
        return {id_: module for id_, module, _ in self.running_modules}

    def _clean_up_finished_modules(self) -> None:
        """Prune the registry of processes that are no longer alive."""
        for id_, module, process in list(self.running_modules):
            if process.is_alive():
                continue
            try:
                try:
                    parent = psutil.Process(process.pid)
                    for child in parent.children(recursive=True):
                        try:
                            child.terminate()
                        except Exception:
                            pass
                    try:
                        parent.terminate()
                        parent.wait(timeout=2)
                    except Exception:
                        pass
                except psutil.NoSuchProcess:
                    pass
                except Exception as exc:
                    logger.exception("Error while cleaning up module {module}: {exc}", module=module, exc=exc)
                logger.debug("Module {module} (uid={id}) finished", module=module, id=id_)
                try:
                    process.join(timeout=1)
                except Exception:
                    pass
            finally:
                self.running_modules.remove((id_, module, process))
                self._finalize_run(id_, module)

    @staticmethod
    def _normalize(obj: Any) -> Any:
        """Convert module results to JSON-serializable structures (recursive)."""
        try:
            if obj is None or isinstance(obj, (str, int, float, bool)):
                return obj
            if hasattr(obj, "to_dict") and hasattr(obj, "columns"):
                try:
                    return obj.to_dict(orient="records")
                except Exception:
                    pass
            if hasattr(obj, "tolist") and not isinstance(obj, dict):
                try:
                    return obj.tolist()
                except Exception:
                    pass
            try:
                from pydantic import BaseModel

                if isinstance(obj, BaseModel):
                    return obj.model_dump()
            except Exception:  # noqa: BLE001 -- duck-typing fallback
                pass
            try:
                from dataclasses import asdict, is_dataclass

                # ``is_dataclass`` narrows to ``DataclassInstance | type[DataclassInstance]``;
                # only the instance form has ``__dataclass_fields__`` for
                # ``asdict`` to walk, so we also gate on ``not isinstance(obj, type)``.
                if is_dataclass(obj) and not isinstance(obj, type):
                    return ModuleManager._normalize(asdict(obj))
            except Exception:  # noqa: BLE001 -- duck-typing fallback
                pass
            if isinstance(obj, dict):
                return {str(k): ModuleManager._normalize(v) for k, v in obj.items()}
            if isinstance(obj, (list, tuple, set)):
                return [ModuleManager._normalize(v) for v in list(obj)]
            return str(obj)
        except Exception:
            return str(obj)

    def get_module_results(self, uid: str) -> Dict[str, Any]:
        """Return stored results for a finished run, normalized for JSON output."""
        try:
            self._clean_up_finished_modules()
            if uid in self.module_results:
                res = self.module_results[uid].get("results")
                normalized = ModuleManager._normalize(res)
                if isinstance(normalized, dict):
                    return dict(normalized)
                return {"data": normalized}
            logger.error("No results found for module with ID: {uid}", uid=uid)
            return {}
        except Exception as exc:
            logger.error("Failed to get results for {uid}: {exc}", uid=uid, exc=exc)
            return {}

    def get_all_finished_modules(self) -> Dict[str, str]:
        """Return mapping of finished run UUID to module name."""
        try:
            self._clean_up_finished_modules()
        except Exception:
            pass
        finished: Dict[str, str] = {}
        for uid, info in dict(self.module_results).items():
            finished[str(uid)] = info.get("module_name", "")
        return finished

    def shutdown(self) -> None:
        """Best-effort cleanup invoked from the FastAPI lifespan shutdown."""
        try:
            for uid, _module, process in list(self.running_modules):
                try:
                    process.terminate()
                    process.join(timeout=2.0)
                except Exception:
                    pass
                self._progress_mp_queues.pop(uid, None)
        except Exception as exc:
            logger.debug("ModuleManager.shutdown error: {exc}", exc=exc)
        try:
            self.manager.shutdown()
        except Exception:
            pass

    def register_scan_id(self, run_id: str, scan_id: str) -> None:
        """Associate a run UUID with the persistence ``scan_id``.

        The API layer calls this immediately after creating the scan
        record so :meth:`_finalize_run` can address the right row.

        Also starts the SSE progress forwarder that drains the child-side
        ``multiprocessing.Queue`` into the per-scan async queue served by
        ``GET /scans/{scan_id}/events`` (Mission Q9 prerequisite), and
        wires the Phase 5 interim-flush accumulator hook
        (:meth:`_on_forwarder_item`) so per-finding progress events drive
        batched ``_persist_batch`` commits as they arrive.
        """
        deferred_module: Optional[str] = None
        should_wire = False
        try:
            # B-E3 (2026-06-04): write the scan_id and drain any pending
            # deferred finalisation under ``_pending_finalize_lock`` — the
            # same lock :meth:`_finalize_run` takes around its readiness
            # re-check. This makes "scan_id becomes visible" and "pending
            # entry recorded" mutually exclusive, closing the lost-wakeup
            # race in which a fast run defers right after register pops an
            # empty pending set.
            with self._pending_finalize_lock:
                # SCAN-005: record scan_id in the parent-only mapping, NOT in
                # the ``module_results`` Manager dict — the child's terminal
                # payload is a full dict replacement and would clobber it.
                self._scan_id_by_uid[run_id] = scan_id
                info = dict(self.module_results.get(run_id) or {})
                deferred_module = self._pending_finalize.pop(run_id, None)

                # SC-05: decide the forwarder wiring inside the same critical
                # section that publishes the scan_id. ``_finalize_run``
                # passes its deferral check the moment the scan_id is
                # visible; if the wiring landed only AFTER that, finalise
                # would pick the legacy terminal-payload source while the
                # forwarder still drains the same findings off the mp queue
                # (double-write). Adding ``_forwarder_wired`` here makes the
                # source selection atomic with the scan_id publication; the
                # HC12 ``_finalised_runs`` check (taken under its own lock,
                # ordering P→F on both paths) additionally bars wiring for a
                # run that already finalised via the legacy-seeded scan_id.
                with self._finalise_lock:
                    already_finalised = run_id in self._finalised_runs
                should_wire = (
                    deferred_module is None
                    and not already_finalised
                    and self._progress_mp_queues.get(run_id) is not None
                    and self.progress_bus.has_loop()
                )
                if should_wire:
                    self._forwarder_wired.add(run_id)

            # Remember module_name so synthetic interim ScanResult payloads
            # carry it. ``info`` may not have it set if the start_module
            # path runs before the child writes its terminal payload.
            existing_module = info.get("module_name")
            if existing_module:
                self._run_module_name[run_id] = str(existing_module)

            # Only wire the SSE forwarder for runs that are still live. A
            # run whose finalisation was deferred has already completed,
            # so its child sentinel is on the mp queue and its terminal
            # ``findings`` payload is authoritative — leaving the forwarder
            # unwired routes the deferred finalise through the legacy
            # terminal-payload path (the correct source for a finished run).
            # The thread spawn itself happens outside the lock; the wiring
            # decision was already published under it (SC-05).
            if should_wire:
                mp_q = self._progress_mp_queues[run_id]
                bound_run_id = run_id

                def _on_item(item: Dict[str, Any]) -> None:
                    self._on_forwarder_item(bound_run_id, item)

                self.progress_bus.start_forwarder(scan_id, mp_q, on_item=_on_item)
        except Exception as exc:
            logger.debug("register_scan_id failed for run_id={run_id}: {exc}", run_id=run_id, exc=exc)

        # B-E3 (2026-06-04): if the run completed before registration, its
        # finalisation was deferred; re-drive it now against the real DB
        # UUID so the scan is never stranded at ``status=RUNNING``. Done
        # outside the try/except so the finish-sink fires even if forwarder
        # wiring raised. The HC12 idempotency guard inside
        # ``_finalize_run`` keeps this exactly-once.
        if deferred_module is not None:
            logger.debug(
                "register_scan_id: re-driving deferred finalisation for " "run_id={run_id} scan_id={scan_id} (B-E3)",
                run_id=run_id,
                scan_id=scan_id,
            )
            self._finalize_run(run_id, deferred_module)
