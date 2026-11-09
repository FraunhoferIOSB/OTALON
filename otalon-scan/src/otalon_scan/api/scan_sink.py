"""Orchestrator-owned persistence sinks for otalon-scan (SCAN-033 extraction).

These four callbacks run on the :class:`~otalon_scan.core.module_manager.ModuleManager`
monitor thread, **not** inside a request. They therefore cannot resolve a
FastAPI dependency and instead receive the shared
:class:`~otalon_scan.api.state.ApiState` instance explicitly at lifespan wiring
time (see :func:`otalon_scan.api.server.lifespan`).

Because :class:`ScanSink` holds a reference to the same ``ApiState`` object
the request dependencies read, a late ``state.repo = ...`` assignment
(lifespan startup, or a test stub) is visible to the sinks immediately —
identical to the ``global _repo`` rebinding this replaces.

Cross-thread dispatch is unchanged: each sink schedules its coroutine onto
the event loop captured at lifespan startup with
:func:`asyncio.run_coroutine_threadsafe` and blocks on the result with its
own timeout (30 s module-finished / 10 s finish / 10 s findings /
60 s persist).

Logging note (SCAN-034): these call sites are on loguru like the rest of the
subproject. The former stdlib ``extra={...}`` dicts became a per-operation
``bound = logger.bind(**fields)`` logger; the fields are rendered by the
``ctx`` column that :func:`otalon_scan.core.log_config._render_context`
folds them into.
"""

from __future__ import annotations

import asyncio
import concurrent.futures as concurrent_futures
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Any, Dict, List, Optional

from loguru import logger
from sqlalchemy.exc import SQLAlchemyError

from ..core.models import DeviceFinding, ScanResult
from ..repositories.models import ScanStatus
from .metrics import PERSISTENCE_ERRORS, SCAN_DURATION_SECONDS, module_label
from .state import ApiState

if TYPE_CHECKING:
    from loguru import Logger

__all__ = ["ScanSink"]

# Map orchestrator status strings to ``ScanStatus`` enum values.
_STATUS_MAP: Dict[str, ScanStatus] = {
    "completed": ScanStatus.COMPLETED,
    "failed": ScanStatus.FAILED,
    "aborted": ScanStatus.ABORTED,
    "cancelled_partial": ScanStatus.CANCELLED_PARTIAL,
}


class ScanSink:
    """The orchestrator-facing persistence boundary, bound to an app state.

    Instantiated once per application in the lifespan startup. Its bound
    methods are handed to the :class:`ModuleManager` as the module-finished
    callback and as the persist / finish / findings sinks.
    """

    def __init__(self, state: ApiState) -> None:
        """Bind the sink to the application's shared runtime state.

        Args:
            state: The :class:`ApiState` container the request dependencies
                also read. Held by reference so later assignments to
                ``state.repo`` / ``state.main_loop`` take effect without
                re-wiring.
        """
        self._state = state

    def on_module_finished(self, run_id: str, module_name: str, results: Any) -> None:
        """Callback invoked by :class:`ModuleManager` when a child process completes.

        Phase 5 (HC16) — the terminal :class:`ScanStatus` update is now owned
        by the orchestrator's finish-sink (:meth:`finish_scan`), so this
        callback only handles the legacy module-specific persistence path
        (ARP/port-scan raw_results normalisation that hasn't yet been folded
        into the device-finding pipeline). It runs on the orchestrator
        monitor thread and dispatches the async repo call onto the captured
        FastAPI event loop.

        HC7 (2026-05-18): the previous ``except Exception`` blocks that
        swallowed DB failures silently are now ``bound.exception(...)`` calls
        with structured bound fields (``run_id``, ``module_name``, ``scan_id``)
        so failures surface in Loki/Grafana with the scan context attached
        instead of being recoverable only by reading raw text.
        """
        state = self._state
        repo = state.repo
        loop = state.main_loop
        if repo is None or loop is None:
            return
        scan_id = state.run_to_scan_map.get(run_id)
        if not scan_id:
            return

        # ``module_name`` (not ``module``) because ``module`` is already a
        # reserved correlation field bound by the orchestrator (log_config).
        bound = logger.bind(run_id=run_id, module_name=module_name, scan_id=scan_id)

        async def _impl() -> None:
            try:
                if module_name.endswith("arp_scan"):
                    await self._save_arp_results(scan_id, module_name, results, bound)
                elif module_name.endswith("port_scan"):
                    if isinstance(results, list):
                        try:
                            await repo.save_port_scan_results(scan_id, results)
                        except SQLAlchemyError:
                            bound.exception("save_port_scan_results failed")
                            PERSISTENCE_ERRORS.labels(
                                module=module_label(module_name)
                            ).inc()
            except Exception:
                bound.exception("_on_module_finished: unexpected error")

        future = asyncio.run_coroutine_threadsafe(_impl(), loop)
        try:
            future.result(timeout=30.0)
        except (asyncio.TimeoutError, concurrent_futures.TimeoutError):
            bound.error("_on_module_finished: coroutine dispatch timed out")
        except Exception:
            bound.exception("_on_module_finished: coroutine dispatch failed")
        state.finished_runs[run_id] = module_name

    async def _save_arp_results(
        self,
        scan_id: str,
        module_name: str,
        results: Any,
        bound: "Logger",
    ) -> None:
        """Normalise and persist ``arp_scan`` raw results as an IP list.

        Args:
            scan_id: The persisted scan id the results belong to.
            module_name: The finished module's name (Prometheus label source).
            results: The child process's raw results object — a pandas
                DataFrame, a list, or something else entirely.
            bound: Logger pre-bound with the failure-path context fields.
        """
        repo = self._state.repo
        if repo is None:
            return
        ip_list: List[str] = []
        try:
            if (
                hasattr(results, "to_dict")
                and hasattr(results, "columns")
                and "IP" in getattr(results, "columns", [])
            ):
                ip_list = [str(x) for x in (results["IP"].tolist() or [])]
        except Exception:  # noqa: BLE001 -- pandas-duck-typing fallback; the
            # ``results`` object may be a DataFrame, a list, or
            # something else entirely; we tolerate every shape
            # by falling through to the ``isinstance(results, list)``
            # branch below.
            ip_list = []
        if not ip_list and isinstance(results, list):
            ip_list = [str(x) for x in results if isinstance(x, (str, int))]
        try:
            await repo.save_arp_scan_results(scan_id, ip_list)
        except SQLAlchemyError:
            bound.exception("save_arp_scan_results failed")
            PERSISTENCE_ERRORS.labels(module=module_label(module_name)).inc()

    def finish_scan(
        self, scan_id: str, status: str, error_message: Optional[str]
    ) -> None:
        """Orchestrator-owned terminal-status sink (Phase 5 / 6.3).

        Called exactly once per scan from :meth:`ModuleManager._finalize_run`
        after the final ``_persist_batch`` flush. Maps the orchestrator's
        string status onto the :class:`ScanStatus` enum and dispatches the
        async ``repo.finish_scan`` coroutine onto the FastAPI event loop.

        HC7 (2026-05-18): error paths log with structured ``extra`` fields
        so the scan_id and target status land in the JSON sink alongside the
        traceback.
        """
        repo = self._state.repo
        loop = self._state.main_loop
        if repo is None or loop is None:
            return
        status_enum = _STATUS_MAP.get(status, ScanStatus.FAILED)
        bound = logger.bind(scan_id=scan_id, target_status=status_enum.value)

        async def _impl() -> None:
            try:
                await repo.finish_scan(
                    scan_id, status=status_enum, error_message=error_message
                )
            except SQLAlchemyError:
                bound.exception("_finish_scan: repo.finish_scan failed")
                PERSISTENCE_ERRORS.labels(module="unknown").inc()
                return

            # F-02 / scan--observability: observe the per-scan wall-clock
            # duration. Cardinality is bounded — see metrics.py docstring.
            try:
                scan_row = await repo.get_scan(scan_id)
            except SQLAlchemyError:
                bound.exception("_finish_scan: post-finish get_scan failed")
                return

            if (
                scan_row is None
                or scan_row.started_at is None
                or scan_row.finished_at is None
            ):
                return
            duration_seconds = (
                scan_row.finished_at - scan_row.started_at
            ).total_seconds()
            if duration_seconds < 0:
                return
            SCAN_DURATION_SECONDS.labels(
                module=module_label(scan_row.module_name),
                status=status_enum.value,
            ).observe(duration_seconds)

        future = asyncio.run_coroutine_threadsafe(_impl(), loop)
        try:
            future.result(timeout=10.0)
        except (asyncio.TimeoutError, concurrent_futures.TimeoutError):
            bound.error("_finish_scan: dispatch timed out")
        except Exception:
            bound.exception("_finish_scan: dispatch failed")

    def persist_scan_findings(
        self, scan_id: str, findings: List[Dict[str, Any]]
    ) -> None:
        """Orchestrator-owned L-02 findings-snapshot sink.

        Called once per scan from :meth:`ModuleManager._finalize_run` with the
        serialised ``DeviceFinding`` dicts the run reported. Persists the
        snapshot onto the :class:`Scan` row so the history detail view can
        replay past results. Dispatches the async ``repo.finish_scan`` write
        onto the FastAPI event loop, preserving the already-set terminal status.
        """
        repo = self._state.repo
        loop = self._state.main_loop
        if repo is None or loop is None:
            return
        bound = logger.bind(scan_id=scan_id, findings=len(findings))

        async def _impl() -> None:
            try:
                scan_row = await repo.get_scan(scan_id)
                if scan_row is None:
                    return
                await repo.finish_scan(
                    scan_id, status=scan_row.status, findings=findings
                )
            except SQLAlchemyError:
                bound.exception("_persist_scan_findings: repo write failed")

        future = asyncio.run_coroutine_threadsafe(_impl(), loop)
        try:
            future.result(timeout=10.0)
        except (asyncio.TimeoutError, concurrent_futures.TimeoutError):
            bound.error("_persist_scan_findings: dispatch timed out")
        except Exception:
            bound.exception("_persist_scan_findings: dispatch failed")

    def persist_findings(
        self, scan_id: str, batch: List[DeviceFinding], result: ScanResult
    ) -> None:
        """Orchestrator-side persistence sink wired into :meth:`ModuleManager._persist_batch`.

        Phase 5 (HC16): each invocation persists the supplied batch as a
        **single transaction** via :meth:`ScannerPostgresRepo.save_findings_batch`,
        rather than the per-row upsert loop the Phase 2 seam used. This is
        what reduces commit count by ≥80 % on the 20-host × 50-port benchmark
        relative to the per-finding shape — each ``_persist_batch`` chunk
        yields one transaction commit instead of two per finding.

        The terminal (final) call additionally folds in
        :meth:`save_port_scan_results` for the legacy port-level
        ``ServiceObservation`` rows that frontend dashboards rely on. That
        call opens its own transaction; for the post-refactor path it is
        one commit, regardless of batch size.

        The repo is async; we dispatch the coroutine onto the FastAPI event
        loop and wait for completion.
        """
        repo = self._state.repo
        loop = self._state.main_loop
        if repo is None or loop is None:
            return

        # ``module_name`` (not ``module``) — stdlib LogRecord reserves
        # ``module`` and would raise KeyError on ``extra=`` collision.
        bound = logger.bind(
            scan_id=scan_id,
            module_name=(
                result.module_name if hasattr(result, "module_name") else None
            ),
            batch_size=len(batch),
        )

        async def _impl() -> None:
            now = datetime.now(tz=timezone.utc)
            protocol = (result.protocol or "").lower()
            module_label_value = module_label(getattr(result, "module_name", None))

            try:
                await repo.save_findings_batch(scan_id, batch, scanned_at=now)
            except SQLAlchemyError:
                bound.exception("_persist_findings: save_findings_batch failed")
                PERSISTENCE_ERRORS.labels(module=module_label_value).inc()

            if protocol == "opcua":
                try:
                    await repo.save_opcua_discover_results(scan_id, batch)
                except SQLAlchemyError:
                    bound.exception(
                        "_persist_findings: save_opcua_discover_results failed",
                    )
                    PERSISTENCE_ERRORS.labels(module=module_label_value).inc()
            elif protocol.endswith("tcp") or protocol.endswith("udp"):
                raw = result.raw_results
                if isinstance(raw, list):
                    try:
                        await repo.save_port_scan_results(scan_id, raw)
                    except SQLAlchemyError:
                        bound.exception(
                            "_persist_findings: save_port_scan_results failed",
                        )
                        PERSISTENCE_ERRORS.labels(module=module_label_value).inc()

        future = asyncio.run_coroutine_threadsafe(_impl(), loop)
        try:
            future.result(timeout=60.0)
        except (asyncio.TimeoutError, concurrent_futures.TimeoutError):
            bound.error("_persist_findings: coroutine dispatch timed out")
        except Exception:
            bound.exception("_persist_findings: coroutine dispatch failed")
