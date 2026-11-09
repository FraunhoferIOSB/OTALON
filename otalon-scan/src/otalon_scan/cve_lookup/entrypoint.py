"""Process entry-point for the CVE lookup auto-loop worker.

Follows the ``passive_seeder`` pattern:

- :func:`main_sync` — synchronous wrapper that builds settings, sets up
  the asyncio loop, runs :func:`_main` until SIGTERM, and returns the
  exit code.
- :func:`_main` — the async coroutine that runs the lookup loop.
- :func:`_run_one_cycle` — stateless: eligible assets → NVD → upsert.

Liveness is signalled via a touch-file so the Docker compose
healthcheck can observe the worker without an HTTP port.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from loguru import logger

from .core import run_lookup
from .settings import CveLookupSettings
from .sources.nvd import NvdSource
from .status_repo import CveLookupStatusRepo

# Liveness marker touched at the end of every lookup cycle.  The Docker
# compose healthcheck for ``otalon-scan-cve-lookup`` uses
# ``find <path> -mmin -<n>`` against this file.
LIVENESS_MARKER_PATH: Path = Path("/tmp/cve-lookup-last-cycle")


def _touch_liveness_marker() -> None:
    """Update the mtime of :data:`LIVENESS_MARKER_PATH`.

    Best-effort: I/O errors are logged at DEBUG level and swallowed.
    """
    try:
        LIVENESS_MARKER_PATH.parent.mkdir(parents=True, exist_ok=True)
        LIVENESS_MARKER_PATH.touch(exist_ok=True)
    except OSError as exc:
        logger.debug(
            "cve_lookup: liveness marker update failed path={} exception={}",
            LIVENESS_MARKER_PATH,
            type(exc).__name__,
        )


STATE_RUNNING = "running"
STATE_DISABLED = "disabled"
STATE_ERROR = "error"


@dataclass(frozen=True)
class CycleOutcome:
    """Outcome persisted after one lookup cycle."""

    findings_count: int = 0
    error: str | None = None


def _emit_disabled() -> None:
    """Log one INFO line announcing that worker is idling disabled."""
    logger.info("cve_lookup: disabled (CVE_LOOKUP_ENABLED=false); idling " "event=cve_lookup_disabled")


def _emit_invalid_config(variable: str, message: str) -> None:
    """Log one ERROR line for an invalid configuration value."""
    logger.error(
        "cve_lookup: invalid configuration variable={} message={} " "event=invalid_config",
        variable,
        message,
    )


def _emit_schema_mismatch(message: str) -> None:
    """Log schema mismatch while preserving operator upgrade hint."""
    logger.error(
        "cve_lookup: schema revision check failed message={} event=schema_revision_mismatch",
        message,
    )


async def _run_one_cycle(
    *,
    settings: CveLookupSettings,
    lookup_assets_callable: object,
    persist_callable: object,
) -> CycleOutcome:
    """Execute one full lookup cycle: eligible assets → NVD → upsert.

    ``lookup_assets_callable`` is the bound
    :meth:`ScannerPostgresRepo.lookup_eligible_assets`.

    ``persist_callable`` is the bound
    :meth:`VulnerabilityObservationRepo.persist_lookup_result`.
    """
    cycle_id = uuid.uuid4().hex
    started = time.monotonic()

    try:
        assets: list[object] = await lookup_assets_callable()  # type: ignore[operator]
    except Exception as exc:  # noqa: BLE001 - loop must survive
        logger.warning(
            "cve_lookup: asset query failed cycle_id={} exception={} " "event=asset_query_failed",
            cycle_id,
            type(exc).__name__,
        )
        _touch_liveness_marker()
        return CycleOutcome(error=str(exc))

    eligible = len(assets)
    if not assets:
        logger.info(
            "cve_lookup: no eligible assets cycle_id={} event=no_eligible_assets",
            cycle_id,
        )
        _touch_liveness_marker()
        return CycleOutcome()

    source = NvdSource(api_key=settings.nvd_api_key)
    result = await run_lookup(assets, source)  # type: ignore[arg-type]

    # Persist requires a synthetic scan row.  The caller-facing
    # ``persist_callable`` is a tiny wrapper that creates the scan,
    # calls persist_lookup_result, and finishes the scan.
    try:
        written = await persist_callable(cycle_id, result)  # type: ignore[operator]
    except Exception as exc:  # noqa: BLE001 - loop must survive
        logger.warning(
            "cve_lookup: persist failed cycle_id={} exception={} " "event=persist_failed",
            cycle_id,
            type(exc).__name__,
        )
        _touch_liveness_marker()
        return CycleOutcome(error=str(exc))

    duration_ms = int((time.monotonic() - started) * 1000)
    assets_with_hits = sum(1 for a in result.per_asset if a.hits)
    logger.info(
        "cve_lookup: cycle finished cycle_id={} eligible={} "
        "checked={} hits={} written={} assets_with_hits={} "
        "duration_ms={} next_cycle_in_s={} event=lookup_finished",
        cycle_id,
        eligible,
        result.assets_checked,
        result.total_hits,
        written,
        assets_with_hits,
        duration_ms,
        settings.interval_s,
    )
    _touch_liveness_marker()
    return CycleOutcome(findings_count=result.total_hits)


async def _record_status(
    status_repo: CveLookupStatusRepo | None,
    *,
    outcome: CycleOutcome,
    interval_s: int,
) -> None:
    """Persist cycle outcome when status repository is configured."""
    if status_repo is None:
        return
    await status_repo.upsert(
        state=STATE_ERROR if outcome.error else STATE_RUNNING,
        interval_s=interval_s,
        findings_count=outcome.findings_count,
        last_error=outcome.error,
    )


async def verify_schema_revision(repo: object) -> str | None:
    """Return schema mismatch message, or ``None`` when schema is current."""
    try:
        await repo.verify_schema_revision()  # type: ignore[attr-defined]
    except RuntimeError as exc:
        return str(exc)
    return None


async def _main(
    *,
    settings: CveLookupSettings,
    lookup_assets_callable: object,
    persist_callable: object,
    stop_event: Optional[asyncio.Event] = None,
    status_repo: CveLookupStatusRepo | None = None,
) -> int:
    """Run the lookup loop until ``stop_event`` is set.

    Returns ``0`` on clean shutdown.
    """
    stop_event = stop_event or asyncio.Event()
    logger.info(
        "cve_lookup: supervisor started interval_s={} nvd_key={} event=cve_lookup_started",
        settings.interval_s,
        "yes" if settings.nvd_api_key else "no",
    )

    was_disabled = False
    while not stop_event.is_set():
        if not settings.enabled:
            if not was_disabled:
                _emit_disabled()
            was_disabled = True
            if status_repo is not None:
                await status_repo.upsert(state=STATE_DISABLED, interval_s=settings.interval_s)
            _touch_liveness_marker()
        else:
            was_disabled = False
            try:
                outcome = await _run_one_cycle(
                    settings=settings,
                    lookup_assets_callable=lookup_assets_callable,
                    persist_callable=persist_callable,
                )
            except Exception as exc:  # noqa: BLE001 - supervisor must survive a cycle error
                logger.error(
                    "cve_lookup: cycle failed exception={} reason={!r} event=cycle_failed",
                    type(exc).__name__,
                    str(exc),
                )
                outcome = CycleOutcome(error=str(exc))
            await _record_status(status_repo, outcome=outcome, interval_s=settings.interval_s)
        try:
            await asyncio.wait_for(
                stop_event.wait(),
                timeout=settings.interval_s,
            )
        except asyncio.TimeoutError:
            continue

    logger.info("cve_lookup: stop requested event=cve_lookup_stopped")
    return 0


def _build_repo(dsn: str) -> object:
    """Construct the ScannerPostgresRepo from a DSN."""
    from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo

    return ScannerPostgresRepo(dsn=dsn)


def _build_persist_callable(repo: object) -> object:
    """Return a callable that creates a scan, persists the result, and finishes.

    Isolated so tests can inject a no-op stub.
    """

    from otalon_scan.repositories.models import ScanStatus
    from otalon_scan.repositories.vulnerability_observation_repo import (
        VulnerabilityObservationRepo,
    )

    async def _persist(cycle_id: str, result: object) -> int:
        r = repo
        scan_id = await r.start_scan(  # type: ignore[attr-defined]
            module_name="cve_lookup",
            parameters={"trigger": "auto", "cycle_id": cycle_id},
        )
        vuln_repo = VulnerabilityObservationRepo(r)  # type: ignore[arg-type]
        written = await vuln_repo.persist_lookup_result(
            scan_id=scan_id,
            result=result,  # type: ignore[arg-type]
        )
        await r.finish_scan(scan_id, ScanStatus.COMPLETED)  # type: ignore[attr-defined]
        return written

    return _persist


def main_sync() -> int:
    """Synchronous entry point invoked by ``python -m otalon_scan.cve_lookup``.

    Steps:

    1. Build :class:`CveLookupSettings` from the environment.  On
       :class:`pydantic.ValidationError`, log one ERROR line and exit
       with code 2.
    2. Build the repo even when disabled so status remains observable.
    3. Verify schema and install SIGINT/SIGTERM handlers that
       flip the asyncio ``stop_event``, and run :func:`_main`.
    """
    try:
        settings = CveLookupSettings()
    except Exception as exc:
        _emit_invalid_config("CVE_LOOKUP_*", str(exc))
        return 2

    dsn = os.environ.get("POSTGRES_DSN", "")
    if not dsn:
        _emit_invalid_config("POSTGRES_DSN", "not set")
        return 2

    repo = _build_repo(dsn)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    try:
        mismatch = loop.run_until_complete(verify_schema_revision(repo))
        if mismatch is not None:
            _emit_schema_mismatch(mismatch)
            return 3
        persist_callable = _build_persist_callable(repo)
        stop_event = asyncio.Event()

        def _request_stop(signum: int, _frame: object) -> None:
            logger.info(
                "cve_lookup: signal received signum={} event=signal_received",
                signum,
            )
            loop.call_soon_threadsafe(stop_event.set)

        signal.signal(signal.SIGTERM, _request_stop)
        signal.signal(signal.SIGINT, _request_stop)
        return loop.run_until_complete(
            _main(
                settings=settings,
                lookup_assets_callable=repo.lookup_eligible_assets,  # type: ignore[attr-defined]
                persist_callable=persist_callable,
                stop_event=stop_event,
                status_repo=CveLookupStatusRepo(repo.engine),  # type: ignore[attr-defined]
            )
        )
    finally:
        loop.close()
