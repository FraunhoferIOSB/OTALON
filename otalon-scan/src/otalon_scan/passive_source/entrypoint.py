"""Process entry-point for the passive asset seeder.

Implements the ``Periodic Poll Cycle``, ``Feature Flag Default-Off``,
``Structured Loguru Observability``, and ``Influx Outage Graceful
Degradation`` requirements from
``openspec/changes/add-passive-asset-seeder/specs/``
``passive-asset-seeding/spec.md``, and design.md decisions
``D-LOGGING`` and ``D-GRACEFUL-DEGRADATION``.

``passive-seeder-runtime-control`` turned the worker into an always-up
supervisor: the disabled state is expressed by idling at the poll
cadence and publishing ``state="disabled"``, never by terminating. The
only remaining legitimate termination is a misconfiguration — an
unparseable environment or a schema revision the code cannot work
against.

Two surfaces are exposed:

- :func:`main_sync` — synchronous wrapper that builds settings, verifies
  the schema revision, sets up the asyncio loop, runs :func:`_main`
  until SIGTERM, and returns the exit code. Used by both the package's
  ``__main__`` and by tests.
- :func:`_main` — the async coroutine that runs the supervisor loop.
  Tests can call it directly with an injected ``InfluxPoller``, runtime
  reader, and status repository to avoid touching real network / DB
  resources.
"""

from __future__ import annotations

import asyncio
import os
import signal
import time
import uuid
from pathlib import Path
from typing import Callable, Optional, Union

from loguru import logger

from .influx_poller import InfluxPoller, InfluxUnreachableError, PollResult
from .mac_filters import is_locally_administered, is_multicast_or_broadcast
from .runtime_config import EffectiveConfig, RuntimeConfigReader
from .runtime_keys import register_runtime_keys
from .settings import PassiveSeederSettings
from .status_repo import (
    STATE_DISABLED,
    STATE_ERROR,
    STATE_RUNNING,
    PassiveSeederStatusRepo,
)

CycleConfig = Union[PassiveSeederSettings, EffectiveConfig]
"""Anything carrying the three per-cycle knobs a poll cycle consumes."""

SCHEMA_MISMATCH_EXIT_CODE: int = 3
"""Exit code used when the live schema revision is not the expected head."""

# Liveness marker touched at the end of every poll cycle. The Docker
# compose healthcheck for ``otalon-scan-passive-seeder`` uses
# ``find <path> -mmin -<n>`` against this file as a process-level
# liveness signal — the worker is NOT an HTTP server, so the
# Dockerfile's default HTTP healthcheck does not apply (bug-cluster
# 2026-05-21).
LIVENESS_MARKER_PATH: Path = Path("/tmp/passive-seeder-last-cycle")


def _touch_liveness_marker() -> None:
    """Update the mtime of :data:`LIVENESS_MARKER_PATH`.

    Best-effort: I/O errors are logged at DEBUG level and swallowed so
    a transient filesystem issue does not crash the worker. Compose
    healthcheck failures from a stale marker will still surface as
    ``(unhealthy)`` via Docker's normal retry policy.
    """
    try:
        LIVENESS_MARKER_PATH.parent.mkdir(parents=True, exist_ok=True)
        LIVENESS_MARKER_PATH.touch(exist_ok=True)
    except OSError as exc:
        logger.debug(
            "passive_seeder: liveness marker update failed path={} exception={}",
            LIVENESS_MARKER_PATH,
            type(exc).__name__,
        )


def _emit_disabled() -> None:
    """Log exactly one INFO line announcing the seeder is disabled.

    Per requirement ``Feature Flag Default-Off`` the line MUST be
    structured and carry ``event=passive_seeder_disabled``. The process
    stays alive and idles at the poll cadence; the disabled state is
    additionally published as a status row so it is observable through
    the api rather than only in the container log.
    """
    logger.info("passive_seeder: disabled (effective enabled=false); idling " "event=passive_seeder_disabled")


def _emit_schema_mismatch(message: str) -> None:
    """Log one ERROR line for a schema revision the code cannot work against.

    The seeder runs as ``python -m otalon_scan.passive_source`` and never reaches
    the FastAPI lifespan that verifies the Alembic head for the scanner
    API, so it performs its own check. The message carries the
    ``run alembic upgrade head`` hint produced by
    :meth:`ScannerPostgresRepo.verify_schema_revision` verbatim so
    operator runbooks can grep for it.
    """
    logger.error(
        "passive_seeder: schema revision check failed message={} " "event=schema_revision_mismatch",
        message,
    )


def _emit_invalid_config(variable: str, message: str) -> None:
    """Log one ERROR line for an invalid configuration value.

    Per requirement ``Environment Variables Contract``, invalid values
    cause the process to exit with code 2 after logging one ERROR
    line identifying the offending variable.
    """
    logger.error(
        "passive_seeder: invalid configuration variable={} message={} " "event=invalid_config",
        variable,
        message,
    )


async def _run_one_cycle(
    *,
    settings: CycleConfig,
    poller: InfluxPoller,
    upsert_callable: object,
    device_upsert_callable: object | None = None,
) -> int:
    """Execute one full poll cycle: Influx query → filter → upsert.

    Returns the number of ``network_interfaces`` rows upserted by this
    cycle so the caller can publish it as ``rows_seeded``.

    Emits exactly one structured INFO line at completion with the
    fields documented in ``D-LOGGING``. On Influx failure, emits one
    WARNING line and skips PostgreSQL writes for the cycle (per
    requirement ``Influx Outage Graceful Degradation``).

    ``upsert_callable`` is the bound
    :meth:`ScannerPostgresRepo.upsert_network_interface`; passed in to
    keep this function trivially testable without depending on
    SQLAlchemy session lifecycles.

    ``device_upsert_callable`` is the bound
    :meth:`ScannerPostgresRepo.upsert_device` (or ``None`` for
    legacy tests that only exercise the interface path). When
    provided, every passive sighting first UPSERTs a ``devices`` row
    keyed on ``primary_mac=<mac>`` and the returned ``device_id`` is
    threaded into the interface UPSERT so the resulting
    ``network_interfaces`` row carries a non-NULL FK. The
    NULL-skipping semantics of :meth:`upsert_device` guarantee that
    a pre-existing active-scan device (with vendor / device_type /
    article_number set) is NOT overwritten by passive observations.
    Bug-cluster 2026-05-21 fix.
    """
    cycle_id = uuid.uuid4().hex
    started = time.monotonic()

    try:
        result: PollResult = await poller.poll_once()
    except InfluxUnreachableError as exc:
        logger.warning(
            "passive_seeder: influx unreachable cycle_id={} reason={!r} " "exception={} event=influx_unreachable",
            cycle_id,
            str(exc),
            type(exc.__cause__).__name__ if exc.__cause__ else "Unknown",
        )
        # Still mark the worker alive so the container healthcheck
        # does NOT flip to ``(unhealthy)`` on a transient Influx
        # outage — the process is fine, the upstream is not.
        _touch_liveness_marker()
        return 0

    macs_seen = len(result.macs)
    filtered_mcast = 0
    filtered_laa = 0
    upserted = 0
    skipped = 0

    # Apply the MAC filter from spec requirement "Multicast and
    # Broadcast MAC Filtering" / design.md D-MAC-FILTER.
    eligible: list[str] = []
    for mac in result.macs:
        try:
            if is_multicast_or_broadcast(mac):
                filtered_mcast += 1
                continue
            if settings.drop_laa and is_locally_administered(mac):
                filtered_laa += 1
                continue
        except ValueError:
            # Malformed MAC string — count as filtered to avoid an
            # infinite retry; the influx query should never produce
            # this but defensive code is cheap.
            filtered_mcast += 1
            continue
        eligible.append(mac)

    for mac in eligible:
        ipv4 = result.mac_to_ipv4.get(mac)
        device_id: int | None = None
        if device_upsert_callable is not None:
            try:
                device_id = await device_upsert_callable(  # type: ignore[operator]
                    primary_mac=mac,
                )
            except Exception as exc:  # noqa: BLE001 - we re-log + continue
                skipped += 1
                logger.warning(
                    "passive_seeder: device upsert failed cycle_id={} mac={} "
                    "exception={} event=device_upsert_failed",
                    cycle_id,
                    mac,
                    type(exc).__name__,
                )
                # Without a device row we still attempt the interface
                # UPSERT — leaving ``device_id=None`` preserves the
                # legacy behaviour and ensures the MAC is at least
                # recorded for the next cycle.
        try:
            await upsert_callable(  # type: ignore[operator]
                mac=mac,
                ipv4=ipv4,
                device_id=device_id,
                source="passive",
            )
            upserted += 1
        except Exception as exc:  # noqa: BLE001 - we re-log + continue
            skipped += 1
            logger.warning(
                "passive_seeder: upsert failed cycle_id={} mac={} " "exception={} event=upsert_failed",
                cycle_id,
                mac,
                type(exc).__name__,
            )

    duration_ms = int((time.monotonic() - started) * 1000)
    logger.info(
        "passive_seeder: cycle finished cycle_id={} lookback_s={} "
        "macs_seen={} macs_filtered_mcast={} macs_filtered_laa={} "
        "interfaces_upserted={} interfaces_skipped={} "
        "uci_malformed={} duration_ms={} next_poll_in_s={} "
        "event=poll_finished",
        cycle_id,
        settings.lookback_window_s,
        macs_seen,
        filtered_mcast,
        filtered_laa,
        upserted,
        skipped,
        result.uci_malformed,
        duration_ms,
        settings.poll_interval_s,
    )
    _touch_liveness_marker()
    return upserted


async def _sleep_or_stop(stop_event: asyncio.Event, seconds: int) -> None:
    """Wait ``seconds`` or return early once ``stop_event`` is set."""
    try:
        await asyncio.wait_for(stop_event.wait(), timeout=seconds)
    except asyncio.TimeoutError:
        return


async def _resolve_cycle_config(
    *,
    settings: PassiveSeederSettings,
    runtime_reader: RuntimeConfigReader | None,
) -> CycleConfig:
    """Return the configuration this cycle runs with.

    Without a reader (legacy call sites and unit tests exercising only the
    poll mechanics) the boot settings are used unchanged.
    """
    if runtime_reader is None:
        return settings
    return await runtime_reader.resolve(settings)


def _apply_lookback(
    poller: InfluxPoller,
    lookback_window_s: int,
    poller_factory: Callable[[int], InfluxPoller] | None,
) -> InfluxPoller:
    """Return a poller reading the effective lookback window.

    :class:`InfluxPoller` binds its window at construction time and is
    deliberately left untouched by this change, so a changed
    ``lookback_window_s`` is applied by rebuilding the poller around the
    same Influx client rather than by mutating it.
    """
    if poller_factory is None or poller.lookback_window_s == lookback_window_s:
        return poller
    logger.info(
        "passive_seeder: lookback window changed from={} to={} " "event=lookback_window_changed",
        poller.lookback_window_s,
        lookback_window_s,
    )
    return poller_factory(lookback_window_s)


async def _record(
    status_repo: PassiveSeederStatusRepo | None,
    *,
    state: str,
    poll_interval_s: int,
    rows_seeded: int = 0,
    last_error: str | None = None,
) -> None:
    """Upsert the status row when a repository is wired, else do nothing."""
    if status_repo is None:
        return
    await status_repo.upsert(
        state=state,
        poll_interval_s=poll_interval_s,
        rows_seeded=rows_seeded,
        last_error=last_error,
    )


async def _supervise_one_iteration(
    *,
    config: CycleConfig,
    poller: InfluxPoller,
    upsert_callable: object,
    device_upsert_callable: object | None,
    status_repo: PassiveSeederStatusRepo | None,
) -> None:
    """Run one enabled iteration and publish its outcome.

    A cycle error is recorded as ``state="error"`` and swallowed so the
    supervisor loop survives it; the liveness marker stays untouched on
    failure, keeping a persistently broken seeder ``(unhealthy)`` to the
    container runtime.
    """
    try:
        rows = await _run_one_cycle(
            settings=config,
            poller=poller,
            upsert_callable=upsert_callable,
            device_upsert_callable=device_upsert_callable,
        )
    except Exception as exc:  # noqa: BLE001 - the loop must survive any cycle error
        logger.error(
            "passive_seeder: cycle failed exception={} reason={!r} " "event=cycle_failed",
            type(exc).__name__,
            str(exc),
        )
        await _record(
            status_repo,
            state=STATE_ERROR,
            poll_interval_s=config.poll_interval_s,
            last_error=str(exc),
        )
        return
    await _record(
        status_repo,
        state=STATE_RUNNING,
        poll_interval_s=config.poll_interval_s,
        rows_seeded=rows,
    )


async def _main(
    *,
    settings: PassiveSeederSettings,
    poller: InfluxPoller,
    upsert_callable: object,
    device_upsert_callable: object | None = None,
    stop_event: Optional[asyncio.Event] = None,
    runtime_reader: RuntimeConfigReader | None = None,
    status_repo: PassiveSeederStatusRepo | None = None,
    poller_factory: Callable[[int], InfluxPoller] | None = None,
) -> int:
    """Run the always-up supervisor loop until ``stop_event`` is set.

    Every iteration resolves the hot keys first and applies them to that
    iteration. When the effective enabled flag is false the iteration
    issues no InfluxDB query and performs no inventory write; it records
    ``state="disabled"`` and idles at the effective cadence. Returns
    ``0`` on clean shutdown.
    """
    stop_event = stop_event or asyncio.Event()
    logger.info(
        "passive_seeder: supervisor started poll_interval_s={} "
        "lookback_window_s={} drop_laa={} event=passive_seeder_started",
        settings.poll_interval_s,
        settings.lookback_window_s,
        settings.drop_laa,
    )

    was_disabled = False
    while not stop_event.is_set():
        config = await _resolve_cycle_config(settings=settings, runtime_reader=runtime_reader)
        if not config.enabled:
            if not was_disabled:
                _emit_disabled()
            was_disabled = True
            await _record(status_repo, state=STATE_DISABLED, poll_interval_s=config.poll_interval_s)
        else:
            was_disabled = False
            poller = _apply_lookback(poller, config.lookback_window_s, poller_factory)
            await _supervise_one_iteration(
                config=config,
                poller=poller,
                upsert_callable=upsert_callable,
                device_upsert_callable=device_upsert_callable,
                status_repo=status_repo,
            )
        await _sleep_or_stop(stop_event, config.poll_interval_s)

    logger.info("passive_seeder: stop requested event=passive_seeder_stopped")
    return 0


def _build_influx_client(settings: PassiveSeederSettings) -> object:
    """Construct an Influx v3 client from the seeder settings.

    Isolated so unit tests can monkey-patch this factory without
    importing the heavy client. Returns ``object`` to keep the type
    surface free of the real ``InfluxDBClient3`` import in modules
    that do not actually need it.
    """
    from influxdb_client_3 import InfluxDBClient3  # local import on purpose

    # influxdb3_python is published without type hints; the constructor
    # is therefore typed as ``Any`` and mypy --strict flags it as an
    # untyped call. Silence narrowly here rather than weakening the
    # whole strict baseline.
    return InfluxDBClient3(  # type: ignore[no-untyped-call]
        host=settings.influx_url,
        token=settings.influx_token or "",
        database=settings.influx_bucket,
    )


def _build_repo(dsn: str) -> object:
    """Construct the ScannerPostgresRepo from a DSN.

    Local import keeps the SQLAlchemy stack out of the import graph
    of tests that exercise only the poll loop with a stub upsert
    callable.
    """
    from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo

    return ScannerPostgresRepo(dsn=dsn)


async def verify_schema_revision(repo: object) -> str | None:
    """Return an error message when the live schema is not the expected head.

    Returns ``None`` when the revision matches. The seeder never runs the
    FastAPI lifespan that performs this check for the scanner API, so it
    owns the check itself; the repository method is reused verbatim so the
    expected-revision constant and the ``run alembic upgrade head`` hint
    cannot drift between the two entry points.
    """
    try:
        await repo.verify_schema_revision()  # type: ignore[attr-defined]
    except RuntimeError as exc:
        return str(exc)
    return None


def _install_signal_handlers(loop: asyncio.AbstractEventLoop, stop_event: asyncio.Event) -> None:
    """Wire SIGTERM/SIGINT to flip *stop_event* on *loop*."""

    def _request_stop(signum: int, _frame: object) -> None:
        logger.info(
            "passive_seeder: signal received signum={} event=signal_received",
            signum,
        )
        loop.call_soon_threadsafe(stop_event.set)

    signal.signal(signal.SIGTERM, _request_stop)
    signal.signal(signal.SIGINT, _request_stop)


def _build_poller_factory(
    client: object,
    settings: PassiveSeederSettings,
) -> Callable[[int], InfluxPoller]:
    """Return a factory rebuilding the poller for a new lookback window."""

    def _factory(lookback_window_s: int) -> InfluxPoller:
        return InfluxPoller(
            client=client,  # type: ignore[arg-type]
            database=settings.influx_bucket,
            lookback_window_s=lookback_window_s,
        )

    return _factory


def main_sync() -> int:
    """Synchronous entry point invoked by ``python -m otalon_scan.passive_source``.

    Steps:

    1. Build :class:`PassiveSeederSettings` from the environment. On
       :class:`pydantic.ValidationError`, log one ERROR line per
       offending variable and exit with code 2.
    2. Resolve the PostgreSQL DSN; exit 2 when it is absent.
    3. Verify the Alembic head; on mismatch log the upgrade hint and
       exit non-zero. This is the only remaining termination path
       besides misconfiguration — a disabled seeder idles instead.
    4. Register the runtime keys, build the Influx client, the repo, the
       runtime reader, and the status repository, install SIGINT/SIGTERM
       handlers, and run :func:`_main` to completion.
    """
    try:
        settings = PassiveSeederSettings()
    except Exception as exc:  # ValidationError or env-loading errors
        _emit_invalid_config("PASSIVE_SEEDER_*", str(exc))
        return 2

    dsn = os.environ.get("POSTGRES_DSN", "")
    if not dsn:
        _emit_invalid_config("POSTGRES_DSN", "not set")
        return 2

    register_runtime_keys()
    repo = _build_repo(dsn)
    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    try:
        mismatch = loop.run_until_complete(verify_schema_revision(repo))
        if mismatch is not None:
            _emit_schema_mismatch(mismatch)
            return SCHEMA_MISMATCH_EXIT_CODE
        return loop.run_until_complete(_run_supervisor(settings=settings, repo=repo))
    finally:
        loop.close()


async def _run_supervisor(*, settings: PassiveSeederSettings, repo: object) -> int:
    """Wire the collaborators and run the supervisor loop to completion."""
    client = _build_influx_client(settings)
    poller_factory = _build_poller_factory(client, settings)
    stop_event = asyncio.Event()
    _install_signal_handlers(asyncio.get_running_loop(), stop_event)
    engine = repo.engine  # type: ignore[attr-defined]
    return await _main(
        settings=settings,
        poller=poller_factory(settings.lookback_window_s),
        upsert_callable=repo.upsert_network_interface,  # type: ignore[attr-defined]
        device_upsert_callable=repo.upsert_device,  # type: ignore[attr-defined]
        stop_event=stop_event,
        runtime_reader=RuntimeConfigReader(engine),
        status_repo=PassiveSeederStatusRepo(engine),
        poller_factory=poller_factory,
    )
