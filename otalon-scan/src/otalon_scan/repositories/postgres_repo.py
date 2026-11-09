"""Async PostgreSQL repository for CyberScan-ICS scan results.

Phase 4 (HC5) — async-first persistence.

This module is the sole DB writer in the production path. All methods are
``async def`` and use SQLAlchemy 2.x :class:`~sqlalchemy.ext.asyncio.AsyncSession`
via :class:`~sqlalchemy.ext.asyncio.async_sessionmaker`. The PostgreSQL driver
is ``asyncpg`` (D1 resolved 2026-05-17). Sync :class:`~sqlalchemy.orm.Session`
MUST NOT be used in production code paths (capability
``scan--persistence-ownership`` § "Async Repository Interface").

Session lifecycle conventions:

- One :class:`AsyncSession` per logical write operation (open via
  ``async with self._Session() as session: async with session.begin(): ...``)
- Never share a session across ``await`` boundaries outside its ``async with``
- Engine pool sized via ``pool_size`` / ``max_overflow`` constructor args

The orchestrator (:class:`~otalon_scan.core.module_manager.ModuleManager`) calls into
this repo from its persistence sink. The sink itself is invoked from a
background monitor thread (the multiprocessing finalisation path) and uses
``asyncio.run_coroutine_threadsafe`` to dispatch into the FastAPI event loop;
see ``src/otalon_scan/api/server.py``.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Literal, Optional, Sequence, Union, cast
from uuid import UUID, uuid4

from loguru import logger
from sqlalchemy import CursorResult, and_, case
from sqlalchemy import cast as sa_cast
from sqlalchemy import delete, func, select
from sqlalchemy.dialects.postgresql import INET
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.exc import IntegrityError, SQLAlchemyError
from sqlalchemy.ext.asyncio import (
    AsyncEngine,
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.sql import ColumnElement

from otalon_scan.cve_lookup import DeviceIdentity, EligibilityResult, select_eligible
from otalon_scan.cve_lookup.sources.base import LookupAsset

from .exceptions import IdentityCollisionError
from .models import (
    CveLookup,
    CveLookupStatus,
    Device,
    NetworkInterface,
    Scan,
    ScanStatus,
    ServiceObservation,
    VulnerabilityObservation,
    VulnStatus,
)

# Local alias so the long ``func.coalesce(...)`` invocations inside the
# F-03 UPSERT helpers stay readable. ``sa_func_coalesce`` is preferred
# over a bare ``coalesce`` import to keep the symbol grep-able.
sa_func_coalesce = func.coalesce

# SCAN-023: the identity fields an operator may manually override and
# lock against scan-overwrite. A field listed in
# ``devices.manual_identity_fields`` is preserved verbatim by
# :meth:`ScannerPostgresRepo.upsert_device`; unlocked fields keep the
# NULL-skipping COALESCE merge. ``description`` / ``device_role`` are
# intentionally NOT lockable — they are descriptive metadata, not asset
# identity.
MANUAL_IDENTITY_FIELDS: tuple[str, ...] = (
    "vendor",
    "device_family",
    "device_type",
    "article_number",
    "firmware_version",
    "product_name",
    "hw_version",
    "sw_version",
)


def _identity_update_set(stmt: Any) -> dict[str, Any]:
    """Build the lock-aware ON CONFLICT update map for identity fields.

    SCAN-023: for each lockable identity field, emit a per-row
    ``CASE WHEN devices.manual_identity_fields ? '<field>'
    THEN devices.<field>   -- operator-locked: keep manual value
    ELSE COALESCE(EXCLUDED.<field>, devices.<field>)   -- NULL-skip merge``
    so a locked field is never clobbered by a subsequent scan while an
    unlocked/empty field still auto-fills. Shared by both
    ``primary_mac``-keyed UPSERT paths (``upsert_device`` and the
    batched ``save_findings_batch`` path) so the lock semantics cannot
    drift between them.

    Args:
        stmt: The ``pg_insert(Device)`` statement (provides ``.excluded``).

    Returns:
        Mapping of identity-field name to its lock-aware SQL expression,
        suitable for merging into the ``on_conflict_do_update`` ``set_``.
    """
    update_set: dict[str, Any] = {}
    for field in MANUAL_IDENTITY_FIELDS:
        excluded_col = getattr(stmt.excluded, field)
        existing_col = getattr(Device, field)
        locked = Device.manual_identity_fields.op("?")(field)
        update_set[field] = case(
            (locked, existing_col),
            else_=sa_func_coalesce(excluded_col, existing_col),
        )
    return update_set


# Fields merged from a DeviceFinding onto an existing Device row by
# :func:`_merge_device_finding` (SC-07). Mirrors the column set the
# ``primary_mac`` UPSERT path writes, plus ``notes`` (descriptive metadata
# carried by the legacy blind-INSERT branch).
_DEVICE_FINDING_MERGE_FIELDS: tuple[str, ...] = (
    "hostname",
    "vendor",
    "device_family",
    "device_type",
    "description",
    "article_number",
    "device_role",
    "firmware_version",
    "product_name",
    "hw_version",
    "sw_version",
    "serial_number",
    "notes",
)


def _merge_device_finding(device: Device, finding: Any, now: datetime) -> None:
    """Merge a device finding onto an existing :class:`Device` row in place.

    SC-07: ORM-side counterpart of the lock-aware ``ON CONFLICT`` update set
    (:func:`_identity_update_set`) used by the ``primary_mac`` UPSERT paths,
    for the MAC-less branch of ``save_findings_batch`` where no natural key
    exists. Semantics:

    - a field listed in ``device.manual_identity_fields`` (SCAN-023 operator
      lock) keeps its stored value;
    - every other field follows the NULL-skipping merge — a non-NULL
      incoming value overwrites, NULL preserves;
    - ``last_scan_at`` always advances.

    Args:
        device: The existing ORM row (must be session-bound).
        finding: The :class:`~otalon_scan.core.models.DeviceFinding`-shaped source.
        now: Timestamp stamped onto ``last_scan_at``.
    """
    locked = set(device.manual_identity_fields or []) & set(MANUAL_IDENTITY_FIELDS)
    for field in _DEVICE_FINDING_MERGE_FIELDS:
        if field in locked:
            continue
        value = getattr(finding, field, None)
        if value is not None:
            setattr(device, field, value)
    device.last_scan_at = now


class ParentRowMissingError(ValueError):
    """Raised by the F-01 UPSERT helpers when a FK parent row is absent.

    F-01 ships only the leaf helpers (:meth:`ScannerPostgresRepo.upsert_service_observation`
    and :meth:`ScannerPostgresRepo.upsert_vulnerability_observation`). The
    parent-row helpers (``upsert_device``/``upsert_network_interface`` with
    the F-03 device-identity strategy) are owned by F-03. Until F-03
    lands, callers MUST insert / upsert parent rows themselves before
    invoking the leaf helpers; if the parent row is missing this
    exception surfaces a clear pointer to the F-01 ↔ F-03 boundary
    rather than letting an opaque ``ForeignKeyViolation`` bubble up.

    See design.md § D-F03-PREREQ.
    """

    def __init__(
        self,
        *,
        constraint: str | None,
        parent_table: str,
        message: str,
    ) -> None:
        """Initialise the typed FK-missing error.

        Args:
            constraint: Name of the FK constraint that raised, when
                available from the original ``IntegrityError``.
            parent_table: Logical parent table the caller must populate
                first (``network_interfaces`` for service observations,
                ``devices`` for vulnerability observations).
            message: Human-readable description that names the missing
                FK and the helper owning the next step (F-03).
        """
        super().__init__(message)
        self.constraint = constraint
        self.parent_table = parent_table


_LOCALIZED_TEXT_RE = re.compile(r"""Text=(?:'([^']*)'|"([^"]*)")""")


def _clean_localized_text(value: Optional[str]) -> Optional[str]:
    """Extract inner text from an asyncua ``LocalizedText`` repr.

    asyncua renders ``LocalizedText`` as
    ``LocalizedText(Locale=None, Text='PLC_1')``; this returns the inner
    ``PLC_1``. A plain string is returned unchanged (defensive duplicate of
    :func:`otalon_scan.modules.opcua_discover.start.clean_localized_text` so the
    persistence layer is robust to upstream findings that bypass the
    source-side cleanup).
    """
    if value is None:
        return None
    match = _LOCALIZED_TEXT_RE.search(value)
    if match is None:
        return value
    return match.group(1) if match.group(1) is not None else match.group(2)


def _read_arp_table_map() -> Dict[str, str]:
    """Read system ARP table and return mapping ip->mac (Linux /proc/net/arp)."""
    mapping: Dict[str, str] = {}
    try:
        path = "/proc/net/arp"
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                next(f, None)  # header
                for line in f:
                    fields = line.split()
                    if len(fields) >= 4:
                        ip = fields[0].strip()
                        mac = fields[3].strip()
                        if ip and mac and mac != "00:00:00:00:00:00":
                            mapping[ip] = mac
    except OSError:
        # best-effort: filesystem read failure tolerated
        pass
    return mapping


def _to_async_dsn(dsn: str) -> str:
    """Rewrite a sync ``postgresql://`` or ``postgresql+psycopg2://`` DSN to
    ``postgresql+asyncpg://`` while leaving an already-async DSN untouched.

    asyncpg does not accept the ``sslmode`` query parameter that libpq uses;
    callers configuring TLS SHALL use asyncpg's native ``ssl=...`` argument.
    """
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    if dsn.startswith("postgresql+psycopg2://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql+psycopg2://") :]
    if dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql://") :]
    if dsn.startswith("postgres://"):
        return "postgresql+asyncpg://" + dsn[len("postgres://") :]
    return dsn


class ScannerPostgresRepo:
    """Async repository for persisting ICS/OT scan results into PostgreSQL.

    Responsibilities:

    - Initialize the schema (idempotent) and provide async sessions
    - Track scan executions (start/finish), including ``cancelled_partial``
      (D4 resolved 2026-05-17) — surfaced as :class:`ScanStatus` values
    - Upsert device and network-interface entities
    - Persist service and vulnerability observations
    - Transform scanner module outputs (ARP, Portscan, SNMP, ...) into the
      relational model

    All write methods are coroutines. The persistence-ownership invariant
    (capability ``scan--persistence-ownership``) forbids module-level imports
    of this class; only :class:`~otalon_scan.core.module_manager.ModuleManager` and
    the API layer may construct or invoke it.
    """

    def __init__(
        self,
        dsn: Optional[str] = None,
        *,
        pool_size: int = 5,
        max_overflow: int = 10,
    ) -> None:
        """Initialize the async repository.

        Args:
            dsn: PostgreSQL DSN. Synchronous DSNs (``postgresql://...``) are
                rewritten to the asyncpg variant transparently. If omitted,
                the ``POSTGRES_DSN`` env var is consulted.
            pool_size: Per-process baseline connection count (asyncpg pool).
            max_overflow: Additional burst connections beyond ``pool_size``.

        Raises:
            ValueError: when no DSN is supplied and the env var is unset.
        """
        raw = dsn or os.getenv("POSTGRES_DSN")
        if not raw:
            raise ValueError("PostgreSQL DSN not provided and POSTGRES_DSN not set in environment.")
        self.dsn: str = _to_async_dsn(raw)
        self.engine: AsyncEngine = create_async_engine(
            self.dsn,
            pool_pre_ping=True,
            pool_size=pool_size,
            max_overflow=max_overflow,
        )
        self._Session: async_sessionmaker[AsyncSession] = async_sessionmaker(
            bind=self.engine,
            expire_on_commit=False,
        )

    # ---- Schema management ----

    # F-01: the legacy "create everything on startup via
    # Base.metadata.create_all" path was removed in
    # ``refactor-otalon-scan-persistence-pipeline-v1``. Schema is now
    # managed by Alembic; the application MUST be started against a
    # pre-migrated database. ``ensure_schema`` is kept as a thin wrapper
    # over :meth:`verify_schema_revision` so the existing FastAPI
    # lifespan call (api/server.py § lifespan) keeps working without
    # any callers reaching back for ``create_all``.

    # The expected head revision SHALL match the latest revision in
    # ``alembic/versions/``. When new migrations land they SHALL bump
    # this constant in the same commit so a misaligned deployment fails
    # loudly at startup instead of running against a stale schema.
    EXPECTED_ALEMBIC_REVISION: str = "0015"

    async def verify_schema_revision(self) -> None:
        """Verify that the live DB has been migrated to the expected head.

        Reads ``alembic_version.version_num`` from the database and
        compares it with :attr:`EXPECTED_ALEMBIC_REVISION`.

        Raises:
            RuntimeError: when the ``alembic_version`` table is missing
                or its value disagrees with the expected head. The
                message contains the resolution hint
                ``"run alembic upgrade head"`` so operator runbooks can
                grep for it.
        """
        expected = self.EXPECTED_ALEMBIC_REVISION
        try:
            async with self.engine.connect() as conn:
                res = await conn.exec_driver_sql("SELECT version_num FROM alembic_version")
                row = res.first()
        except SQLAlchemyError as exc:
            raise RuntimeError(
                "alembic_version table not found — run alembic upgrade head "
                f"from otalon-scan/ to apply revision {expected} "
                f"(underlying error: {exc})"
            ) from exc
        if row is None:
            raise RuntimeError(
                "alembic_version table is empty — run alembic upgrade head "
                f"from otalon-scan/ to apply revision {expected}"
            )
        current = str(row[0])
        if current != expected:
            raise RuntimeError(
                f"alembic_version mismatch: live DB at revision {current!r}, "
                f"expected {expected!r} — run alembic upgrade head from otalon-scan/ "
                f"to bring the schema in sync"
            )

    async def ensure_schema(self) -> None:
        """Compatibility shim: verify the alembic head, do NOT create schema.

        F-01: ``Base.metadata.create_all`` is removed. Callers used to
        invoke this method from the FastAPI lifespan to bring up the
        schema; that responsibility now belongs to ``alembic upgrade
        head`` (see ``otalon-scan/alembic/README.md``). Keeping the
        method as a thin wrapper preserves the lifespan call-site (see
        ``src/otalon_scan/api/server.py`` § lifespan) while making the failure mode
        explicit: if the DB is not migrated, this raises ``RuntimeError``
        and the lifespan exits non-zero.
        """
        await self.verify_schema_revision()

    # ---- Scan lifecycle ----

    async def start_scan(
        self,
        module_name: str,
        source_ip: Optional[str] = None,
        source_mac: Optional[str] = None,
        parameters: Optional[Dict[str, Any]] = None,
    ) -> UUID:
        """Create a new :class:`Scan` record with ``RUNNING`` status.

        Returns:
            The generated scan UUID.
        """
        scan_id = uuid4()
        async with self._Session() as session:
            async with session.begin():
                session.add(
                    Scan(
                        id=scan_id,
                        module_name=module_name,
                        status=ScanStatus.RUNNING,
                        source_ip=source_ip,
                        source_mac=source_mac,
                        parameters=dict(parameters or {}),
                        started_at=datetime.now(tz=timezone.utc),
                    )
                )
        return scan_id

    async def finish_scan(
        self,
        scan_id: Union[UUID, str],
        status: ScanStatus,
        error_message: Optional[str] = None,
        findings: Optional[List[Dict[str, Any]]] = None,
    ) -> None:
        """Finalize a :class:`Scan` record: set status, finished_at, and
        optional error message + findings snapshot.

        Idempotent: re-finishing an already-finished scan overwrites the
        terminal state (the orchestrator may transition RUNNING → SUCCESS
        and later CANCELLED → CANCELLED_PARTIAL on D4 flush).

        Args:
            scan_id: The scan UUID to finalize.
            status: Terminal :class:`ScanStatus`.
            error_message: Optional error detail (only set when truthy).
            findings: Optional L-02 point-in-time findings snapshot (a list
                of ``DeviceFinding`` dicts) persisted onto the row so the
                history detail view can replay what the scan reported. Only
                written when a non-``None`` list is supplied so a later
                idempotent re-finish without findings does not erase it.
        """
        sid = UUID(str(scan_id))
        async with self._Session() as session:
            async with session.begin():
                scan = await session.get(Scan, sid)
                if not scan:
                    return
                scan.status = status
                scan.finished_at = datetime.now(tz=timezone.utc)
                if error_message:
                    scan.error_message = error_message
                if findings is not None:
                    scan.findings = findings

    # ---- CVE-lookup job lifecycle (SCAN-026 Welle A, WA.2) ----

    async def start_lookup(
        self,
        *,
        scope: str,
        source: str = "nvd",
        api_key_used: bool = False,
        device_id: Optional[int] = None,
    ) -> UUID:
        """Create a new :class:`CveLookup` job-header with ``RUNNING`` status.

        Mirrors :meth:`start_scan`: the row is persisted immediately with
        ``status=running`` and ``started_at`` stamped so the job is
        trackable from the moment it is dispatched (design.md § D2 step 2).

        Args:
            scope: ``"all"`` or ``"device"`` (CONCEPT §6).
            source: CVE provider that will be queried (``"nvd"`` |
                ``"cert_vde"``).
            api_key_used: Whether an API key was supplied to the source —
                feeds the V2 rate-limit box.
            device_id: Best-effort device PK for a per-device lookup;
                ``None`` for ``scope='all'``.

        Returns:
            The generated lookup job UUID (the ``job_id``).
        """
        lookup_id = uuid4()
        async with self._Session() as session:
            async with session.begin():
                session.add(
                    CveLookup(
                        id=lookup_id,
                        scope=scope,
                        source=source,
                        api_key_used=api_key_used,
                        device_id=device_id,
                        status=CveLookupStatus.RUNNING,
                        started_at=datetime.now(tz=timezone.utc),
                    )
                )
        return lookup_id

    async def finish_lookup(
        self,
        lookup_id: Union[UUID, str],
        status: CveLookupStatus,
        summary: Optional[Dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        """Finalize a :class:`CveLookup` job-header.

        Mirrors :meth:`finish_scan`: sets the terminal ``status``,
        stamps ``finished_at``, and writes the aggregated ``summary``
        (on success) or the ``error`` text (on failure). Idempotent — a
        missing row is a silent no-op (the job may have been reconciled
        away on a prior crash-recovery pass).

        Args:
            lookup_id: The job UUID returned by :meth:`start_lookup`.
            status: Terminal :class:`CveLookupStatus`
                (``completed`` / ``failed``).
            summary: Aggregated job summary (CONCEPT §6 shape); written
                verbatim into the ``summary`` jsonb column.
            error: Failure text; written into ``error`` on a failed job.
        """
        lid = UUID(str(lookup_id))
        async with self._Session() as session:
            async with session.begin():
                lookup = await session.get(CveLookup, lid)
                if not lookup:
                    return
                lookup.status = status
                lookup.finished_at = datetime.now(tz=timezone.utc)
                if summary is not None:
                    lookup.summary = dict(summary)
                if error:
                    lookup.error = error

    async def list_lookups(self, *, limit: int = 100, offset: int = 0) -> List[CveLookup]:
        """List :class:`CveLookup` job-headers, newest first.

        Ordering is stable (``started_at DESC, id DESC``) so the most
        recent job for a given start-time wins on ties — the Recent-Lookups
        list ordering (Welle B).

        Args:
            limit: Maximum number of rows to return (default 100).
            offset: Skip the first ``offset`` rows.

        Returns:
            List of :class:`CveLookup` rows; empty when none exist.
        """
        stmt = (
            select(CveLookup)
            .order_by(CveLookup.started_at.desc(), CveLookup.id.desc())
            .offset(max(0, offset))
            .limit(max(1, limit))
        )
        async with self._Session() as session:
            res = await session.execute(stmt)
            return list(res.scalars().all())

    async def get_lookup(self, lookup_id: Union[UUID, str]) -> Optional[CveLookup]:
        """Retrieve a single :class:`CveLookup` job-header by id.

        Args:
            lookup_id: The job UUID.

        Returns:
            The :class:`CveLookup` row, or ``None`` when no row matches.

        Raises:
            ValueError: when ``lookup_id`` is not a valid UUID.
        """
        lid = UUID(str(lookup_id))
        async with self._Session() as session:
            return await session.get(CveLookup, lid)

    async def reconcile_interrupted_lookups(self, *, active_job_ids: Sequence[str]) -> int:
        """Fail any ``running`` lookup not backed by a live registry task.

        Crash-recovery (design.md § D2 Risk / WA.5): an in-process task
        does not survive a service restart, so a job left ``running`` in
        the DB after a crash has no live task to finalize it. On startup
        this marks every such orphaned ``running`` job as ``failed`` with
        an ``"interrupted"`` error so it never strands.

        Args:
            active_job_ids: Job ids that DO have a live registry task and
                therefore MUST NOT be reconciled (normally empty at a
                cold start).

        Returns:
            The number of job-headers transitioned to ``failed``.
        """
        active = {str(jid) for jid in active_job_ids}
        now = datetime.now(tz=timezone.utc)
        count = 0
        async with self._Session() as session:
            async with session.begin():
                res = await session.execute(select(CveLookup).where(CveLookup.status == CveLookupStatus.RUNNING))
                for lookup in res.scalars().all():
                    if str(lookup.id) in active:
                        continue
                    lookup.status = CveLookupStatus.FAILED
                    lookup.finished_at = now
                    lookup.error = "interrupted: service restarted while lookup was running"
                    count += 1
        return count

    async def reconcile_interrupted_scans(self, *, active_run_ids: Sequence[str] = ()) -> int:
        """Abort any ``running`` scan not backed by a live in-process run.

        Crash-recovery (E2E-B2): a scan executes inside an in-process
        ``ModuleManager`` run (or, for ``cve_lookup``, a registry task)
        that does not survive a service restart. A row left ``RUNNING``
        with ``finished_at NULL`` after a crash/restart therefore has no
        live executor to finalize it and would otherwise show as a
        permanently-stuck "running" in the Recent/History list.

        On startup this marks every such orphaned ``running`` scan as
        ``ABORTED`` with ``finished_at=now()`` and an explanatory
        ``error_message`` so the history never strands. Idempotent: a
        second pass finds no ``running`` rows and is a no-op. Safe: it only
        UPDATEs the terminal columns of orphaned rows, never deletes.

        Args:
            active_run_ids: Scan ids that DO have a live in-process run and
                MUST NOT be reconciled (empty at a cold start, where every
                ``running`` row is by definition orphaned).

        Returns:
            The number of scans transitioned to ``aborted``.
        """
        active = {str(rid) for rid in active_run_ids}
        now = datetime.now(tz=timezone.utc)
        count = 0
        async with self._Session() as session:
            async with session.begin():
                res = await session.execute(select(Scan).where(Scan.status == ScanStatus.RUNNING))
                for scan in res.scalars().all():
                    if str(scan.id) in active:
                        continue
                    scan.status = ScanStatus.ABORTED
                    scan.finished_at = now
                    if not scan.error_message:
                        scan.error_message = "interrupted by scanner restart"
                    count += 1
        return count

    # ---- Device upsert/link ----

    async def upsert_device_legacy(
        self,
        vendor: Optional[str] = None,
        device_family: Optional[str] = None,
        device_type: Optional[str] = None,
        description: Optional[str] = None,
        article_number: Optional[str] = None,
        device_role: Optional[str] = None,
        firmware_version: Optional[str] = None,
        update_available: Optional[bool] = None,
        last_scan_at: Optional[datetime] = None,
        notes: Optional[str] = None,
        device_id: Optional[int] = None,
    ) -> Device:
        """Pre-F-03 device upsert path; insert-or-update by surrogate id.

        Insert or update a :class:`Device`. If ``device_id`` is provided,
        updates that record. Otherwise inserts a new device without a
        natural-key dedup.

        F-01: the legacy ``vulnerabilities`` jsonb cache was removed; pass
        vulnerability rows through :meth:`upsert_vulnerability_observation`
        instead. The aggregated view ``device_topology_view`` exposes the
        per-device vulnerabilities array for UI consumers.

        F-03 (``refactor-otalon-scan-device-network-ownership-v1``)
        introduces the canonical natural-key UPSERT path
        :meth:`upsert_device` (keyed on ``primary_mac``). This legacy
        method is retained for the F-01 batched-finding path
        (:meth:`save_findings_batch`) and existing integration tests
        that do not yet flow through the F-03 natural key; new code
        SHALL prefer the natural-key helper. See spec
        ``scan--persistence-ownership`` § "Device Upsert Helper".
        """
        async with self._Session() as session:
            async with session.begin():
                if device_id is not None:
                    dev = await session.get(Device, device_id)
                    if not dev:
                        raise ValueError(f"Device with id={device_id} not found")
                else:
                    dev = Device()

                dev.vendor = vendor
                dev.device_family = device_family
                dev.device_type = device_type
                dev.description = description
                dev.article_number = article_number
                dev.device_role = device_role
                dev.firmware_version = firmware_version
                dev.update_available = (
                    bool(update_available) if update_available is not None else (dev.update_available or False)
                )
                dev.last_scan_at = last_scan_at
                dev.notes = notes

                session.add(dev)
                await session.flush()
                # Refresh inside the transaction so the caller sees the PK
                await session.refresh(dev)
            return dev

    async def find_device_by_signature(
        self,
        vendor: Optional[str],
        device_type: Optional[str],
        article_number: Optional[str],
    ) -> Optional[Device]:
        """Attempt to find an existing :class:`Device` by the natural
        signature ``(vendor, device_type, article_number)``.

        Returns the first match or ``None``.
        """
        async with self._Session() as session:
            conditions = []
            if vendor is not None:
                conditions.append(Device.vendor == vendor)
            else:
                conditions.append(Device.vendor.is_(None))
            if device_type is not None:
                conditions.append(Device.device_type == device_type)
            else:
                conditions.append(Device.device_type.is_(None))
            if article_number is not None:
                conditions.append(Device.article_number == article_number)
            else:
                conditions.append(Device.article_number.is_(None))

            stmt = select(Device).where(and_(*conditions))
            res = await session.execute(stmt)
            return res.scalar_one_or_none()

    # ---- F-03 natural-key UPSERT helpers (parent rows) ----

    async def upsert_device(
        self,
        *,
        primary_mac: str,
        hostname: Optional[str] = None,
        vendor: Optional[str] = None,
        device_family: Optional[str] = None,
        device_type: Optional[str] = None,
        description: Optional[str] = None,
        article_number: Optional[str] = None,
        device_role: Optional[str] = None,
        firmware_version: Optional[str] = None,
        product_name: Optional[str] = None,
        hw_version: Optional[str] = None,
        sw_version: Optional[str] = None,
        serial_number: Optional[str] = None,
    ) -> int:
        """UPSERT a :class:`Device` row keyed on ``primary_mac``.

        F-03 (``refactor-otalon-scan-device-network-ownership-v1``):
        the canonical natural-key device-upsert helper. Uses
        ``INSERT … ON CONFLICT … DO UPDATE`` against the partial
        UNIQUE index ``uq_devices_primary_mac`` introduced by alembic
        revision ``0002_device_identity_and_parents``.

        Args:
            primary_mac: REQUIRED. Canonical lowercase colon-separated
                MAC address (e.g. ``"aa:bb:cc:dd:ee:ff"``). MUST satisfy
                the ``ck_devices_primary_mac_format`` CHECK constraint.
                Callers SHOULD invoke
                :func:`otalon_scan.utils.mac.canonicalise` first; the helper
                does NOT silently normalise the input.
            hostname: Optional discovered network name (PROFINET
                station-name / SNMP ``sysName``). P8 Welle A: follows the
                same NULL-skipping COALESCE merge as the descriptive
                fields below.
            vendor, device_family, device_type, description,
                article_number, device_role, firmware_version,
                product_name, hw_version, sw_version, serial_number:
                Optional descriptive fields. NULL values do NOT
                overwrite earlier non-NULL values on conflict
                (NULL-skipping — see design.md § D-UPSERT-DEVICE). The
                SNMP asset master-data fields (``product_name`` /
                ``hw_version`` / ``sw_version`` / ``serial_number``) were
                added by SCAN-018 and follow the same merge rule (D5: an
                active SNMP scan supplies a non-NULL value and therefore
                overwrites; passive callers leave them NULL and never
                clobber an active value).

        Returns:
            int: The ``devices.id`` of the new or existing row.

        Raises:
            ValueError: If ``primary_mac`` violates
                ``ck_devices_primary_mac_format`` (the helper translates
                the PostgreSQL ``IntegrityError`` into a clearer
                ``ValueError`` identifying the bad value).

        On-conflict semantics (see design.md § D-UPSERT-DEVICE):

        - ``last_scan_at`` SHALL be refreshed to ``now()``.
        - Descriptive fields SHALL be overwritten only when the caller
          passes a non-NULL value; NULLs in the call preserve existing
          non-NULL values (per-scan enrichment accumulates over time).
        - ``primary_mac`` is the conflict key and SHALL NOT be updated.
        - ``created_at`` SHALL NOT be updated.

        Call-ordering contract: this helper is the FIRST step of the
        canonical UPSERT chain (per spec
        ``scan--persistence-ownership`` § "Writer Call Ordering
        Contract"). Callers SHALL invoke this BEFORE
        :meth:`upsert_network_interface` and BEFORE the leaf helpers
        :meth:`upsert_service_observation` /
        :meth:`upsert_vulnerability_observation`. The leaf helpers
        raise :class:`ParentRowMissingError` (F-01 contract,
        design.md § D-F03-PREREQ) when their FK target does not exist.
        """
        # Build the INSERT values dict; the ON CONFLICT update dict
        # filters out NULLs so the NULL-skipping semantics holds.
        now = datetime.now(tz=timezone.utc)
        insert_payload: dict[str, Any] = {
            "primary_mac": primary_mac,
            "hostname": hostname,
            "vendor": vendor,
            "device_family": device_family,
            "device_type": device_type,
            "description": description,
            "article_number": article_number,
            "device_role": device_role,
            "firmware_version": firmware_version,
            "product_name": product_name,
            "hw_version": hw_version,
            "sw_version": sw_version,
            "serial_number": serial_number,
            "last_scan_at": now,
            "created_at": now,
            "update_available": False,
        }
        stmt = pg_insert(Device).values(**insert_payload)
        # NULL-skipping: COALESCE(EXCLUDED.x, devices.x) — if the caller
        # passed NULL for ``x``, keep the existing value; otherwise use
        # the caller's value.
        update_set: dict[str, Any] = {
            "last_scan_at": now,
            # Non-lockable descriptive metadata: plain NULL-skipping merge.
            # P8 Welle A: ``hostname`` is not an operator-lockable identity
            # field, so it follows the same COALESCE merge as description.
            "hostname": sa_func_coalesce(stmt.excluded.hostname, Device.hostname),
            "description": sa_func_coalesce(stmt.excluded.description, Device.description),
            "device_role": sa_func_coalesce(stmt.excluded.device_role, Device.device_role),
            # SCAN-018 D5: same COALESCE merge — an active SNMP scan
            # supplies a non-NULL value and overwrites; NULL preserves.
            "serial_number": sa_func_coalesce(stmt.excluded.serial_number, Device.serial_number),
        }
        # SCAN-023: lock-aware merge for the eight identity fields — a
        # field listed in ``manual_identity_fields`` keeps its manual
        # value; unlocked fields fall back to the COALESCE merge.
        update_set.update(_identity_update_set(stmt))
        upsert_stmt = stmt.on_conflict_do_update(
            index_elements=["primary_mac"],
            index_where=Device.primary_mac.isnot(None),
            set_=update_set,
        ).returning(Device.id)

        bound = logger.bind(op="upsert_device", primary_mac=primary_mac)
        async with self._Session() as session:
            try:
                async with session.begin():
                    res = await session.execute(upsert_stmt)
                    row = res.first()
                    if row is None:
                        # Defensive: RETURNING on a successful UPSERT
                        # always yields a row; if the driver elided it,
                        # fall back to a SELECT.
                        sel = await session.execute(select(Device.id).where(Device.primary_mac == primary_mac))
                        fallback = sel.scalar_one_or_none()
                        if fallback is None:
                            raise RuntimeError(
                                f"upsert_device: no row returned and no row found for " f"primary_mac={primary_mac!r}"
                            )
                        bound.debug("upsert_device ok id={} (fallback SELECT)", fallback)
                        return int(fallback)
                    device_id = int(row[0])
                    bound.debug("upsert_device ok id={}", device_id)
                    return device_id
            except IntegrityError as exc:
                # asyncpg surfaces the constraint name either on the
                # outer ``IntegrityError`` (via ``orig.constraint_name``
                # — newer asyncpg versions) or only inside the raw
                # exception message. Check both paths so the typed
                # ``ValueError`` is reliably surfaced on CHECK
                # violations regardless of driver version.
                exc_text = str(exc)
                orig = getattr(exc, "orig", None)
                constraint_name = getattr(orig, "constraint_name", None) if orig is not None else None
                if constraint_name == "ck_devices_primary_mac_format" or ("ck_devices_primary_mac_format" in exc_text):
                    bound.warning("upsert_device CHECK violation primary_mac={!r}", primary_mac)
                    raise ValueError(
                        f"upsert_device: primary_mac={primary_mac!r} violates "
                        f"ck_devices_primary_mac_format (expected canonical lowercase "
                        f"colon-separated MAC matching '^[0-9a-f]{{2}}(:[0-9a-f]{{2}}){{5}}$'); "
                        f"call otalon_scan.utils.mac.canonicalise() before this helper"
                    ) from exc
                # Surface any other IntegrityError to the caller —
                # this is unexpected (no other constraint should fire
                # on a Device insert) but propagating loudly beats
                # silent swallowing.
                bound.warning("upsert_device unexpected IntegrityError: {}", exc)
                raise

    async def upsert_network_interface(
        self,
        *,
        mac: Optional[str],
        ipv4: Optional[str] = None,
        ipv6: Optional[str] = None,
        subnet: Optional[str] = None,
        device_id: Optional[int] = None,
        source: Literal["active", "passive"] = "active",
    ) -> int:
        """UPSERT a :class:`NetworkInterface` row, returning the row id.

        F-03 (``refactor-otalon-scan-device-network-ownership-v1``):
        the canonical natural-key interface-upsert helper. Uses
        PostgreSQL ``INSERT … ON CONFLICT … DO UPDATE`` against the
        F-01 UNIQUE constraints ``uq_iface_mac`` /
        ``uq_iface_ipv4`` / ``uq_iface_ipv6``.

        ``add-passive-asset-seeder`` extends this helper additively
        with the ``source`` keyword and the active-vs-passive merge
        rule documented in
        ``openspec/changes/add-passive-asset-seeder/design.md``
        decisions ``D-UPSERT-SIGNATURE`` and ``D-MERGE-RULE``. The
        keyword defaults to ``'active'``, so every existing F-03 caller
        keeps working without modification.

        Conflict-target selection (priority order):

        1. ``mac`` is non-None  → conflict target ``uq_iface_mac``
        2. else ``ipv4`` is non-None → conflict target ``uq_iface_ipv4``
        3. else ``ipv6`` is non-None → conflict target ``uq_iface_ipv6``

        At least one of ``mac`` / ``ipv4`` / ``ipv6`` MUST be non-None;
        the helper raises :class:`ValueError` if all three are NULL.

        Args:
            mac: Canonical lowercase colon-separated MAC, or ``None``.
            ipv4: IPv4 dotted-quad string, or ``None``.
            ipv6: IPv6 textual address, or ``None``.
            subnet: Optional CIDR / subnet string describing the
                network the interface lives on. Back-filled on conflict
                only if the existing row's ``subnet`` is NULL.
            device_id: Optional ``devices.id`` FK. Linked on first
                insert; on conflict, linked only when the existing row
                has ``device_id IS NULL`` (link-once-then-immutable —
                see design.md § D-UPSERT-NET-IFACE).
            source: Provenance of the observation, one of ``'active'``
                (default; an active-scan module) or ``'passive'`` (the
                passive asset seeder). Governs the active-vs-passive
                merge rule and the timestamp-column refresh semantics
                below. Validated at runtime by the
                ``ck_network_interfaces_source`` CHECK constraint.

        Returns:
            int: The ``network_interfaces.id`` of the new or existing
            row.

        Raises:
            ValueError: If all of ``mac``, ``ipv4``, ``ipv6`` are NULL.
            IdentityCollisionError: If a non-conflict-target identity
                column (``ipv4`` / ``ipv6``) collides with a UNIQUE on
                a different existing row. The exception message names
                both the conflicting column and (when extractable) the
                offending existing row id.

        On-conflict semantics:

        - Identity columns (``mac`` / ``ipv4`` / ``ipv6`` / ``subnet``):
          back-filled from the call value only if the existing column
          is NULL. Once set, identity columns SHALL NOT be changed by
          a subsequent UPSERT.
        - ``device_id``: linked from the call value only if the
          existing row's ``device_id IS NULL``. Once linked, a
          subsequent call with a different ``device_id`` SHALL silently
          preserve the existing link (link-once).
        - ``created_at``: never updated.
        - ``last_scan_at``: refreshed (``now()``) ONLY when ``source``
          is ``'active'``. Passive-source calls SHALL NOT touch
          ``last_scan_at``, preserving its historical "last active
          reachability check" semantics for existing dashboards.
        - ``last_seen_passive_at``: refreshed (``now()``) ONLY when
          ``source`` is ``'passive'``. Active-source calls SHALL NOT
          touch this column.
        - ``first_seen_passive_at``: back-filled (``now()``) on the
          FIRST passive-source call against the row. Subsequent
          passive calls SHALL NOT modify it; active-source calls SHALL
          NOT touch it.
        - ``source`` (merge rule, see ``D-MERGE-RULE``):
            - existing active + call active → ``'active'`` (idempotent)
            - existing active + call passive → ``'active'`` (NO DOWNGRADE)
            - existing passive + call active → ``'active'`` (UPGRADE)
            - existing passive + call passive → ``'passive'`` (idempotent)
        """
        if mac is None and ipv4 is None and ipv6 is None:
            raise ValueError("upsert_network_interface: at least one of mac, ipv4, ipv6 must be non-None")

        # Conflict-target selection per priority order.
        if mac is not None:
            index_elements: list[str] = ["mac_address"]
            conflict_col: str = "mac_address"
        elif ipv4 is not None:
            index_elements = ["ipv4_address"]
            conflict_col = "ipv4_address"
        else:
            index_elements = ["ipv6_address"]
            conflict_col = "ipv6_address"

        now = datetime.now(tz=timezone.utc)
        is_passive_call = source == "passive"
        # Pre-compute insert-row values for the passive provenance
        # columns so the row inserted on the no-conflict path already
        # carries the correct first/last passive timestamps without
        # needing an ON-CONFLICT UPDATE round-trip.
        insert_last_scan_at = None if is_passive_call else now
        insert_first_seen_passive_at = now if is_passive_call else None
        insert_last_seen_passive_at = now if is_passive_call else None

        insert_payload: dict[str, Any] = {
            "mac_address": mac,
            "ipv4_address": ipv4,
            "ipv6_address": ipv6,
            "subnet": subnet,
            "device_id": device_id,
            "source": source,
            "last_scan_at": insert_last_scan_at,
            "first_seen_passive_at": insert_first_seen_passive_at,
            "last_seen_passive_at": insert_last_seen_passive_at,
            "created_at": now,
        }
        stmt = pg_insert(NetworkInterface).values(**insert_payload)

        # Identity columns: back-fill only if existing is NULL.
        # device_id: link-once — only if existing is NULL.
        # source / timestamps: governed by the active-vs-passive merge
        # rule from add-passive-asset-seeder/design.md § D-MERGE-RULE.
        ni = NetworkInterface  # alias for readability
        update_set: dict[str, Any] = {
            "mac_address": sa_func_coalesce(ni.mac_address, stmt.excluded.mac_address),
            "ipv4_address": sa_func_coalesce(ni.ipv4_address, stmt.excluded.ipv4_address),
            "ipv6_address": sa_func_coalesce(ni.ipv6_address, stmt.excluded.ipv6_address),
            "subnet": sa_func_coalesce(ni.subnet, stmt.excluded.subnet),
            "device_id": sa_func_coalesce(ni.device_id, stmt.excluded.device_id),
            # last_scan_at: refresh only on active calls; preserve the
            # historical "last active reachability" semantics.
            "last_scan_at": case(
                (stmt.excluded.source == "active", now),
                else_=ni.last_scan_at,
            ),
            # last_seen_passive_at: refresh only on passive calls.
            "last_seen_passive_at": case(
                (stmt.excluded.source == "passive", now),
                else_=ni.last_seen_passive_at,
            ),
            # first_seen_passive_at: back-fill once on first passive call.
            "first_seen_passive_at": case(
                (
                    and_(
                        stmt.excluded.source == "passive",
                        ni.first_seen_passive_at.is_(None),
                    ),
                    now,
                ),
                else_=ni.first_seen_passive_at,
            ),
            # source: active never downgrades; passive upgrades to
            # active when an active call arrives.
            "source": case(
                (ni.source == "active", "active"),
                (stmt.excluded.source == "active", "active"),
                else_="passive",
            ),
        }
        upsert_stmt = stmt.on_conflict_do_update(
            index_elements=index_elements,
            set_=update_set,
        ).returning(NetworkInterface.id)

        bound = logger.bind(
            op="upsert_network_interface",
            mac=mac,
            ipv4=ipv4,
            ipv6=ipv6,
            source=source,
            conflict_target=conflict_col,
        )
        async with self._Session() as session:
            try:
                async with session.begin():
                    res = await session.execute(upsert_stmt)
                    row = res.first()
                    if row is None:
                        # See upsert_device for rationale.
                        col = getattr(ni, conflict_col)
                        sel = await session.execute(select(ni.id).where(col == insert_payload[conflict_col]))
                        fallback = sel.scalar_one_or_none()
                        if fallback is None:
                            raise RuntimeError(
                                f"upsert_network_interface: no row returned and none "
                                f"found for {conflict_col}={insert_payload[conflict_col]!r}"
                            )
                        bound.debug("upsert_network_interface ok id={} (fallback)", fallback)
                        return int(fallback)
                    iface_id = int(row[0])
                    bound.debug("upsert_network_interface ok id={}", iface_id)
                    return iface_id
            except IntegrityError as exc:
                # Extract the constraint name via either the asyncpg
                # exception attribute (newer driver versions) or the
                # message string (older versions). Mirrors the dual-
                # path used by :meth:`upsert_device` above.
                exc_text = str(exc)
                orig = getattr(exc, "orig", None)
                constraint_name = getattr(orig, "constraint_name", None) if orig is not None else None
                # If the conflict happened on a UNIQUE we did NOT choose
                # as the conflict target, surface IdentityCollisionError.
                colliding_constraints = {
                    "uq_iface_mac": ("mac_address", mac),
                    "uq_iface_ipv4": ("ipv4_address", ipv4),
                    "uq_iface_ipv6": ("ipv6_address", ipv6),
                }
                if constraint_name is None:
                    for cand in colliding_constraints:
                        if cand in exc_text:
                            constraint_name = cand
                            break
                self_target_constraint = f"uq_iface_{conflict_col.replace('_address', '')}"
                if constraint_name in colliding_constraints and constraint_name != self_target_constraint:
                    coll_col, coll_val = colliding_constraints[constraint_name]
                    bound.warning(
                        "upsert_network_interface identity collision on {}={!r}",
                        coll_col,
                        coll_val,
                    )
                    # Best-effort look-up of the offending row id.
                    existing_id: Optional[int] = None
                    try:
                        async with self._Session() as session2:
                            col_attr = getattr(ni, coll_col)
                            sel = await session2.execute(select(ni.id).where(col_attr == coll_val))
                            existing_id = sel.scalar_one_or_none()
                    except SQLAlchemyError:
                        existing_id = None
                    raise IdentityCollisionError(
                        message=(
                            f"upsert_network_interface: identity collision — "
                            f"{coll_col}={coll_val!r} already bound to a different "
                            f"row (existing id={existing_id}); chose conflict target "
                            f"{conflict_col!r} but UNIQUE {constraint_name!r} fired"
                        ),
                        conflict_column=coll_col,
                        conflict_value=str(coll_val) if coll_val is not None else None,
                        existing_row_id=existing_id,
                    ) from exc
                # Other IntegrityError — propagate.
                bound.warning("upsert_network_interface unexpected IntegrityError: {}", exc)
                raise

    # ---- Interface upsert/link ----

    async def _find_interface(
        self,
        session: AsyncSession,
        ipv4: Optional[str] = None,
        mac: Optional[str] = None,
        ipv6: Optional[str] = None,
    ) -> Optional[NetworkInterface]:
        """Locate an existing interface using strong identifiers: MAC > IPv4 > IPv6.

        The INET comparisons cast the bind parameter explicitly: under
        SQLAlchemy 2.0.36 (workspace venv) the asyncpg dialect otherwise
        types the bind as VARCHAR and Postgres raises
        ``operator does not exist: inet = character varying``; on the pinned
        2.0.44 the cast is a semantic no-op.
        """
        if mac:
            res = await session.execute(select(NetworkInterface).where(NetworkInterface.mac_address == mac))
            iface = res.scalar_one_or_none()
            if iface:
                return iface
        if ipv4:
            res = await session.execute(
                select(NetworkInterface).where(NetworkInterface.ipv4_address == sa_cast(ipv4, INET))
            )
            iface = res.scalar_one_or_none()
            if iface:
                return iface
        if ipv6:
            res = await session.execute(
                select(NetworkInterface).where(NetworkInterface.ipv6_address == sa_cast(ipv6, INET))
            )
            iface = res.scalar_one_or_none()
            if iface:
                return iface
        return None

    async def upsert_interface_legacy(
        self,
        ipv4: Optional[str] = None,
        mac: Optional[str] = None,
        ipv6: Optional[str] = None,
        subnet: Optional[str] = None,
        notes: Optional[str] = None,
        device_id: Optional[int] = None,
        last_scan_at: Optional[datetime] = None,
    ) -> NetworkInterface:
        """Pre-F-03 SELECT-then-write interface upsert (returns the ORM row).

        Insert or update a :class:`NetworkInterface`. Correlates by
        MAC/IPv4/IPv6.

        F-01: the legacy ``open_ports_summary`` jsonb cache was removed.
        Per-port records belong in :class:`ServiceObservation` (see
        :meth:`upsert_service_observation`); the aggregated array is now
        served by ``network_interface_ports_view``.

        F-03 (``refactor-otalon-scan-device-network-ownership-v1``)
        introduces the canonical natural-key UPSERT path
        :meth:`upsert_network_interface` (PostgreSQL
        ``INSERT … ON CONFLICT … DO UPDATE`` against ``uq_iface_mac`` /
        ``uq_iface_ipv4`` / ``uq_iface_ipv6``). This legacy method is
        retained for callers that still need the ORM row back; new code
        SHALL prefer :meth:`upsert_network_interface` which returns the
        ``id`` directly and honours the link-once-then-immutable rule
        for ``device_id``.
        """
        async with self._Session() as session:
            async with session.begin():
                iface = await self._find_interface(session, ipv4=ipv4, mac=mac, ipv6=ipv6)
                if not iface:
                    iface = NetworkInterface()

                iface.mac_address = mac or iface.mac_address
                iface.ipv4_address = ipv4 or iface.ipv4_address
                iface.ipv6_address = ipv6 or iface.ipv6_address
                iface.subnet = subnet or iface.subnet
                iface.notes = notes or iface.notes
                iface.device_id = device_id if device_id is not None else iface.device_id
                iface.last_scan_at = last_scan_at or iface.last_scan_at
                # add-passive-asset-seeder D-MERGE-RULE: legacy ORM
                # path is invoked exclusively by active-scan code,
                # so stamp ``source='active'`` on insert and upgrade
                # any pre-existing passive row.
                iface.source = "active"

                session.add(iface)
                await session.flush()
                await session.refresh(iface)
            return iface

    async def link_interface_to_device(self, interface_id: int, device_id: Optional[int]) -> bool:
        """Link/unlink an interface to a device (nullable for manual correlation)."""
        async with self._Session() as session:
            async with session.begin():
                iface = await session.get(NetworkInterface, interface_id)
                if not iface:
                    return False
                iface.device_id = device_id
                return True

    async def delete_device(self, device_id: int) -> bool:
        """Hard-delete a device and all of its descendants in one transaction.

        The FK topology around ``devices`` uses ``ON DELETE SET NULL``
        for ``network_interfaces.device_id`` and
        ``vulnerability_observations.device_id`` (see alembic revision
        ``0001_initial_view_and_upserts`` and :mod:`otalon_scan.repositories.models`).
        SET NULL would orphan the children, which contradicts the
        operator intent of "the entries gone, not archived". This helper
        therefore explicitly cascades inside a single transaction:

        1. Resolve all ``network_interfaces.id`` belonging to the device.
        2. Delete ``service_observations`` referencing those interfaces.
        3. Delete ``vulnerability_observations`` referencing the device
           or any of its interfaces.
        4. Delete the ``network_interfaces`` rows.
        5. Delete the ``devices`` row.

        Args:
            device_id: Primary key of the ``devices`` row to remove.

        Returns:
            ``True`` when the device row existed and was deleted,
            ``False`` when no row matched ``device_id`` (caller should
            translate to HTTP 404).
        """
        async with self._Session() as session:
            async with session.begin():
                iface_id_rows = await session.execute(
                    select(NetworkInterface.id).where(NetworkInterface.device_id == device_id)
                )
                interface_ids: List[int] = [row[0] for row in iface_id_rows.all()]

                if interface_ids:
                    await session.execute(
                        delete(ServiceObservation).where(ServiceObservation.interface_id.in_(interface_ids))
                    )

                vuln_filter = VulnerabilityObservation.device_id == device_id
                if interface_ids:
                    vuln_filter = vuln_filter | VulnerabilityObservation.interface_id.in_(interface_ids)
                await session.execute(delete(VulnerabilityObservation).where(vuln_filter))

                if interface_ids:
                    await session.execute(delete(NetworkInterface).where(NetworkInterface.device_id == device_id))

                result = cast(
                    CursorResult[Any],
                    await session.execute(delete(Device).where(Device.id == device_id)),
                )
                return bool(result.rowcount and result.rowcount > 0)

    async def delete_devices(self, device_ids: List[int]) -> Dict[str, List[int]]:
        """Hard-delete a batch of devices atomically in a single transaction.

        Bulk counterpart to :meth:`delete_device`. Mirrors the same explicit
        cascade order (service / vulnerability observations →
        network_interfaces → device) so SET NULL on the FK targets does not
        orphan child rows.

        The operation is atomic: either every existing id in ``device_ids``
        is removed together with its descendants, or no row is touched.
        Non-existent ids do not cause a rollback — they are simply reported
        back in ``not_found``. An empty input list short-circuits without
        opening a DB session.

        Args:
            device_ids: List of ``devices.id`` primary keys to remove.
                Duplicates are tolerated (deduplicated internally before
                the SELECT round-trip).

        Returns:
            A dict with two keys:

            - ``deleted``: ids of devices that existed and were removed,
              in input order.
            - ``not_found``: ids that did not match any ``devices`` row,
              in input order.
        """
        if not device_ids:
            return {"deleted": [], "not_found": []}

        unique_ids = list(dict.fromkeys(device_ids))

        async with self._Session() as session:
            async with session.begin():
                existing_rows = await session.execute(select(Device.id).where(Device.id.in_(unique_ids)))
                existing_ids: List[int] = [row[0] for row in existing_rows.all()]

                if not existing_ids:
                    not_found = [d for d in device_ids if d in unique_ids]
                    return {"deleted": [], "not_found": list(dict.fromkeys(not_found))}

                iface_id_rows = await session.execute(
                    select(NetworkInterface.id).where(NetworkInterface.device_id.in_(existing_ids))
                )
                interface_ids: List[int] = [row[0] for row in iface_id_rows.all()]

                if interface_ids:
                    await session.execute(
                        delete(ServiceObservation).where(ServiceObservation.interface_id.in_(interface_ids))
                    )

                vuln_filter: ColumnElement[bool] = VulnerabilityObservation.device_id.in_(existing_ids)
                if interface_ids:
                    vuln_filter = vuln_filter | VulnerabilityObservation.interface_id.in_(interface_ids)
                await session.execute(delete(VulnerabilityObservation).where(vuln_filter))

                if interface_ids:
                    await session.execute(delete(NetworkInterface).where(NetworkInterface.device_id.in_(existing_ids)))

                await session.execute(delete(Device).where(Device.id.in_(existing_ids)))

        existing_set = set(existing_ids)
        deleted = [d for d in device_ids if d in existing_set]
        not_found = [d for d in device_ids if d not in existing_set]
        return {
            "deleted": list(dict.fromkeys(deleted)),
            "not_found": list(dict.fromkeys(not_found)),
        }

    # ---- Observations — UPSERT helpers (F-01) ----

    async def upsert_service_observation(
        self,
        *,
        scan_id: Union[UUID, str],
        interface_id: int,
        port: int,
        transport: str,
        ip_address: Optional[str] = None,
        mac_address: Optional[str] = None,
        protocol: Optional[str] = None,
        service_name: Optional[str] = None,
        product: Optional[str] = None,
        version: Optional[str] = None,
        cpe: Optional[str] = None,
        extra_info: Optional[str] = None,
        seen_at: Optional[datetime] = None,
    ) -> None:
        """UPSERT a service observation keyed on ``(interface_id, port, transport)``.

        Implements the F-01 idempotent persistence semantics: a re-run of
        the same module against the same target produces zero new rows;
        instead the existing row is updated in-place
        (``last_seen_at = now()``, plus overwrites of the descriptive
        fields ``service_name`` / ``product`` / ``version`` / ``cpe`` /
        ``extra_info``). ``first_seen_at`` and ``created_at`` are
        **never** modified on conflict.

        Args:
            scan_id: UUID of the originating ``scans`` row.
            interface_id: PK of the parent ``network_interfaces`` row.
                Non-nullable by design — see design.md § D-UPSERT-ORDER.
                Callers MUST upsert the interface first; if the FK target
                is missing the call raises :class:`ParentRowMissingError`.
            port: TCP/UDP port number.
            transport: ``"tcp"`` / ``"udp"``.
            ip_address, mac_address: Best-effort attribution copies; not
                part of the UNIQUE key and not touched on conflict.
            protocol: Optional application-layer protocol label (e.g.
                ``"modbus"``); not part of the UNIQUE key, overwritten
                on conflict.
            service_name, product, version, cpe, extra_info: Descriptive
                fields — overwritten on conflict.
            seen_at: Timestamp for ``first_seen_at`` / ``last_seen_at``;
                defaults to ``datetime.now(tz=timezone.utc)``.

        Raises:
            ParentRowMissingError: when ``interface_id`` does not point
                to an existing row in ``network_interfaces``. The caller
                should ensure the parent interface row exists first
                (see :meth:`upsert_interface`, or in F-03
                ``upsert_network_interface``).
        """
        sid = UUID(str(scan_id))
        now = seen_at or datetime.now(tz=timezone.utc)
        insert_payload: dict[str, Any] = {
            "scan_id": sid,
            "interface_id": interface_id,
            "ip_address": ip_address,
            "mac_address": mac_address,
            "port": port,
            "transport": transport,
            "protocol": protocol,
            "service_name": service_name,
            "product": product,
            "version": version,
            "cpe": cpe,
            "extra_info": extra_info,
            "first_seen_at": now,
            "last_seen_at": now,
            "created_at": now,
        }
        stmt = pg_insert(ServiceObservation).values(**insert_payload)
        stmt = stmt.on_conflict_do_update(
            constraint="uq_service_observations_iface_port_transport_secmode",
            set_={
                "last_seen_at": now,
                "service_name": stmt.excluded.service_name,
                "product": stmt.excluded.product,
                "version": stmt.excluded.version,
                "cpe": stmt.excluded.cpe,
                "extra_info": stmt.excluded.extra_info,
                # ``protocol`` is overwrite-on-conflict too: the
                # application-layer protocol may be refined by a later
                # scan (banner-grab classifying a generic TCP port as
                # ``modbus``). first_seen_at, created_at are NOT touched.
                "protocol": stmt.excluded.protocol,
            },
        )
        # Bind run_id (design.md § D-RUN-ID: run_id == str(scans.id)) so
        # operators can grep otalon-scan.log by scan and find the matching
        # ``SELECT * FROM scans WHERE id = '<uuid>'`` row.
        bound = logger.bind(run_id=str(sid), op="upsert_service_observation")
        async with self._Session() as session:
            try:
                async with session.begin():
                    await session.execute(stmt)
                    bound.debug(
                        "upsert_service_observation ok interface_id={} port={}/{}",
                        interface_id,
                        port,
                        transport,
                    )
            except IntegrityError as exc:
                bound.warning(
                    "upsert_service_observation FK violation interface_id={}",
                    interface_id,
                )
                raise self._wrap_fk_violation(
                    exc=exc,
                    parent_table="network_interfaces",
                    helper="upsert_service_observation",
                    parent_helper="upsert_network_interface (F-03) or upsert_interface",
                    fk_value=interface_id,
                    fk_name="network_interfaces.id",
                ) from exc

    async def upsert_vulnerability_observation(
        self,
        *,
        scan_id: Union[UUID, str],
        device_id: int,
        vuln_id: str,
        severity: Optional[str] = None,
        summary: Optional[str] = None,
        source_module: Optional[str] = None,
        metadata_json: Optional[Dict[str, Any]] = None,
        interface_id: Optional[int] = None,
        detected_at: Optional[datetime] = None,
    ) -> None:
        """UPSERT a vulnerability observation keyed on ``(device_id, vuln_id)``.

        Implements the F-01 idempotent persistence semantics: re-running
        the same CVE lookup updates ``last_seen_at`` and the descriptive
        fields (``severity``, ``summary``, ``source_module``,
        ``metadata_json``) but preserves the operator-set status columns
        (``status``, ``status_changed_at``, ``status_changed_by``),
        ``detected_at``, ``first_seen_at`` (n/a — schema has no
        ``first_seen_at`` here; ``detected_at`` plays that role), and
        ``created_at``.

        ``interface_id`` is **first-insert only** (design.md § D-VULN-IFACE):
        the column records best-effort evidence-of-source. If the first
        insert had no interface info and a later UPSERT does, the value
        is NOT back-filled.

        Args:
            scan_id: UUID of the originating ``scans`` row.
            device_id: PK of the parent ``devices`` row. Non-nullable by
                design — callers MUST upsert the device first.
            vuln_id: CVE id or vendor-specific identifier; the second
                half of the natural key.
            severity, summary, source_module: Descriptive fields,
                overwritten on conflict.
            metadata_json: Optional jsonb metadata, overwritten on
                conflict (deep-merge would be ambiguous and is left for
                a future change if needed).
            interface_id: Best-effort source attribution. First-insert
                only; not touched on conflict.
            detected_at: Timestamp for ``detected_at`` (first insert
                only); defaults to ``datetime.now(tz=timezone.utc)``.

        Raises:
            ParentRowMissingError: when ``device_id`` does not point to
                an existing row in ``devices``.
        """
        sid = UUID(str(scan_id))
        now = detected_at or datetime.now(tz=timezone.utc)
        insert_payload: dict[str, Any] = {
            "scan_id": sid,
            "device_id": device_id,
            "interface_id": interface_id,
            "source_module": source_module,
            "vuln_id": vuln_id,
            "severity": severity,
            "summary": summary,
            "metadata_json": dict(metadata_json) if metadata_json else None,
            "detected_at": now,
            "last_seen_at": now,
            "created_at": now,
            # status defaults to 'active' via server_default; explicit
            # passthrough so the INSERT statement carries it for clarity.
            "status": "active",
        }
        stmt = pg_insert(VulnerabilityObservation).values(**insert_payload)
        # Both ``excluded`` and the ``set_`` dict keys address the
        # underlying DB column names, not ORM attribute names: the
        # ``metadata_json`` attribute maps to a column literally named
        # ``metadata`` (see VulnerabilityObservation in models.py).
        excluded_metadata = stmt.excluded["metadata"]
        stmt = stmt.on_conflict_do_update(
            constraint="uq_vuln_observations_device_vuln",
            set_={
                "last_seen_at": now,
                "severity": stmt.excluded.severity,
                "summary": stmt.excluded.summary,
                "source_module": stmt.excluded.source_module,
                "metadata": excluded_metadata,
                # status / status_changed_at / status_changed_by:
                #     operator-owned, NEVER touched on conflict.
                # interface_id: first-insert only (design.md § D-VULN-IFACE).
                # detected_at / created_at: first-insert only.
            },
        )
        bound = logger.bind(run_id=str(sid), op="upsert_vulnerability_observation")
        async with self._Session() as session:
            try:
                async with session.begin():
                    await session.execute(stmt)
                    bound.debug(
                        "upsert_vulnerability_observation ok device_id={} vuln_id={}",
                        device_id,
                        vuln_id,
                    )
            except IntegrityError as exc:
                bound.warning(
                    "upsert_vulnerability_observation FK violation device_id={}",
                    device_id,
                )
                raise self._wrap_fk_violation(
                    exc=exc,
                    parent_table="devices",
                    helper="upsert_vulnerability_observation",
                    parent_helper="upsert_device (F-03)",
                    fk_value=device_id,
                    fk_name="devices.id",
                ) from exc

    @staticmethod
    def _wrap_fk_violation(
        *,
        exc: IntegrityError,
        parent_table: str,
        helper: str,
        parent_helper: str,
        fk_value: int,
        fk_name: str,
    ) -> ParentRowMissingError:
        """Translate a Postgres FK violation into a typed F-01 error.

        Inspects the original ``IntegrityError`` for the underlying
        ``ForeignKeyViolation``; if the failure is anything else (e.g.
        a UNIQUE-but-not-FK error), the wrapper still produces a
        ``ParentRowMissingError`` but constraint may be ``None``.
        Callers MUST always inspect ``ParentRowMissingError`` first
        (the F-01 ↔ F-03 boundary) before considering other failure
        modes (which should propagate as ``IntegrityError``).
        """
        # asyncpg embeds the original message in ``exc.orig``; SQL state
        # ``23503`` is foreign_key_violation per PostgreSQL docs.
        constraint = None
        orig = getattr(exc, "orig", None)
        sqlstate = getattr(orig, "sqlstate", None) if orig is not None else None
        constraint_name = getattr(orig, "constraint_name", None) if orig is not None else None
        if constraint_name:
            constraint = str(constraint_name)
        message = (
            f"{helper}: {fk_name}={fk_value} does not exist; "
            f"{parent_helper} owns the parent-row upsert, or the caller "
            f"must insert the {parent_table} row first."
        )
        if sqlstate is not None and sqlstate != "23503":
            # Not a FK violation — surface the underlying SQLSTATE so
            # the test surface can distinguish.
            message = f"{message} (underlying SQLSTATE={sqlstate}; not a FK violation)"
        return ParentRowMissingError(
            constraint=constraint,
            parent_table=parent_table,
            message=message,
        )

    # ---- Batched device-finding writes (Phase 5 / HC16) ----

    async def save_findings_batch(
        self,
        scan_id: Union[UUID, str],
        findings: Sequence[Any],
        scanned_at: Optional[datetime] = None,
    ) -> int:
        """Persist a batch of device findings inside a single transaction.

        This is the Phase 5 (HC16) batched-commit path. Whereas calling
        :meth:`upsert_device` / :meth:`upsert_interface` once per finding
        produces one commit per call (each method wraps its work in its
        own ``async with session.begin():``), this method opens **one**
        session and one transaction for the whole batch, so the entire
        chunk lands as a single commit.

        Args:
            scan_id: Persistence scan UUID (unused at the row level today
                but accepted for symmetry / future correlation joins).
            findings: Sequence of :class:`DeviceFinding`-shaped objects;
                each provides ``ipv4`` / ``mac`` / ``ipv6`` / ``vendor`` /
                ``device_type`` / ``open_ports_summary`` etc.
            scanned_at: Optional timestamp stamped onto all rows;
                defaults to ``datetime.now(tz=timezone.utc)``.

        Returns:
            The number of interfaces upserted (devices are not counted
            because they may legitimately remain ``None`` when a finding
            has no device-side metadata).
        """
        _ = scan_id  # consumed for symmetry; future correlation joins may use it
        now = scanned_at or datetime.now(tz=timezone.utc)
        upserted_ifaces = 0
        arp_map = _read_arp_table_map()

        # Local import to avoid a top-level cycle (utils.mac → models in
        # other paths). canonicalise() is a pure function.
        from otalon_scan.utils.mac import InvalidMacError, canonicalise

        async with self._Session() as session:
            async with session.begin():
                for finding in findings:
                    device_id: Optional[int] = None

                    # Resolve the finding's MAC up-front. arp_scan emits a
                    # MAC directly; other modules may leave it None and we
                    # may recover it from the host ARP table via the IP.
                    ipv4 = getattr(finding, "ipv4", None)
                    mac_raw = getattr(finding, "mac", None)
                    ipv6 = getattr(finding, "ipv6", None)
                    if not mac_raw and ipv4 and ipv4 in arp_map:
                        mac_raw = arp_map[ipv4]

                    # Canonicalise the MAC for the F-03 primary-key path.
                    # Bad values (non-hex, wrong length, …) downgrade to
                    # ``None`` so the rest of the batch still persists.
                    primary_mac: Optional[str] = None
                    if mac_raw:
                        try:
                            primary_mac = canonicalise(mac_raw)
                        except InvalidMacError:
                            logger.warning(
                                "save_findings_batch: skipping device upsert — "
                                "non-canonical MAC {mac!r} in finding "
                                "(ipv4={ipv4!r}, ipv6={ipv6!r})",
                                mac=mac_raw,
                                ipv4=ipv4,
                                ipv6=ipv6,
                            )

                    has_device_attrs = any(
                        (
                            getattr(finding, "hostname", None),
                            getattr(finding, "vendor", None),
                            getattr(finding, "device_type", None),
                            getattr(finding, "device_role", None),
                            getattr(finding, "firmware_version", None),
                            getattr(finding, "description", None),
                            getattr(finding, "article_number", None),
                            getattr(finding, "product_name", None),
                            getattr(finding, "hw_version", None),
                            getattr(finding, "sw_version", None),
                            getattr(finding, "serial_number", None),
                        )
                    )

                    # F-03 canonical device-upsert path: when the finding
                    # carries a MAC (or one was recovered from the ARP
                    # table), key the device on ``primary_mac`` so repeat
                    # scans dedupe to a single row and ``last_scan_at``
                    # advances per the on-conflict semantics documented in
                    # ``upsert_device``. This is the path the UI's Devices
                    # page reads (it joins on ``primary_mac``).
                    if primary_mac:
                        insert_payload: dict[str, Any] = {
                            "primary_mac": primary_mac,
                            "hostname": getattr(finding, "hostname", None),
                            "vendor": getattr(finding, "vendor", None),
                            "device_family": getattr(finding, "device_family", None),
                            "device_type": getattr(finding, "device_type", None),
                            "description": getattr(finding, "description", None),
                            "article_number": getattr(finding, "article_number", None),
                            "device_role": getattr(finding, "device_role", None),
                            "firmware_version": getattr(finding, "firmware_version", None),
                            # SCAN-018 SNMP asset master-data (D1/D5).
                            "product_name": getattr(finding, "product_name", None),
                            "hw_version": getattr(finding, "hw_version", None),
                            "sw_version": getattr(finding, "sw_version", None),
                            "serial_number": getattr(finding, "serial_number", None),
                            "last_scan_at": now,
                            "created_at": now,
                            "update_available": False,
                        }
                        stmt = pg_insert(Device).values(**insert_payload)
                        update_set: dict[str, Any] = {
                            "last_scan_at": now,
                            # Non-lockable descriptive metadata.
                            # P8 Welle A: ``hostname`` NULL-skipping merge.
                            "hostname": sa_func_coalesce(stmt.excluded.hostname, Device.hostname),
                            "description": sa_func_coalesce(stmt.excluded.description, Device.description),
                            "device_role": sa_func_coalesce(stmt.excluded.device_role, Device.device_role),
                            # SCAN-018 D5: an active SNMP scan overwrites
                            # existing values. COALESCE(EXCLUDED.x, devices.x)
                            # picks the incoming non-NULL value (overwrite)
                            # and only preserves the existing value when the
                            # scan supplied NULL — mirrors the seeder
                            # NULL-skipping merge rule.
                            "serial_number": sa_func_coalesce(stmt.excluded.serial_number, Device.serial_number),
                        }
                        # SCAN-023: lock-aware merge for the eight identity
                        # fields — locked fields keep their manual value.
                        update_set.update(_identity_update_set(stmt))
                        upsert_stmt = stmt.on_conflict_do_update(
                            index_elements=["primary_mac"],
                            index_where=Device.primary_mac.isnot(None),
                            set_=update_set,
                        ).returning(Device.id)
                        res = await session.execute(upsert_stmt)
                        row = res.first()
                        if row is not None:
                            device_id = int(row[0])
                    elif has_device_attrs:
                        # SC-07: MAC-less device finding (e.g. ``snmp_scan``
                        # returning an SNMP-only host absent from the ARP
                        # table). The previous blind INSERT created a
                        # duplicate ``devices`` row on EVERY scan and
                        # bypassed the SCAN-023 identity lock. Correlate
                        # through the finding's interface identity
                        # (IPv4/IPv6): if the interface is already linked to
                        # a device, merge into that row with the same
                        # NULL-skipping, lock-aware semantics as the
                        # ``primary_mac`` UPSERT path; only a finding with
                        # no correlatable interface keeps the single
                        # legacy INSERT.
                        existing_device: Optional[Device] = None
                        if ipv4 or ipv6:
                            corr_iface = await self._find_interface(session, ipv4=ipv4, ipv6=ipv6)
                            if corr_iface is not None and corr_iface.device_id is not None:
                                existing_device = await session.get(Device, corr_iface.device_id)
                        if existing_device is not None:
                            device_id = int(existing_device.id)
                            _merge_device_finding(existing_device, finding, now)
                            session.add(existing_device)
                        else:
                            dev = Device(
                                hostname=getattr(finding, "hostname", None),
                                vendor=getattr(finding, "vendor", None),
                                device_family=getattr(finding, "device_family", None),
                                device_type=getattr(finding, "device_type", None),
                                description=getattr(finding, "description", None),
                                article_number=getattr(finding, "article_number", None),
                                device_role=getattr(finding, "device_role", None),
                                firmware_version=getattr(finding, "firmware_version", None),
                                product_name=getattr(finding, "product_name", None),
                                hw_version=getattr(finding, "hw_version", None),
                                sw_version=getattr(finding, "sw_version", None),
                                serial_number=getattr(finding, "serial_number", None),
                                last_scan_at=now,
                                notes=getattr(finding, "notes", None),
                                update_available=False,
                            )
                            session.add(dev)
                            await session.flush()
                            device_id = int(dev.id)

                    # Interface upsert.
                    if ipv4 or primary_mac or mac_raw or ipv6:
                        iface_mac = primary_mac or mac_raw
                        iface = await self._find_interface(session, ipv4=ipv4, mac=iface_mac, ipv6=ipv6)
                        if not iface:
                            iface = NetworkInterface()
                        iface.ipv4_address = ipv4 or iface.ipv4_address
                        iface.mac_address = iface_mac or iface.mac_address
                        iface.ipv6_address = ipv6 or iface.ipv6_address
                        iface.subnet = getattr(finding, "subnet", None) or iface.subnet
                        # F-01: open_ports_summary column dropped — the
                        # finding's port list is now written to the
                        # service_observations table by ``save_port_scan_results``
                        # (or, in F-03, by per-module persistence wiring).
                        notes = getattr(finding, "notes", None)
                        if notes:
                            iface.notes = notes
                        if device_id is not None:
                            iface.device_id = device_id
                        iface.last_scan_at = now
                        # add-passive-asset-seeder D-MERGE-RULE: this
                        # path is an active-scan write, so the row's
                        # ``source`` SHALL be ``'active'``. If the row
                        # was previously ``'passive'`` (passive-seeder
                        # observation only), this UPGRADE is required
                        # by the spec scenario "Passive upgrades to
                        # active". Fresh inserts inherit ``'active'``
                        # via the column DEFAULT, but ORM-side .add
                        # does not exercise the default on UPDATE, so
                        # the explicit assignment is required.
                        iface.source = "active"
                        session.add(iface)
                        await session.flush()
                        upserted_ifaces += 1
        return upserted_ifaces

    # ---- Transformers from module outputs ----

    async def save_arp_scan_results(
        self,
        scan_id: Union[UUID, str],
        ip_list: Sequence[str],
        subnet: Optional[str] = None,
    ) -> List[int]:
        """Normalize ARP scan results: create/update interfaces for discovered IPv4 addresses.

        Returns:
            List of interface ids processed.
        """
        processed: List[int] = []
        now = datetime.now(tz=timezone.utc)
        arp_map = _read_arp_table_map()
        async with self._Session() as session:
            async with session.begin():
                for ip in ip_list:
                    iface = await self._find_interface(session, ipv4=ip)
                    if not iface:
                        iface = NetworkInterface(ipv4_address=ip)
                    mac = arp_map.get(ip)
                    if mac and not iface.mac_address:
                        iface.mac_address = mac
                    iface.subnet = subnet or iface.subnet
                    iface.last_scan_at = now
                    # add-passive-asset-seeder D-MERGE-RULE: ARP scan
                    # is an active-scan path; promote any passive-only
                    # row to ``'active'`` and stamp the active default
                    # on fresh inserts.
                    iface.source = "active"
                    session.add(iface)
                    await session.flush()
                    await session.refresh(iface)
                    processed.append(int(iface.id))

        # B-E3 (2026-06-04): the terminal scan lifecycle — ``status`` AND
        # ``finished_at`` set together, atomically — is owned exclusively by
        # :meth:`finish_scan`, which the orchestrator finish-sink
        # (``src/otalon_scan/api/server.py::_finish_scan``) invokes exactly once per run.
        # This result normalizer previously stamped ``finished_at`` without
        # touching ``status``; if the finish-sink then raced or missed the
        # row, the scan was left in the inconsistent
        # ``finished_at != NULL AND status = RUNNING`` state. Result
        # normalizers must not write lifecycle columns.
        return processed

    async def save_port_scan_results(
        self,
        scan_id: Union[UUID, str],
        portscan_results: Sequence[Dict[str, Any]],
        transport_default: Optional[str] = None,
    ) -> List[int]:
        """Normalize Nmap port scan results parsed by core.nmap_utils.

        Each element in ``portscan_results`` should contain:

        - ip_address: str
        - hostnames: List[str]
        - open_ports: List[Dict[str, Any]] with keys: port, protocol, state,
          service, product, version, extrainfo, cpe

        F-01 (``refactor-otalon-scan-persistence-pipeline-v1``): writes
        now go through the UPSERT path against the
        ``uq_service_observations_iface_port_transport_secmode`` constraint, so
        re-running the same port scan against the same host produces
        zero new rows. Rows missing a usable ``(port, transport)`` key
        (port=None or transport empty) are skipped — the UNIQUE
        constraint requires both, and Nmap output with no port number
        is not actionable anyway.

        Returns:
            List of interface ids that received at least one observation
            (kept for backwards compatibility with existing callers; the
            previous "observation ids" semantics is no longer applicable
            because the UPSERT path does not produce per-row PKs in the
            same transaction).
        """
        sid = UUID(str(scan_id))
        touched_iface_ids: List[int] = []
        now = datetime.now(tz=timezone.utc)
        arp_map = _read_arp_table_map()
        async with self._Session() as session:
            async with session.begin():
                for host in portscan_results:
                    host_ip = str(host.get("ip_address") or "")
                    open_ports = list(host.get("open_ports") or [])
                    iface = await self._find_interface(session, ipv4=host_ip)
                    if not iface:
                        iface = NetworkInterface(ipv4_address=host_ip)
                    mac = arp_map.get(host_ip)
                    if mac and not iface.mac_address:
                        iface.mac_address = mac
                    iface.last_scan_at = now
                    # add-passive-asset-seeder D-MERGE-RULE: port-scan
                    # writes are active-scan persistence; promote any
                    # passive-only row to ``'active'``.
                    iface.source = "active"

                    session.add(iface)
                    await session.flush()
                    await session.refresh(iface)
                    iface_id = int(iface.id)

                    for p in open_ports:
                        try:
                            port_num: Optional[int] = int(p.get("port")) if p.get("port") is not None else None
                        except (ValueError, TypeError):
                            port_num = None

                        transport = str(p.get("protocol") or transport_default or "") or None
                        if port_num is None or not transport:
                            # F-01: UNIQUE constraint requires both
                            # interface_id, port and transport to be
                            # non-null. Skip rows we cannot key cleanly.
                            continue

                        upsert_payload: dict[str, Any] = {
                            "scan_id": sid,
                            "interface_id": iface_id,
                            "ip_address": host_ip or None,
                            "mac_address": mac,
                            "port": port_num,
                            "transport": transport,
                            "protocol": None,
                            "service_name": str(p.get("service") or "") or None,
                            "product": str(p.get("product") or "") or None,
                            "version": str(p.get("version") or "") or None,
                            "cpe": str(p.get("cpe") or "") or None,
                            "extra_info": str(p.get("extrainfo") or "") or None,
                            "first_seen_at": now,
                            "last_seen_at": now,
                            "created_at": now,
                        }
                        stmt = pg_insert(ServiceObservation).values(**upsert_payload)
                        stmt = stmt.on_conflict_do_update(
                            constraint="uq_service_observations_iface_port_transport_secmode",
                            set_={
                                "last_seen_at": now,
                                "service_name": stmt.excluded.service_name,
                                "product": stmt.excluded.product,
                                "version": stmt.excluded.version,
                                "cpe": stmt.excluded.cpe,
                                "extra_info": stmt.excluded.extra_info,
                                "protocol": stmt.excluded.protocol,
                            },
                        )
                        await session.execute(stmt)

                    if iface_id not in touched_iface_ids:
                        touched_iface_ids.append(iface_id)

        # B-E3 (2026-06-04): see :meth:`save_arp_scan_results`. The
        # ``finished_at`` stamp removed from here violated the
        # single-finish-sink invariant by setting ``finished_at`` without
        # ``status``. The terminal lifecycle is owned solely by
        # :meth:`finish_scan`; this normalizer only writes observation rows.
        return touched_iface_ids

    async def save_opcua_discover_results(
        self,
        scan_id: Union[UUID, str],
        findings: Sequence[Any],
    ) -> List[int]:
        """Persist OPC UA discovery findings as service observations.

        Each :class:`DeviceFinding` in ``findings`` is expected to carry
        an ``extra.endpoint`` dict with keys such as ``Endpoint URL``,
        ``Application URI``, ``Product URI``, and ``Application Name``.
        The endpoint URL is parsed for host/port; when parsing fails the
        default OPC UA port 4840 is used.

        Rows are UPSERTed against the
        ``uq_service_observations_iface_port_transport_secmode`` constraint so
        re-scanning the same endpoint produces zero new rows.
        """
        sid = UUID(str(scan_id))
        touched_iface_ids: List[int] = []
        now = datetime.now(tz=timezone.utc)
        arp_map = _read_arp_table_map()
        async with self._Session() as session:
            async with session.begin():
                for finding in findings:
                    ip_val = getattr(finding, "ipv4", None) or getattr(finding, "ipv6", None) or ""
                    if not ip_val:
                        continue
                    iface = await self._find_interface(session, ipv4=ip_val)
                    if not iface:
                        iface = NetworkInterface(ipv4_address=ip_val)
                    mac = getattr(finding, "mac_address", None) or arp_map.get(ip_val)
                    if mac and not iface.mac_address:
                        iface.mac_address = mac
                    iface.last_scan_at = now
                    iface.source = "active"
                    session.add(iface)
                    await session.flush()
                    await session.refresh(iface)
                    iface_id = int(iface.id)

                    extra = getattr(finding, "extra", None) or {}
                    ep = extra.get("endpoint") if isinstance(extra, dict) else {}
                    ep = ep or {}

                    endpoint_url = str(ep.get("Endpoint URL") or ep.get("Discovery URL") or "").strip()
                    product_uri = str(ep.get("Product URI") or "").strip() or None
                    app_name = _clean_localized_text(str(ep.get("Application Name") or "").strip()) or None
                    security_mode = str(ep.get("Security Mode") or "").strip()
                    security_policy = str(ep.get("Security Policy URI") or "").strip()

                    port_num = 4840
                    if endpoint_url:
                        try:
                            s = endpoint_url.split("://", 1)[1].split("/", 1)[0]
                            _, _, port_s = s.partition(":")
                            port_num = int(port_s) if port_s and port_s.isdigit() else 4840
                        except Exception:
                            pass

                    upsert_payload: dict[str, Any] = {
                        "scan_id": sid,
                        "interface_id": iface_id,
                        "ip_address": ip_val or None,
                        "mac_address": mac,
                        "port": port_num,
                        "transport": "tcp",
                        "protocol": "opcua",
                        "service_name": app_name or "opcua",
                        "product": product_uri,
                        "version": None,
                        "cpe": None,
                        "extra_info": json.dumps(ep) if ep else None,
                        "security_mode": security_mode,
                        "security_policy": security_policy,
                        "first_seen_at": now,
                        "last_seen_at": now,
                        "created_at": now,
                    }
                    stmt = pg_insert(ServiceObservation).values(**upsert_payload)
                    stmt = stmt.on_conflict_do_update(
                        constraint="uq_service_observations_iface_port_transport_secmode",
                        set_={
                            "last_seen_at": now,
                            "service_name": stmt.excluded.service_name,
                            "product": stmt.excluded.product,
                            "version": stmt.excluded.version,
                            "cpe": stmt.excluded.cpe,
                            "extra_info": stmt.excluded.extra_info,
                            "protocol": stmt.excluded.protocol,
                        },
                    )
                    await session.execute(stmt)
                    if iface_id not in touched_iface_ids:
                        touched_iface_ids.append(iface_id)
        return touched_iface_ids

    # ---- Utility accessors ----

    async def lookup_eligible_devices(self) -> List[EligibilityResult]:
        """Evaluate the D4 identity cutoff over every ``devices`` row.

        Welle A GATE selector (CVE Feature, spec
        ``scan--device-identity-enrichment`` § "lookup-eligibility").
        Reads the three identity-cutoff columns (``vendor`` /
        ``product_name`` / ``firmware_version``) for all devices, maps
        them onto :class:`~otalon_scan.cve_lookup.DeviceIdentity`, and applies
        the pure :func:`~otalon_scan.cve_lookup.select_eligible` selector. The DB
        read stays here; the cutoff logic stays pure and unit-tested.

        Returns:
            One :class:`~otalon_scan.cve_lookup.EligibilityResult` per device.
            ``eligible`` rows carry a complete identity (vendor AND
            product AND version); non-eligible rows carry the ordered
            ``missing_fields`` list (containing ``firmware_version`` when
            the version is empty) so the operator sees why an asset is
            skipped. No partial-identity asset is ever eligible.
        """
        stmt = select(
            Device.id,
            Device.vendor,
            Device.product_name,
            Device.firmware_version,
        )
        async with self._Session() as session:
            res = await session.execute(stmt)
            identities = [
                DeviceIdentity(
                    device_id=int(row[0]),
                    vendor=row[1],
                    product=row[2],
                    version=row[3],
                )
                for row in res.all()
            ]
        return select_eligible(identities)

    async def lookup_eligible_assets(self) -> List[LookupAsset]:
        """Return :class:`LookupAsset` objects for every D4-eligible device.

        Mirrors :meth:`lookup_eligible_devices` but returns the concrete
        identity values the CVE source needs, not just the eligibility
        flag.  Rows lacking any of vendor / product_name / firmware_version
        are silently skipped (the cutoff gate still holds).
        """
        stmt = select(
            Device.id,
            Device.vendor,
            Device.product_name,
            Device.firmware_version,
            Device.device_family,
            Device.article_number,
            Device.description,
        )
        async with self._Session() as session:
            res = await session.execute(stmt)
            assets: List[LookupAsset] = []
            for row in res.all():
                vendor = (row[1] or "").strip()
                product = (row[2] or "").strip()
                version = (row[3] or "").strip()
                if vendor and product and version:
                    assets.append(
                        LookupAsset(
                            device_id=int(row[0]),
                            vendor=vendor,
                            product=product,
                            version=version,
                            device_family=row[4],
                            article_number=row[5],
                            description=row[6],
                        )
                    )
            return assets

    async def get_interfaces_by_ip(self, ipv4: str) -> List[NetworkInterface]:
        """Retrieve interfaces matching the given IPv4 address."""
        async with self._Session() as session:
            res = await session.execute(select(NetworkInterface).where(NetworkInterface.ipv4_address == ipv4))
            return list(res.scalars().all())

    async def get_scan(self, scan_id: Union[UUID, str]) -> Optional[Scan]:
        """Retrieve a :class:`Scan` by id."""
        sid = UUID(str(scan_id))
        async with self._Session() as session:
            return await session.get(Scan, sid)

    async def list_scans(
        self,
        *,
        status: Optional[str] = None,
        module: Optional[str] = None,
        since: Optional[datetime] = None,
        limit: int = 100,
        offset: int = 0,
    ) -> List[Scan]:
        """List :class:`Scan` rows ordered by ``started_at DESC``.

        Filters are AND-combined; ``None`` filters are skipped. Ordering
        is stable (``started_at DESC, id DESC``) so the most recent run
        for a given start-time wins on ties.

        Args:
            status: Optional :class:`ScanStatus` value (case-insensitive
                string match against the enum value, e.g. ``"running"``,
                ``"completed"``). Unknown values yield an empty list.
            module: Optional module-name filter; matches the
                :attr:`Scan.module_name` column verbatim (leaf slug as
                stored by the orchestrator, e.g. ``"arp_scan"``).
            since: Optional ``started_at >= since`` lower bound (UTC).
            limit: Maximum number of rows to return (default 100).
            offset: Skip the first ``offset`` rows.

        Returns:
            List of :class:`Scan` rows; empty when no rows match.
        """
        stmt = select(Scan)
        if status is not None:
            try:
                status_enum = ScanStatus(status.lower())
            except ValueError:
                return []
            stmt = stmt.where(Scan.status == status_enum)
        if module is not None:
            stmt = stmt.where(Scan.module_name == module)
        if since is not None:
            stmt = stmt.where(Scan.started_at >= since)
        stmt = stmt.order_by(Scan.started_at.desc(), Scan.id.desc())
        stmt = stmt.offset(max(0, offset)).limit(max(1, limit))
        async with self._Session() as session:
            res = await session.execute(stmt)
            return list(res.scalars().all())

    async def get_device(self, device_id: int) -> Optional[Device]:
        """Return a single :class:`Device` by surrogate id, or ``None``.

        SCAN-023: used by the ``PATCH /devices/{id}`` handler to return
        the updated device. The row is expunged from the session so the
        caller can read its attributes after the session closes.
        """
        async with self._Session() as session:
            row = await session.get(Device, device_id)
            if row is not None:
                session.expunge(row)
            return row

    async def set_manual_identity(
        self,
        device_id: int,
        fields: Dict[str, Optional[str]],
    ) -> Optional[Device]:
        """Manually set identity fields and lock them against scan-overwrite.

        SCAN-023: writes each supplied identity value onto the device and
        records the field name in ``manual_identity_fields`` so a
        subsequent :meth:`upsert_device` keeps the operator value instead
        of clobbering it. Only keys in :data:`MANUAL_IDENTITY_FIELDS` are
        accepted; unknown keys raise :class:`ValueError`. A value of
        ``None`` clears the field's stored value but STILL locks it (the
        operator asserting "this field has no value, do not auto-fill it").

        Args:
            device_id: Surrogate PK of the device to update.
            fields: Mapping of identity-field name to its new value. Must
                be non-empty and contain only lockable identity fields.

        Returns:
            The updated :class:`Device` (expunged), or ``None`` when no
            row matches ``device_id`` (caller translates to a 404).

        Raises:
            ValueError: When ``fields`` is empty or names a non-identity
                field.
        """
        if not fields:
            raise ValueError("set_manual_identity: no identity fields supplied")
        unknown = set(fields) - set(MANUAL_IDENTITY_FIELDS)
        if unknown:
            raise ValueError(f"set_manual_identity: not lockable identity fields: {sorted(unknown)}")
        async with self._Session() as session:
            async with session.begin():
                row = await session.get(Device, device_id)
                if row is None:
                    return None
                locked = set(row.manual_identity_fields or [])
                for field, value in fields.items():
                    setattr(row, field, value)
                    locked.add(field)
                # Reassign (not in-place mutate) so SQLAlchemy flags the
                # JSONB column dirty; sort for a stable, grep-able value.
                row.manual_identity_fields = sorted(locked)
                await session.flush()
                await session.refresh(row)
                session.expunge(row)
                return row

    async def device_exists(self, device_id: int) -> bool:
        """Return whether a ``devices`` row with ``device_id`` exists.

        Used by the device-scoped read endpoints (B-E1) to distinguish a
        genuinely-absent device (fachliche 404) from an existing device
        that simply has no associated rows yet (empty list, HTTP 200).
        """
        async with self._Session() as session:
            res = await session.execute(select(Device.id).where(Device.id == device_id).limit(1))
            return res.scalar_one_or_none() is not None

    async def list_device_scans(self, device_id: int) -> List[Scan]:
        """List :class:`Scan` rows that produced observations for a device.

        A scan "touched" a device when it wrote any
        ``service_observations`` row against one of the device's
        ``network_interfaces`` or any ``vulnerability_observations`` row
        carrying ``device_id``. The union of those scan ids is returned
        as full :class:`Scan` rows ordered by ``started_at DESC``.

        Returns an empty list when the device exists but no scan has
        touched it; the caller validates device existence separately via
        :meth:`device_exists` to surface a fachliche 404.
        """
        iface_subq = select(NetworkInterface.id).where(NetworkInterface.device_id == device_id)
        svc_scan_ids = select(ServiceObservation.scan_id).where(ServiceObservation.interface_id.in_(iface_subq))
        vuln_scan_ids = select(VulnerabilityObservation.scan_id).where(VulnerabilityObservation.device_id == device_id)
        stmt = (
            select(Scan)
            .where(Scan.id.in_(svc_scan_ids.union(vuln_scan_ids)))
            .order_by(Scan.started_at.desc(), Scan.id.desc())
        )
        async with self._Session() as session:
            res = await session.execute(stmt)
            return list(res.scalars().all())

    async def list_device_observations(self, device_id: int) -> List[ServiceObservation]:
        """List service observations for all interfaces of a device.

        Joins ``service_observations`` to the device's
        ``network_interfaces`` and returns the rows ordered by
        ``last_seen_at DESC``. Returns an empty list when the device
        exists but has no observations; the caller validates device
        existence separately to surface a fachliche 404.
        """
        iface_subq = select(NetworkInterface.id).where(NetworkInterface.device_id == device_id)
        stmt = (
            select(ServiceObservation)
            .where(ServiceObservation.interface_id.in_(iface_subq))
            .order_by(ServiceObservation.last_seen_at.desc(), ServiceObservation.id.desc())
        )
        async with self._Session() as session:
            res = await session.execute(stmt)
            return list(res.scalars().all())

    async def delete_scan(self, scan_id: Union[UUID, str]) -> bool:
        """Hard-delete a single scan row.

        Observations referencing the scan are removed automatically via
        ``ON DELETE CASCADE`` on the FK columns
        ``service_observations.scan_id`` and
        ``vulnerability_observations.scan_id``; no manual cascade is
        required.

        Args:
            scan_id: UUID of the ``scans`` row to remove.

        Returns:
            ``True`` when the row existed and was deleted, ``False``
            otherwise (caller should translate to HTTP 404).
        """
        sid = UUID(str(scan_id))
        async with self._Session() as session:
            async with session.begin():
                result = cast(
                    CursorResult[Any],
                    await session.execute(delete(Scan).where(Scan.id == sid)),
                )
                return bool(result.rowcount and result.rowcount > 0)

    async def delete_scans(self, scan_ids: List[Union[UUID, str]]) -> Dict[str, List[str]]:
        """Hard-delete a batch of scans atomically in a single transaction.

        Bulk counterpart to :meth:`delete_scan`. Leverages the same
        ``ON DELETE CASCADE`` FK semantics so child observations are
        removed automatically.

        The operation is atomic: either every existing id in
        ``scan_ids`` is removed, or no row is touched. Non-existent ids
        do not cause a rollback — they are reported back in
        ``not_found``. An empty input list short-circuits without
        opening a DB session.

        Args:
            scan_ids: List of ``scans.id`` primary keys to remove.
                Duplicates are tolerated (deduplicated internally).

        Returns:
            A dict with two keys:

            - ``deleted``: stringified UUIDs that existed and were
              removed, in input order.
            - ``not_found``: ids that did not match any ``scans`` row,
              in input order.
        """
        if not scan_ids:
            return {"deleted": [], "not_found": []}

        try:
            sids = [UUID(str(s)) for s in scan_ids]
        except ValueError:
            return {"deleted": [], "not_found": [str(s) for s in scan_ids]}

        unique_sids = list(dict.fromkeys(sids))

        async with self._Session() as session:
            async with session.begin():
                existing_rows = await session.execute(select(Scan.id).where(Scan.id.in_(unique_sids)))
                existing_ids: List[UUID] = [row[0] for row in existing_rows.all()]

                if existing_ids:
                    await session.execute(delete(Scan).where(Scan.id.in_(existing_ids)))

        existing_set = {str(s) for s in existing_ids}
        deleted = [str(s) for s in scan_ids if str(s) in existing_set]
        not_found = [str(s) for s in scan_ids if str(s) not in existing_set]
        return {
            "deleted": list(dict.fromkeys(deleted)),
            "not_found": list(dict.fromkeys(not_found)),
        }

    async def update_vulnerability(
        self,
        vuln_id: int,
        *,
        status: Optional[VulnStatus] = None,
        severity: Optional[str] = None,
        summary: Optional[str] = None,
        status_changed_by: Optional[str] = None,
    ) -> Optional[VulnerabilityObservation]:
        """Patch the mutable triage fields of a vulnerability observation.

        Only the supplied (non-``None``) fields are written. When
        ``status`` changes, ``status_changed_at`` is stamped (UTC) and
        ``status_changed_by`` recorded if provided. Returns the updated
        row, or ``None`` when no ``vulnerability_observations`` row
        matches ``vuln_id`` (caller translates to a fachliche 404).
        """
        async with self._Session() as session:
            async with session.begin():
                row = await session.get(VulnerabilityObservation, vuln_id)
                if row is None:
                    return None
                if status is not None and status != row.status:
                    row.status = status
                    row.status_changed_at = datetime.now(tz=timezone.utc)
                    if status_changed_by is not None:
                        row.status_changed_by = status_changed_by
                if severity is not None:
                    row.severity = severity
                if summary is not None:
                    row.summary = summary
                await session.flush()
                await session.refresh(row)
                session.expunge(row)
                return row

    async def ping(self) -> None:
        """Liveness check against the DB.

        Issues a trivial ``SELECT 1`` over a freshly acquired connection.
        Used by the ``GET /health`` endpoint to verify that the
        PostgreSQL connection is still alive after startup (HC4). Raises
        the underlying :class:`sqlalchemy.exc.SQLAlchemyError` (or any
        driver exception) on failure so the caller can downgrade the
        health response.
        """
        async with self.engine.connect() as conn:
            await conn.exec_driver_sql("SELECT 1")

    async def probe(self) -> tuple[bool, Optional[str]]:
        """Non-raising liveness probe used by ``GET /health?deep=true``.

        Issues a trivial ``SELECT 1`` with a 1-second timeout. Returns
        ``(True, None)`` on success, ``(False, <error message>)`` on
        any failure (timeout, connection refused, auth failure, etc.).

        Companion to :meth:`ping` (which raises) for callers that want
        a structured success/failure tuple instead of an exception —
        notably the F-02 deep-health endpoint and the lifespan startup
        gate (scan--app-lifecycle "Fail-Loud Startup on Postgres
        Unavailability").
        """
        try:
            await asyncio.wait_for(self.ping(), timeout=1.0)
        except asyncio.TimeoutError:
            return False, "Postgres SELECT 1 probe timed out after 1.0s"
        except Exception as exc:  # noqa: BLE001 -- structured tuple is the contract
            return False, str(exc)
        return True, None

    async def dispose(self) -> None:
        """Dispose the async engine connections (lifespan shutdown)."""
        try:
            await self.engine.dispose()
        except SQLAlchemyError:
            pass
