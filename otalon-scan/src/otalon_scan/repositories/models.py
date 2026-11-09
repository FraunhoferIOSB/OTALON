from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, List, Optional
from uuid import UUID, uuid4

# ruff: noqa: I001
# isort and ruff's I001 disagree on how to order ``from sqlalchemy import``
# blocks that include an aliased ``Enum as SQLEnum`` mid-alphabet entry.
# isort wants the aliased line interposed between alphabetically-adjacent
# sibling lines (DateTime → Enum → ForeignKey); ruff wants the
# non-aliased sibling lines merged into one. We follow isort (which is
# the workspace-wide canonical tool per AGENTS.md) and silence ruff's
# I001 for the file. The rest of the file is fully ruff/black-clean.
from sqlalchemy import Boolean, DateTime
from sqlalchemy import Enum as SQLEnum
from sqlalchemy import ForeignKey, Index, Integer, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import CIDR, INET, JSONB
from sqlalchemy.dialects.postgresql import UUID as PGUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


def _utc_now() -> datetime:
    """Return the current UTC time as a timezone-aware ``datetime``.

    Used as the SQLAlchemy ``default=`` / ``onupdate=`` callable on
    timestamp columns. Replaces the deprecated ``datetime.utcnow`` per
    F-02 (refactor-otalon-scan-code-quality-v1) HC22 cleanup.
    """
    return datetime.now(tz=timezone.utc)


class Base(DeclarativeBase):
    """Declarative base for CyberScan-ICS models."""


class ScanStatus(str, Enum):
    """Execution status for scanner runs.

    ``CANCELLED_PARTIAL`` (D4 resolved 2026-05-17) marks scans that were
    cancelled mid-flight but produced device findings that were flushed
    to disk by ``ModuleManager._persist_batch`` before re-raising the
    ``asyncio.CancelledError``. Queries that need "complete scans only"
    SHALL filter on ``status = 'completed'``.
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"
    CANCELLED_PARTIAL = "cancelled_partial"


class CveLookupStatus(str, Enum):
    """Execution status for CVE-lookup jobs (SCAN-026 Welle A).

    Mirrors the :class:`ScanStatus` vocabulary deliberately (design.md
     § D1): a CVE lookup is just another tracked job, so it reuses the
     proven ``pending → running → completed | failed`` lifecycle. The
     ``cancelled_partial`` member of :class:`ScanStatus` is intentionally
     omitted — a lookup that is stopped mid-sweep does not flush a
     partial result, so there is no ``cancelled_partial`` analogue. The
     terminal ``aborted`` member (R-02) IS carried so an operator can
     cooperatively cancel an in-flight lookup before the NVD sweep
     completes. Kept as a separate Postgres enum (``cve_lookup_status``)
     rather than reusing ``scan_status`` so the two job tables stay
     decoupled (design.md § D1 / Risk note).
    """

    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    ABORTED = "aborted"


class VulnStatus(str, Enum):
    """Lifecycle status of a vulnerability observation (mission §10 Q8).

    Defaults to :attr:`ACTIVE` on first insert; operator transitions to
    :attr:`MITIGATED`, :attr:`FALSE_POSITIVE`, or :attr:`RESOLVED`
    populate ``status_changed_at`` and ``status_changed_by``.

    Introduced by F-01 (``refactor-otalon-scan-persistence-pipeline-v1``).
    The Postgres enum type is named ``vuln_status``; values are in the
    documented mission order and SHALL NOT be reordered.
    """

    ACTIVE = "active"
    MITIGATED = "mitigated"
    FALSE_POSITIVE = "false_positive"
    RESOLVED = "resolved"


class Device(Base):
    """
    Represents a physical or logical device in an ICS/OT environment.

    This model intentionally keeps relationships to network interfaces loose:
    interfaces can be linked later by a human if automatic correlation is not possible.
    """

    __tablename__ = "devices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    # F-03 device-identity natural key (refactor-otalon-scan-device-network-ownership-v1).
    # Canonical lowercase colon-separated MAC (e.g. ``aa:bb:cc:dd:ee:ff``).
    # Constrained at the DB level by ``ck_devices_primary_mac_format`` and
    # deduplicated by the partial UNIQUE index ``uq_devices_primary_mac``
    # (both introduced by alembic revision ``0002_device_identity_and_parents``).
    # Nullable so legacy rows without a known MAC keep working; all new
    # rows from :meth:`ScannerPostgresRepo.upsert_device` MUST provide a
    # non-NULL ``primary_mac``.
    primary_mac: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # P8 Welle A (F-04/F-10): the device's discovered network name (PROFINET
    # station-name, SNMP ``sysName``). Previously these landed in
    # ``device_type`` — a hostname is NOT a device type, so the UI rendered
    # e.g. ``Type: bk9103-2``. The name now has its own column; ``device_type``
    # holds only a genuine device type and stays NULL when none is known
    # (no guessing). Populated by pn_discovery / snmp_scan; other modules
    # leave it NULL (NULL-skipping merge). Added by alembic revision
    # ``0010_device_hostname``.
    hostname: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    vendor: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    device_family: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    device_type: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    article_number: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    device_role: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    firmware_version: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # SCAN-018 SNMP asset-enrichment: additive nullable master-data
    # columns populated by the SNMP walker (alembic revision
    # ``0005_snmp_asset_enrichment``). Per operator decision D1 they are
    # device-scoped (one value per device, no observation-scoped scan
    # history); D2 maps SNMP ``product_family`` onto the existing
    # ``device_family`` column (no new column); D3 keeps ``firmware_version``
    # alongside the new ``hw_version`` / ``sw_version``.
    product_name: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    hw_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    sw_version: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    serial_number: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # SCAN-023 operator manual-identity override. JSONB array listing the
    # identity-field names an operator has manually set (e.g.
    # ``["vendor", "firmware_version"]``). A field named here is
    # operator-locked: :meth:`ScannerPostgresRepo.upsert_device` SHALL
    # NOT overwrite it on a subsequent scan (it keeps the manual value),
    # while unlocked fields keep their existing NULL-skipping COALESCE
    # merge. A single JSONB array is preferred over eight ``*_locked``
    # boolean columns because it is one additive column, extends to new
    # identity fields without further migrations, and mirrors the
    # provenance-marker style already used on
    # :class:`NetworkInterface` (``source``). Added by alembic revision
    # ``0007_manual_identity_fields``; defaults to ``[]`` (no locks).
    manual_identity_fields: Mapped[list[str]] = mapped_column(
        JSONB,
        nullable=False,
        default=list,
        server_default="[]",
    )

    # Legacy jsonb cache ``vulnerabilities`` removed in F-01
    # (refactor-otalon-scan-persistence-pipeline-v1); the authoritative
    # source is now ``vulnerability_observations`` and the aggregated
    # ``device_topology_view``. See migration 0001_initial_view_and_upserts.

    update_available: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utc_now)

    # Relationships
    interfaces: Mapped[List["NetworkInterface"]] = relationship(back_populates="device", lazy="selectin")

    def __repr__(self) -> str:
        return f"<Device id={self.id} vendor={self.vendor!r} type={self.device_type!r}>"


class NetworkInterface(Base):
    """
    Represents a network interface observed in the network.

    - device_id is nullable to allow later manual linking of interfaces to devices.
    - Per-port/service observations are stored in ``ServiceObservation``;
      the legacy ``open_ports_summary`` jsonb cache was removed in F-01
      (refactor-otalon-scan-persistence-pipeline-v1). UI consumers now
      read the aggregated array from ``network_interface_ports_view``.
    """

    __tablename__ = "network_interfaces"
    __table_args__ = (
        UniqueConstraint("mac_address", name="uq_iface_mac"),
        UniqueConstraint("ipv4_address", name="uq_iface_ipv4"),
        UniqueConstraint("ipv6_address", name="uq_iface_ipv6"),
        Index("ix_network_interfaces_device_id", "device_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)

    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    mac_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    ipv4_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    ipv6_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    subnet: Mapped[Optional[str]] = mapped_column(CIDR, nullable=True)

    last_scan_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    notes: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    # add-passive-asset-seeder: provenance marker columns. ``source``
    # distinguishes active-scan vs passive-seeder originated rows; the
    # two timestamp columns record passive sightings. See alembic
    # revision ``0003_passive_source_marker`` and the merge rule in
    # ``add-passive-asset-seeder/design.md`` § D-MERGE-RULE.
    source: Mapped[str] = mapped_column(
        Text,
        nullable=False,
        default="active",
        server_default="active",
    )
    first_seen_passive_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    last_seen_passive_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utc_now)

    # Relationships
    device: Mapped[Optional["Device"]] = relationship(back_populates="interfaces", lazy="joined")
    service_observations: Mapped[List["ServiceObservation"]] = relationship(
        back_populates="interface",
        lazy="selectin",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )
    vulnerability_observations: Mapped[List["VulnerabilityObservation"]] = relationship(
        back_populates="interface",
        lazy="selectin",
        cascade="all, delete-orphan",
        passive_deletes=True,
    )

    def __repr__(self) -> str:
        return f"<NetworkInterface id={self.id} mac={self.mac_address!r} ipv4={self.ipv4_address!r}>"


class Scan(Base):
    """
    Tracks a single scan execution of a module (e.g., ARP, Port Scan, SNMP, OPC UA).

    The 'parameters' column stores the effective configuration used for the run.
    """

    __tablename__ = "scans"

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    module_name: Mapped[str] = mapped_column(String, nullable=False)
    status: Mapped[ScanStatus] = mapped_column(
        SQLEnum(ScanStatus, name="scan_status"),
        nullable=False,
        default=ScanStatus.PENDING,
    )
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    source_ip: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    source_mac: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    parameters: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)

    # L-02: per-scan findings snapshot persisted at finalization so a past
    # scan's discovered devices/services remain inspectable in the history
    # detail view. The live findings still flow into the asset/observation
    # tables via the persist sink; this column is an immutable point-in-time
    # record of exactly what THIS scan reported (list of DeviceFinding dicts).
    findings: Mapped[Optional[list[dict[str, Any]]]] = mapped_column(JSONB, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utc_now)

    # Relationships
    service_observations: Mapped[List["ServiceObservation"]] = relationship(back_populates="scan", lazy="selectin")
    vulnerability_observations: Mapped[List["VulnerabilityObservation"]] = relationship(
        back_populates="scan", lazy="selectin"
    )

    def __repr__(self) -> str:
        return f"<Scan id={self.id} module={self.module_name} status={self.status}>"


class CveLookup(Base):
    """Job-header record for a CVE-lookup run (SCAN-026 Welle A, D1).

    The CVE-lookup job mirrors the :class:`Scan` job-record pattern: one
    row per triggered lookup carrying its parameters, lifecycle status,
    start/finish timestamps, an aggregated ``summary`` and an optional
    ``error`` message. This is the job **header** only — the CVE hits
    themselves stay in :class:`VulnerabilityObservation` (design.md
    § D1). The ``id`` doubles as the ``job_id`` correlation key across
    the REST/SSE/DB surface.

    ``summary`` carries the CONCEPT §6 shape
    ``{assets_scanned, cves_found, critical, per_asset:[...],
    rate_limit_hits}`` once the job finishes; it is NULL while the job is
    ``pending`` / ``running``.
    """

    __tablename__ = "cve_lookups"
    __table_args__ = (Index("ix_cve_lookups_started_at", "started_at"),)

    id: Mapped[UUID] = mapped_column(PGUUID(as_uuid=True), primary_key=True, default=uuid4)
    # ``all`` | ``device`` — whether the job covers every eligible asset
    # or a single device (the latter sets ``device_id``).
    scope: Mapped[str] = mapped_column(String, nullable=False)
    # Best-effort device PK for a per-device lookup (UI-049); NULL for
    # ``scope='all'``. Intentionally NOT a FK so a job-header survives a
    # later device delete (audit trail), mirroring the loose coupling of
    # the scan job-record.
    device_id: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    # CVE provider that was queried (``nvd`` | ``cert_vde``).
    source: Mapped[str] = mapped_column(String, nullable=False, default="nvd")
    # Whether an API key was supplied to the source — feeds the
    # rate-limit box in the V2 detail pane.
    api_key_used: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[CveLookupStatus] = mapped_column(
        SQLEnum(
            CveLookupStatus,
            name="cve_lookup_status",
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
        ),
        nullable=False,
        default=CveLookupStatus.PENDING,
    )
    summary: Mapped[Optional[dict[str, Any]]] = mapped_column(JSONB, nullable=True)
    error: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    finished_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utc_now)

    def __repr__(self) -> str:
        return f"<CveLookup id={self.id} scope={self.scope!r} status={self.status}>"


class ServiceObservation(Base):
    """
    Observation of an open port/service on an interface from a particular scan.

    The interface relation is nullable to allow recording findings even if we cannot
    correlate to a persisted interface yet. Post-processing can link later.
    """

    __tablename__ = "service_observations"
    __table_args__ = (
        # F-01: UNIQUE supports the UPSERT semantics in
        # ``ScannerPostgresRepo.upsert_service_observation``.
        # ``interface_id`` is NOT NULL at the helper-signature level
        # (design.md § D-UPSERT-ORDER); writers that bypass the helper
        # with raw SQL will be detected by this constraint.
        # SCAN-015: ``security_mode`` / ``security_policy`` extend the
        # discriminator so OPC UA endpoints that share one
        # ``(interface_id, port, transport)`` triple but differ by
        # Security Mode / Policy persist as distinct rows. Both default
        # to ``''`` (NOT NULL) so non-OPC-UA writers keep their idempotent
        # UPSERT (all share ``('', '')``); see migration 0004.
        UniqueConstraint(
            "interface_id",
            "port",
            "transport",
            "security_mode",
            "security_policy",
            name="uq_service_observations_iface_port_transport_secmode",
        ),
        Index("ix_service_observations_interface", "interface_id"),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    interface_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("network_interfaces.id", ondelete="SET NULL"),
        nullable=True,
    )

    ip_address: Mapped[Optional[str]] = mapped_column(INET, nullable=True)
    mac_address: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    transport: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # tcp / udp
    protocol: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # application layer protocol
    service_name: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    product: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    version: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    cpe: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    extra_info: Mapped[Optional[str]] = mapped_column(String, nullable=True)

    # SCAN-015: OPC UA Security Mode / Policy discriminator. NOT NULL with
    # ``''`` default so non-OPC-UA writers (port_scan / arp) that never set
    # them still dedup (all share ``('', '')``); OPC UA endpoints carry
    # their distinct pair and persist as separate rows.
    security_mode: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")
    security_policy: Mapped[str] = mapped_column(String, nullable=False, default="", server_default="")

    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utc_now)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="service_observations", lazy="joined")
    interface: Mapped[Optional["NetworkInterface"]] = relationship(back_populates="service_observations", lazy="joined")

    def __repr__(self) -> str:
        return f"<ServiceObservation id={self.id} ip={self.ip_address} port={self.port}/{self.transport}>"


class VulnerabilityObservation(Base):
    """
    Observation of a vulnerability related to a device or interface.

    Association with a Device or a NetworkInterface is optional to allow deferred correlation.

    F-01 (``refactor-otalon-scan-persistence-pipeline-v1``) added:

    - ``status`` enum column (mission §10 Q8: active / mitigated /
      false_positive / resolved), default ``active``;
    - ``status_changed_at`` / ``status_changed_by`` audit columns;
    - ``last_seen_at`` timestamp (needed by the UPSERT helper);
    - UNIQUE constraint on ``(device_id, vuln_id)`` enforcing the
      idempotent UPSERT semantics from mission §10 Q7.
    """

    __tablename__ = "vulnerability_observations"
    __table_args__ = (
        UniqueConstraint(
            "device_id",
            "vuln_id",
            name="uq_vuln_observations_device_vuln",
        ),
        Index(
            "ix_vuln_observations_device_status",
            "device_id",
            "status",
        ),
    )

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scan_id: Mapped[UUID] = mapped_column(
        PGUUID(as_uuid=True),
        ForeignKey("scans.id", ondelete="CASCADE"),
        nullable=False,
    )
    device_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("devices.id", ondelete="SET NULL"),
        nullable=True,
    )
    interface_id: Mapped[Optional[int]] = mapped_column(
        ForeignKey("network_interfaces.id", ondelete="SET NULL"),
        nullable=True,
    )

    source_module: Mapped[Optional[str]] = mapped_column(String, nullable=True)
    vuln_id: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # e.g., CVE-2024-XXXX or vendor-specific id
    severity: Mapped[Optional[str]] = mapped_column(String, nullable=True)  # LOW/MEDIUM/HIGH/CRITICAL
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    # 'metadata' attribute name is reserved in SQLAlchemy; use 'metadata_json' with DB column name "metadata".
    metadata_json: Mapped[Optional[dict[str, Any]]] = mapped_column("metadata", JSONB, nullable=True)

    # F-01: status enum + audit columns + last_seen_at.
    status: Mapped[VulnStatus] = mapped_column(
        SQLEnum(
            VulnStatus,
            name="vuln_status",
            values_callable=lambda enum_cls: [member.value for member in enum_cls],
            create_type=False,
        ),
        nullable=False,
        default=VulnStatus.ACTIVE,
        server_default="active",
    )
    status_changed_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), nullable=True)
    status_changed_by: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    detected_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False, default=_utc_now)
    updated_at: Mapped[Optional[datetime]] = mapped_column(DateTime(timezone=True), onupdate=_utc_now)

    # Relationships
    scan: Mapped["Scan"] = relationship(back_populates="vulnerability_observations", lazy="joined")
    interface: Mapped[Optional["NetworkInterface"]] = relationship(
        back_populates="vulnerability_observations", lazy="joined"
    )
    device: Mapped[Optional["Device"]] = relationship(lazy="joined")

    def __repr__(self) -> str:
        return f"<VulnerabilityObservation id={self.id} vuln_id={self.vuln_id!r} severity={self.severity!r}>"
