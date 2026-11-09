"""core_base_tables

Base Alembic migration for otalon-scan; added retroactively as part of the
SCAN-031 fix wave (SUITE-031 audit finding **SC-06**).

The chain historically started at ``0001_initial_view_and_upserts``, which
ALTERS and DROPs columns on tables no migration ever created — the core
schema had only ever been produced by the retired
``Base.metadata.create_all`` startup path. A fresh database therefore could
not be migrated: ``alembic upgrade head`` died at ``0001`` with
``relation "vulnerability_observations" does not exist``.

This migration reconstructs the **pre-0001 baseline** of the five core
tables, derived from :mod:`otalon_scan.repositories.models` (the authoritative ORM)
minus every column/constraint introduced by revisions ``0001``–``0014`` and
plus the two legacy jsonb caches that ``0001`` drops
(``devices.vulnerabilities``, ``network_interfaces.open_ports_summary``):

1. ``devices`` — asset master data (identity enrichment columns arrive in
   0002/0005/0007/0010).
2. ``network_interfaces`` — interfaces with the pre-existing UNIQUE
   constraints ``uq_iface_mac`` / ``uq_iface_ipv4`` / ``uq_iface_ipv6`` and
   index ``ix_network_interfaces_device_id`` (the passive-source columns
   arrive in 0003).
3. ``scans`` — job records on the ``scan_status`` enum (member-name labels,
   matching the ORM's ``SQLEnum(ScanStatus)`` without ``values_callable``).
4. ``service_observations`` — per-scan port/service observations (the
   5-tuple UNIQUE arrives in 0001/0004).
5. ``vulnerability_observations`` — per-scan vulnerability observations
   (status/audit columns arrive in 0001).

Every statement is idempotent (``IF NOT EXISTS`` / ``DO``-block guard) so a
database that already carries some of this shape (e.g. from the retired
``create_all`` path) cannot wedge on re-run. Existing populated databases
are untouched in practice: they are stamped at a revision ``>= 0001``, and
Alembic never revisits the base.

``downgrade`` drops exactly what this migration created.

Revision ID: 0000
Revises: None (new chain root)
Create Date: 2026-08-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0000"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the pre-0001 baseline of the five core tables (idempotent)."""
    # ``scan_status`` enum with the member-name labels SQLAlchemy emits for
    # ``SQLEnum(ScanStatus, name="scan_status")`` (no ``values_callable``).
    # ``CANCELLED_PARTIAL`` is appended later by revision 0015, mirroring
    # the historical order of events.
    op.execute(
        """
        DO $$
        BEGIN
            CREATE TYPE scan_status AS ENUM ('PENDING', 'RUNNING', 'COMPLETED', 'FAILED', 'ABORTED');
        EXCEPTION
            WHEN duplicate_object THEN NULL;
        END
        $$;
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS devices (
            id SERIAL PRIMARY KEY,
            vendor VARCHAR,
            device_family VARCHAR,
            device_type VARCHAR,
            description TEXT,
            article_number VARCHAR,
            device_role VARCHAR,
            firmware_version VARCHAR,
            vulnerabilities JSONB,
            update_available BOOLEAN NOT NULL,
            last_scan_at TIMESTAMPTZ,
            notes TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS network_interfaces (
            id SERIAL PRIMARY KEY,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            mac_address VARCHAR,
            ipv4_address INET,
            ipv6_address INET,
            subnet CIDR,
            open_ports_summary JSONB,
            last_scan_at TIMESTAMPTZ,
            notes TEXT,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ,
            CONSTRAINT uq_iface_mac UNIQUE (mac_address),
            CONSTRAINT uq_iface_ipv4 UNIQUE (ipv4_address),
            CONSTRAINT uq_iface_ipv6 UNIQUE (ipv6_address)
        )
        """
    )
    op.execute("CREATE INDEX IF NOT EXISTS ix_network_interfaces_device_id " "ON network_interfaces (device_id)")

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS scans (
            id UUID PRIMARY KEY,
            module_name VARCHAR NOT NULL,
            status scan_status NOT NULL,
            error_message TEXT,
            source_ip INET,
            source_mac VARCHAR,
            parameters JSONB,
            started_at TIMESTAMPTZ NOT NULL,
            finished_at TIMESTAMPTZ,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS service_observations (
            id SERIAL PRIMARY KEY,
            scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            interface_id INTEGER REFERENCES network_interfaces(id) ON DELETE SET NULL,
            ip_address INET,
            mac_address VARCHAR,
            port INTEGER,
            transport VARCHAR,
            protocol VARCHAR,
            service_name VARCHAR,
            product VARCHAR,
            version VARCHAR,
            cpe VARCHAR,
            extra_info VARCHAR,
            first_seen_at TIMESTAMPTZ NOT NULL,
            last_seen_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ
        )
        """
    )

    op.execute(
        """
        CREATE TABLE IF NOT EXISTS vulnerability_observations (
            id SERIAL PRIMARY KEY,
            scan_id UUID NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
            device_id INTEGER REFERENCES devices(id) ON DELETE SET NULL,
            interface_id INTEGER REFERENCES network_interfaces(id) ON DELETE SET NULL,
            source_module VARCHAR,
            vuln_id VARCHAR,
            severity VARCHAR,
            summary TEXT,
            metadata JSONB,
            detected_at TIMESTAMPTZ NOT NULL,
            created_at TIMESTAMPTZ NOT NULL,
            updated_at TIMESTAMPTZ
        )
        """
    )


def downgrade() -> None:
    """Drop exactly the objects this migration created."""
    op.execute("DROP TABLE IF EXISTS vulnerability_observations")
    op.execute("DROP TABLE IF EXISTS service_observations")
    op.execute("DROP TABLE IF EXISTS scans")
    op.execute("DROP TABLE IF EXISTS network_interfaces")
    op.execute("DROP TABLE IF EXISTS devices")
    op.execute("DROP TYPE IF EXISTS scan_status")
