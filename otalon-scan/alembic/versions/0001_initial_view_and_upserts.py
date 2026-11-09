"""initial_view_and_upserts

Initial Alembic migration for otalon-scan; introduced as part of
``refactor-otalon-scan-persistence-pipeline-v1`` (F-01).

This migration captures the **post-change** persistence-pipeline schema
state in a single revision (see design.md § D-MIG for the
one-big-migration decision). It:

1. Creates the ``vuln_status`` PostgreSQL enum type with the four
   mission §10 Q8 values (``active``, ``mitigated``, ``false_positive``,
   ``resolved``).
2. Adds 4 columns to ``vulnerability_observations``: ``status``,
   ``status_changed_at``, ``status_changed_by``, ``last_seen_at``
   (mission §10 Q7 / Q8).
3. Adds UNIQUE constraints needed for the new UPSERT semantics:
   ``uq_service_observations_iface_port_transport`` on
   ``service_observations(interface_id, port, transport)`` and
   ``uq_vuln_observations_device_vuln`` on
   ``vulnerability_observations(device_id, vuln_id)``.
4. Adds supporting indexes so the new views are index-only:
   ``ix_vuln_observations_device_status`` and
   ``ix_service_observations_interface``.
5. Drops the legacy jsonb caches ``devices.vulnerabilities`` and
   ``network_interfaces.open_ports_summary`` (mission §10 Q1).
6. Creates ``device_topology_view`` (devices + aggregated active
   vulnerabilities array) and ``network_interface_ports_view``
   (interfaces + aggregated open_ports_summary array).
7. Grants ``SELECT`` on both views to the API role (best-effort —
   silently skipped if the role does not exist; the standard workspace
   deployment uses the ``postgres`` superuser which already has access).

``downgrade`` reverses the schema in inverse order but cannot restore
the content of the dropped jsonb columns (operator-curated demo data;
re-imported by ``scripts/migrate_demo_jsonb_to_observations.py`` after
``upgrade head``). For full content recovery, restore from a
``pg_dump`` snapshot taken before the upgrade.

Revision ID: 0001
Revises: 0000
Create Date: 2026-05-18

Refs:
- proposal.md / design.md / tasks.md under
  ``openspec/changes/refactor-otalon-scan-persistence-pipeline-v1/``
- ``openspec/specs/scan--persistence-pipeline/spec.md`` (delta)
- ``openspec/specs/scan--persistence-ownership/spec.md`` (delta)
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0001"
# SC-06: 0001 originally rooted the chain although it only ever ALTERs the
# core tables. Revision ``0000_core_base_tables`` (added retroactively in
# the SCAN-031 wave) now creates them, so a fresh database can migrate.
down_revision: Union[str, None] = "0000"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


# Mission §10 Q8 — authoritative enum values, in the documented order.
_VULN_STATUS_VALUES: tuple[str, ...] = (
    "active",
    "mitigated",
    "false_positive",
    "resolved",
)

# Postgres role granted SELECT on the new views. The standard workspace
# deployment uses the ``postgres`` superuser everywhere (which already
# has full privilege), so the GRANT is informational; if the deployment
# ever introduces a dedicated ``otalon_api`` role, the migration
# below grants explicitly.
_API_ROLE_NAME: str = "otalon_api"


def upgrade() -> None:
    """Apply the F-01 persistence-pipeline schema delta."""
    bind = op.get_bind()

    # 1) Create the vuln_status enum.
    vuln_status_enum = sa.Enum(
        *_VULN_STATUS_VALUES,
        name="vuln_status",
        create_type=False,
    )
    vuln_status_enum.create(bind, checkfirst=True)

    # 2) Add the four new columns on vulnerability_observations.
    #    last_seen_at defaults to now() for migration safety on rows that
    #    already exist on the live DB (server_default ensures the
    #    column-add itself doesn't fail under the NOT NULL constraint).
    op.add_column(
        "vulnerability_observations",
        sa.Column(
            "status",
            sa.Enum(*_VULN_STATUS_VALUES, name="vuln_status", create_type=False),
            nullable=False,
            server_default="active",
        ),
    )
    op.add_column(
        "vulnerability_observations",
        sa.Column(
            "status_changed_at",
            sa.DateTime(timezone=True),
            nullable=True,
        ),
    )
    op.add_column(
        "vulnerability_observations",
        sa.Column(
            "status_changed_by",
            sa.Text(),
            nullable=True,
        ),
    )
    op.add_column(
        "vulnerability_observations",
        sa.Column(
            "last_seen_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # 3) UNIQUE constraints. NULL handling is enforced by the type
    #    system at the repo helper level (interface_id: int, device_id:
    #    int — see design.md § D-UPSERT-ORDER). The constraint here is
    #    the SQL-level guard that catches direct-SQL bypasses.
    op.create_unique_constraint(
        "uq_service_observations_iface_port_transport",
        "service_observations",
        ["interface_id", "port", "transport"],
    )
    op.create_unique_constraint(
        "uq_vuln_observations_device_vuln",
        "vulnerability_observations",
        ["device_id", "vuln_id"],
    )

    # 4) Supporting indexes (the two views below filter / join on these
    #    columns and we want the subqueries to be index-only).
    op.create_index(
        "ix_vuln_observations_device_status",
        "vulnerability_observations",
        ["device_id", "status"],
    )
    op.create_index(
        "ix_service_observations_interface",
        "service_observations",
        ["interface_id"],
    )

    # 5) Drop the legacy jsonb caches.
    op.drop_column("devices", "vulnerabilities")
    op.drop_column("network_interfaces", "open_ports_summary")

    # 6) Create the two read views.
    op.execute(
        """
        CREATE VIEW device_topology_view AS
        SELECT
            d.id,
            d.vendor,
            d.device_family,
            d.device_type,
            d.description,
            d.article_number,
            d.device_role,
            d.firmware_version,
            d.update_available,
            d.last_scan_at,
            d.notes,
            d.created_at,
            d.updated_at,
            COALESCE(
                (
                    SELECT jsonb_agg(jsonb_build_object(
                        'vuln_id', v.vuln_id,
                        'severity', v.severity,
                        'summary', v.summary,
                        'source_module', v.source_module,
                        'detected_at', v.detected_at,
                        'last_seen_at', v.last_seen_at,
                        'status', v.status
                    ) ORDER BY v.severity DESC NULLS LAST, v.vuln_id)
                    FROM vulnerability_observations v
                    WHERE v.device_id = d.id
                      AND v.status = 'active'
                ),
                '[]'::jsonb
            ) AS vulnerabilities
        FROM devices d;
        """
    )
    op.execute(
        """
        CREATE VIEW network_interface_ports_view AS
        SELECT
            ni.id AS interface_id,
            ni.device_id,
            COALESCE(
                (
                    SELECT jsonb_agg(jsonb_build_object(
                        'port', s.port,
                        'service', s.service_name,
                        'protocol', s.transport,
                        'product', s.product,
                        'version', s.version,
                        'last_seen_at', s.last_seen_at
                    ) ORDER BY s.port)
                    FROM service_observations s
                    WHERE s.interface_id = ni.id
                ),
                '[]'::jsonb
            ) AS open_ports_summary
        FROM network_interfaces ni;
        """
    )

    # 7) Grant SELECT on both views to the API role, best-effort.
    #    DO-block silently skips the GRANT if the role doesn't exist
    #    (typical for dev deployments that use the postgres superuser).
    op.execute(
        f"""
        DO $$
        BEGIN
            IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '{_API_ROLE_NAME}') THEN
                EXECUTE 'GRANT SELECT ON device_topology_view TO {_API_ROLE_NAME}';
                EXECUTE 'GRANT SELECT ON network_interface_ports_view TO {_API_ROLE_NAME}';
            END IF;
        END
        $$;
        """
    )


def downgrade() -> None:
    """Reverse the F-01 persistence-pipeline schema delta.

    Re-creates the dropped jsonb columns but does NOT restore content
    (operator-curated demo data is lost; restore from a pre-upgrade
    ``pg_dump`` snapshot if needed).
    """
    bind = op.get_bind()

    # 7→6) Drop views.
    op.execute("DROP VIEW IF EXISTS network_interface_ports_view")
    op.execute("DROP VIEW IF EXISTS device_topology_view")

    # 5) Re-create the dropped jsonb columns (empty).
    op.add_column(
        "network_interfaces",
        sa.Column(
            "open_ports_summary",
            sa.dialects.postgresql.JSONB(),
            nullable=True,
        ),
    )
    op.add_column(
        "devices",
        sa.Column(
            "vulnerabilities",
            sa.dialects.postgresql.JSONB(),
            nullable=True,
        ),
    )

    # 4) Drop supporting indexes.
    op.drop_index(
        "ix_service_observations_interface",
        table_name="service_observations",
    )
    op.drop_index(
        "ix_vuln_observations_device_status",
        table_name="vulnerability_observations",
    )

    # 3) Drop UNIQUE constraints.
    op.drop_constraint(
        "uq_vuln_observations_device_vuln",
        "vulnerability_observations",
        type_="unique",
    )
    op.drop_constraint(
        "uq_service_observations_iface_port_transport",
        "service_observations",
        type_="unique",
    )

    # 2) Drop the four added columns from vulnerability_observations.
    op.drop_column("vulnerability_observations", "last_seen_at")
    op.drop_column("vulnerability_observations", "status_changed_by")
    op.drop_column("vulnerability_observations", "status_changed_at")
    op.drop_column("vulnerability_observations", "status")

    # 1) Drop the enum type.
    vuln_status_enum = sa.Enum(
        *_VULN_STATUS_VALUES,
        name="vuln_status",
        create_type=False,
    )
    vuln_status_enum.drop(bind, checkfirst=True)
