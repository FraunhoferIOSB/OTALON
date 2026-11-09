"""device_hostname

Tenth Alembic migration for otalon-scan; part of the P8-findings
overnight run (Welle A — F-04 / F-10).

pn_discovery (PROFINET station-name) and snmp_scan (SNMP ``sysName``)
discover a device's network NAME but historically stored it in the
``devices.device_type`` column. A hostname is not a device type, so the
UI rendered e.g. ``Type: bk9103-2`` / ``Device Type: axc-f-2152-1``.

This migration gives the discovered name its own home:

1. Adds a nullable ``devices.hostname TEXT`` column. It is additive and
   backfills NULL for existing rows. The operator decision is explicit:
   ``device_type`` holds only a genuine device type and is left NULL
   when none is known — values are NOT guessed or invented. Existing
   mis-stored ``device_type`` values are therefore NOT auto-migrated
   into ``hostname`` here (a later re-scan re-populates the correct
   field via the fixed capture path); a blind copy could move a real
   type into ``hostname``.
2. Recreates ``device_topology_view`` to surface ``d.hostname`` (the
   view is otherwise byte-for-byte the 0008 definition).

``downgrade`` restores the 0008 view (without ``hostname``) and drops
the column.

Revision ID: 0010
Revises: 0009
Create Date: 2026-06-28
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0010"
down_revision: Union[str, None] = "0009"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add ``devices.hostname`` and surface it in ``device_topology_view``."""
    op.add_column("devices", sa.Column("hostname", sa.Text(), nullable=True))
    op.execute("DROP VIEW IF EXISTS device_topology_view")
    op.execute(
        """
        CREATE VIEW device_topology_view AS
        SELECT
            d.id,
            d.hostname,
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
                        'id', v.id,
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


def downgrade() -> None:
    """Restore the 0008 ``device_topology_view`` and drop ``hostname``."""
    op.execute("DROP VIEW IF EXISTS device_topology_view")
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
                        'id', v.id,
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
    op.drop_column("devices", "hostname")
