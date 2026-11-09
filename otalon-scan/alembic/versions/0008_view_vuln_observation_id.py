"""view_vuln_observation_id

Eighth Alembic migration for otalon-scan; part of FIX-NOW wave for
scan-interfaces-ux (V1 scoped triage).

The ``device_topology_view`` aggregates active vulnerabilities per device
but omitted the ``vulnerability_observations.id`` primary key. Without it
the UI can only PATCH by CVE string, which mutates every observation with
that CVE across all assets instead of the single observation the operator
clicked.

This migration recreates the view with ``'id', v.id`` added to the
``jsonb_build_object`` so the frontend receives a per-observation unique
identifier for PATCH calls.

Revision ID: 0008
Revises: 0007
Create Date: 2026-06-28
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0008"
down_revision: Union[str, None] = "0007"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Recreate ``device_topology_view`` with observation ``id`` included."""
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


def downgrade() -> None:
    """Restore the previous ``device_topology_view`` without observation ``id``."""
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
