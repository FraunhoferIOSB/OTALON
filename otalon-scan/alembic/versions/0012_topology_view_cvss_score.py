"""topology_view_cvss_score

Twelfth Alembic migration for otalon-scan; part of the P8-findings
overnight run (G2-01 — CVSS score in the device vulnerabilities payload).

The CVE-lookup pipeline already stores the numeric CVSS score in
``vulnerability_observations.metadata`` (JSONB) under the ``cvss_score``
key (plus ``cvss_version`` and ``cvss_raw_scores``), but
``device_topology_view`` never surfaced it: the per-vulnerability
``jsonb_build_object`` emitted only id/vuln_id/severity/summary/
source_module/detected_at/last_seen_at/status. As a result the UI could
render severity-only and had no numeric score to display.

This migration recreates ``device_topology_view`` (otherwise byte-for-byte
the 0010 definition) and adds two fields to each vulnerability object:

1. ``cvss_score`` — ``metadata->>'cvss_score'`` cast to ``numeric``. When
   the key is absent the ``->>`` operator yields NULL and the cast keeps
   it NULL, so observations without a score emit ``null`` rather than a
   misleading ``0.0``. The UI already renders severity-only on ``null``.
2. ``cvss_version`` — ``metadata->>'cvss_version'`` (text, nullable). This
   is the raw metric key the CVE source selected (e.g. ``cvssMetricV31``
   / ``cvssMetricV2``); passed through as-is for provenance.

No table schema change and no data migration: the values already live in
the JSONB column. This is a forward-only view recreation.

``downgrade`` restores the 0010 view (without ``cvss_score`` /
``cvss_version``).

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-02
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0012"
down_revision: Union[str, None] = "0011"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Surface ``cvss_score`` / ``cvss_version`` in ``device_topology_view``."""
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
                        'status', v.status,
                        'cvss_score', (v.metadata->>'cvss_score')::numeric,
                        'cvss_version', v.metadata->>'cvss_version'
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
    """Restore the 0010 ``device_topology_view`` (no CVSS fields)."""
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
