"""scan_findings_snapshot

Ninth Alembic migration for otalon-scan; part of the FIX-NOW wave for
scan-interfaces-ux lifecycle findings (L-02).

The history-detail view (``ScanDetailModal``) could only show scan metadata
(module / status / duration / parameters) because the ``scans`` row never
recorded the findings the run produced — those flowed only through the
ephemeral SSE stream into the asset inventory. Past scan results were thus
not reproducibly inspectable.

This migration adds a nullable ``findings`` JSONB column to ``scans`` that
``_finalize_run`` populates with a point-in-time snapshot (a list of
``DeviceFinding`` dicts) of exactly what the scan reported. It is additive
and backfills NULL for existing rows.

Revision ID: 0009
Revises: 0008
Create Date: 2026-06-28
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from sqlalchemy.dialects.postgresql import JSONB

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0009"
down_revision: Union[str, None] = "0008"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Add the nullable ``findings`` JSONB snapshot column to ``scans``."""
    op.add_column("scans", sa.Column("findings", JSONB(), nullable=True))


def downgrade() -> None:
    """Drop the ``findings`` snapshot column."""
    op.drop_column("scans", "findings")
