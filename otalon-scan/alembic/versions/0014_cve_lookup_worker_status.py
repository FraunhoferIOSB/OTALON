"""Persisted operational status for the CVE lookup worker."""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

revision: str = "0014"
down_revision: Union[str, None] = "0013"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the CVE lookup worker status table."""
    op.create_table(
        "cve_lookup_worker_status",
        sa.Column("service", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("last_run_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("findings_count", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("interval_s", sa.Integer(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )


def downgrade() -> None:
    """Drop the CVE lookup worker status table."""
    op.drop_table("cve_lookup_worker_status")
