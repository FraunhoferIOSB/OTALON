"""passive_seeder_status

Thirteenth Alembic migration for otalon-scan; part of
``passive-seeder-runtime-control`` (UI-015 Stage 1, Wave C).

The passive seeder previously expressed its disabled state by exiting with
code 0. Combined with the compose restart policy that produced a perpetual
restart loop whose reason was invisible to every observer outside
``docker logs``. The seeder now stays alive and publishes its operational
state into PostgreSQL instead, so the api (and through it the UI) can report
what the worker is doing.

This migration creates the table that state is written to. It is purely
additive: no existing table, view, or index is touched.

Columns:

- ``service`` — owning service identifier, primary key. The seeder writes
  under ``otalon-scan`` (the *service*), not under the container name
  ``otalon-scan-passive-seeder``, matching the ``runtime_config`` rows it
  resolves.
- ``state`` — ``running`` / ``disabled`` / ``error``.
- ``last_cycle_at`` — end of the last completed cycle.
- ``last_error`` — message of the last failed cycle, cleared on a clean one.
- ``rows_seeded`` — interface rows written by the last cycle.
- ``poll_interval_s`` — the interval actually in effect for that cycle, so a
  reader can distinguish "configured" from "effective" during the one-cycle
  window after a configuration change.
- ``updated_at`` — write timestamp.

``downgrade`` drops the table.

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-29
"""

from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0013"
down_revision: Union[str, None] = "0012"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Create the ``passive_seeder_status`` table."""
    op.create_table(
        "passive_seeder_status",
        sa.Column("service", sa.String(length=128), primary_key=True, nullable=False),
        sa.Column("state", sa.String(length=32), nullable=False),
        sa.Column("last_cycle_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("last_error", sa.Text(), nullable=True),
        sa.Column("rows_seeded", sa.Integer(), nullable=False, server_default="0"),
        sa.Column("poll_interval_s", sa.Integer(), nullable=True),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )


def downgrade() -> None:
    """Drop the ``passive_seeder_status`` table."""
    op.drop_table("passive_seeder_status")
