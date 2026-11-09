"""cve_lookup_aborted_status

Eleventh Alembic migration for otalon-scan; part of the P8-findings
restfix run (R-02 — operator-cancellable CVE lookups).

The CVE-lookup running-state Stop button was disabled because the
``cve_lookups`` job had no terminal state for an operator-requested
cancellation. This migration adds the ``aborted`` value to the
``cve_lookup_status`` Postgres enum so a cooperatively-cancelled lookup
can be finalized honestly (running → aborted) instead of being faked as
``failed`` or left dangling ``running``.

``upgrade`` appends the enum value (idempotently — re-running is a
no-op). ``downgrade`` is a documented no-op: Postgres provides no
in-place ``ALTER TYPE ... DROP VALUE``, and removing an enum member that
existing rows may reference would corrupt those rows. Reverting the value
would require recreating the type and rewriting every dependent column —
out of scope for a forward-only additive change.

Revision ID: 0011
Revises: 0010
Create Date: 2026-06-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0011"
down_revision: Union[str, None] = "0010"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Append ``aborted`` to the ``cve_lookup_status`` enum (idempotent)."""
    op.execute("ALTER TYPE cve_lookup_status ADD VALUE IF NOT EXISTS 'aborted'")


def downgrade() -> None:
    """No-op: Postgres enum values cannot be dropped in place.

    Removing ``aborted`` would require recreating ``cve_lookup_status``
    and rewriting every dependent column, and would corrupt any
    ``cve_lookups`` row already finalized as ``aborted``. The value is
    therefore left in place on downgrade (forward-only additive change).
    """
