"""scan_status_cancelled_partial

Fifteenth Alembic migration for otalon-scan; part of the SCAN-031 fix wave
(SUITE-031 audit finding **SC-02**).

:class:`~otalon_scan.repositories.models.ScanStatus` gained ``CANCELLED_PARTIAL``
with the D4 cancellation work (2026-05-17), and
:meth:`ModuleManager._finalize_run` reports it for a cancelled scan whose
findings were partially flushed. No migration ever added the value to the
``scan_status`` Postgres enum, so every D4 cancel failed the
``finish_scan`` UPDATE with ``invalid input value for enum scan_status``
and the scan stranded at ``RUNNING``.

Label-case note: the ORM column is
``SQLEnum(ScanStatus, name="scan_status")`` WITHOUT ``values_callable``, so
SQLAlchemy persists the enum *member names* (uppercase) as labels — the
pre-existing labels are ``{PENDING,RUNNING,COMPLETED,FAILED,ABORTED}``.
The value added here is therefore ``'CANCELLED_PARTIAL'`` (uppercase), the
label the driver actually sends.

``upgrade`` appends the enum value idempotently (re-running is a no-op).
``downgrade`` is a documented no-op: Postgres provides no in-place
``ALTER TYPE ... DROP VALUE``, and removing an enum member that existing
rows may reference would corrupt those rows. Mirrors the forward-only
precedent of revision ``0011_cve_lookup_aborted_status``.

Revision ID: 0015
Revises: 0014
Create Date: 2026-08-29
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0015"
down_revision: Union[str, None] = "0014"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Append ``CANCELLED_PARTIAL`` to the ``scan_status`` enum (idempotent)."""
    op.execute("ALTER TYPE scan_status ADD VALUE IF NOT EXISTS 'CANCELLED_PARTIAL'")


def downgrade() -> None:
    """No-op: Postgres enum values cannot be dropped in place.

    Removing ``CANCELLED_PARTIAL`` would require recreating
    ``scan_status`` and rewriting every dependent column, and would
    corrupt any ``scans`` row already finalized as ``CANCELLED_PARTIAL``.
    The value is therefore left in place on downgrade (forward-only
    additive change).
    """
