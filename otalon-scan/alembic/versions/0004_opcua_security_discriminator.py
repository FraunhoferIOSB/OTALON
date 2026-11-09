"""opcua_security_discriminator

Fourth Alembic migration for otalon-scan; introduced as part of the
``SCAN-015`` bug fix (OPC UA discovery persisted only 1 of N endpoints).

OPC UA servers expose several endpoints that share one
``(interface_id, port, transport)`` triple and differ only by their
**Security Mode** and **Security Policy**. The pre-existing UNIQUE
constraint ``uq_service_observations_iface_port_transport`` collapsed all
of them onto one row via UPSERT, dropping every endpoint but the last.

This migration is **additive and reversible**. It:

1. Adds ``service_observations.security_mode TEXT NOT NULL DEFAULT ''``.
2. Adds ``service_observations.security_policy TEXT NOT NULL DEFAULT ''``.
3. Drops the old UNIQUE constraint
   ``uq_service_observations_iface_port_transport`` and replaces it with
   ``uq_service_observations_iface_port_transport_secmode`` over
   ``(interface_id, port, transport, security_mode, security_policy)``.

NULL-handling decision (see design note below): the two new columns are
``NOT NULL DEFAULT ''`` rather than nullable. A Postgres UNIQUE
constraint treats two NULLs as **distinct**, so if these columns were
nullable, the existing non-OPC-UA writers (port_scan / arp), which never
set them, would write NULL on both and every re-scan would INSERT a fresh
row instead of UPSERTing — breaking their dedup. An empty-string sentinel
compares equal, so those writers keep their idempotent UPSERT (all share
``('', '')``) while OPC-UA endpoints carry their distinct
``(security_mode, security_policy)`` pairs and persist as separate rows.

``upgrade`` defaults every existing row to ``('', '')`` via the column
DEFAULT, so the new constraint is satisfied immediately without a
back-fill UPDATE. ``downgrade`` restores the original three-column
constraint and drops the two columns; the per-endpoint security
discriminator is discarded but is regenerable on the next OPC UA scan, so
no permanent data is lost outside the new columns themselves.

Revision ID: 0004
Revises: 0003
Create Date: 2026-06-14

Refs:
- ``.dev/todo/TODO_otalon-scan.md`` item SCAN-015
- ``.dev/runtime/scan015-opcua-persist-report.md``
"""

from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "0004"
down_revision: Union[str, None] = "0003"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_OLD_CONSTRAINT: str = "uq_service_observations_iface_port_transport"
_NEW_CONSTRAINT: str = "uq_service_observations_iface_port_transport_secmode"


def upgrade() -> None:
    """Apply the SCAN-015 OPC UA security-discriminator schema delta.

    Steps run in this order so each statement is valid against the schema
    state produced by the previous step:

    1. Add ``security_mode TEXT NOT NULL DEFAULT ''``. All existing rows
       inherit ``''`` automatically via the DEFAULT.
    2. Add ``security_policy TEXT NOT NULL DEFAULT ''`` (same back-fill).
    3. Drop the old three-column UNIQUE constraint and create the new
       five-column one. The new constraint passes immediately because
       every existing row now carries ``('', '')`` for the two new
       columns, preserving their original ``(interface_id, port,
       transport)`` uniqueness while admitting OPC UA endpoints that
       differ only by security mode / policy.
    """
    op.execute("ALTER TABLE service_observations " "ADD COLUMN security_mode TEXT NOT NULL DEFAULT ''")
    op.execute("ALTER TABLE service_observations " "ADD COLUMN security_policy TEXT NOT NULL DEFAULT ''")
    op.drop_constraint(_OLD_CONSTRAINT, "service_observations", type_="unique")
    op.create_unique_constraint(
        _NEW_CONSTRAINT,
        "service_observations",
        ["interface_id", "port", "transport", "security_mode", "security_policy"],
    )


def downgrade() -> None:
    """Reverse the SCAN-015 schema delta.

    Drops the five-column UNIQUE constraint, restores the original
    three-column constraint, and drops the two added columns. Any
    per-endpoint security discriminator populated since the upgrade is
    discarded; it is regenerable on the next OPC UA scan so no permanent
    data is lost outside the new columns themselves.

    Note: if duplicate ``(interface_id, port, transport)`` rows exist
    (multiple OPC UA endpoints persisted under the new scheme), restoring
    the old constraint will fail until those duplicates are removed. This
    is the expected, documented consequence of reverting a constraint that
    was relaxed to admit them.
    """
    op.drop_constraint(_NEW_CONSTRAINT, "service_observations", type_="unique")
    op.create_unique_constraint(
        _OLD_CONSTRAINT,
        "service_observations",
        ["interface_id", "port", "transport"],
    )
    op.execute("ALTER TABLE service_observations " "DROP COLUMN IF EXISTS security_policy")
    op.execute("ALTER TABLE service_observations " "DROP COLUMN IF EXISTS security_mode")
