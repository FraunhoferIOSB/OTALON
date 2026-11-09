"""Schema-shape tests for the ``0003_passive_source_marker`` migration.

Implements task 5.5 of ``add-passive-asset-seeder/tasks.md``: assert
the three new columns and the CHECK constraint on
``network_interfaces`` are present after the migration runs. The
tests read from ``information_schema`` / ``pg_catalog`` so they are
side-effect-free against the live ``otalon-clas`` database.

Maps to spec scenarios from
``openspec/changes/add-passive-asset-seeder/specs/``
``scan--persistence-ownership/spec.md``:

- ``New row from active scan defaults to active`` (DEFAULT 'active' on column)
- ``CHECK constraint rejects unknown source value`` (CHECK presence)
- ``Devices table carries no source column``
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from sqlalchemy.ext.asyncio import AsyncEngine, create_async_engine

from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


def _to_async_dsn(dsn: str) -> str:
    if dsn.startswith("postgresql+asyncpg://"):
        return dsn
    if dsn.startswith("postgresql+psycopg2://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql+psycopg2://") :]
    if dsn.startswith("postgresql://"):
        return "postgresql+asyncpg://" + dsn[len("postgresql://") :]
    return dsn


@pytest.fixture
async def engine() -> AsyncIterator[AsyncEngine]:
    raw = os.environ.get("POSTGRES_DSN")
    if not raw:
        pytest.skip("POSTGRES_DSN not set; cannot run 0003 schema tests")
    eng = create_async_engine(_to_async_dsn(raw), pool_pre_ping=True)
    try:
        yield eng
    finally:
        await eng.dispose()


async def test_alembic_head_at_current_revision(engine: AsyncEngine) -> None:
    """The ``alembic_version`` table SHALL be at or past revision ``0003``.

    The 0003 passive-source-marker schema this module asserts remains in
    place; SCAN-015's 0004, SCAN-018's 0005 and SCAN-026's 0006 migrations
    are additive descendants, so the guard only requires the head to be at
    least ``"0003"`` (string compare is safe for zero-padded numeric ids).
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT version_num FROM alembic_version")
        row = res.first()
    assert row is not None
    assert row[0] >= "0003"


async def test_source_column_exists_with_default_active(engine: AsyncEngine) -> None:
    """``network_interfaces.source`` SHALL exist as TEXT NOT NULL DEFAULT 'active'."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'network_interfaces' AND column_name = 'source'
            """
        )
        row = res.first()
    assert row is not None, "network_interfaces.source column missing"
    data_type, is_nullable, column_default = row
    assert data_type == "text"
    assert is_nullable == "NO"
    assert column_default is not None
    assert "active" in column_default


async def test_first_seen_passive_at_column_exists_nullable(
    engine: AsyncEngine,
) -> None:
    """``first_seen_passive_at`` SHALL exist as TIMESTAMPTZ NULL."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'network_interfaces'
              AND column_name = 'first_seen_passive_at'
            """
        )
        row = res.first()
    assert row is not None, "first_seen_passive_at column missing"
    assert row[0] == "timestamp with time zone"
    assert row[1] == "YES"


async def test_last_seen_passive_at_column_exists_nullable(
    engine: AsyncEngine,
) -> None:
    """``last_seen_passive_at`` SHALL exist as TIMESTAMPTZ NULL."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT data_type, is_nullable
            FROM information_schema.columns
            WHERE table_name = 'network_interfaces'
              AND column_name = 'last_seen_passive_at'
            """
        )
        row = res.first()
    assert row is not None, "last_seen_passive_at column missing"
    assert row[0] == "timestamp with time zone"
    assert row[1] == "YES"


async def test_ck_network_interfaces_source_constraint_present(
    engine: AsyncEngine,
) -> None:
    """``ck_network_interfaces_source`` CHECK SHALL constrain to (active,passive)."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT pg_get_constraintdef(oid)
            FROM pg_constraint
            WHERE conname = 'ck_network_interfaces_source'
              AND conrelid = 'public.network_interfaces'::regclass
            """
        )
        row = res.first()
    assert row is not None, "ck_network_interfaces_source CHECK missing"
    definition = row[0]
    assert "active" in definition
    assert "passive" in definition


async def test_devices_has_no_source_column(engine: AsyncEngine) -> None:
    """``devices`` table SHALL NOT carry any source/passive column.

    Per design.md decision Fork 2 = b, device-level provenance is
    derived in the UI by aggregating over network_interfaces rows.
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT column_name
            FROM information_schema.columns
            WHERE table_name = 'devices'
              AND column_name IN ('source', 'first_seen_passive_at', 'last_seen_passive_at')
            """
        )
        rows = res.fetchall()
    assert rows == [], f"devices must not carry source-related columns, got: {rows}"
