"""Schema-shape tests for the ``0006_cve_lookups_job_header`` migration.

SCAN-026 Welle A adds the additive ``cve_lookups`` job-header table and
the ``cve_lookup_status`` enum type. These tests read from
``information_schema`` / ``pg_type`` so they are side-effect-free against
the live ``otalon-clas`` database and skip when ``$POSTGRES_DSN`` is unset.

Maps to design.md § D1 (own table, own enum, additive — hits stay in
``vulnerability_observations``).
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

_EXPECTED_COLUMNS = {
    "id": ("uuid", "NO"),
    "scope": ("text", "NO"),
    "device_id": ("integer", "YES"),
    "source": ("text", "NO"),
    "api_key_used": ("boolean", "NO"),
    "status": ("USER-DEFINED", "NO"),
    "summary": ("jsonb", "YES"),
    "error": ("text", "YES"),
    "started_at": ("timestamp with time zone", "NO"),
    "finished_at": ("timestamp with time zone", "YES"),
    "created_at": ("timestamp with time zone", "NO"),
    "updated_at": ("timestamp with time zone", "YES"),
}


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
        pytest.skip("POSTGRES_DSN not set; cannot run 0006 schema tests")
    eng = create_async_engine(_to_async_dsn(raw), pool_pre_ping=True)
    try:
        yield eng
    finally:
        await eng.dispose()


_KNOWN_HEADS_AT_OR_ABOVE_0006 = {
    "0006",
    "0007",
    "0008",
    "0009",
    "0010",
    "0011",
    "0012",
    "0013",
    "0014",
    "0015",
}


async def test_alembic_head_at_0006(engine: AsyncEngine) -> None:
    """The ``alembic_version`` SHALL be at the SCAN-026 head ``"0006"`` or a descendant.

    The exact-equality pin broke on every migration landed after SCAN-026
    (0007..0015; current head ``0015``). The ``cve_lookups`` table +
    ``cve_lookup_status`` enum are additive and survive those descendants,
    so membership in the known-good descendant set is the stable assertion.
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT version_num FROM alembic_version")
        row = res.first()
    assert row is not None
    assert row[0] in _KNOWN_HEADS_AT_OR_ABOVE_0006, f"unexpected alembic head: {row[0]!r}"


@pytest.mark.parametrize("column", sorted(_EXPECTED_COLUMNS))
async def test_cve_lookups_column_shape(engine: AsyncEngine, column: str) -> None:
    """Each ``cve_lookups`` column SHALL match the expected type/nullability."""
    expected_type, expected_nullable = _EXPECTED_COLUMNS[column]
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            "SELECT data_type, is_nullable "
            "FROM information_schema.columns "
            f"WHERE table_name = 'cve_lookups' AND column_name = '{column}'"
        )
        row = res.first()
    assert row is not None, f"cve_lookups.{column} column missing"
    assert row[0] == expected_type
    assert row[1] == expected_nullable


async def test_cve_lookup_status_enum_values(engine: AsyncEngine) -> None:
    """The ``cve_lookup_status`` enum SHALL carry the ScanStatus-style values.

    Migration ``0011_cve_lookup_aborted_status`` (R-02 cooperative
    cancellation) appended the terminal ``aborted`` value so an
    operator-cancelled lookup is recorded honestly; the assertion tracks
    that landed enum shape.
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            "SELECT enumlabel FROM pg_enum e "
            "JOIN pg_type t ON e.enumtypid = t.oid "
            "WHERE t.typname = 'cve_lookup_status' "
            "ORDER BY e.enumsortorder"
        )
        values = [r[0] for r in res.fetchall()]
    assert values == ["pending", "running", "completed", "failed", "aborted"]


async def test_started_at_index_exists(engine: AsyncEngine) -> None:
    """The newest-first list index SHALL exist on ``cve_lookups``."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            "SELECT indexname FROM pg_indexes "
            "WHERE tablename = 'cve_lookups' AND indexname = 'ix_cve_lookups_started_at'"
        )
        row = res.first()
    assert row is not None, "ix_cve_lookups_started_at index missing"


async def test_existing_tables_untouched(engine: AsyncEngine) -> None:
    """The migration is additive: core scan tables SHALL still exist."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' "
            "AND tablename IN ('devices', 'network_interfaces', 'scans', "
            "'service_observations', 'vulnerability_observations')"
        )
        present = {r[0] for r in res.fetchall()}
    assert present == {
        "devices",
        "network_interfaces",
        "scans",
        "service_observations",
        "vulnerability_observations",
    }
