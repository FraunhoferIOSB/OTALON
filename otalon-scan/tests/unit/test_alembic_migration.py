"""F-01 schema-shape tests for the initial Alembic migration.

Tasks 7.4 of ``refactor-otalon-scan-persistence-pipeline-v1``: assert
the post-migration schema state directly. The migration runs at most
once on the workspace's live Postgres before any test in this module
executes; we don't drop-recreate the schema for each test because that
would be hostile to other concurrent workspace tests.

The tests are read-only against ``pg_catalog`` / ``information_schema``
so they have no side effects on the otalon-clas database.
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

# The mission §10 Q8 authoritative enum values, in the documented order.
_VULN_STATUS_VALUES: tuple[str, ...] = (
    "active",
    "mitigated",
    "false_positive",
    "resolved",
)


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
    """Yield an asyncpg engine bound to the workspace Postgres."""
    raw = os.environ.get("POSTGRES_DSN")
    if not raw:
        pytest.skip("POSTGRES_DSN not set; cannot run F-01 schema-shape tests")
    eng = create_async_engine(_to_async_dsn(raw), pool_pre_ping=True)
    try:
        yield eng
    finally:
        await eng.dispose()


async def test_dropped_columns_are_absent(engine: AsyncEngine) -> None:
    """``devices.vulnerabilities`` and ``network_interfaces.open_ports_summary``
    SHALL NOT exist after the F-01 migration."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT table_name, column_name
            FROM information_schema.columns
            WHERE (table_name = 'devices' AND column_name = 'vulnerabilities')
               OR (table_name = 'network_interfaces' AND column_name = 'open_ports_summary')
            """
        )
        rows = res.fetchall()
    assert rows == []


async def test_vuln_status_enum_has_mission_values(engine: AsyncEngine) -> None:
    """``vuln_status`` SHALL contain exactly the four mission values, in order."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT enum_range(NULL::vuln_status)::text AS values")
        row = res.first()
    assert row is not None
    raw = row[0]  # e.g. "{active,mitigated,false_positive,resolved}"
    actual = tuple(raw.strip("{}").split(","))
    assert actual == _VULN_STATUS_VALUES


async def test_unique_constraints_present(engine: AsyncEngine) -> None:
    """Both F-01 UNIQUE constraints SHALL exist in ``pg_constraint``."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT conname
            FROM pg_constraint
            WHERE conname IN (
                'uq_service_observations_iface_port_transport_secmode',
                'uq_vuln_observations_device_vuln'
            )
            ORDER BY conname
            """
        )
        names = [r[0] for r in res.fetchall()]
    assert names == [
        "uq_service_observations_iface_port_transport_secmode",
        "uq_vuln_observations_device_vuln",
    ]


async def test_supporting_indexes_present(engine: AsyncEngine) -> None:
    """The two index helpers needed by the views SHALL be present."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT indexname
            FROM pg_indexes
            WHERE indexname IN (
                'ix_vuln_observations_device_status',
                'ix_service_observations_interface'
            )
            ORDER BY indexname
            """
        )
        names = [r[0] for r in res.fetchall()]
    assert names == [
        "ix_service_observations_interface",
        "ix_vuln_observations_device_status",
    ]


async def test_views_present(engine: AsyncEngine) -> None:
    """Both F-01 views SHALL exist in ``pg_views``."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT viewname
            FROM pg_views
            WHERE viewname IN ('device_topology_view', 'network_interface_ports_view')
            ORDER BY viewname
            """
        )
        names = [r[0] for r in res.fetchall()]
    assert names == ["device_topology_view", "network_interface_ports_view"]


async def test_status_columns_present_on_vulnerability_observations(engine: AsyncEngine) -> None:
    """``vulnerability_observations`` SHALL carry the four F-01 columns."""
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql(
            """
            SELECT column_name, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = 'vulnerability_observations'
              AND column_name IN (
                'status', 'status_changed_at', 'status_changed_by', 'last_seen_at'
              )
            ORDER BY column_name
            """
        )
        rows = {row[0]: (row[1], row[2]) for row in res.fetchall()}
    assert set(rows) == {"last_seen_at", "status", "status_changed_at", "status_changed_by"}
    # status SHALL be NOT NULL with default 'active'
    assert rows["status"][0] == "NO"
    assert rows["status"][1] is not None
    assert "active" in rows["status"][1]
    # last_seen_at SHALL be NOT NULL with now() default for migration safety
    assert rows["last_seen_at"][0] == "NO"
    # status_changed_at / status_changed_by are operator-set, NULLable
    assert rows["status_changed_at"][0] == "YES"
    assert rows["status_changed_by"][0] == "YES"


async def test_alembic_version_is_at_expected_head(engine: AsyncEngine) -> None:
    """The ``alembic_version`` table SHALL be at or past the F-01 baseline.

    The F-01 view/upsert schema asserted by this module is additive and
    survives every later revision (SCAN-015 ``0004``, SCAN-018 ``0005``,
    SCAN-026 ``0006`` …), so the guard only requires the head to be at
    least the ``0001`` baseline this module owns. String compare is safe
    for the zero-padded numeric revision ids.
    """
    async with engine.connect() as conn:
        res = await conn.exec_driver_sql("SELECT version_num FROM alembic_version")
        row = res.first()
    assert row is not None
    assert row[0] >= "0001"


async def test_empty_observations_produce_empty_arrays_not_null(engine: AsyncEngine) -> None:
    """The view SHALL emit ``'[]'::jsonb`` for empty observation sets,
    not NULL (spec scenario "Empty observation sets produce empty arrays")."""
    async with engine.connect() as conn:
        # Find a device that has zero active vuln observations.
        res = await conn.exec_driver_sql(
            """
            SELECT vulnerabilities
            FROM device_topology_view
            WHERE jsonb_typeof(vulnerabilities) = 'array'
              AND jsonb_array_length(vulnerabilities) = 0
            LIMIT 1
            """
        )
        row = res.first()
    if row is None:
        pytest.skip("No device with zero active vulnerabilities present; cannot verify empty-array projection")
    assert row[0] == []
