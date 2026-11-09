"""Repo test for ``lookup_eligible_devices`` (Welle A / Task 1.3, D4 GATE).

Exercises the DB-backed cutoff selector against the workspace Postgres
(seeded via ``$POSTGRES_DSN`` in ``tests/conftest.py`` — skips when the
instance is unreachable, mirroring ``test_postgres_repo_upsert.py``).
Creates throwaway devices with a complete and an incomplete identity,
asserts the eligible flag and the missing-field list, and cleans up the
rows it created so it leaves no state behind.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from sqlalchemy import delete

from otalon_scan.cve_lookup.eligibility import FIELD_VERSION
from otalon_scan.repositories.models import Device
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """ScannerPostgresRepo bound to the workspace Postgres, or skip."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run eligibility repo test")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


@pytest.mark.asyncio
async def test_lookup_eligible_devices_applies_cutoff(repo: ScannerPostgresRepo) -> None:
    """A complete device is eligible; a firmware-less device is not."""
    suffix = os.urandom(3).hex()
    complete_mac = f"02:ce:00:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"
    partial_mac = f"02:ce:01:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"

    complete_id = await repo.upsert_device(
        primary_mac=complete_mac,
        vendor="Siemens",
        product_name="SCALANCE XC216",
        firmware_version="V4.3",
    )
    partial_id = await repo.upsert_device(
        primary_mac=partial_mac,
        vendor="Siemens",
        product_name="SCALANCE XC216",
    )

    try:
        results = await repo.lookup_eligible_devices()
        by_id = {r.device_id: r for r in results}

        assert by_id[complete_id].eligible is True
        assert by_id[complete_id].missing_fields == []

        assert by_id[partial_id].eligible is False
        assert FIELD_VERSION in by_id[partial_id].missing_fields
    finally:
        async with repo._Session() as session:
            async with session.begin():
                await session.execute(delete(Device).where(Device.id.in_([complete_id, partial_id])))
