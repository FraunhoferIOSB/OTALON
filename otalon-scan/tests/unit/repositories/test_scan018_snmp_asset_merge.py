"""Tests for the SCAN-018 SNMP asset-enrichment conflict-policy (D5).

Operator decision D5 (``.dev/concepts/snmp-asset-enrichment/CONCEPT.md``):
an active SNMP scan ALWAYS overwrites an existing device asset value.
This is implemented by the same ``COALESCE(EXCLUDED.x, devices.x)``
NULL-skipping merge already used for the pre-existing device columns, so
the precedence table is:

- A scan that supplies a non-NULL value -> overwrite (active wins).
- A scan that supplies NULL -> preserve the stored value (no clobber).

The tests run against the workspace Postgres (``otalon-clas``) at the
SCAN-018 head and clean up after themselves. They skip when
``POSTGRES_DSN`` is unset or the schema is not migrated, mirroring the
F-03 / passive-seeder fixture pattern in
``test_upsert_iface_source_merge.py``.
"""

from __future__ import annotations

import os
from typing import AsyncIterator

import pytest
from sqlalchemy import delete, select

from otalon_scan.repositories.models import Device
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a repo bound to the workspace Postgres at the SCAN-018 head."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run SCAN-018 merge tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not at SCAN-018 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


def _random_mac() -> str:
    """Return a unique LAA-prefixed MAC so concurrent tests do not collide."""
    suffix = os.urandom(3).hex()
    return f"02:18:00:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"


async def _cleanup(repo: ScannerPostgresRepo, mac: str) -> None:
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(Device).where(Device.primary_mac == mac))


async def _fetch(repo: ScannerPostgresRepo, mac: str) -> Device:
    async with repo._Session() as session:
        res = await session.execute(select(Device).where(Device.primary_mac == mac))
        row = res.scalar_one()
    return row


async def test_fresh_snmp_scan_persists_all_asset_fields(
    repo: ScannerPostgresRepo,
) -> None:
    """A first SNMP scan SHALL persist every new asset field."""
    mac = _random_mac()
    try:
        await repo.upsert_device(
            primary_mac=mac,
            product_name="SCALANCE XC216",
            hw_version="4",
            sw_version="V4.3",
            serial_number="SVPL1234567",
        )
        row = await _fetch(repo, mac)
        assert row.product_name == "SCALANCE XC216"
        assert row.hw_version == "4"
        assert row.sw_version == "V4.3"
        assert row.serial_number == "SVPL1234567"
    finally:
        await _cleanup(repo, mac)


async def test_active_scan_overwrites_existing_value(repo: ScannerPostgresRepo) -> None:
    """D5: an active SNMP scan with a non-NULL value SHALL overwrite."""
    mac = _random_mac()
    try:
        await repo.upsert_device(primary_mac=mac, sw_version="V4.2", hw_version="3")
        await repo.upsert_device(primary_mac=mac, sw_version="V4.3", hw_version="4")
        row = await _fetch(repo, mac)
        assert row.sw_version == "V4.3"  # overwritten (active wins)
        assert row.hw_version == "4"
    finally:
        await _cleanup(repo, mac)


async def test_null_scan_value_preserves_stored_value(
    repo: ScannerPostgresRepo,
) -> None:
    """A scan supplying NULL SHALL preserve the previously-stored value.

    This mirrors the seeder NULL-skipping rule: a later scan that did not
    resolve a field (e.g. a non-SNMP module) does not clobber the asset
    data an earlier SNMP scan established.
    """
    mac = _random_mac()
    try:
        await repo.upsert_device(
            primary_mac=mac,
            product_name="SCALANCE XC216",
            serial_number="SVPL1234567",
        )
        # Second upsert leaves the asset fields NULL (e.g. an ARP scan).
        await repo.upsert_device(primary_mac=mac, vendor="Siemens")
        row = await _fetch(repo, mac)
        assert row.product_name == "SCALANCE XC216"  # preserved
        assert row.serial_number == "SVPL1234567"  # preserved
        assert row.vendor == "Siemens"
    finally:
        await _cleanup(repo, mac)
