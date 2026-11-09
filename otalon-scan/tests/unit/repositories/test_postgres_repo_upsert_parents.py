"""F-03 tests for the parent-row UPSERT helpers on :class:`ScannerPostgresRepo`.

Covers the spec scenarios from
``openspec/changes/refactor-otalon-scan-device-network-ownership-v1/specs/scan--persistence-ownership/spec.md``
("Device Identity Key Strategy", "Network Interface Upsert Helper",
"Device Upsert Helper", "Writer Call Ordering Contract") and tasks 5.1
through 5.3 of the change's tasks.md.

Test layout:

- :func:`test_iface_*` cover :meth:`ScannerPostgresRepo.upsert_network_interface`.
- :func:`test_device_*` cover :meth:`ScannerPostgresRepo.upsert_device`.
- :func:`test_call_order_*` cover the negative path through the leaf
  helpers' :class:`ParentRowMissingError` contract (F-01's
  ``D-F03-PREREQ``).

The tests use the workspace's live Postgres via ``$POSTGRES_DSN`` (same
fixture pattern as F-01's ``test_postgres_repo_upsert.py``). Each test
cleans up the rows it creates so subsequent runs see a stable state.
The tests live under ``tests/unit/`` per AGENTS.md "Tests under each
subproject's ``tests/`` directory mirroring the package structure".
"""

from __future__ import annotations

import os
from typing import AsyncIterator
from uuid import UUID

import pytest
from sqlalchemy import delete, select

from otalon_scan.repositories.exceptions import IdentityCollisionError
from otalon_scan.repositories.models import (
    Device,
    NetworkInterface,
    Scan,
    ServiceObservation,
    VulnerabilityObservation,
)
from otalon_scan.repositories.postgres_repo import ParentRowMissingError, ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a :class:`ScannerPostgresRepo` bound to the workspace Postgres.

    Skips when ``$POSTGRES_DSN`` is missing or the live DB is not at the
    F-03 head revision.
    """
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run F-03 parent-helper tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to F-03 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


# ---- Helpers ------------------------------------------------------------------


def _random_mac() -> str:
    """Generate a locally-administered, deterministic-prefix random MAC.

    The ``02:`` prefix marks locally-administered (RFC 7042); deliberately
    avoiding the OUI space keeps test MACs out of any vendor lookups
    other tests might do.
    """
    suffix = os.urandom(3).hex()
    return f"02:fe:00:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"


async def _mark_device_as_fixture(repo: ScannerPostgresRepo, device_id: int) -> None:
    """Stamp ``notes='__fixture__'`` on a device created by a test.

    The F-03 ``upsert_device`` helper does not (and SHOULD not) expose
    ``notes`` because production scan modules never set it on the
    canonical path. Tests still need to mark the rows they create so
    ``scripts/cleanup_db_fixtures.py`` can reap them in case a test
    crashes before its own cleanup runs. See
    ``otalon-scan/CONTRIBUTING.md`` § "Test Fixtures".
    """
    async with repo._Session() as session:
        async with session.begin():
            dev = await session.get(Device, device_id)
            if dev is not None:
                dev.notes = "__fixture__"


async def _cleanup_device(repo: ScannerPostgresRepo, primary_mac: str) -> None:
    """Best-effort removal of a device + any linked interfaces."""
    async with repo._Session() as session:
        async with session.begin():
            res = await session.execute(select(Device).where(Device.primary_mac == primary_mac))
            dev = res.scalar_one_or_none()
            if dev is None:
                return
            await session.execute(delete(NetworkInterface).where(NetworkInterface.device_id == dev.id))
            await session.execute(delete(Device).where(Device.id == dev.id))


async def _cleanup_iface_by_mac(repo: ScannerPostgresRepo, mac: str) -> None:
    """Best-effort removal of an interface row by MAC."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(NetworkInterface).where(NetworkInterface.mac_address == mac))


# ---- upsert_network_interface (D-UPSERT-NET-IFACE) ----------------------------


async def test_iface_first_insert_returns_new_id(repo: ScannerPostgresRepo) -> None:
    """First-insert with only MAC SHALL return a new id; row has expected NULLs."""
    mac = _random_mac()
    try:
        iface_id = await repo.upsert_network_interface(mac=mac)
        assert iface_id > 0
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, iface_id)
            assert ni is not None
            assert ni.mac_address == mac
            assert ni.ipv4_address is None
            assert ni.ipv6_address is None
            assert ni.device_id is None
            assert ni.last_scan_at is not None
    finally:
        await _cleanup_iface_by_mac(repo, mac)


async def test_iface_conflict_on_mac_refreshes_last_scan_at(
    repo: ScannerPostgresRepo,
) -> None:
    """Repeated call with same MAC SHALL return same id and refresh last_scan_at."""
    mac = _random_mac()
    try:
        id1 = await repo.upsert_network_interface(mac=mac)
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id1)
            assert ni is not None
            first_ts = ni.last_scan_at

        id2 = await repo.upsert_network_interface(mac=mac)
        assert id1 == id2
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id2)
            assert ni is not None
            assert ni.last_scan_at is not None
            assert first_ts is not None
            # ``last_scan_at`` must have advanced (or at least not gone backwards).
            assert ni.last_scan_at >= first_ts
            # Identity column unchanged.
            assert ni.mac_address == mac
    finally:
        await _cleanup_iface_by_mac(repo, mac)


async def test_iface_ipv4_backfill_then_immutable(repo: ScannerPostgresRepo) -> None:
    """Conflict on MAC with ipv4 in 2nd call SHALL back-fill; 3rd different ipv4 ignored."""
    mac = _random_mac()
    ipv4_a = "10.250.0.10"
    ipv4_b = "10.250.0.99"
    try:
        await repo.upsert_network_interface(mac=mac)
        id2 = await repo.upsert_network_interface(mac=mac, ipv4=ipv4_a)
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id2)
            assert ni is not None
            assert str(ni.ipv4_address) == ipv4_a

        id3 = await repo.upsert_network_interface(mac=mac, ipv4=ipv4_b)
        assert id3 == id2
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id3)
            assert ni is not None
            # Must NOT have been overwritten with ipv4_b.
            assert str(ni.ipv4_address) == ipv4_a
    finally:
        await _cleanup_iface_by_mac(repo, mac)


async def test_iface_link_once_for_device_id(repo: ScannerPostgresRepo) -> None:
    """Existing device_id IS NULL SHALL be linked; subsequent different device_id ignored."""
    mac = _random_mac()
    pm_a = _random_mac()
    pm_b = _random_mac()
    try:
        # Create two distinct devices.
        dev_a = await repo.upsert_device(primary_mac=pm_a, vendor="LinkTest")
        dev_b = await repo.upsert_device(primary_mac=pm_b, vendor="LinkTest")
        await _mark_device_as_fixture(repo, dev_a)
        await _mark_device_as_fixture(repo, dev_b)

        # First call: no device_id (orphan).
        id1 = await repo.upsert_network_interface(mac=mac)
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id1)
            assert ni is not None and ni.device_id is None

        # Second call: link to dev_a.
        await repo.upsert_network_interface(mac=mac, device_id=dev_a)
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id1)
            assert ni is not None and ni.device_id == dev_a

        # Third call: try to relink to dev_b — link-once must preserve dev_a.
        await repo.upsert_network_interface(mac=mac, device_id=dev_b)
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, id1)
            assert ni is not None
            assert ni.device_id == dev_a, f"link-once violated: expected device_id={dev_a}, got {ni.device_id}"
    finally:
        await _cleanup_iface_by_mac(repo, mac)
        await _cleanup_device(repo, pm_a)
        await _cleanup_device(repo, pm_b)


async def test_iface_all_null_identity_raises(repo: ScannerPostgresRepo) -> None:
    """All three identity columns NULL SHALL raise ValueError without touching DB."""
    with pytest.raises(ValueError, match="at least one of mac, ipv4, ipv6"):
        await repo.upsert_network_interface(mac=None, ipv4=None, ipv6=None)


async def test_iface_identity_collision_raises(repo: ScannerPostgresRepo) -> None:
    """Different MAC + same IPv4 as existing row SHALL raise IdentityCollisionError."""
    mac_a = _random_mac()
    mac_b = _random_mac()
    shared_ipv4 = "10.250.250.50"
    try:
        # Pre-insert row A bound to (mac_a, shared_ipv4).
        await repo.upsert_network_interface(mac=mac_a, ipv4=shared_ipv4)
        # Now upsert with mac_b + same ipv4 — UNIQUE on ipv4_address fires,
        # not on mac_address (the chosen conflict target).
        with pytest.raises(IdentityCollisionError) as excinfo:
            await repo.upsert_network_interface(mac=mac_b, ipv4=shared_ipv4)
        assert excinfo.value.conflict_column == "ipv4_address"
        assert excinfo.value.conflict_value == shared_ipv4
        assert excinfo.value.existing_row_id is not None
    finally:
        await _cleanup_iface_by_mac(repo, mac_a)
        await _cleanup_iface_by_mac(repo, mac_b)


# ---- upsert_device (D-UPSERT-DEVICE) ------------------------------------------


async def test_device_first_insert_sets_passed_fields(repo: ScannerPostgresRepo) -> None:
    """First-insert SHALL persist all passed non-NULL fields."""
    pm = _random_mac()
    try:
        did = await repo.upsert_device(
            primary_mac=pm,
            vendor="Siemens",
            firmware_version="V2.8.1",
            article_number="6ES7515-2AM02-0AB0",
        )
        await _mark_device_as_fixture(repo, did)
        async with repo._Session() as session:
            d = await session.get(Device, did)
            assert d is not None
            assert d.primary_mac == pm
            assert d.vendor == "Siemens"
            assert d.firmware_version == "V2.8.1"
            assert d.article_number == "6ES7515-2AM02-0AB0"
            assert d.device_type is None  # not passed
            assert d.last_scan_at is not None
    finally:
        await _cleanup_device(repo, pm)


async def test_device_null_skipping_preserves_enrichment(
    repo: ScannerPostgresRepo,
) -> None:
    """NULL in subsequent call SHALL preserve earlier non-NULL value."""
    pm = _random_mac()
    try:
        first_did = await repo.upsert_device(primary_mac=pm, vendor="Siemens", firmware_version="V2.8.1")
        await _mark_device_as_fixture(repo, first_did)
        # Second call: pass vendor=None (must NOT overwrite), firmware_version=new,
        # description=fresh.
        await repo.upsert_device(
            primary_mac=pm,
            vendor=None,
            firmware_version="V2.8.2",
            description="S7-1500 PLC",
        )
        async with repo._Session() as session:
            res = await session.execute(select(Device).where(Device.primary_mac == pm))
            d = res.scalar_one()
            assert d.vendor == "Siemens", "NULL must not overwrite existing non-NULL"
            assert d.firmware_version == "V2.8.2", "non-NULL must overwrite"
            assert d.description == "S7-1500 PLC", "back-fill from NULL with non-NULL"
    finally:
        await _cleanup_device(repo, pm)


async def test_device_invalid_primary_mac_raises_value_error(
    repo: ScannerPostgresRepo,
) -> None:
    """Malformed primary_mac SHALL raise ValueError naming the bad value."""
    for bad in ("INVALID", "AA:BB:CC:DD:EE:FF", "aabbccddeeff", "aa:bb:cc:dd:ee"):
        with pytest.raises(ValueError, match="ck_devices_primary_mac_format"):
            await repo.upsert_device(primary_mac=bad)


async def test_device_idempotency_under_n_repetitions(repo: ScannerPostgresRepo) -> None:
    """10 calls with same payload SHALL produce 1 row; last call wins last_scan_at."""
    pm = _random_mac()
    try:
        ids: list[int] = []
        for _ in range(10):
            ids.append(await repo.upsert_device(primary_mac=pm, vendor="IdemTest"))
        await _mark_device_as_fixture(repo, ids[0])
        assert len(set(ids)) == 1, f"expected single id across 10 upserts, got {set(ids)}"

        # Exactly one row exists.
        async with repo._Session() as session:
            res = await session.execute(select(Device).where(Device.primary_mac == pm))
            rows = res.scalars().all()
            assert len(rows) == 1
            assert rows[0].vendor == "IdemTest"
    finally:
        await _cleanup_device(repo, pm)


async def test_device_firmware_null_skipping_specifically(
    repo: ScannerPostgresRepo,
) -> None:
    """Scenario: existing firmware_version='1.2.3' + call passes None → preserved."""
    pm = _random_mac()
    try:
        did = await repo.upsert_device(primary_mac=pm, firmware_version="1.2.3")
        await _mark_device_as_fixture(repo, did)
        await repo.upsert_device(primary_mac=pm, firmware_version=None, vendor="Z")
        async with repo._Session() as session:
            res = await session.execute(select(Device).where(Device.primary_mac == pm))
            d = res.scalar_one()
            assert d.firmware_version == "1.2.3"
            assert d.vendor == "Z"
    finally:
        await _cleanup_device(repo, pm)


# ---- Call-ordering contract (delegated to F-01 leaves) ------------------------


async def test_call_order_vuln_missing_device_raises_parent_row_missing(
    repo: ScannerPostgresRepo,
) -> None:
    """upsert_vulnerability_observation with nonexistent device_id SHALL raise ParentRowMissingError."""
    scan_id = await repo.start_scan(module_name="_f03_call_order")
    try:
        # Pick a device id that almost certainly does not exist.
        nonexistent_id = 2_147_483_640
        async with repo._Session() as session:
            d = await session.get(Device, nonexistent_id)
            if d is not None:
                pytest.skip(f"sentinel id {nonexistent_id} unexpectedly exists; cannot run test")
        with pytest.raises(ParentRowMissingError) as excinfo:
            await repo.upsert_vulnerability_observation(
                scan_id=scan_id,
                device_id=nonexistent_id,
                vuln_id="CVE-2099-TEST",
            )
        assert excinfo.value.parent_table == "devices"
    finally:
        await _cleanup_scan(repo, scan_id)


async def test_call_order_service_missing_interface_raises_parent_row_missing(
    repo: ScannerPostgresRepo,
) -> None:
    """upsert_service_observation with nonexistent interface_id SHALL raise ParentRowMissingError."""
    scan_id = await repo.start_scan(module_name="_f03_call_order")
    try:
        nonexistent_id = 2_147_483_641
        async with repo._Session() as session:
            ni = await session.get(NetworkInterface, nonexistent_id)
            if ni is not None:
                pytest.skip(f"sentinel id {nonexistent_id} unexpectedly exists; cannot run test")
        with pytest.raises(ParentRowMissingError) as excinfo:
            await repo.upsert_service_observation(
                scan_id=scan_id,
                interface_id=nonexistent_id,
                port=443,
                transport="tcp",
            )
        assert excinfo.value.parent_table == "network_interfaces"
    finally:
        await _cleanup_scan(repo, scan_id)


async def _cleanup_scan(repo: ScannerPostgresRepo, scan_id: UUID) -> None:
    """Remove the Scan row + any observation rows attached to it."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(ServiceObservation).where(ServiceObservation.scan_id == scan_id))
            await session.execute(delete(VulnerabilityObservation).where(VulnerabilityObservation.scan_id == scan_id))
            await session.execute(delete(Scan).where(Scan.id == scan_id))
