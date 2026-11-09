"""SCAN-015 tests: OPC UA endpoints persist per Security Mode / Policy.

Covers the bug where ``save_opcua_discover_results`` collapsed all
endpoints of one OPC UA server onto a single ``service_observations`` row
because the UPSERT keyed only on ``(interface_id, port, transport)``.

Scenarios:

- 4 endpoints of one server, same ``ip`` / port 4840 / tcp, differing
  only by Security Mode / Policy → 4 distinct rows, each retaining its
  security discriminator.
- Re-running the same 4 endpoints → still 4 rows (idempotent UPSERT, not
  8).
- ``service_name`` is the clean LocalizedText inner text, never the raw
  ``LocalizedText(...)`` repr.
- The pure :func:`clean_localized_text` helper (no DB).
- A non-OPC-UA service observation still dedups across two writes.

The DB tests use the workspace's live Postgres reachable via
``$POSTGRES_DSN`` (seeded by ``tests/conftest.py``), mirroring
``test_postgres_repo_upsert.py``. Each test cleans up its own rows.
"""

from __future__ import annotations

import os
from typing import Any, AsyncIterator, Dict, List
from uuid import UUID

import pytest
from sqlalchemy import delete, select

from otalon_scan.core.models import DeviceFinding
from otalon_scan.modules.opcua_discover.start import clean_localized_text
from otalon_scan.repositories.models import Scan, ServiceObservation
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres

_TEST_IP = "203.0.113.215"

_SECURITY_VARIANTS: List[Dict[str, str]] = [
    {"mode": "1", "policy": "http://opcfoundation.org/UA/SecurityPolicy#None"},
    {"mode": "2", "policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256"},
    {"mode": "3", "policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256"},
    {"mode": "3", "policy": "http://opcfoundation.org/UA/SecurityPolicy#Basic256Sha256"},
]


def _make_endpoint_finding(variant: Dict[str, str]) -> DeviceFinding:
    """Build a DeviceFinding mirroring one ``opcua_discover`` endpoint."""
    endpoint: Dict[str, Any] = {
        "Endpoint URL": f"opc.tcp://{_TEST_IP}:4840",
        "Application URI": "urn:SIMATIC.S7-1500.OPC-UA.Application:PLC_1",
        "Product URI": "urn:SIEMENS.SIMATIC.S7-1500",
        "Application Name": "LocalizedText(Locale=None, Text='PLC_1')",
        "Security Mode": variant["mode"],
        "Security Policy URI": variant["policy"],
    }
    return DeviceFinding(ipv4=_TEST_IP, extra={"endpoint": endpoint})


def _four_endpoint_findings() -> List[DeviceFinding]:
    """Four endpoints sharing ip/port/transport, differing by security."""
    return [_make_endpoint_finding(v) for v in _SECURITY_VARIANTS]


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a ScannerPostgresRepo bound to the workspace Postgres."""
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run SCAN-015 persistence tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to SCAN-015 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


async def _cleanup_rows_by_scan_id(repo: ScannerPostgresRepo, scan_id: UUID) -> None:
    """Remove all rows produced by ``scan_id``, including the scan row."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(ServiceObservation).where(ServiceObservation.scan_id == scan_id))
            await session.execute(delete(Scan).where(Scan.id == scan_id))


async def _opcua_rows(repo: ScannerPostgresRepo, scan_id: UUID) -> List[ServiceObservation]:
    """Return this scan's OPC UA service observations ordered by id."""
    async with repo._Session() as session:
        res = await session.execute(
            select(ServiceObservation).where(ServiceObservation.scan_id == scan_id).order_by(ServiceObservation.id)
        )
        return list(res.scalars().all())


# ---- (c) LocalizedText cleanup helper (pure) ----


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("LocalizedText(Locale=None, Text='PLC_1')", "PLC_1"),
        ('LocalizedText(Locale=None, Text="PLC_1")', "PLC_1"),
        ("LocalizedText(Locale='en', Text='SIMATIC S7')", "SIMATIC S7"),
        ("PLC_1", "PLC_1"),
        ("", ""),
        (None, None),
    ],
)
def test_clean_localized_text(raw: Any, expected: Any) -> None:
    """The helper SHALL return inner Text or pass plain strings through."""
    assert clean_localized_text(raw) == expected


# ---- (a) 4 endpoints → 4 rows with clean name + security discriminator ----


async def test_four_endpoints_persist_as_four_rows(repo: ScannerPostgresRepo) -> None:
    """4 endpoints differing only by security SHALL persist as 4 rows."""
    scan_id = await repo.start_scan(module_name="_scan015_four_endpoints")
    try:
        await repo.save_opcua_discover_results(scan_id, _four_endpoint_findings())
        rows = await _opcua_rows(repo, scan_id)
        assert len(rows) == 4
        for row in rows:
            assert row.service_name == "PLC_1"
            assert row.port == 4840
            assert row.protocol == "opcua"
        pairs = {(row.security_mode, row.security_policy) for row in rows}
        expected = {(v["mode"], v["policy"]) for v in _SECURITY_VARIANTS}
        assert pairs == expected
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- (b) re-scan same 4 → still 4 (idempotent UPSERT, not 8) ----


async def test_rescan_same_endpoints_is_idempotent(repo: ScannerPostgresRepo) -> None:
    """Re-running the same 4 endpoints SHALL keep exactly 4 rows."""
    scan_id = await repo.start_scan(module_name="_scan015_idempotent")
    try:
        await repo.save_opcua_discover_results(scan_id, _four_endpoint_findings())
        await repo.save_opcua_discover_results(scan_id, _four_endpoint_findings())
        rows = await _opcua_rows(repo, scan_id)
        assert len(rows) == 4
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)


# ---- (d) non-OPC-UA observation still dedups ----


async def test_non_opcua_observation_still_dedups(repo: ScannerPostgresRepo) -> None:
    """A non-OPC-UA port observation SHALL dedup across two writes.

    The empty-string security discriminator ('', '') is shared by all
    non-OPC-UA writers, so the five-column UNIQUE constraint behaves like
    the original three-column one for them.
    """
    suffix = os.urandom(3).hex()
    mac = f"02:01:f0:{suffix[0:2]}:{suffix[2:4]}:{suffix[4:6]}"
    iface = await repo.upsert_interface_legacy(mac=mac)
    iface_id = int(iface.id)
    scan_id = await repo.start_scan(module_name="_scan015_non_opcua_dedup")
    try:
        for _ in range(2):
            await repo.upsert_service_observation(
                scan_id=scan_id,
                interface_id=iface_id,
                port=502,
                transport="tcp",
                service_name="modbus",
            )
        async with repo._Session() as session:
            res = await session.execute(
                select(ServiceObservation).where(
                    ServiceObservation.interface_id == iface_id,
                    ServiceObservation.port == 502,
                    ServiceObservation.transport == "tcp",
                )
            )
            rows = list(res.scalars().all())
        assert len(rows) == 1
        assert rows[0].security_mode == ""
        assert rows[0].security_policy == ""
    finally:
        await _cleanup_rows_by_scan_id(repo, scan_id)
