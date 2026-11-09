"""WA.2 tests for the CVE-lookup job-header repo methods (SCAN-026).

Covers the lifecycle of :class:`~otalon_scan.repositories.models.CveLookup` rows
through :meth:`ScannerPostgresRepo.start_lookup` /
:meth:`~ScannerPostgresRepo.finish_lookup` plus the
:meth:`~ScannerPostgresRepo.list_lookups` /
:meth:`~ScannerPostgresRepo.get_lookup` reads and the WA.5
:meth:`~ScannerPostgresRepo.reconcile_interrupted_lookups` crash-recovery
pass:

- ``start_lookup`` creates a ``running`` record with ``started_at`` set;
- ``finish_lookup`` transitions ``running → completed`` with ``summary``
  persisted (and ``finished_at`` stamped);
- ``finish_lookup`` transitions ``running → failed`` with ``error``
  persisted;
- ``list_lookups`` returns the job-headers newest-first and ``get_lookup``
  resolves a single row (and ``None`` for an unknown id);
- ``reconcile_interrupted_lookups`` fails an orphaned ``running`` record
  but leaves an ``active`` one alone.

Like the F-01 repo tests, these run against the workspace's live Postgres
reached via ``$POSTGRES_DSN`` (seeded by ``tests/conftest.py``). Each test
deletes the rows it creates so it leaves no state behind. The suite is
marked ``unit`` to match the directory; per :file:`pytest.ini` it carries
a 20 s timeout. The fixture ``pytest.skip``s when the DB is unreachable or
not migrated to the SCAN-026 head.
"""

from __future__ import annotations

import os
from typing import AsyncIterator
from uuid import UUID, uuid4

import pytest
from sqlalchemy import delete

from otalon_scan.repositories.models import CveLookup, CveLookupStatus
from otalon_scan.repositories.postgres_repo import ScannerPostgresRepo
from testsupport import requires_postgres

# Drives real PostgreSQL (schema/migrations/SQL); a mock would not
# exercise what these assert. Skipped (not deleted) when no database is
# reachable, so the suite is green-or-explicit (SUITE-034).
pytestmark = requires_postgres


@pytest.fixture
async def repo() -> AsyncIterator[ScannerPostgresRepo]:
    """Provide a ScannerPostgresRepo bound to the workspace Postgres.

    Skips when ``$POSTGRES_DSN`` is missing or unreachable / unmigrated.
    The repo's engine is disposed at teardown so the pool does not leak.
    """
    dsn = os.environ.get("POSTGRES_DSN")
    if not dsn:
        pytest.skip("POSTGRES_DSN not set; cannot run SCAN-026 lookup-repo tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated to SCAN-026 head: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


async def _delete_lookup(repo: ScannerPostgresRepo, lookup_id: UUID) -> None:
    """Hard-delete one ``cve_lookups`` row so the test leaves no state."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(CveLookup).where(CveLookup.id == lookup_id))


async def test_start_lookup_creates_running_record(repo: ScannerPostgresRepo) -> None:
    """``start_lookup`` SHALL persist a ``running`` row with ``started_at``."""
    lookup_id = await repo.start_lookup(scope="all", source="nvd", api_key_used=True)
    try:
        row = await repo.get_lookup(lookup_id)
        assert row is not None
        assert row.status is CveLookupStatus.RUNNING
        assert row.scope == "all"
        assert row.source == "nvd"
        assert row.api_key_used is True
        assert row.started_at is not None
        assert row.finished_at is None
        assert row.summary is None
        assert row.error is None
    finally:
        await _delete_lookup(repo, lookup_id)


async def test_finish_lookup_completed_writes_summary(repo: ScannerPostgresRepo) -> None:
    """running → completed SHALL persist the ``summary`` and ``finished_at``."""
    lookup_id = await repo.start_lookup(scope="all")
    summary = {
        "assets_scanned": 4,
        "cves_found": 7,
        "critical": 2,
        "per_asset": [{"device_id": 1, "ip": "10.0.0.1", "cve_count": 7}],
        "rate_limit_hits": 0,
    }
    try:
        await repo.finish_lookup(lookup_id, CveLookupStatus.COMPLETED, summary=summary)
        row = await repo.get_lookup(lookup_id)
        assert row is not None
        assert row.status is CveLookupStatus.COMPLETED
        assert row.finished_at is not None
        assert row.error is None
        assert row.summary == summary
    finally:
        await _delete_lookup(repo, lookup_id)


async def test_finish_lookup_failed_writes_error(repo: ScannerPostgresRepo) -> None:
    """running → failed SHALL persist the ``error`` text and ``finished_at``."""
    lookup_id = await repo.start_lookup(scope="device", device_id=42)
    try:
        await repo.finish_lookup(
            lookup_id,
            CveLookupStatus.FAILED,
            error="NVD unreachable: connection timed out",
        )
        row = await repo.get_lookup(lookup_id)
        assert row is not None
        assert row.status is CveLookupStatus.FAILED
        assert row.finished_at is not None
        assert row.error == "NVD unreachable: connection timed out"
        assert row.device_id == 42
    finally:
        await _delete_lookup(repo, lookup_id)


async def test_get_lookup_unknown_id_returns_none(repo: ScannerPostgresRepo) -> None:
    """``get_lookup`` SHALL return ``None`` for an id with no matching row."""
    assert await repo.get_lookup(uuid4()) is None


async def test_list_lookups_newest_first(repo: ScannerPostgresRepo) -> None:
    """``list_lookups`` SHALL return the job-headers newest-first."""
    first = await repo.start_lookup(scope="all")
    second = await repo.start_lookup(scope="device", device_id=7)
    try:
        rows = await repo.list_lookups(limit=50)
        ids = [str(r.id) for r in rows]
        assert str(first) in ids
        assert str(second) in ids
        # ``second`` was started after ``first`` → must appear earlier.
        assert ids.index(str(second)) < ids.index(str(first))
    finally:
        await _delete_lookup(repo, first)
        await _delete_lookup(repo, second)


async def test_reconcile_fails_orphaned_running_keeps_active(
    repo: ScannerPostgresRepo,
) -> None:
    """WA.5: an orphaned ``running`` row → ``failed``; an active one is kept."""
    orphan = await repo.start_lookup(scope="all")
    active = await repo.start_lookup(scope="all")
    try:
        count = await repo.reconcile_interrupted_lookups(active_job_ids=[str(active)])
        assert count >= 1
        orphan_row = await repo.get_lookup(orphan)
        active_row = await repo.get_lookup(active)
        assert orphan_row is not None and active_row is not None
        assert orphan_row.status is CveLookupStatus.FAILED
        assert orphan_row.error is not None and "interrupted" in orphan_row.error
        assert active_row.status is CveLookupStatus.RUNNING
    finally:
        await _delete_lookup(repo, orphan)
        await _delete_lookup(repo, active)
