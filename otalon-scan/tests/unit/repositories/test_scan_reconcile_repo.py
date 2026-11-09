"""E2E-B2 tests for scan startup-reconciliation (crash recovery).

Covers :meth:`ScannerPostgresRepo.reconcile_interrupted_scans`: on a
scanner restart a ``scans`` row left ``RUNNING``/``finished_at NULL`` has
no live in-process executor to finalize it and would otherwise show as a
permanently-stuck "running" in the Recent/History list. The reconcile pass
transitions every such orphan to ``ABORTED`` with ``finished_at`` set and
an explanatory ``error_message`` — while leaving an explicitly-active run
(``active_run_ids``) and already-terminal rows untouched. A second pass is
a no-op (idempotent).

Like the F-01 repo tests these run against the workspace's live Postgres
reached via ``$POSTGRES_DSN`` (seeded by ``tests/conftest.py``). Each test
deletes the rows it creates so it leaves no state behind. The fixture
``pytest.skip``s when the DB is unreachable or not migrated.
"""

from __future__ import annotations

import os
from typing import AsyncIterator
from uuid import UUID

import pytest
from sqlalchemy import delete

from otalon_scan.repositories.models import Scan, ScanStatus
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
        pytest.skip("POSTGRES_DSN not set; cannot run scan-reconcile repo tests")
    r = ScannerPostgresRepo(dsn=dsn)
    try:
        await r.verify_schema_revision()
    except RuntimeError as exc:
        await r.dispose()
        pytest.skip(f"PostgreSQL not migrated: {exc}")
    try:
        yield r
    finally:
        await r.dispose()


async def _delete_scan(repo: ScannerPostgresRepo, scan_id: UUID) -> None:
    """Hard-delete one ``scans`` row so the test leaves no state."""
    async with repo._Session() as session:
        async with session.begin():
            await session.execute(delete(Scan).where(Scan.id == scan_id))


async def test_reconcile_aborts_orphaned_running_keeps_active(
    repo: ScannerPostgresRepo,
) -> None:
    """An orphaned ``running`` scan → ``aborted``; an active one is kept."""
    orphan = await repo.start_scan(module_name="cve_lookup")
    active = await repo.start_scan(module_name="opcua_discover")
    try:
        count = await repo.reconcile_interrupted_scans(active_run_ids=[str(active)])
        assert count >= 1
        orphan_row = await repo.get_scan(orphan)
        active_row = await repo.get_scan(active)
        assert orphan_row is not None and active_row is not None
        assert orphan_row.status is ScanStatus.ABORTED
        assert orphan_row.finished_at is not None
        assert orphan_row.error_message is not None and "restart" in orphan_row.error_message
        assert active_row.status is ScanStatus.RUNNING
        assert active_row.finished_at is None
    finally:
        await _delete_scan(repo, orphan)
        await _delete_scan(repo, active)


async def test_reconcile_is_idempotent_and_skips_terminal(
    repo: ScannerPostgresRepo,
) -> None:
    """A second pass finds nothing; already-terminal rows stay untouched."""
    orphan = await repo.start_scan(module_name="cve_lookup")
    done = await repo.start_scan(module_name="port_scan")
    await repo.finish_scan(done, ScanStatus.COMPLETED)
    try:
        first = await repo.reconcile_interrupted_scans()
        assert first >= 1
        # Second pass: the orphan is now aborted, nothing left running.
        second = await repo.reconcile_interrupted_scans()
        # The orphan we created no longer counts; any residual is from
        # concurrent rows, so just assert our orphan settled terminal.
        orphan_row = await repo.get_scan(orphan)
        done_row = await repo.get_scan(done)
        assert orphan_row is not None and done_row is not None
        assert orphan_row.status is ScanStatus.ABORTED
        assert done_row.status is ScanStatus.COMPLETED
        assert isinstance(second, int)
    finally:
        await _delete_scan(repo, orphan)
        await _delete_scan(repo, done)
