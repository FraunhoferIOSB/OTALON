"""Real import domain-query entry points with a declared synthetic SQL seam."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from otalon_api.dependencies import get_pcap_import_service, get_settings
from otalon_api.domain.operations import OperationsJob
from otalon_api.main import app
from otalon_api.repositories.operations_jobs_repo import OperationsJobsRepository
from otalon_api.services.operations_jobs_service import OperationsJobsService
from otalon_api.services.pcap_import_service import PcapImportConfig, PcapImportService
from tests.helpers.pcap_fixtures import FakeJobsService
from tests.unit.test_pcap_import_router import _OPERATOR_HEADERS, _make_settings

pytestmark = pytest.mark.unit
_BASE = datetime(2026, 6, 1, tzinfo=timezone.utc)


class _QueryRows:
    """Evaluate only predicates actually present in the production SELECT.

    This is a unit SQL seam, not a PostgreSQL engine or persistence proof.
    """

    def __init__(self, rows: list[OperationsJob]) -> None:
        self.rows = rows
        self.calls: list[tuple[str, dict[str, Any]]] = []

    def _execute_query(self, sql: str, params: dict[str, Any]) -> list[dict[str, Any]]:
        self.calls.append((sql, params))
        rows = self.rows
        for key, column in (("state", "state"), ("type", "type"), ("actor", "actor")):
            if f"{column} = %({key})s" in sql:
                rows = [row for row in rows if getattr(row, column) == params[key]]
        if "started_at >= %(since)s" in sql:
            rows = [row for row in rows if row.started_at >= datetime.fromisoformat(params["since"])]
        if "params->>'kind' = %(kind)s" in sql:
            assert sql.index("params->>'kind'") < sql.index("ORDER BY") < sql.index("LIMIT")
            rows = [row for row in rows if row.params.get("kind") == params["kind"]]
        assert "ORDER BY started_at DESC" in sql
        assert "LIMIT %(limit)s" in sql
        return [
            row.model_dump() for row in sorted(rows, key=lambda row: row.started_at, reverse=True)[: params["limit"]]
        ]


def _mixed_rows() -> tuple[list[OperationsJob], OperationsJob]:
    """1000 newer other ingestion rows cannot hide one older active import."""
    store = FakeJobsService()
    target = store.seed(
        state="running",
        started_at=_BASE,
        actor="operator",
        params={"kind": "pcap-import", "original_filename": "older-active.pcap", "size_bytes": 64},
    )
    for index in range(1000):
        store.seed(
            state="running",
            started_at=_BASE + timedelta(seconds=index + 1),
            actor="operator",
            params={"kind": "other-ingest"},
        )
    store.seed(state="completed", started_at=_BASE + timedelta(days=1), params={"kind": "pcap-import"})
    store.seed(type="backup", state="running", started_at=_BASE + timedelta(days=2), params={"kind": "pcap-import"})
    return list(store.jobs.values()), target


def test_state_filtered_router_finds_older_import_and_passes_limit_to_repository(tmp_path: Path) -> None:
    """Exercise router -> owner -> generic service -> real repository SQL."""
    rows, target = _mixed_rows()
    pg = _QueryRows(rows)
    jobs = OperationsJobsService(pg, MagicMock())  # type: ignore[arg-type]
    owner = PcapImportService(jobs, MagicMock(), MagicMock(), PcapImportConfig(import_dir=tmp_path))
    settings = _make_settings()
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_pcap_import_service] = lambda: owner
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            response = TestClient(app).get(
                "/api/v1/operations/pcap-import?state=running&limit=200", headers=_OPERATOR_HEADERS
            )
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
    assert response.status_code == 200
    body = response.json()
    assert set(body) == {"items", "total"}
    assert body["total"] == len(body["items"]) == 1
    assert body["items"][0]["display_id"] == target.display_id
    assert body["items"][0]["original_filename"] == "older-active.pcap"
    assert body["items"][0]["state"] == "running"
    sql, params = pg.calls[0]
    assert params == {"state": "running", "type": "ingest", "kind": "pcap-import", "limit": 200}
    assert sql.index("params->>'kind' = %(kind)s") < sql.index("ORDER BY") < sql.index("LIMIT")


def test_repository_parameterizes_kind_before_order_and_limit() -> None:
    """Untrusted kind values are bound, not interpolated into SQL."""
    pg = MagicMock()
    pg._execute_query.return_value = []
    kind = "pcap-import' OR true --"
    assert OperationsJobsRepository(pg).list_jobs("running", "ingest", "operator", _BASE, 7, kind=kind) == []
    sql, params = pg._execute_query.call_args.args
    assert kind not in sql
    assert params == {
        "limit": 7,
        "state": "running",
        "type": "ingest",
        "actor": "operator",
        "since": _BASE.isoformat(),
        "kind": kind,
    }
    assert sql.index("WHERE") < sql.index("params->>'kind' = %(kind)s") < sql.index("ORDER BY") < sql.index("LIMIT")


async def test_generic_no_kind_positional_calls_and_summaries_are_unchanged() -> None:
    """Absent kind preserves original positional arguments, defaults and page semantics."""
    rows, _ = _mixed_rows()
    pg = _QueryRows(rows)
    service = OperationsJobsService(pg, MagicMock())  # type: ignore[arg-type]
    generic = await service.list_jobs("running", "ingest", "operator", _BASE, 2)
    assert len(generic) == 2
    assert all(job.params["kind"] == "other-ingest" for job in generic)
    with patch.object(service, "list_jobs", AsyncMock(return_value=[])) as summary_query:
        assert await service.list_summaries("running", "ingest", "operator", _BASE, 2) == []
    summary_query.assert_awaited_once_with("running", "ingest", "operator", _BASE, 2)
    for sql, params in pg.calls:
        assert "params->>'kind'" not in sql
        assert params == {
            "state": "running",
            "type": "ingest",
            "actor": "operator",
            "since": _BASE.isoformat(),
            "limit": 2,
        }
    await service.list_jobs()
    sql, params = pg.calls[-1]
    assert "WHERE" not in sql
    assert params == {"limit": 1000}


async def test_absent_kind_keeps_original_repository_call_shape() -> None:
    """Existing five-argument repository seams need no new keyword when absent."""
    service = OperationsJobsService(MagicMock(), MagicMock())
    with patch.object(service._jobs, "list_jobs", return_value=[]) as query:
        assert await service.list_jobs("running", "ingest", "operator", _BASE, 3) == []
    query.assert_called_once_with("running", "ingest", "operator", _BASE, 3)


@pytest.mark.parametrize("limit", (1, 20, 200))
async def test_owner_filters_kind_state_type_before_limit_and_preserves_newest_order(
    tmp_path: Path, limit: int
) -> None:
    """Owner passes the actual bound and domain predicates down to SQL."""
    store = FakeJobsService()
    for index in range(205):
        store.seed(state="queued", started_at=_BASE + timedelta(seconds=index), params={"kind": "pcap-import"})
    pg = _QueryRows(list(store.jobs.values()))
    jobs = OperationsJobsService(pg, MagicMock())  # type: ignore[arg-type]
    owner = PcapImportService(jobs, MagicMock(), MagicMock(), PcapImportConfig(import_dir=tmp_path))
    result = await owner.list_jobs(state="queued", limit=limit)
    assert len(result) == limit
    assert [job.id for job in result] == list(range(205, 205 - limit, -1))
    assert pg.calls[-1][1] == {"state": "queued", "type": "ingest", "kind": "pcap-import", "limit": limit}


async def test_named_helper_kind_before_bound_and_idempotency_reuse() -> None:
    """The retained helper must align with real query and insert-row reuse semantics."""
    rows, target = _mixed_rows()
    store = FakeJobsService()
    for row in rows:
        store.seed(**row.model_dump())
    result = await store.list_jobs("running", "ingest", "operator", _BASE, 1, kind="pcap-import")
    assert result == [target]
    generic = await store.list_jobs("running", "ingest", "operator", _BASE, 1)
    assert len(generic) == 1 and generic[0].params["kind"] == "other-ingest"
    original = await store.record_job(
        "ingest", "original", "operator", {"filename": "original.pcap"}, idempotency_key="a" * 64
    )
    reused = await store.record_job("ingest", "new", "operator", {"filename": "new.pcap"}, idempotency_key="a" * 64)
    assert reused == original
    assert reused.params == {"filename": "original.pcap"}
    first = await store.record_job("ingest", "no-key", "operator")
    second = await store.record_job("ingest", "no-key", "operator")
    assert first.id != second.id


async def test_owner_passes_optional_kind_to_generic_service(tmp_path: Path) -> None:
    """A consumer-only spy supplements, but does not replace, the SQL tests."""
    jobs = MagicMock()
    jobs.list_jobs = AsyncMock(return_value=[])
    owner = PcapImportService(jobs, MagicMock(), MagicMock(), PcapImportConfig(import_dir=tmp_path))
    assert await owner.list_jobs(state="cancelling", limit=200) == []
    jobs.list_jobs.assert_awaited_once_with(state="cancelling", type_="ingest", kind="pcap-import", limit=200)


@pytest.mark.parametrize("query,limit", (("", 20), ("?limit=1", 1), ("?limit=200", 200)))
def test_router_passes_default_and_boundary_limits_without_shape_change(tmp_path: Path, query: str, limit: int) -> None:
    """Default and explicit endpoint bounds reach the owner, not just slicing."""
    jobs = MagicMock()
    jobs.list_jobs = AsyncMock(return_value=[])
    owner = PcapImportService(jobs, MagicMock(), MagicMock(), PcapImportConfig(import_dir=tmp_path))
    settings = _make_settings()
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_pcap_import_service] = lambda: owner
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            response = TestClient(app).get(f"/api/v1/operations/pcap-import{query}", headers=_OPERATOR_HEADERS)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
    assert response.status_code == 200
    assert response.json() == {"items": [], "total": 0}
    jobs.list_jobs.assert_awaited_once_with(state=None, type_="ingest", kind="pcap-import", limit=limit)


@pytest.mark.parametrize("query", ("?limit=0", "?limit=201", "?state=not-a-state"))
def test_router_retains_state_and_limit_validation_without_query(tmp_path: Path, query: str) -> None:
    """Invalid inputs are rejected before querying the owning service."""
    jobs = MagicMock()
    jobs.list_jobs = AsyncMock(return_value=[])
    owner = PcapImportService(jobs, MagicMock(), MagicMock(), PcapImportConfig(import_dir=tmp_path))
    settings = _make_settings()
    previous = app.dependency_overrides.copy()
    app.dependency_overrides[get_pcap_import_service] = lambda: owner
    app.dependency_overrides[get_settings] = lambda: settings
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=settings):
            response = TestClient(app).get(f"/api/v1/operations/pcap-import{query}", headers=_OPERATOR_HEADERS)
    finally:
        app.dependency_overrides.clear()
        app.dependency_overrides.update(previous)
    assert response.status_code == 422
    jobs.list_jobs.assert_not_awaited()
