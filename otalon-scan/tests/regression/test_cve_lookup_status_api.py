"""API integration tests for the CVE-lookup status surface (SCAN-026 WB).

WB.1 added ``GET /vulnerabilities/lookups`` (list, newest-first) and
``GET /vulnerabilities/lookups/{job_id}`` (detail). WB.2 added the SSE
stream ``GET /vulnerabilities/lookups/{job_id}/events`` that emits
per-asset ``progress`` events plus exactly one terminal ``done`` /
``failed`` event before closing — the contract the global notification
layer (UI-051) depends on. These tests assert that contract with a stub
repository (no Postgres) and the real
:class:`~otalon_scan.cve_lookup.job.LookupJobRegistry`.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Iterator, Optional
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import otalon_scan.api.server as server_mod
from otalon_scan.api.server import app
from otalon_scan.core.auth import get_allowed_keys, set_allowed_keys
from otalon_scan.repositories.models import CveLookupStatus

_VIEWER_KEY = "viewer-secret-0123456789"
_OPERATOR_KEY = "operator-secret-0123456789"


@pytest.fixture
def auth_client() -> Iterator[TestClient]:
    """Yield a :class:`TestClient` with a known allow-list installed."""
    previous = get_allowed_keys()
    set_allowed_keys(
        {
            _VIEWER_KEY: ("ui-prod", "viewer"),
            _OPERATOR_KEY: ("mcp-prod", "operator"),
        }
    )
    try:
        yield TestClient(app)
    finally:
        set_allowed_keys(previous)


class _Row:
    """Minimal stand-in for a :class:`CveLookup` SQLAlchemy row."""

    def __init__(
        self,
        *,
        row_id: UUID,
        scope: str = "all",
        device_id: Optional[int] = None,
        source: str = "nvd",
        api_key_used: bool = False,
        status: CveLookupStatus = CveLookupStatus.COMPLETED,
        summary: Optional[dict[str, Any]] = None,
        error: Optional[str] = None,
    ) -> None:
        self.id = row_id
        self.scope = scope
        self.device_id = device_id
        self.source = source
        self.api_key_used = api_key_used
        self.status = status
        self.summary = summary
        self.error = error
        self.started_at = datetime(2026, 6, 21, 12, 0, tzinfo=timezone.utc)
        self.finished_at = datetime(2026, 6, 21, 12, 1, tzinfo=timezone.utc)


class _StubRepo:
    """Stub repo serving fixed lookup rows for the status endpoints."""

    def __init__(self, rows: list[_Row]) -> None:
        self._rows = rows
        self._by_id = {str(r.id): r for r in rows}

    async def list_lookups(self, *, limit: int = 100, offset: int = 0) -> list[_Row]:
        return self._rows[offset : offset + limit]

    async def get_lookup(self, lookup_id: Any) -> Optional[_Row]:
        # Mirror the real repo: a non-UUID id raises ValueError.
        UUID(str(lookup_id))
        return self._by_id.get(str(lookup_id))


def test_list_lookups_requires_api_key(auth_client: TestClient) -> None:
    """``GET /vulnerabilities/lookups`` without a key SHALL return 401."""
    assert auth_client.get("/vulnerabilities/lookups").status_code == 401


def test_list_lookups_returns_headers_newest_first(auth_client: TestClient) -> None:
    """The viewer key lists job-headers in repo order (newest-first)."""
    newest = UUID("11111111-1111-1111-1111-111111111111")
    older = UUID("22222222-2222-2222-2222-222222222222")
    rows = [
        _Row(row_id=newest, summary={"cves_found": 3, "critical": 1}),
        _Row(row_id=older, status=CveLookupStatus.FAILED, error="boom"),
    ]
    previous = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = _StubRepo(rows)
    try:
        resp = auth_client.get("/vulnerabilities/lookups", headers={"X-API-Key": _VIEWER_KEY})
        assert resp.status_code == 200
        lookups = resp.json()["lookups"]
        assert [item["job_id"] for item in lookups] == [str(newest), str(older)]
        assert lookups[0]["summary"]["cves_found"] == 3
        assert lookups[1]["status"] == "failed"
        assert lookups[1]["error"] == "boom"
    finally:
        server_mod.app.state.api_state.repo = previous


def test_get_lookup_detail_returns_summary(auth_client: TestClient) -> None:
    """Detail returns the job-header with its summary."""
    job_id = UUID("33333333-3333-3333-3333-333333333333")
    rows = [_Row(row_id=job_id, summary={"cves_found": 5, "critical": 2})]
    previous = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = _StubRepo(rows)
    try:
        resp = auth_client.get(
            f"/vulnerabilities/lookups/{job_id}",
            headers={"X-API-Key": _VIEWER_KEY},
        )
        assert resp.status_code == 200
        body = resp.json()
        assert body["job_id"] == str(job_id)
        assert body["summary"]["critical"] == 2
    finally:
        server_mod.app.state.api_state.repo = previous


def test_get_lookup_unknown_id_returns_404(auth_client: TestClient) -> None:
    """An unknown (but valid-UUID) id SHALL yield a fachliche 404."""
    previous = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = _StubRepo([])
    try:
        unknown = "44444444-4444-4444-4444-444444444444"
        resp = auth_client.get(
            f"/vulnerabilities/lookups/{unknown}",
            headers={"X-API-Key": _VIEWER_KEY},
        )
        assert resp.status_code == 404
    finally:
        server_mod.app.state.api_state.repo = previous


def _parse_sse(text: str) -> list[dict[str, Any]]:
    """Parse a ``text/event-stream`` body into ``{event, data}`` dicts."""
    events: list[dict[str, Any]] = []
    for block in text.strip().split("\n\n"):
        if not block.strip():
            continue
        event = "message"
        data = ""
        for line in block.splitlines():
            if line.startswith("event:"):
                event = line[len("event:") :].strip()
            elif line.startswith("data:"):
                data += line[len("data:") :].strip()
        events.append({"event": event, "data": json.loads(data) if data else {}})
    return events


def test_sse_replays_terminal_event_for_finished_job(auth_client: TestClient) -> None:
    """A job finished before connect still receives the terminal event.

    This is the UI-051 contract: the SSE stream MUST hand a late
    subscriber exactly one terminal ``done`` event carrying
    ``{job_id, status, cves_found, critical}`` by replay (design.md
    § D5), even though no live progress queue exists anymore.
    """
    job_id = UUID("55555555-5555-5555-5555-555555555555")
    rows = [_Row(row_id=job_id, summary={"cves_found": 2, "critical": 1})]
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = _StubRepo(rows)
    # Seed the registry with a retained terminal event for the finished
    # job (as the real job wrapper would have, before its queue closed).
    server_mod.app.state.api_state.lookup_registry.progress_bus._terminal[str(job_id)] = {
        "event": "done",
        "data": {
            "job_id": str(job_id),
            "status": "completed",
            "cves_found": 2,
            "critical": 1,
        },
    }
    try:
        resp = auth_client.get(
            f"/vulnerabilities/lookups/{job_id}/events",
            headers={"X-API-Key": _VIEWER_KEY},
        )
        assert resp.status_code == 200
        events = _parse_sse(resp.text)
        terminal = [e for e in events if e["event"] in ("done", "failed")]
        assert len(terminal) == 1
        assert terminal[0]["event"] == "done"
        assert terminal[0]["data"]["job_id"] == str(job_id)
        assert terminal[0]["data"]["status"] == "completed"
        assert terminal[0]["data"]["cves_found"] == 2
        assert terminal[0]["data"]["critical"] == 1
    finally:
        server_mod.app.state.api_state.lookup_registry.progress_bus._terminal.pop(str(job_id), None)
        server_mod.app.state.api_state.repo = previous_repo


def test_sse_unknown_job_returns_404(auth_client: TestClient) -> None:
    """SSE for an unknown job id SHALL 404 before opening the stream."""
    previous = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = _StubRepo([])
    try:
        unknown = "66666666-6666-6666-6666-666666666666"
        resp = auth_client.get(
            f"/vulnerabilities/lookups/{unknown}/events",
            headers={"X-API-Key": _VIEWER_KEY},
        )
        assert resp.status_code == 404
    finally:
        server_mod.app.state.api_state.repo = previous
