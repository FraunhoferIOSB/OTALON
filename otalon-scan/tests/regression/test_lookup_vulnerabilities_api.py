"""API integration tests for ``POST /vulnerabilities/lookup``.

SCAN-026 WA.4 rewrote the endpoint from a synchronous 200-with-summary
proxy into an async **job** that returns ``202 Accepted`` with a
``job_id`` immediately (the 502-fix core, design.md § D3). These tests
therefore assert the new contract:

- missing ``X-API-Key`` → 401
- viewer key → 403
- operator key + stub repo → 202 with ``{job_id, status, eligible_assets}``
  returned without waiting for the lookup, and a tracked job registered
- repo not initialised → 500

Uses FastAPI's :class:`TestClient` with a stub repository (no Postgres
required). The lookup job body is dispatched through the real
:class:`~otalon_scan.cve_lookup.job.LookupJobRegistry`, but the CVE source and
the persist path are stubbed so no network or DB write happens.
"""

from __future__ import annotations

from typing import Any, Iterator
from uuid import UUID

import pytest
from fastapi.testclient import TestClient

import otalon_scan.api.server as server_mod
from otalon_scan.api.server import app
from otalon_scan.core.auth import get_allowed_keys, set_allowed_keys
from otalon_scan.cve_lookup.sources.base import CveHit, LookupAsset

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


class _StubRepo:
    """Stub repository that records calls and replays fixed replies."""

    def __init__(
        self,
        *,
        eligible_assets: list[LookupAsset],
    ) -> None:
        self.eligible_assets = eligible_assets
        self.calls: list[dict[str, Any]] = []
        self._scan_id = UUID("12345678-1234-1234-1234-123456789abc")
        self._job_id = UUID("abcdabcd-1234-1234-1234-abcdabcdabcd")

    async def lookup_eligible_assets(self) -> list[LookupAsset]:
        return self.eligible_assets

    async def start_scan(self, **kwargs: Any) -> UUID:
        self.calls.append({"op": "start_scan", **kwargs})
        return self._scan_id

    async def finish_scan(self, scan_id: Any, status: Any) -> None:
        self.calls.append(
            {
                "op": "finish_scan",
                "scan_id": str(scan_id),
                "status": status.value if hasattr(status, "value") else str(status),
            }
        )

    async def start_lookup(self, **kwargs: Any) -> UUID:
        self.calls.append({"op": "start_lookup", **kwargs})
        return self._job_id

    async def finish_lookup(self, lookup_id: Any, status: Any, summary: Any = None, error: Any = None) -> None:
        self.calls.append(
            {
                "op": "finish_lookup",
                "lookup_id": str(lookup_id),
                "status": status.value if hasattr(status, "value") else str(status),
                "summary": summary,
                "error": error,
            }
        )


class _FakeSource:
    """CVE source returning a fixed hit list per asset (no network)."""

    def __init__(self, hits_by_device: dict[int, list[CveHit]]) -> None:
        self._hits = hits_by_device

    async def fetch(self, asset: LookupAsset) -> list[CveHit]:
        return list(self._hits.get(asset.device_id, []))


def test_lookup_requires_api_key(auth_client: TestClient) -> None:
    """``POST /vulnerabilities/lookup`` without ``X-API-Key`` SHALL return 401."""
    response = auth_client.post("/vulnerabilities/lookup", json={"all": True})
    assert response.status_code == 401


def test_lookup_rejects_viewer(auth_client: TestClient) -> None:
    """A viewer key SHALL receive 403; the endpoint is operator-only."""
    response = auth_client.post(
        "/vulnerabilities/lookup",
        json={"all": True},
        headers={"X-API-Key": _VIEWER_KEY},
    )
    assert response.status_code == 403


def test_lookup_operator_all_accepts_202_with_job_id(
    auth_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operator key + all=True returns 202 + job_id and registers a job."""
    stub_repo = _StubRepo(
        eligible_assets=[
            LookupAsset(device_id=1, vendor="Siemens", product="S7-1500", version="2.8"),
            LookupAsset(device_id=2, vendor="Phoenix", product="ILC", version="1.0"),
        ]
    )
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = stub_repo

    import otalon_scan.api.routers.vulnerabilities as srv

    # Replace the NVD source with a fake so the background job touches no
    # network; the job body (run_lookup) still runs for real.
    fake_source = _FakeSource(
        {
            1: [CveHit(vuln_id="CVE-2024-0001", severity="critical", cvss_score=9.8)],
            2: [],
        }
    )
    monkeypatch.setattr(srv, "NvdSource", lambda *a, **k: fake_source)

    persisted: list[dict[str, Any]] = []

    class _StubVulnRepo:
        def __init__(self, _repo: Any) -> None:
            pass

        async def persist_lookup_result(self, *, scan_id: Any, result: Any) -> int:
            hits = int(result.total_hits)
            persisted.append({"scan_id": str(scan_id), "hits": hits})
            return hits

    monkeypatch.setattr(srv, "VulnerabilityObservationRepo", _StubVulnRepo)

    try:
        response = auth_client.post(
            "/vulnerabilities/lookup",
            json={"all": True},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 202
        body = response.json()
        assert body["job_id"] == "abcdabcd-1234-1234-1234-abcdabcdabcd"
        assert body["status"] == "running"
        assert body["eligible_assets"] == 2
        # The job-header and synthetic scan were both created synchronously,
        # before the 202 returned — proving the job was dispatched without
        # waiting on the lookup itself.
        assert any(c["op"] == "start_scan" for c in stub_repo.calls)
        assert any(c["op"] == "start_lookup" for c in stub_repo.calls)
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_lookup_operator_device_ids_scopes_job(
    auth_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Operator key + device_ids scopes the job to the requested ids."""
    stub_repo = _StubRepo(
        eligible_assets=[
            LookupAsset(device_id=1, vendor="Siemens", product="S7-1500", version="2.8"),
            LookupAsset(device_id=2, vendor="Phoenix", product="ILC", version="1.0"),
            LookupAsset(device_id=3, vendor="Hirschmann", product="OCTOPUS", version="3.1"),
        ]
    )
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = stub_repo

    import otalon_scan.api.routers.vulnerabilities as srv

    class _NoopSource:
        async def fetch(self, asset: LookupAsset) -> list[CveHit]:
            return []

    monkeypatch.setattr(srv, "NvdSource", lambda *a, **k: _NoopSource())

    class _StubVulnRepo:
        def __init__(self, _repo: Any) -> None:
            pass

        async def persist_lookup_result(self, *, scan_id: Any, result: Any) -> int:
            return 0

    monkeypatch.setattr(srv, "VulnerabilityObservationRepo", _StubVulnRepo)

    try:
        response = auth_client.post(
            "/vulnerabilities/lookup",
            json={"device_ids": [1, 3]},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 202
        body = response.json()
        # Only the scoped (eligible) assets count — 1 and 3, not 2.
        assert body["eligible_assets"] == 2
        # scope=device was recorded on the job-header.
        start_lookup = next(c for c in stub_repo.calls if c["op"] == "start_lookup")
        assert start_lookup["scope"] == "device"
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_lookup_returns_500_when_repo_not_initialized(auth_client: TestClient) -> None:
    """If the lifespan startup did not run, the handler SHALL return 500."""
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = None
    try:
        response = auth_client.post(
            "/vulnerabilities/lookup",
            json={"all": True},
            headers={"X-API-Key": _OPERATOR_KEY},
        )
        assert response.status_code == 500
        assert response.json() == {"detail": "Repository not initialized"}
    finally:
        server_mod.app.state.api_state.repo = previous_repo
