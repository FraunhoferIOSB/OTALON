"""HC4 — fail-fast on DB connectivity + ``/health`` DB-aware probe.

Covers ``.dev/TODO_otalon-scan.md`` HC4 acceptance criteria:

- Startup with unreachable PostgreSQL exits the process with a non-zero
  code (no more silent fallback to an in-memory store).
- ``GET /health`` reports HTTP 503 when the DB connection has been lost
  after a successful startup, and HTTP 200 again after recovery.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

import otalon_scan.api.server as server_mod

# HC13/HC14 (2026-05-18): these tests stub the repo locally but still
# enter the FastAPI app graph, so they share the integration marker.
pytestmark = pytest.mark.integration


@pytest.mark.asyncio
async def test_startup_exits_when_postgres_unreachable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Lifespan startup SHALL ``sys.exit(1)`` when ``ensure_schema`` fails.

    The previous behaviour silently swapped in an in-memory store and let
    ``/health`` keep reporting ``ok`` — see
    :file:`src/otalon_scan/api/server.py:74-118` (pre-HC4) and the HC4 acceptance
    criteria in ``.dev/TODO_otalon-scan.md``.

    We drive the lifespan context manager directly (rather than via
    :class:`asgi_lifespan.LifespanManager`, whose internal task group
    can wrap ``SystemExit`` in opaque ways) so the ``SystemExit`` raised
    by ``sys.exit(1)`` propagates cleanly to the test.
    """
    from fastapi import FastAPI

    from otalon_scan.api import server as srv

    async def _boom(self: object) -> None:
        raise ConnectionError("simulated DB outage at startup")

    monkeypatch.setattr(
        "otalon_scan.repositories.postgres_repo.ScannerPostgresRepo.ensure_schema",
        _boom,
    )

    fake_app = FastAPI()
    with pytest.raises(SystemExit) as excinfo:
        async with srv.lifespan(fake_app):
            pass  # pragma: no cover — lifespan should exit before reaching here

    assert excinfo.value.code == 1


def test_health_plain_returns_200_regardless_of_repo_state() -> None:
    """F-02: ``GET /health`` (no query) SHALL be a cheap liveness probe.

    Replaces the HC4 behaviour where ``/health`` itself pinged the DB —
    F-02 moves the DB-aware probe to ``?deep=true``. Plain ``/health``
    now returns 200 whenever the FastAPI process is alive, regardless
    of whether the repo is wired.
    """
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = None
    try:
        client = TestClient(server_mod.app)
        response = client.get("/health")
        assert response.status_code == 200
        assert response.json().get("status") == "ok"
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_health_deep_returns_503_when_repo_uninitialized() -> None:
    """``GET /health?deep=true`` SHALL return 503 when no repo is wired."""
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = None
    try:
        client = TestClient(server_mod.app)
        response = client.get("/health?deep=true")
        assert response.status_code == 503
        body = response.json()
        detail = body.get("detail")
        assert isinstance(detail, dict)
        assert detail.get("postgres") == "error"
        assert detail.get("error_message") == "repo_not_initialized"
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_health_deep_returns_503_when_db_unreachable_then_200_on_recovery() -> None:
    """``/health?deep=true`` flips 503 → 200 when DB connectivity is restored.

    Uses a stub repo whose ``probe`` returns ``(False, ...)`` while
    ``unhealthy`` is set, then ``(True, None)`` once cleared. Validates
    that the deep endpoint reflects the live DB state on every request.
    """

    class _FlakyRepo:
        def __init__(self) -> None:
            self.unhealthy = True

        async def probe(self) -> tuple[bool, str | None]:
            if self.unhealthy:
                return False, "simulated DB outage"
            return True, None

    flaky = _FlakyRepo()
    previous_repo = server_mod.app.state.api_state.repo
    server_mod.app.state.api_state.repo = flaky
    try:
        client = TestClient(server_mod.app)

        r1 = client.get("/health?deep=true")
        assert r1.status_code == 503
        detail = r1.json().get("detail")
        assert isinstance(detail, dict)
        assert detail.get("postgres") == "error"
        assert "simulated DB outage" in (detail.get("error_message") or "")

        flaky.unhealthy = False
        r2 = client.get("/health?deep=true")
        assert r2.status_code == 200
        body = r2.json()
        assert body.get("postgres") == "ok"
        assert "modules_discovered" in body
        assert "active_scans" in body
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_memory_repo_no_longer_present_in_production_module() -> None:
    """HC4: ``_MemoryRepo`` SHALL be removed from ``otalon_scan.api.server``.

    Production code SHOULD only ever instantiate
    :class:`ScannerPostgresRepo`. Tests that want an in-memory fake
    build their own — there is no shared production helper any more.
    """
    assert not hasattr(server_mod, "_MemoryRepo")
