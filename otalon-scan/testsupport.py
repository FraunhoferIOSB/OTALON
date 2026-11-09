"""Shared test-support helpers for otalon-scan.

A top-level module rather than something under ``tests/`` because
``tests`` is not a package here — ``tests/conftest.py`` puts the project
root on ``sys.path``, so ``import testsupport`` resolves from any test
module while ``from tests.conftest import ...`` does not.

Provides the database-availability probe used to skip the DB-backed tests
when no PostgreSQL is reachable (SUITE-034), and the request factory that
lets a unit test drive a SCAN-033 state dependency without standing up a
full app.
"""

from __future__ import annotations

import os
from types import SimpleNamespace
from typing import TYPE_CHECKING

import pytest

if TYPE_CHECKING:  # pragma: no cover - typing-only imports
    from starlette.requests import Request

    from otalon_scan.api.state import ApiState


def postgres_available() -> bool:
    """Return whether the database these tests target can be opened.

    A real connect rather than a port probe: PostgreSQL may well be
    listening while the database the tests address does not exist (the
    suite defaults to ``otalon-clas``, which is absent on a developer box
    that hosts ``cyberclas``). A port check would report "available" and
    every test would still error with
    ``InvalidCatalogNameError``.

    Returns:
        ``True`` when a connection to the configured database succeeds.
    """
    try:
        import psycopg2
    except ImportError:  # pragma: no cover - psycopg2 is a hard dependency
        return False

    try:
        conn = psycopg2.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            dbname=os.environ.get("POSTGRES_DATABASE", "otalon-clas"),
            user=os.environ.get("POSTGRES_USER", "postgres"),
            password=os.environ.get("POSTGRES_PASSWORD", ""),
            connect_timeout=2,
        )
    except Exception:
        return False
    conn.close()
    return True


POSTGRES_AVAILABLE: bool = os.environ.get("OTALON_TEST_DB_PROBE", "0") == "1" and postgres_available()

requires_postgres = pytest.mark.skipif(
    not POSTGRES_AVAILABLE,
    reason=(
        "needs a reachable PostgreSQL holding the target database "
        "(POSTGRES_HOST/PORT/DATABASE, default localhost:5432/otalon-clas). "
        "Start it with `docker compose --profile core-db up -d`. "
        "Tracked in SUITE-034."
    ),
)
"""Skip marker for tests that require a live database.

DB-backed tests are skipped rather than left permanently red: an
always-red suite hides regressions, and these assert real schema and SQL
behaviour that a mock would not exercise honestly.
"""


def make_state_request(state: "ApiState") -> "Request":
    """Build a minimal ASGI :class:`Request` carrying ``state`` on its app.

    SCAN-033: the API dependencies in :mod:`otalon_scan.api.dependencies` resolve
    ``request.app.state.api_state``. Unit tests that drive a dependency
    directly (rather than through the HTTP stack) need a request whose app
    exposes that attribute; building a whole FastAPI app per assertion
    would be slower and would drag the lifespan in.

    Args:
        state: The :class:`~otalon_scan.api.state.ApiState` the dependency should see.

    Returns:
        A :class:`starlette.requests.Request` whose ``app.state.api_state``
        is ``state``.
    """
    from starlette.requests import Request

    class _App:
        def __init__(self) -> None:
            self.state = SimpleNamespace(api_state=state)

    request = Request({"type": "http", "method": "GET", "path": "/", "headers": []})
    request.scope["app"] = _App()
    return request
