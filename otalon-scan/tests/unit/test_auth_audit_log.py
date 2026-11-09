"""Audit-log assertion tests for the API-key auth dependency.

Phase 5 / scan--api-auth: every authenticated and rejected call SHALL
emit a structured loguru log line. The full key SHALL NEVER appear
anywhere in the log; rejected keys are truncated to a fixed prefix.

The tests drive the dependency through a minimal FastAPI app + the
synchronous :class:`TestClient`. A loguru sink fixture captures every
log line; assertions then check substring presence of the structured
fields and explicit absence of the full key.
"""

from __future__ import annotations

from typing import Iterator, List

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from loguru import logger

from otalon_scan.core.auth import KEY_PREFIX_LEN, get_allowed_keys, set_allowed_keys, verify_api_key

_VIEWER_KEY = "viewer-secret-LONGENOUGH-1234567890"
_OPERATOR_KEY = "operator-secret-LONGENOUGH-1234567890"
_VIEWER_NAME = "ui-prod"
_OPERATOR_NAME = "mcp-prod"


# ---- Fixtures ----


@pytest.fixture
def loguru_sink() -> Iterator[List[str]]:
    """Capture loguru output into an in-memory list."""
    captured: List[str] = []
    sink_id = logger.add(
        captured.append,
        level="DEBUG",
        format="{level}|{message}",
    )
    try:
        yield captured
    finally:
        logger.remove(sink_id)


@pytest.fixture
def auth_app() -> Iterator[TestClient]:
    """Minimal FastAPI app exposing a viewer and an operator endpoint.

    Saves and restores the global allow-list around the test.
    """
    previous = get_allowed_keys()
    set_allowed_keys(
        {
            _VIEWER_KEY: (_VIEWER_NAME, "viewer"),
            _OPERATOR_KEY: (_OPERATOR_NAME, "operator"),
        }
    )

    app = FastAPI()

    @app.get("/read", dependencies=[Depends(verify_api_key("viewer"))])
    async def _read() -> dict[str, str]:
        return {"ok": "true"}

    @app.post("/mutate", dependencies=[Depends(verify_api_key("operator"))])
    async def _mutate() -> dict[str, str]:
        return {"ok": "true"}

    try:
        yield TestClient(app)
    finally:
        set_allowed_keys(previous)


# ---- Accept events ----


def test_accept_event_logged_with_name_and_role(auth_app: TestClient, loguru_sink: List[str]) -> None:
    """Successful authentication SHALL emit one INFO ``auth.accept`` line."""
    response = auth_app.get("/read", headers={"X-API-Key": _VIEWER_KEY})
    assert response.status_code == 200

    accept_lines = [line for line in loguru_sink if "event=auth.accept" in line]
    assert len(accept_lines) == 1, loguru_sink
    line = accept_lines[0]

    assert line.startswith("INFO|"), line
    assert f"name={_VIEWER_NAME}" in line
    assert "role=viewer" in line
    assert "method=GET" in line
    assert "path=/read" in line
    # key_prefix must be present, must be the truncated form (8 chars + ...).
    expected_prefix = f"key_prefix={_VIEWER_KEY[:KEY_PREFIX_LEN]}..."
    assert expected_prefix in line, line

    # The full key MUST NOT appear anywhere in the log.
    for entry in loguru_sink:
        assert _VIEWER_KEY not in entry, entry


def test_accept_event_for_operator_on_mutate(auth_app: TestClient, loguru_sink: List[str]) -> None:
    """Accept on a mutating endpoint records the operator name and role."""
    response = auth_app.post("/mutate", headers={"X-API-Key": _OPERATOR_KEY})
    assert response.status_code == 200

    accept_lines = [line for line in loguru_sink if "event=auth.accept" in line]
    assert len(accept_lines) == 1
    line = accept_lines[0]
    assert f"name={_OPERATOR_NAME}" in line
    assert "role=operator" in line
    assert "method=POST" in line
    assert "path=/mutate" in line
    for entry in loguru_sink:
        assert _OPERATOR_KEY not in entry


# ---- Reject events ----


def test_reject_missing_logged(auth_app: TestClient, loguru_sink: List[str]) -> None:
    """A missing ``X-API-Key`` SHALL emit a WARNING ``auth.reject reason=missing``."""
    response = auth_app.get("/read")
    assert response.status_code == 401

    reject_lines = [line for line in loguru_sink if "event=auth.reject" in line]
    assert len(reject_lines) == 1
    line = reject_lines[0]
    assert line.startswith("WARNING|"), line
    assert "reason=missing" in line
    assert "path=/read" in line
    assert "key_prefix=(empty)" in line


def test_reject_invalid_logs_truncated_key(auth_app: TestClient, loguru_sink: List[str]) -> None:
    """Invalid keys SHALL be logged truncated; the full key SHALL NOT appear."""
    bad_key = "badkeythatisverylong123456789"
    response = auth_app.get("/read", headers={"X-API-Key": bad_key})
    assert response.status_code == 401

    reject_lines = [line for line in loguru_sink if "event=auth.reject" in line]
    assert len(reject_lines) == 1
    line = reject_lines[0]
    assert line.startswith("WARNING|"), line
    assert "reason=invalid" in line
    assert f"key_prefix={bad_key[:KEY_PREFIX_LEN]}..." in line
    # Full key MUST NOT appear anywhere in the captured log.
    for entry in loguru_sink:
        assert bad_key not in entry, entry


def test_reject_short_invalid_key_not_truncated_but_still_safe(auth_app: TestClient, loguru_sink: List[str]) -> None:
    """A short invalid key (<= prefix length) is logged verbatim.

    This is acceptable because we are already revealing nothing
    sensitive about valid keys (the value did not match anything in
    the allow-list, by definition). The spec only mandates truncation
    when the rejected key is longer than the prefix length.
    """
    bad_key = "shortkey"  # exactly KEY_PREFIX_LEN chars
    response = auth_app.get("/read", headers={"X-API-Key": bad_key})
    assert response.status_code == 401

    reject_lines = [line for line in loguru_sink if "event=auth.reject" in line]
    assert len(reject_lines) == 1
    assert "key_prefix=shortkey" in reject_lines[0]


def test_reject_insufficient_role_logs_required_role(auth_app: TestClient, loguru_sink: List[str]) -> None:
    """A viewer key on an operator endpoint SHALL emit ``reason=insufficient_role``.

    The audit line SHALL surface the caller name, the caller's role,
    AND the required role so operators can tell from the log alone
    which key was used and why it was rejected.
    """
    response = auth_app.post("/mutate", headers={"X-API-Key": _VIEWER_KEY})
    assert response.status_code == 403

    reject_lines = [line for line in loguru_sink if "event=auth.reject" in line]
    assert len(reject_lines) == 1
    line = reject_lines[0]
    assert line.startswith("WARNING|"), line
    assert "reason=insufficient_role" in line
    assert f"caller={_VIEWER_NAME}" in line
    assert "role=viewer" in line
    assert "required_role=operator" in line
    assert "method=POST" in line
    assert "path=/mutate" in line
    # The full viewer key must not appear in this branch's log line either.
    for entry in loguru_sink:
        assert _VIEWER_KEY not in entry
