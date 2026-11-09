"""Integration tests for the reshaped ``POST /scans/start`` request shape.

Covers Phase 2 of the ``harden-otalon-scan-security`` OpenSpec change:

- Unknown keys in ``overrides`` → HTTP 422.
- Wrong types in ``overrides`` → HTTP 422.
- Unknown ``module_name`` → HTTP 422.
- A structurally valid request body parses without raising and is accepted
  by Pydantic (whether the scan actually starts depends on host
  capabilities and is not under test here).

These tests deliberately bypass the FastAPI lifespan so they don't require
a running PostgreSQL: ``StartScanRequest`` is exercised directly. The
HTTP-status mapping (``ValueError`` → 422) is verified via a thin
``TestClient`` fixture that registers a stub endpoint just for these
checks; the real endpoint is also exercised through the existing
``test_api_server.py`` integration tests, which already prove the
FastAPI plumbing.
"""

from __future__ import annotations

from typing import Any

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient
from pydantic import ValidationError

from otalon_scan.api.schemas.scans import StartScanRequest

# ---- Direct Pydantic-level checks (no HTTP layer) ----


def test_start_scan_request_rejects_unknown_module_name() -> None:
    """An unknown ``module_name`` SHALL fail Pydantic validation."""
    with pytest.raises(ValidationError):
        StartScanRequest.model_validate({"module_name": "modules/does_not_exist", "overrides": {}})


def test_start_scan_request_rejects_unknown_override_key() -> None:
    """Unknown override keys SHALL fail Pydantic validation."""
    with pytest.raises(ValidationError):
        StartScanRequest.model_validate(
            {
                "module_name": "modules/arp_scan",
                "overrides": {"definitely_not_a_real_field": "x"},
            }
        )


def test_start_scan_request_rejects_wrong_type_for_port_range() -> None:
    """A wrong-type override value SHALL fail Pydantic validation."""
    with pytest.raises(ValidationError):
        StartScanRequest.model_validate(
            {
                "module_name": "modules/port_scan",
                # port_range MUST be a string; passing an int violates the
                # field type and additionally the validator's isinstance check.
                "overrides": {"port_range": 22},
            }
        )


def test_start_scan_request_rejects_descending_port_range() -> None:
    """A semantically invalid override SHALL fail Pydantic validation."""
    with pytest.raises(ValidationError):
        StartScanRequest.model_validate(
            {
                "module_name": "modules/port_scan",
                "overrides": {"port_range": "1024-22"},
            }
        )


def test_start_scan_request_accepts_empty_overrides() -> None:
    """A valid module_name with ``overrides=None`` SHALL parse cleanly."""
    req = StartScanRequest.model_validate({"module_name": "modules/arp_scan", "overrides": None})
    assert req.module_name == "modules/arp_scan"
    assert req.overrides is None


def test_start_scan_request_normalises_valid_overrides() -> None:
    """A valid override payload SHALL parse and be replaced with the canonical form."""
    req = StartScanRequest.model_validate(
        {
            "module_name": "modules/arp_scan",
            "overrides": {"target_subnet": "10.0.0.5/24"},
        }
    )
    assert req.overrides == {"target_subnet": "10.0.0.0/24"}


def test_start_scan_request_accepts_leaf_slug_and_path_prefixed_form() -> None:
    """Both ``arp_scan`` and ``modules/arp_scan`` SHALL resolve to the same schema."""
    a = StartScanRequest.model_validate({"module_name": "arp_scan", "overrides": {"target_subnet": "10.0.0.0/24"}})
    b = StartScanRequest.model_validate(
        {
            "module_name": "modules/arp_scan",
            "overrides": {"target_subnet": "10.0.0.0/24"},
        }
    )
    assert a.overrides == b.overrides == {"target_subnet": "10.0.0.0/24"}


# ---- HTTP-level checks (FastAPI maps ValidationError → 422) ----


@pytest.fixture
def http_client() -> TestClient:
    """Stand up a minimal FastAPI app whose only route exercises ``StartScanRequest``.

    We don't use the real ``otalon_scan.api.server.app`` here because its lifespan
    requires a working PostgreSQL connection. The contract we want to
    verify is purely "Pydantic ValidationError on this model → HTTP 422",
    which is FastAPI default behaviour — a minimal route is sufficient.
    """
    app = FastAPI()

    @app.post("/scans/start")
    async def _start(req: StartScanRequest) -> dict[str, Any]:  # noqa: ANN401
        return {"module_name": req.module_name, "overrides": req.overrides}

    return TestClient(app)


def test_http_unknown_module_name_returns_422(http_client: TestClient) -> None:
    r = http_client.post(
        "/scans/start",
        json={"module_name": "modules/does_not_exist", "overrides": {}},
    )
    assert r.status_code == 422, r.text


def test_http_unknown_override_key_returns_422(http_client: TestClient) -> None:
    r = http_client.post(
        "/scans/start",
        json={
            "module_name": "modules/arp_scan",
            "overrides": {"definitely_not_a_real_field": "x"},
        },
    )
    assert r.status_code == 422, r.text


def test_http_wrong_type_returns_422(http_client: TestClient) -> None:
    r = http_client.post(
        "/scans/start",
        json={
            "module_name": "modules/port_scan",
            "overrides": {"port_range": 22},
        },
    )
    assert r.status_code == 422, r.text


def test_http_semantically_invalid_override_returns_422(
    http_client: TestClient,
) -> None:
    r = http_client.post(
        "/scans/start",
        json={
            "module_name": "modules/port_scan",
            "overrides": {"port_range": "1024-22"},
        },
    )
    assert r.status_code == 422, r.text


def test_http_valid_request_returns_200(http_client: TestClient) -> None:
    r = http_client.post(
        "/scans/start",
        json={
            "module_name": "modules/arp_scan",
            "overrides": {"target_subnet": "10.0.0.0/24"},
        },
    )
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["module_name"] == "modules/arp_scan"
    assert body["overrides"] == {"target_subnet": "10.0.0.0/24"}
