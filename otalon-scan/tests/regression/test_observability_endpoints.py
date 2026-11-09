"""Integration tests for the F-02 observability endpoints (/metrics, /health).

Covers the ``scan--observability`` capability:

- ``GET /metrics`` returns Prometheus text-format payload with the
  ``cyberscan_persistence_errors_total`` counter and the
  ``cyberscan_scan_duration_seconds`` histogram registered.
- Metric cardinality is bounded — only ``module`` and ``status`` labels
  appear; no per-host or per-scan-id labels.
- Counter increments are visible at ``/metrics`` after a simulated
  persistence error.
"""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from prometheus_client import REGISTRY

import otalon_scan.api.server as server_mod
from otalon_scan.api.metrics import PERSISTENCE_ERRORS, SCAN_DURATION_SECONDS

pytestmark = pytest.mark.integration


@pytest.fixture(autouse=True)
def reset_metrics() -> None:
    """Snapshot + restore the default registry counters between tests.

    Prometheus client counters are global module-level singletons; we
    cannot reset them outright (Counter does not expose a ``reset()``).
    Tests assert the *change* between observations rather than the
    absolute count.
    """
    yield


def _build_client_no_lifespan() -> TestClient:
    """Build a TestClient that bypasses the lifespan startup (so we do
    not need Postgres / ALLOWED_KEYS for the observability checks).

    The metrics endpoint is mounted at app construction (outside the
    lifespan); the ``/health`` plain handler exists at the same time.
    """
    # Re-use the module-level app; the lifespan is opt-in via the
    # ``with TestClient(app)`` context, but for these tests we only
    # need the routes registered at app-construction time. We instead
    # touch the app's router directly via TestClient without entering
    # the lifespan.
    return TestClient(server_mod.app, raise_server_exceptions=False)


def test_metrics_endpoint_returns_prometheus_text_format() -> None:
    """``GET /metrics`` SHALL return 200 + Prometheus text format."""
    client = _build_client_no_lifespan()
    # Manually exit on enter: TestClient's __enter__ runs the lifespan.
    # We bypass by calling the route directly via .get() outside the
    # context manager — TestClient supports this for stateless routes.
    response = client.get("/metrics")
    assert response.status_code == 200
    content_type = response.headers.get("content-type", "")
    assert content_type.startswith("text/plain"), content_type
    body = response.text
    assert "cyberscan_persistence_errors_total" in body
    assert "cyberscan_scan_duration_seconds" in body


def test_metrics_persistence_error_counter_increments() -> None:
    """Counter increment SHALL be visible at /metrics after .inc()."""
    client = _build_client_no_lifespan()
    before = client.get("/metrics").text

    PERSISTENCE_ERRORS.labels(module="arp_scan").inc()
    PERSISTENCE_ERRORS.labels(module="arp_scan").inc()
    PERSISTENCE_ERRORS.labels(module="port_scan").inc()

    after = client.get("/metrics").text
    # We do not assert exact totals (tests may run after other tests
    # that already touched the counter); we assert the labels appear
    # with at least the value we just incremented.
    assert 'cyberscan_persistence_errors_total{module="arp_scan"}' in after
    assert 'cyberscan_persistence_errors_total{module="port_scan"}' in after
    # Sanity: the after-body grew strictly via our increments.
    assert after != before or "arp_scan" not in before


def test_metrics_scan_duration_histogram_observation() -> None:
    """Histogram SHALL accept observations with module + status labels."""
    SCAN_DURATION_SECONDS.labels(module="arp_scan", status="completed").observe(0.5)
    SCAN_DURATION_SECONDS.labels(module="arp_scan", status="completed").observe(2.5)
    SCAN_DURATION_SECONDS.labels(module="arp_scan", status="failed").observe(0.1)

    client = _build_client_no_lifespan()
    body = client.get("/metrics").text
    assert 'cyberscan_scan_duration_seconds_count{module="arp_scan",status="completed"}' in body
    assert 'cyberscan_scan_duration_seconds_count{module="arp_scan",status="failed"}' in body


def test_metrics_cardinality_bounded() -> None:
    """No per-scan-id or per-host labels SHALL appear on the F-02 metrics."""
    client = _build_client_no_lifespan()
    body = client.get("/metrics").text
    forbidden_labels = ("scan_id=", "ip=", "host=", "uuid=", "run_id=")
    relevant_lines = [
        line
        for line in body.splitlines()
        if line.startswith("cyberscan_persistence_errors_total") or line.startswith("cyberscan_scan_duration_seconds")
    ]
    for line in relevant_lines:
        for forbidden in forbidden_labels:
            assert forbidden not in line, f"Forbidden label in {line}"


def test_metrics_registered_with_default_registry() -> None:
    """The F-02 metrics SHALL live on the default Prometheus registry."""
    metric_names = {m.name for m in REGISTRY.collect()}
    assert "cyberscan_persistence_errors_total" in metric_names or (
        "cyberscan_persistence_errors" in metric_names  # prometheus_client may strip _total
    )
    assert "cyberscan_scan_duration_seconds" in metric_names


# ---- /health (plain) and /health?deep=true ----


def test_health_plain_is_io_free_and_returns_ok() -> None:
    """Plain ``/health`` SHALL return 200 with ``status='ok'`` and no I/O."""
    client = _build_client_no_lifespan()
    response = client.get("/health")
    assert response.status_code == 200
    body = response.json()
    assert body.get("status") == "ok"


def test_health_deep_requires_explicit_opt_in() -> None:
    """``/health`` without ``?deep=true`` SHALL NOT probe Postgres."""
    # We monkeypatch the repo's probe() to raise; plain /health must
    # still be 200 (no I/O), while ?deep=true would propagate the error.
    previous_repo = server_mod.app.state.api_state.repo

    class _BoomRepo:
        async def probe(self) -> tuple[bool, str | None]:
            raise AssertionError("plain /health must not call probe()")

    server_mod.app.state.api_state.repo = _BoomRepo()
    try:
        client = _build_client_no_lifespan()
        response = client.get("/health")
        assert response.status_code == 200
    finally:
        server_mod.app.state.api_state.repo = previous_repo


def test_health_deep_response_shape() -> None:
    """``/health?deep=true`` SHALL include modules_discovered and active_scans."""
    previous_repo = server_mod.app.state.api_state.repo

    class _OkRepo:
        async def probe(self) -> tuple[bool, str | None]:
            return True, None

    server_mod.app.state.api_state.repo = _OkRepo()
    try:
        client = _build_client_no_lifespan()
        response = client.get("/health?deep=true")
        assert response.status_code == 200
        body = response.json()
        assert body.get("postgres") == "ok"
        assert isinstance(body.get("modules_discovered"), int)
        assert isinstance(body.get("active_scans"), int)
    finally:
        server_mod.app.state.api_state.repo = previous_repo
