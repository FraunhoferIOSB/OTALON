"""Prometheus metrics for otalon-scan (F-02 / scan--observability).

Exposes:

- :data:`PERSISTENCE_ERRORS` (Counter, label ``module``) — incremented
  every time the orchestrator's persist path raises a database error.
  Spec-mandated metric name: ``cyberscan_persistence_errors_total``.
- :data:`SCAN_DURATION_SECONDS` (Histogram, labels ``module`` /
  ``status``) — observed once per scan run at orchestrator
  finalisation; ``status`` ∈
  {``completed``, ``failed``, ``aborted``, ``cancelled_partial``}.
  Spec-mandated metric name: ``cyberscan_scan_duration_seconds``.
- :func:`mount_metrics` — register ``GET /metrics`` (Prometheus text
  format) on a FastAPI app. Mounted from the lifespan startup so the
  endpoint becomes available alongside the rest of the API surface.
- :func:`module_label` — canonicalise a module name into the bounded
  ``module`` label value both metrics use.

Cardinality is bounded by design: ``module`` ≤ 6 values (the shipped
modules), ``status`` = 4 values. No per-host, no per-scan-id labels —
keeping the series count to O(modules × statuses) = O(24).

No authentication is required on the metrics endpoint; the trust
boundary stays at ``otalon-api`` per the mission Q2/Q4 decision.
"""

from __future__ import annotations

from typing import Optional

from fastapi import FastAPI, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    REGISTRY,
    Counter,
    Histogram,
    generate_latest,
)

__all__ = [
    "PERSISTENCE_ERRORS",
    "SCAN_DURATION_SECONDS",
    "module_label",
    "mount_metrics",
]


def module_label(module_name: Optional[str]) -> str:
    """Return the canonical leaf-slug for the ``module`` Prometheus label.

    Accepts both path-prefixed (``"modules/arp_scan"``,
    ``"T1018/arp_scan"``) and leaf-only (``"arp_scan"``) shapes;
    falls back to ``"unknown"`` when ``module_name`` is empty / None
    so the counter cardinality stays bounded even on error paths
    that cannot identify the module.
    """
    if not module_name:
        return "unknown"
    return module_name.split("/")[-1]


# Re-using the default global registry keeps the metric names visible
# to ``prometheus_client.generate_latest()`` without an explicit
# registry argument. The module-level definitions are deliberately
# created at import time: Prometheus counters/histograms are
# multiprocessing-safe and idempotent on repeated import (the
# ``unit-test`` reload pattern is handled by the registry's existing
# duplicate-collector logic).

PERSISTENCE_ERRORS: Counter = Counter(
    "cyberscan_persistence_errors_total",
    "Total number of persistence errors raised by ScannerPostgresRepo.",
    labelnames=("module",),
)

SCAN_DURATION_SECONDS: Histogram = Histogram(
    "cyberscan_scan_duration_seconds",
    "Wall-clock duration of a scan run, in seconds.",
    labelnames=("module", "status"),
)


def mount_metrics(app: "FastAPI") -> None:
    """Register ``GET /metrics`` (Prometheus text format) on ``app``.

    The endpoint serialises the default Prometheus registry on each
    request via :func:`prometheus_client.generate_latest` and returns
    it with ``Content-Type: text/plain; version=0.0.4`` (the value
    Prometheus scrapers expect; constant
    :data:`prometheus_client.CONTENT_TYPE_LATEST`).

    Mounting via a plain handler (rather than
    ``prometheus_client.make_asgi_app()`` as a sub-application) keeps
    the route inside the main FastAPI app so the OpenAPI schema, the
    auth machinery, and the existing test harness pick it up without
    additional plumbing.
    """

    @app.get("/metrics", include_in_schema=False)
    async def _metrics_handler() -> Response:  # pragma: no cover - trivial wrapper
        payload = generate_latest(REGISTRY)
        return Response(content=payload, media_type=CONTENT_TYPE_LATEST)
