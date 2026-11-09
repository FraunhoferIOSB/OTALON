"""Tests for bound-review cache invalidation dispatch."""

from __future__ import annotations

import json
from typing import cast

from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.runtime.bounds_invalidator import BoundsInvalidator


def _listener() -> BoundsInvalidator:
    return BoundsInvalidator(
        connector=cast("PostgresConnector", None),
        poll_interval_seconds=30,
        on_invalidate=lambda _module, _series: None,
        on_periodic_refresh=lambda: None,
    )


def test_dispatch_invalidates_module_and_series() -> None:
    """Sender payload reaches callback with exact contract values."""
    received: list[tuple[str, str]] = []
    listener = _listener()
    listener._on_invalidate = lambda module, series: received.append((module, series))

    listener._dispatch(json.dumps({"module": "proto_traffic", "series_id": "s-7"}))

    assert received == [("proto_traffic", "s-7")]


def test_dispatch_rejects_incomplete_payload() -> None:
    """Malformed or incomplete notifications do not invalidate caches."""
    received: list[tuple[str, str]] = []
    listener = _listener()
    listener._on_invalidate = lambda module, series: received.append((module, series))

    listener._dispatch(json.dumps({"module": "conn"}))
    listener._dispatch("not-json")

    assert received == []
