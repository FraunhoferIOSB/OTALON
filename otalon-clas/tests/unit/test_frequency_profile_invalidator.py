"""Wire and payload tests for frequency-profile invalidation."""

from __future__ import annotations

import json
from collections.abc import Callable
from types import SimpleNamespace
from typing import cast

import pytest

from otalon_clas import main
from otalon_clas.common.postgres_connector import PostgresConnector
from otalon_clas.detection.frequency_profile_repository import FrequencyProfileInvalidator


def _invalidator(callback: Callable[[str, str], None]) -> FrequencyProfileInvalidator:
    """Build an invalidator without starting its background thread."""
    return FrequencyProfileInvalidator(
        connector=cast("PostgresConnector", None),
        channel="frequency_profiles",
        refresh_interval_seconds=30,
        on_invalidate=callback,
        on_periodic_refresh=lambda: None,
    )


def test_valid_payload_routes_module_and_series() -> None:
    """Valid JSON reaches invalidation callback with exact values."""
    received = []
    _invalidator(lambda module, series: received.append((module, series)))._dispatch_payload(
        json.dumps({"module": "conn", "series_id": "s1"})
    )
    assert received == [("conn", "s1")]


def test_invalid_payloads_are_ignored() -> None:
    """Malformed JSON and missing fields do not raise or dispatch."""
    received = []
    listener = _invalidator(lambda module, series: received.append((module, series)))
    listener._dispatch_payload("not-json")
    listener._dispatch_payload(json.dumps({"module": "conn"}))
    listener._dispatch_payload(json.dumps({"series_id": "s1"}))
    assert received == []


def test_callback_failure_is_swallowed() -> None:
    """A routing callback failure cannot crash the listener loop."""
    listener = _invalidator(lambda _module, _series: (_ for _ in ()).throw(RuntimeError("boom")))
    listener._dispatch_payload(json.dumps({"module": "conn", "series_id": "s1"}))


def test_main_router_scopes_known_modules_and_ignores_unknown(monkeypatch: pytest.MonkeyPatch) -> None:
    """Main wiring reloads only the bundle named by a valid module payload."""
    calls: list[str] = []
    conn_monitor = SimpleNamespace(repository=object(), apply_invalidation=lambda series: calls.append(series))
    mac_monitor = SimpleNamespace(repository=object(), apply_invalidation=lambda series: calls.append(f"mac:{series}"))
    bundles = [
        SimpleNamespace(config=SimpleNamespace(name="conn"), freq_monitor=conn_monitor),
        SimpleNamespace(config=SimpleNamespace(name="mac_traffic"), freq_monitor=mac_monitor),
    ]
    captured: dict[str, Callable[[str, str], None]] = {}

    class FakeInvalidator:
        def __init__(self, **kwargs: object) -> None:
            captured["callback"] = cast(Callable[[str, str], None], kwargs["on_invalidate"])

        def start(self) -> bool:
            return True

    monkeypatch.setattr(main, "FrequencyProfileInvalidator", FakeInvalidator)
    config = SimpleNamespace(
        frequency_monitor=SimpleNamespace(
            persistence_enabled=True,
            notify_channel="frequency_profiles",
            refresh_interval_seconds=30,
        )
    )
    main._start_frequency_invalidator(config, cast("PostgresConnector", None), bundles)

    captured["callback"]("mac_traffic", "s2")
    captured["callback"]("unknown", "s3")
    captured["callback"]("conn", "s1")
    assert calls == ["mac:s2", "s1"]
