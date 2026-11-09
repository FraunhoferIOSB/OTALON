"""Liveness-marker wiring for the otalon-clas container healthcheck (SUITE-052).

``otalon-clas`` has no HTTP port, so its Docker ``HEALTHCHECK`` (and the
mirroring compose block) cannot be a socket probe. It is a file-mtime probe
against ``/tmp/otalon-clas-last-tick`` instead, which only works if the live
loop actually refreshes that file after every tick. These tests pin both
halves: the stamping helper and its call site inside ``run_live``.

The probe path and the 180 s tolerance live in three places (Dockerfile,
compose, module). ``tests/security/test_compose_healthchecks.py`` asserts that
they agree on the path; the tests here prove the module half really writes it.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

import pytest

from otalon_clas import main as main_module
from otalon_clas.main import _touch_liveness_marker


def _old_marker(path: Path) -> None:
    """Create the marker with an mtime far outside the probe tolerance."""
    path.write_text("", encoding="utf-8")
    stale = time.time() - 600
    os.utime(path, (stale, stale))


def test_touch_liveness_marker_creates_the_file(tmp_path: Path) -> None:
    """A fresh container has no marker; the first tick must create it."""
    marker = tmp_path / "otalon-clas-last-tick"

    _touch_liveness_marker(marker)

    assert marker.exists()


def test_touch_liveness_marker_refreshes_a_stale_file(tmp_path: Path) -> None:
    """A completed tick must move the mtime forward, not leave it stale."""
    marker = tmp_path / "otalon-clas-last-tick"
    _old_marker(marker)
    stale = marker.stat().st_mtime

    _touch_liveness_marker(marker)

    assert marker.stat().st_mtime > stale


def test_touch_liveness_marker_never_raises_on_unwritable_path(tmp_path: Path) -> None:
    """A marker failure must not take the detection pipeline down."""
    unwritable = tmp_path / "missing-dir" / "otalon-clas-last-tick"

    _touch_liveness_marker(unwritable)

    assert not unwritable.exists()


class _StopInvalidator:
    """Invalidator double that records the shutdown call."""

    def __init__(self) -> None:
        self.stopped = 0

    def stop(self) -> None:
        self.stopped += 1


def _config() -> Any:
    """Minimal AppConfig double covering what ``run_live`` reads before the loop."""
    return SimpleNamespace(
        prediction=SimpleNamespace(
            live=SimpleNamespace(
                poll_interval_seconds=5,
                delay_seconds=0,
                grouping_interval_seconds=60,
            )
        ),
        suppression=SimpleNamespace(
            suppression_cache_ttl_s=30,
            ml_confidence_persist_threshold=0.6,
            drop_low_signal_anomalies=True,
        ),
    )


def test_run_live_refreshes_the_liveness_marker(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """The loop must re-stamp the marker after each tick, not only at boot.

    The boot stamp alone would keep the container ``(healthy)`` for the whole
    probe tolerance after startup even if every later tick hung. The first
    simulated tick therefore ages the marker past the tolerance and returns;
    only the post-tick stamp inside the loop can bring it back.
    """
    marker = tmp_path / "otalon-clas-last-tick"
    monkeypatch.setattr(main_module, "LIVENESS_MARKER_PATH", marker)

    invalidation = _StopInvalidator()
    monkeypatch.setattr(main_module, "_load_persisted_models", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_bootstrap_frequency_profiles", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_start_frequency_invalidator", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_start_bounds_invalidator", lambda *a, **k: invalidation)
    monkeypatch.setattr(main_module, "_start_port_rule_refresher", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "SuppressionService", lambda *a, **k: object())
    monkeypatch.setattr(main_module, "AnomalyPersister", lambda *a, **k: object())
    monkeypatch.setattr(main_module, "RuntimeConfigRepository", lambda *a, **k: object())
    monkeypatch.setattr(main_module, "_init_group_classifier", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_compute_dynamic_gap_tolerance", lambda *a, **k: 60)
    monkeypatch.setattr(main_module, "_get_rule_based_gap_tolerance", lambda *a, **k: 60)
    monkeypatch.setattr(main_module, "_flush_frequency_last_seen", lambda *a, **k: None)
    monkeypatch.setattr(main_module, "_maybe_run_grouping", lambda *a, **k: 0.0)

    calls = 0

    def _tick(*args: object, **kwargs: object) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            _old_marker(marker)
            return
        raise KeyboardInterrupt

    monkeypatch.setattr(main_module, "_live_tick", _tick)

    pg = cast(Any, object())
    model_store = cast(Any, object())
    pipeline_builder = cast(Any, object())

    main_module.run_live(_config(), pg, None, model_store, [], pipeline_builder)

    tolerance_s = 180
    age_s = time.time() - marker.stat().st_mtime
    assert age_s < tolerance_s, "the live loop must re-stamp the marker after a tick"
    assert invalidation.stopped == 1
