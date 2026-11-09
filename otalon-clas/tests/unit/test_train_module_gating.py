"""Unit tests for the ML-training gate in ``_train_module``.

``_train_module`` was moved into ``otalon_clas.runtime.training_helpers``
during the runtime-retraining refactor (audit A-01); it resolves its
per-artifact trainers from that module, so the trainers are patched on
``training_helpers`` here.

Covers the fix from ``.dev/concepts/ml-training-decoupling.md``: the ML
training stage MUST be gated on ``classification.training_enabled``
(driven by ``$TRAINING_CLASSIFICATION_ENABLED``) and NOT on
``classification.enabled`` (driven by ``$PREDICTION_CLASSIFICATION_ENABLED``,
which is mandatorily ``True`` in live operation).

Acceptance from the TODO:

- With ``training_enabled=False`` (and ``enabled=True``), bounds +
  frequency stages run, the ML stage is skipped, and an INFO log line
  containing the literal phrase ``"skipping ML training"`` is emitted.
- With ``training_enabled=True``, the ML stage runs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any
from unittest.mock import MagicMock

import polars as pl
import pytest

from otalon_clas.common.settings import (
    ClassificationConfig,
    FrequencyMonitorConfig,
    ModuleConfig,
    PreprocessorConfig,
)
from otalon_clas.runtime import training_helpers as th_module


@dataclass
class _StubBundle:
    """Minimal stand-in for :class:`ModuleBundle`.

    The real bundle wires repositories, an Influx client, a preprocessor
    and the bounds/frequency trainers. The gating test only needs the
    ``config`` attribute and an ``influx`` whose ``fetch`` returns a
    non-empty Polars DataFrame so the early-return in ``_train_module``
    is not taken.
    """

    config: ModuleConfig
    influx: Any = field(default_factory=MagicMock)
    preprocessor: Any = field(default_factory=MagicMock)


def _module_config(*, training_enabled: bool, enabled: bool = True) -> ModuleConfig:
    """Build a minimal ``ModuleConfig`` with the two gate flags set."""
    return ModuleConfig(
        name="conn",
        enabled=True,
        database="netcap",
        measurement="network_metrics",
        tag_key="uci",
        features=["packet_count"],
        preprocessor=PreprocessorConfig(type="passthrough"),
        bounds_enabled=True,
        frequency_monitor=FrequencyMonitorConfig(enabled=True),
        classification=ClassificationConfig(
            enabled=enabled,
            training_enabled=training_enabled,
        ),
    )


def _wire_bundle(mod: ModuleConfig) -> _StubBundle:
    """Wire a stub bundle whose I/O returns a single-row DataFrame."""
    df = pl.DataFrame({"packet_count": [1.0], "uci": ["x"], "time": [0]})
    bundle = _StubBundle(config=mod)
    bundle.influx.fetch.return_value = df
    bundle.preprocessor.preprocess_for_training.return_value = df
    return bundle


def test_train_module_skips_ml_when_training_enabled_false(
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Bounds + frequency run, ML is skipped with the canonical log line."""
    mod = _module_config(training_enabled=False, enabled=True)
    bundle = _wire_bundle(mod)
    config_mock = MagicMock()
    model_store_mock = MagicMock()

    bounds_called: list[bool] = []
    freq_called: list[bool] = []
    cls_called: list[bool] = []

    monkeypatch.setattr(
        th_module,
        "_train_bounds",
        lambda *a, **k: bounds_called.append(True),
    )
    monkeypatch.setattr(
        th_module,
        "_train_frequency",
        lambda *a, **k: freq_called.append(True),
    )
    monkeypatch.setattr(
        th_module,
        "_train_classification",
        lambda *a, **k: cls_called.append(True),
    )

    # loguru → caplog bridge: route logs to standard logging.
    handler_id = th_module.logger.add(caplog.handler, format="{message}")
    try:
        th_module._train_module(
            config=config_mock,
            model_store=model_store_mock,
            bundle=bundle,  # type: ignore[arg-type]
            start="2026-01-01 00:00:00",
            stop="2026-01-01 01:00:00",
        )
    finally:
        th_module.logger.remove(handler_id)

    assert bounds_called == [True], "bounds stage must run"
    assert freq_called == [True], "frequency stage must run"
    assert cls_called == [], "ML stage must be skipped"

    skip_lines = [r for r in caplog.records if "skipping ML training" in r.getMessage()]
    assert skip_lines, (
        "Expected at least one log record containing 'skipping ML training'; "
        f"got: {[r.getMessage() for r in caplog.records]}"
    )


def test_train_module_runs_ml_when_training_enabled_true(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """All three stages run when ``training_enabled`` is True."""
    mod = _module_config(training_enabled=True, enabled=True)
    bundle = _wire_bundle(mod)
    config_mock = MagicMock()
    model_store_mock = MagicMock()

    bounds_called: list[bool] = []
    freq_called: list[bool] = []
    cls_called: list[bool] = []

    monkeypatch.setattr(
        th_module,
        "_train_bounds",
        lambda *a, **k: bounds_called.append(True),
    )
    monkeypatch.setattr(
        th_module,
        "_train_frequency",
        lambda *a, **k: freq_called.append(True),
    )
    monkeypatch.setattr(
        th_module,
        "_fetch_ml_training_df",
        lambda *a, **k: bundle.influx.fetch.return_value,
    )
    monkeypatch.setattr(
        th_module,
        "_train_classification",
        lambda *a, **k: cls_called.append(True),
    )

    th_module._train_module(
        config=config_mock,
        model_store=model_store_mock,
        bundle=bundle,  # type: ignore[arg-type]
        start="2026-01-01 00:00:00",
        stop="2026-01-01 01:00:00",
    )

    assert bounds_called == [True]
    assert freq_called == [True]
    assert cls_called == [True], "ML stage must run when training_enabled=True"


def test_train_module_ml_gate_ignores_prediction_enabled_flag(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Even with ``enabled=True`` (prediction flag), ML stays skipped
    when ``training_enabled=False``.

    This guards the actual bug from
    ``.dev/concepts/ml-training-decoupling.md``: the live-prediction
    flag must never drive the training-time decision.
    """
    mod = _module_config(training_enabled=False, enabled=True)
    bundle = _wire_bundle(mod)

    monkeypatch.setattr(th_module, "_train_bounds", lambda *a, **k: None)
    monkeypatch.setattr(th_module, "_train_frequency", lambda *a, **k: None)
    cls_called: list[bool] = []
    monkeypatch.setattr(
        th_module,
        "_train_classification",
        lambda *a, **k: cls_called.append(True),
    )

    th_module._train_module(
        config=MagicMock(),
        model_store=MagicMock(),
        bundle=bundle,  # type: ignore[arg-type]
        start="2026-01-01 00:00:00",
        stop="2026-01-01 01:00:00",
    )

    assert cls_called == [], (
        "ML training must remain gated on training_enabled, not on the "
        "live-prediction flag (regression guard for "
        ".dev/concepts/ml-training-decoupling.md)"
    )
