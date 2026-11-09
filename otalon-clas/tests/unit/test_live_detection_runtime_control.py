"""Tests for per-tick live-detection runtime gate handling."""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any, cast

import polars as pl
import pytest
from loguru import logger

from otalon_clas import main as main_module
from otalon_clas.detection.frequency_monitor import (
    ABSENCE_ANOMALY,
    FREQUENCY_ANOMALY,
    FrequencyResult,
)
from otalon_clas.main import (
    LiveDetectionGateSnapshot,
    _detect,
    _gate_ml_prediction,
    _module_gates,
    _resolve_live_detection_gates,
)
from otalon_clas.runtime.module_bundle import InferenceModel, ModuleBundle

MODULES = ("conn", "mac_traffic", "proto_traffic")


def _bundle(name: str = "conn", bounds_enabled: bool = True, classification_enabled: bool = True) -> Any:
    """Build a minimal module bundle double for live gate tests."""
    return SimpleNamespace(
        config=SimpleNamespace(
            name=name,
            bounds_enabled=bounds_enabled,
            classification=SimpleNamespace(enabled=classification_enabled),
            frequency_monitor=SimpleNamespace(enabled=True),
            tag_key="uci",
            features=["value"],
        )
    )


class _RuntimeConfigDouble:
    """In-memory runtime repository double."""

    def __init__(self, values: dict[str, bool] | None = None, fail: bool = False) -> None:
        self.values = values or {}
        self.fail = fail
        self.calls: list[str] = []

    def get_bool(self, service: str, key: str, default: bool) -> bool:
        """Return persisted value or supplied boot fallback."""
        assert service == "otalon-clas"
        self.calls.append(key)
        if self.fail:
            raise RuntimeError("database unavailable")
        return self.values.get(key, default)


def test_missing_runtime_rows_fall_back_to_each_boot_gate() -> None:
    """Absent rows retain each module's independent boot values."""
    bundles = [_bundle("conn", False, True), _bundle("mac_traffic", True, False)]
    snapshot = _resolve_live_detection_gates(cast(Any, _RuntimeConfigDouble()), bundles)

    assert snapshot.for_module("conn") == (False, True)
    assert snapshot.for_module("mac_traffic") == (True, False)


def test_persisted_gate_changes_only_its_module_and_gate() -> None:
    """One persisted key does not affect other module gates."""
    values = {"detection.mac_traffic.classification_enabled": False}
    bundles = [_bundle(name) for name in MODULES]
    snapshot = _resolve_live_detection_gates(cast(Any, _RuntimeConfigDouble(values)), bundles)

    assert snapshot.for_module("mac_traffic") == (True, False)
    assert snapshot.for_module("conn") == (True, True)
    assert snapshot.for_module("proto_traffic") == (True, True)


def test_repository_failure_uses_boot_values_for_all_gates() -> None:
    """A runtime read failure preserves boot behavior without raising."""
    bundles = [_bundle("conn", False, False)]
    repository = _RuntimeConfigDouble(fail=True)

    snapshot = _resolve_live_detection_gates(cast(Any, repository), bundles)

    assert snapshot.for_module("conn") == (False, False)
    assert len(repository.calls) == 3


def test_gate_resolution_does_not_mutate_boot_configuration() -> None:
    """Runtime resolution leaves bundle boot values unchanged."""
    bundle = _bundle("conn", bounds_enabled=True, classification_enabled=True)
    repository = _RuntimeConfigDouble(
        {
            "detection.conn.bounds_enabled": False,
            "detection.conn.classification_enabled": False,
        }
    )

    snapshot = _resolve_live_detection_gates(cast(Any, repository), [bundle])

    assert snapshot.for_module("conn") == (False, False)
    assert bundle.config.bounds_enabled is True
    assert bundle.config.classification.enabled is True


def test_tick_workers_receive_one_coherent_gate_snapshot(monkeypatch: Any) -> None:
    """Every submitted module worker receives the same resolved snapshot."""
    bundles = [_bundle(name) for name in MODULES]
    repository = _RuntimeConfigDouble({"detection.conn.bounds_enabled": False})
    received: list[LiveDetectionGateSnapshot] = []

    def _fake_predict(*args: Any, **_: Any) -> None:
        received.append(args[-1])

    monkeypatch.setattr(main_module, "predict_module", _fake_predict)
    main_module._live_tick(
        config=cast(Any, None),
        pg=cast(Any, None),
        pcap_client=None,
        bundles=bundles,
        pipeline_builder=cast(Any, None),
        persister=cast(Any, None),
        last_timestamps={},
        poll_interval=5,
        delay=1,
        align_cache={},
        runtime_config=cast(Any, repository),
    )

    assert len(received) == len(MODULES)
    assert len({id(snapshot) for snapshot in received}) == 1
    assert received[0].for_module("conn") == (False, True)


def test_tick_survives_repository_failure_and_uses_boot_snapshot(
    monkeypatch: Any,
) -> None:
    """A failed runtime read does not prevent worker submission."""
    bundle = _bundle("conn", bounds_enabled=False, classification_enabled=False)
    repository = _RuntimeConfigDouble(fail=True)
    received: list[LiveDetectionGateSnapshot] = []

    monkeypatch.setattr(
        main_module,
        "predict_module",
        lambda *args, **_: received.append(args[-1]),
    )
    main_module._live_tick(
        cast(Any, None),
        cast(Any, None),
        None,
        [bundle],
        cast(Any, None),
        cast(Any, None),
        {},
        5,
        1,
        {},
        runtime_config=cast(Any, repository),
    )

    assert received[0].for_module("conn") == (False, False)


def test_snapshot_is_immutable_and_shared_by_module_lookup() -> None:
    """Frozen mappings prevent workers from observing a changed tick gate."""
    snapshot = LiveDetectionGateSnapshot({"conn": True}, {"conn": False}, {"conn": True})

    assert snapshot.for_module("conn") == (True, False)
    try:
        snapshot.bounds_enabled["conn"] = False  # type: ignore[index]
    except TypeError:
        pass
    else:
        raise AssertionError("snapshot mapping accepted mutation")


def test_bounds_off_preserves_frequency_fusion_and_skips_bounds() -> None:
    """Bounds-off produces frequency output without invoking bounds checks."""
    bundle = _bundle(bounds_enabled=False)
    bundle.bounds_manager = SimpleNamespace(check=lambda **_: (_ for _ in ()).throw(AssertionError()))
    bundle.freq_monitor = SimpleNamespace(check=lambda **_: [FrequencyResult(True, FREQUENCY_ANOMALY, 0.8, "series-a")])
    bundle.model_snapshot = lambda: None
    bundle.label_map = {}
    frame = pl.DataFrame({"uci": ["series-a"], "value": [1.0]})

    outcome = _detect(
        bundle,
        frame,
        frame,
        "2026-01-01T00:00:00+00:00",
        LiveDetectionGateSnapshot({"conn": False}, {"conn": True}, {"conn": True}),
    )

    assert outcome.fused is not None
    assert outcome.fused["anomaly_type"].to_list() == [FREQUENCY_ANOMALY]
    assert outcome.fused["bounds_type"].to_list() == [None]


def test_bounds_off_preserves_absence_results() -> None:
    """Bounds-off does not suppress independent absence persistence output."""
    bundle = _bundle(bounds_enabled=False)
    bundle.bounds_manager = SimpleNamespace(check=lambda **_: (_ for _ in ()).throw(AssertionError()))
    bundle.freq_monitor = SimpleNamespace(
        check=lambda **_: [FrequencyResult(True, ABSENCE_ANOMALY, 1.0, "silent-series")]
    )
    bundle.model_snapshot = lambda: None
    bundle.label_map = {}
    frame = pl.DataFrame({"uci": ["series-a"], "value": [1.0]})

    outcome = _detect(
        bundle,
        frame,
        frame,
        "2026-01-01T00:00:00+00:00",
        LiveDetectionGateSnapshot({"conn": False}, {"conn": True}, {"conn": True}),
    )

    assert [result.anomaly_type for result in outcome.absence_results] == [ABSENCE_ANOMALY]


def test_classification_off_never_invokes_ml(monkeypatch: Any) -> None:
    """Classification-off returns before model preprocessing or inference."""
    bundle = _bundle()
    bounds = pl.DataFrame(
        {
            "uci": ["series-a"],
            "value": [1.0],
            "is_anomaly": [True],
            "anomaly_type": ["BoundViolation"],
        }
    )
    frequency: list[FrequencyResult] = []
    called = False

    def _unexpected(*_: Any, **__: Any) -> None:
        nonlocal called
        called = True

    monkeypatch.setattr("otalon_clas.main._run_ml_prediction", _unexpected)
    result = _gate_ml_prediction(bundle, bounds, frequency, bounds, enabled=False)

    assert result is None
    assert called is False


def test_non_live_calls_keep_existing_unconditional_detection_gates() -> None:
    """Offline callers without a snapshot retain prior detection semantics."""
    bundle = _bundle(bounds_enabled=False, classification_enabled=False)

    assert _module_gates(bundle, None) == (True, True, True)


def test_runtime_classification_enable_uses_model_when_boot_gate_is_disabled(
    monkeypatch: Any,
) -> None:
    """A runtime classification enable opens inference with boot gate off."""
    model = InferenceModel(backend=object(), scaler=object(), label_map={0: "attack"})
    bundle = _bundle(classification_enabled=False)
    bundle.preprocessor = SimpleNamespace()
    bundle.set_inference_model = lambda value: setattr(bundle, "model", value)
    bundle.model_snapshot = lambda: getattr(bundle, "model", None)
    store = SimpleNamespace(load=lambda _name: (model.backend, model.scaler, {"label_map": {"0": "attack"}}))
    main_module._load_persisted_models(cast(Any, store), [bundle])
    runtime = _RuntimeConfigDouble({"detection.conn.classification_enabled": True})
    snapshot = _resolve_live_detection_gates(cast(Any, runtime), [bundle])
    called = False

    def _run(*_: Any, **__: Any) -> pl.DataFrame:
        nonlocal called
        called = True
        return pl.DataFrame({"ml_type": ["attack"]})

    monkeypatch.setattr(main_module, "_run_ml_prediction", _run)
    bounds = pl.DataFrame({"is_anomaly": [True]})
    result = _gate_ml_prediction(bundle, bounds, [], bounds, snapshot.for_module("conn")[1])

    assert result is not None
    assert called is True


def _real_bundle(name: str) -> ModuleBundle:
    """Build a real bundle so the production gate path is exercised."""
    from otalon_clas.ml.pipeline import MLPipeline

    class _Preprocessor:
        def get_feature_columns(self) -> list[str]:
            return ["value"]

    return ModuleBundle(
        config=cast(Any, SimpleNamespace(name=name, tag_key="uci", features=["value"])),
        influx=cast(Any, object()),
        preprocessor=cast(Any, _Preprocessor()),
        bounds_manager=cast(Any, object()),
        bounds_trainer=cast(Any, object()),
        bounds_repository=cast(Any, object()),
        freq_monitor=cast(Any, object()),
        ml_pipeline=MLPipeline(backend=cast(Any, object()), confidence_threshold=0.5),
    )


def test_gate_without_model_skips_silently(caplog: pytest.LogCaptureFixture) -> None:
    """A module without an artifact never runs the gate and never logs per tick."""
    handler_id = logger.add(caplog.handler, format="{message}")
    try:
        bundle = _real_bundle("mac_traffic")
        bounds = pl.DataFrame({"is_anomaly": [True]})

        results = [_gate_ml_prediction(bundle, bounds, [], bounds) for _ in range(3)]
    finally:
        logger.remove(handler_id)

    assert results == [None, None, None]
    messages = [record.getMessage() for record in caplog.records]
    assert not [
        message for message in messages if "classification gate enabled but no usable ML model loaded" in message
    ], messages


def test_gate_without_model_does_not_scan_bounds(monkeypatch: Any) -> None:
    """The skip happens before the anomaly scan, not after it."""
    bundle = _real_bundle("proto_traffic")
    scanned = False

    def _scan(_: pl.DataFrame) -> bool:
        nonlocal scanned
        scanned = True
        return True

    monkeypatch.setattr(main_module, "_has_anomaly_flag", _scan)

    assert _gate_ml_prediction(bundle, pl.DataFrame({"is_anomaly": [True]}), [], pl.DataFrame()) is None
    assert scanned is False


def test_existing_model_keeps_classification_active(monkeypatch: Any) -> None:
    """A module with a usable model still runs inference after the change."""
    bundle = _real_bundle("conn")
    bundle.set_inference_model(InferenceModel(backend=object(), scaler=object(), label_map={0: "attack"}))
    called = False

    def _run(*_: Any, **__: Any) -> pl.DataFrame:
        nonlocal called
        called = True
        return pl.DataFrame({"ml_type": ["attack"]})

    monkeypatch.setattr(main_module, "_run_ml_prediction", _run)
    bounds = pl.DataFrame({"is_anomaly": [True]})
    result = _gate_ml_prediction(bundle, bounds, [], bounds)

    assert called is True
    assert result is not None


def test_bundle_without_model_api_is_treated_as_model_absent() -> None:
    """A legacy bundle double without model_snapshot is skipped, not crashed."""
    bundle = _bundle("mac_traffic")
    bounds = pl.DataFrame({"is_anomaly": [True]})

    assert _gate_ml_prediction(bundle, bounds, [], bounds) is None


def test_missing_artifact_logs_exactly_one_skip_line(caplog: pytest.LogCaptureFixture) -> None:
    """The boot load announces the skipped gate once per module."""
    handler_id = logger.add(caplog.handler, format="{message}")
    try:
        bundle = _real_bundle("proto_traffic")
        store = SimpleNamespace(load=lambda _name: (_ for _ in ()).throw(FileNotFoundError()))

        main_module._load_persisted_models(cast(Any, store), [bundle])
    finally:
        logger.remove(handler_id)

    skip_lines = [
        record.getMessage() for record in caplog.records if "no persisted ML model found" in record.getMessage()
    ]
    assert len(skip_lines) == 1, skip_lines
    assert "proto_traffic" in skip_lines[0]
    assert "classification gate skipped" in skip_lines[0]
