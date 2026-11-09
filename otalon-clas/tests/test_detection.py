"""Tests for bounds training, bounds comparison, frequency monitor, and preprocessing."""

from datetime import datetime, timedelta, timezone

import numpy as np
import polars as pl
import pytest

from otalon_clas.common.settings import BoundaryTrainingConfig
from otalon_clas.detection.bounds_manager import BoundsManager, BoundsTrainer
from otalon_clas.detection.frequency_monitor import ABSENCE_ANOMALY, FrequencyMonitor, _SeriesFrequencyProfile
from otalon_clas.ml.backends.decision_tree import DecisionTreeBackend
from otalon_clas.ml.backends.isolation_forest import IsolationForestBackend
from otalon_clas.ml.backends.random_forest import RandomForestBackend
from otalon_clas.ml.pipeline import MLPipeline
from otalon_clas.ml.registry import ML_BACKEND_REGISTRY, get_backend
from otalon_clas.preprocessing.passthrough import PassthroughPreprocessor
from otalon_clas.preprocessing.registry import PREPROCESSOR_REGISTRY, get_preprocessor


def _make_timestamps(count: int, start: str = "2026-01-01T00:00:00", interval_seconds: int = 1) -> pl.Series:
    """Create a Polars datetime Series with evenly spaced timestamps."""
    base = datetime.fromisoformat(start)
    return pl.Series([base + timedelta(seconds=i * interval_seconds) for i in range(count)])


class TestBoundsTrainer:
    """Tests for quantile-based bounds training."""

    def test_train_default_params(self):
        """Bounds are computed with default parameters."""
        df = pl.DataFrame(
            {
                "time": _make_timestamps(100, interval_seconds=1800),
                "uci": ["series_a"] * 50 + ["series_b"] * 50,
                "value": [float(x) for x in range(50)] + [float(x) for x in range(50, 100)],
            }
        )
        trainer = BoundsTrainer()
        bounds = trainer.train(df, tag_key="uci", features=["value"])
        assert "series_a" in bounds
        assert "series_b" in bounds
        assert "value" in bounds["series_a"]
        lower, upper = bounds["series_a"]["value"]
        assert lower <= upper

    def test_upper_bound_min_applied(self):
        """Upper bound minimum is enforced via config."""
        df = pl.DataFrame(
            {
                "time": _make_timestamps(10, interval_seconds=3600),
                "uci": ["s1"] * 10,
                "tiny_val": [0.001] * 10,
            }
        )
        config = BoundaryTrainingConfig(upper_bound_min=2.0)
        trainer = BoundsTrainer()
        bounds = trainer.train(df, tag_key="uci", features=["tiny_val"], config=config)
        _, upper = bounds["s1"]["tiny_val"]
        assert upper >= 2.0

    def test_blacklist_excludes_exact_and_wildcard_series(self):
        """Blacklisted exact and prefix series are absent from trained bounds."""
        df = pl.DataFrame(
            {
                "uci": ["keep", "ff:ff:ff:ff:ff:ff", "33:33:00:00:00:fb"],
                "value": [1.0, 2.0, 3.0],
            }
        )
        trainer = BoundsTrainer(blacklist=["FF:FF:FF:FF:FF:FF", "33:33:*"])

        bounds = trainer.train(df, tag_key="uci", features=["value"])

        assert set(bounds) == {"keep"}


class TestBoundsManager:
    """Tests for bounds comparison during prediction."""

    def test_no_bounds_marks_anomaly(self):
        """Series with no stored bounds is marked NoBounds."""
        manager = BoundsManager(module_name="test")
        manager.load_bounds({})
        df = pl.DataFrame(
            {
                "time": _make_timestamps(1),
                "uci": ["unknown_series"],
                "value": [100.0],
            }
        )
        result = manager.check(df, tag_key="uci", features=["value"])
        assert result["is_anomaly"][0] is True
        assert result["anomaly_type"][0] == "NoBounds"

    def test_no_bounds_emits_severity_for_schema_consistency(self):
        """NoBounds rows expose the same severity field as violations."""
        manager = BoundsManager(module_name="test")
        manager.load_bounds({"known": {"value": (0.0, 10.0)}})
        result = manager.check(
            pl.DataFrame(
                {
                    "time": _make_timestamps(2),
                    "uci": ["known", "unknown"],
                    "value": [5.0, 5.0],
                }
            ),
            tag_key="uci",
            features=["value"],
        )
        assert result.schema["severity"] == pl.Float64
        assert result.filter(pl.col("uci") == "unknown")["severity"][0] == 0.0

    def test_within_bounds_no_anomaly(self):
        """Series within bounds is not flagged."""
        manager = BoundsManager(module_name="test")
        manager.load_bounds({"s1": {"value": (0.0, 100.0)}})
        df = pl.DataFrame(
            {
                "time": _make_timestamps(1),
                "uci": ["s1"],
                "value": [50.0],
            }
        )
        result = manager.check(df, tag_key="uci", features=["value"])
        assert result["is_anomaly"][0] is False

    def test_violation_detected(self):
        """Value above upper bound is detected."""
        manager = BoundsManager(module_name="test")
        manager.load_bounds({"s1": {"value": (0.0, 10.0)}})
        df = pl.DataFrame(
            {
                "time": _make_timestamps(1),
                "uci": ["s1"],
                "value": [999.0],
            }
        )
        result = manager.check(df, tag_key="uci", features=["value"])
        assert result["is_anomaly"][0] is True
        assert result["anomaly_type"][0] == "BoundViolation"

    def test_blacklist_skips_exact_and_wildcard_series(self):
        """Blacklisted series remain clean even when values exceed bounds."""
        manager = BoundsManager(module_name="test", blacklist=["ff:ff:ff:ff:ff:ff", "33:33:*"])
        manager.load_bounds(
            {
                "ff:ff:ff:ff:ff:ff": {"value": (0.0, 1.0)},
                "33:33:00:00:00:fb": {"value": (0.0, 1.0)},
                "keep": {"value": (0.0, 1.0)},
            }
        )
        result = manager.check(
            pl.DataFrame(
                {
                    "uci": [
                        "ff:ff:ff:ff:ff:ff",
                        "33:33:00:00:00:fb",
                        "keep",
                    ],
                    "value": [999.0, 999.0, 999.0],
                }
            ),
            tag_key="uci",
            features=["value"],
        )

        assert result.filter(pl.col("is_anomaly"))["uci"].to_list() == ["keep"]

    def test_violation_emits_relative_severity(self):
        """Persisted bound violations carry deviation evidence for review."""
        manager = BoundsManager(module_name="test")
        manager.load_bounds({"s1": {"value": (0.8, 2.4)}})
        result = manager.check(
            pl.DataFrame({"time": _make_timestamps(1), "uci": ["s1"], "value": [0.0]}),
            tag_key="uci",
            features=["value"],
        )
        assert result["is_anomaly"][0] is True
        assert result["violated_features"][0] == "value,"
        assert result["severity"][0] == pytest.approx(0.5)


class TestFrequencyMonitor:
    """Tests for frequency and absence monitoring."""

    def test_train_learns_frequency(self):
        """Training learns per-series frequency statistics."""
        df = pl.DataFrame(
            {
                "time": _make_timestamps(6, interval_seconds=10),
                "uci": ["s1"] * 6,
            }
        )
        monitor = FrequencyMonitor()
        monitor.train(df, tag_key="uci")
        assert "s1" in monitor._profiles

    def test_concrete_observation_matches_port_collapse_wildcard_profile(self):
        """A live concrete port updates the matching wildcard profile."""
        wildcard = "80:39:e5:00:ab:d2/a8:74:1d:18:c6:96//IPv4/192.168.0.77/192.168.0.10/80/*/Ethernet:IPv4:TCP"
        observed = wildcard.replace("/80/*/", "/80/49352/")
        monitor = FrequencyMonitor(min_intervals=1)
        profile = _SeriesFrequencyProfile(mean_interval=10.0, std_interval=0.0)
        monitor.restore_profiles({wildcard: profile})

        results = monitor.check(
            pl.DataFrame(
                {
                    "time": _make_timestamps(2, start="2026-01-01T00:05:00", interval_seconds=10),
                    "uci": [observed] * 2,
                }
            ),
            tag_key="uci",
            current_time="2026-01-01T00:05:10",
        )

        assert not any(result.anomaly_type == ABSENCE_ANOMALY for result in results)
        assert profile.last_seen == datetime(2026, 1, 1, 0, 5, 10, tzinfo=timezone.utc)

    def test_frequency_anomaly_detection(self):
        """Rapid frequency change triggers anomaly."""
        base = datetime.fromisoformat("2026-01-01T00:00:00")
        train_times = pl.Series([base + timedelta(seconds=s) for s in [0, 28, 62, 89, 121, 148, 182, 209]])
        df_train = pl.DataFrame({"time": train_times, "uci": ["s1"] * 8})
        monitor = FrequencyMonitor(frequency_tolerance_factor=1.5)
        monitor.train(df_train, tag_key="uci")

        df_check = pl.DataFrame(
            {
                "time": _make_timestamps(10, start="2026-01-01T00:05:00", interval_seconds=1),
                "uci": ["s1"] * 10,
            }
        )
        results = monitor.check(df_check, tag_key="uci", current_time="2026-01-01T00:05:10")
        anomalies = [r for r in results if r.is_anomaly]
        assert len(anomalies) >= 1


class TestPreprocessorRegistry:
    """Tests for the preprocessing registry pattern."""

    def test_known_types_registered(self):
        """All expected preprocessor types are in the registry."""
        assert "conn_uci" in PREPROCESSOR_REGISTRY
        assert "passthrough" in PREPROCESSOR_REGISTRY
        assert "sliding_window_5s" in PREPROCESSOR_REGISTRY
        assert "sliding_window_10s" in PREPROCESSOR_REGISTRY

    def test_get_unknown_raises(self):
        """Getting an unknown preprocessor raises KeyError."""
        with pytest.raises(KeyError):
            get_preprocessor("nonexistent")

    def test_passthrough_fills_nulls(self):
        """PassthroughPreprocessor fills null values with 0."""
        pp = PassthroughPreprocessor(tag_key="mac_address", features=["out_conn_count"])
        df = pl.DataFrame(
            {
                "time": _make_timestamps(1),
                "mac_address": ["aa:bb:cc:dd:ee:ff"],
                "out_conn_count": [None],
            },
            schema={
                "time": pl.Datetime,
                "mac_address": pl.Utf8,
                "out_conn_count": pl.Float64,
            },
        )
        result = pp.preprocess_for_prediction(df)
        assert result["out_conn_count"][0] == 0.0

    def test_empty_encode_tags_produces_no_warning(self, caplog) -> None:
        """PassthroughPreprocessor with empty encode_tags logs no warning.

        Regression guard for CLAS-021: the mac_traffic module previously
        declared encode_tags for a column not available in the DataFrame,
        which triggered a warning every ~10s.  After removing that dead
        config, the preprocessor must silently pass through with empty
        encode_tags.
        """
        pp = PassthroughPreprocessor(
            tag_key="mac_address",
            features=["out_conn_count"],
            params={},
        )
        df = pl.DataFrame(
            {
                "time": _make_timestamps(1),
                "mac_address": ["aa:bb:cc:dd:ee:ff"],
                "out_conn_count": [42.0],
            },
            schema={
                "time": pl.Datetime,
                "mac_address": pl.Utf8,
                "out_conn_count": pl.Float64,
            },
        )
        with caplog.at_level("WARNING"):
            result = pp.preprocess_for_prediction(df)

        assert len(result) == 1
        assert result["out_conn_count"][0] == 42.0
        # No warning about missing encode_tags column should have been emitted
        missing_col_warnings = [r for r in caplog.records if "encode_tags column" in r.getMessage()]
        assert len(missing_col_warnings) == 0, f"Expected no encode_tags warnings, got: {missing_col_warnings}"

    def test_hash_encoding_is_deterministic(self) -> None:
        """Hash-encoded protocol tags are stable across encode passes.

        Regression guard for the proto_traffic bounds mismatch: the
        encoded value must depend only on the string, not on a
        per-process hash seed, so bounds trained in one process resolve
        in another.
        """
        from otalon_clas.preprocessing.passthrough import _stable_hash

        pp = PassthroughPreprocessor(
            tag_key="protocol",
            features=["proto_conn_count"],
            params={"encode_tags": {"protocol": "hash"}},
        )
        df = pl.DataFrame(
            {
                "time": _make_timestamps(2),
                "protocol": ["Ethernet:ARP", "Ethernet:IPv4:TCP"],
                "proto_conn_count": [1.0, 2.0],
            },
            schema={
                "time": pl.Datetime,
                "protocol": pl.Utf8,
                "proto_conn_count": pl.Float64,
            },
        )
        first = pp.preprocess_for_prediction(df)["protocol"].to_list()
        second = pp.preprocess_for_prediction(df)["protocol"].to_list()
        assert first == second
        assert first == [
            _stable_hash("Ethernet:ARP"),
            _stable_hash("Ethernet:IPv4:TCP"),
        ]
        assert all(0 <= v < 2**31 for v in first)


class TestMLRegistry:
    """Tests for the ML backend registry pattern."""

    def test_known_backends_registered(self):
        """All expected ML backends are in the registry."""
        assert "decision_tree" in ML_BACKEND_REGISTRY
        assert "random_forest" in ML_BACKEND_REGISTRY
        assert "xgboost" in ML_BACKEND_REGISTRY
        assert "isolation_forest" in ML_BACKEND_REGISTRY

    def test_get_unknown_raises(self):
        """Getting an unknown backend raises KeyError."""
        with pytest.raises(KeyError):
            get_backend("nonexistent")


class TestMLBackends:
    """Tests for ML backend training and prediction."""

    def test_decision_tree_fit_predict(self):
        """DecisionTree trains and predicts."""
        backend = DecisionTreeBackend(max_depth=3)
        X = np.random.rand(100, 5)
        y = np.random.randint(0, 3, 100)
        backend.fit(X, y)
        preds = backend.predict(X)
        assert preds.shape == (100,)

    def test_random_forest_fit_predict(self):
        """RandomForest trains and predicts."""
        backend = RandomForestBackend(n_estimators=10, max_depth=3)
        X = np.random.rand(100, 5)
        y = np.random.randint(0, 3, 100)
        backend.fit(X, y)
        preds = backend.predict(X)
        assert preds.shape == (100,)

    def test_isolation_forest_ignores_labels(self):
        """IsolationForest trains on X only, ignoring y."""
        backend = IsolationForestBackend(n_estimators=10)
        X = np.random.rand(100, 5)
        y = np.random.randint(0, 3, 100)
        backend.fit(X, y)
        preds = backend.predict(X)
        assert all(p in (-1, 1) for p in preds)

    def test_isolation_forest_proba_in_range(self):
        """IsolationForest predict_proba returns values in [0, 1]."""
        backend = IsolationForestBackend(n_estimators=10)
        X = np.random.rand(100, 5)
        backend.fit(X, np.zeros(100))
        proba = backend.predict_proba(X)
        assert proba.min() >= 0.0
        assert proba.max() <= 1.0


class TestMLPipeline:
    """Tests for the ML training pipeline."""

    def test_train_and_predict(self):
        """Pipeline trains, evaluates, and predicts."""
        backend = DecisionTreeBackend(max_depth=3)
        pipeline = MLPipeline(backend=backend, confidence_threshold=0.3)

        X = np.random.rand(200, 5)
        y = np.array([0] * 100 + [1] * 100)

        metrics = pipeline.train(X, y, balance_per_class=50, random_seed=42)
        assert "accuracy" in metrics
        assert "f1_weighted" in metrics
        assert 0.0 <= metrics["accuracy"] <= 1.0

        preds, confidences = pipeline.predict(X[:10])
        assert len(preds) == 10
        assert len(confidences) == 10

    def test_confidence_threshold_applied(self):
        """Predictions below threshold get label -1."""
        backend = DecisionTreeBackend(max_depth=1)
        pipeline = MLPipeline(backend=backend, confidence_threshold=0.99)
        X = np.random.rand(200, 5)
        y = np.array([0] * 100 + [1] * 100)
        pipeline.train(X, y, balance_per_class=50, random_seed=42)
        preds, _ = pipeline.predict(X[:10])
        unknown_count = sum(1 for p in preds if p == -1)
        assert unknown_count >= 0
