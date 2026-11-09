"""Tests for configuration loading, validation, and env-var substitution."""

from pathlib import Path

import pytest

from otalon_clas.common.config_validator import validate_config
from otalon_clas.common.settings import (
    AppConfig,
    LoggingConfig,
    OfflinePredictionConfig,
    PreprocessorConfig,
    StageConfig,
)


@pytest.fixture()
def minimal_env(monkeypatch):
    """Set the minimum required environment variables for config loading."""
    env_vars = {
        "INFLUX_URL": "http://localhost:8181",
        "INFLUX_TOKEN": "test-token",
        "POSTGRES_DSN": "postgresql://user:pass@localhost:5432/otalon",
        "TRAINING_ENABLED": "false",
        "MODULE_CONN_ENABLED": "true",
        "MODULE_MAC_TRAFFIC_ENABLED": "false",
        "MODULE_PROTO_TRAFFIC_ENABLED": "false",
        "PCAP_FLAGGING_ENABLED": "false",
        "PCAP_RECORDER_URL": "http://localhost:9090",
        "LOG_FILE": "/tmp/test.log",
        "MODELS_DIR": "/tmp/models",
        "CONN_BLACKLIST": "",
        "TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE": "",
        "TRAINING_START": "2026-01-01 00:00:00",
        "TRAINING_STOP": "2026-01-02 00:00:00",
    }
    for key, val in env_vars.items():
        monkeypatch.setenv(key, val)
    return env_vars


@pytest.fixture()
def config_path(tmp_path):
    """Return the path to the project config.json."""
    return Path(__file__).parent.parent / "config" / "config.json"


class TestConfigLoading:
    """Tests for loading config from JSON with env-var substitution."""

    def test_load_full_config(self, minimal_env, config_path):
        """Full config.json loads successfully with required env vars."""
        config = AppConfig.from_json(config_path)
        assert config.influx.url == "http://localhost:8181"
        assert config.influx.token == "test-token"
        assert config.postgres.dsn == "postgresql://user:pass@localhost:5432/otalon"
        # ``AppConfig.training_enabled`` was removed with static boot
        # training; the per-module flag now lives on ClassificationConfig
        # (SUITE-034).
        conn = next(m for m in config.modules if m.name == "conn")
        assert conn.classification.training_enabled is False

    def test_env_var_resolution(self, minimal_env, config_path):
        """Environment variables are correctly resolved in config values."""
        config = AppConfig.from_json(config_path)
        assert config.influx.url == "http://localhost:8181"
        assert config.pcap_flagging.pcap_recorder_url == "http://localhost:9090"

    def test_boolean_coercion(self, minimal_env, config_path, monkeypatch):
        """String 'true'/'false' from env vars are coerced to boolean.

        Previously asserted ``config.training_enabled``, which no longer
        exists: static boot training was removed (``TRAINING_ENABLED`` is
        now only recognised by ``_legacy_training_requested`` so the
        service can refuse it), and the per-module flag moved to
        ``ClassificationConfig.training_enabled``. Coercion is now
        asserted on a boolean the config actually carries (SUITE-034).
        """
        monkeypatch.setenv("PCAP_FLAGGING_ENABLED", "true")
        config = AppConfig.from_json(config_path)

        assert isinstance(config.pcap_flagging.enabled, bool)
        assert config.pcap_flagging.enabled is True

    def test_enabled_modules_filter(self, minimal_env, config_path):
        """get_enabled_modules returns only modules with enabled=True.

        The count is derived from the config rather than hard-coded: the
        shipped config enables all three modules today, and the assertion
        of exactly one dated from when env vars gated them (SUITE-034).
        The filter property is what matters and is asserted directly.
        """
        config = AppConfig.from_json(config_path)
        enabled = config.get_enabled_modules()
        expected = [m.name for m in config.modules if m.enabled]

        assert [m.name for m in enabled] == expected
        assert all(m.enabled for m in enabled)
        assert "conn" in {m.name for m in enabled}

    def test_module_features(self, minimal_env, config_path):
        """Module features list is loaded correctly."""
        config = AppConfig.from_json(config_path)
        conn = next(m for m in config.modules if m.name == "conn")
        assert len(conn.features) == 10
        assert conn.features[0] == "packet_count"

    def test_mac_traffic_no_dead_encode_tags(self, config_path: Path) -> None:
        """mac_traffic module no longer encodes dominant_protocol.

        Regression guard for CLAS-021: the dominant_protocol tag exists in
        InfluxDB but is not fetched by the InfluxModule query (only tag_key
        and features are selected).  The old encode_tags config caused a
        warning every ~10s at runtime.  The encoded column is not used by
        any downstream stage (bounds, ML, frequency), so the config entry
        was dead and has been removed.

        Reads the raw JSON rather than AppConfig.from_json to avoid a
        pre-existing missing-env-var issue in the minimal_env fixture.
        """
        import json

        raw = json.loads(config_path.read_text())
        mac = next(m for m in raw["modules"] if m["name"] == "mac_traffic")
        params = mac.get("preprocessor", {}).get("params", {})
        encode_tags = params.get("encode_tags", {})
        assert encode_tags == {}, f"Expected empty encode_tags for mac_traffic, got {encode_tags}"
        assert "dominant_protocol" not in encode_tags

    def test_training_defaults(self, minimal_env, config_path):
        """Training boundary defaults are loaded from config."""
        config = AppConfig.from_json(config_path)
        boundary = config.training.boundary
        assert boundary.quantile == 0.0001
        assert boundary.bounds_variation == 0.2
        assert boundary.upper_bound_min == 2.0

    def test_per_feature_overrides(self, minimal_env, config_path):
        """Per-feature overrides are parsed into PerFeatureOverride models."""
        config = AppConfig.from_json(config_path)
        overrides = config.training.boundary.per_feature_overrides
        assert "mean_interarrival_time" in overrides
        assert overrides["mean_interarrival_time"].bounds_variation == 1.0
        assert overrides["mean_interarrival_time"].upper_bound_min == 5.0

    def test_scoring_weights(self, minimal_env, config_path):
        """Scoring weights are loaded from config."""
        config = AppConfig.from_json(config_path)
        weights = config.prediction.anomaly_grouping.scoring.weights
        assert weights.rate == 0.60
        assert weights.coverage == 0.20
        assert weights.persist == 0.20
        assert weights.severity == 0.0


class TestConfigValidation:
    """Tests for Pydantic validation errors and registry key checks."""

    def test_invalid_log_level_rejected(self):
        """Invalid log level raises validation error."""
        with pytest.raises(ValueError, match="Invalid log level"):
            LoggingConfig(level="VERBOSE")

    def test_offline_enabled_without_window_rejected(self):
        """Offline mode enabled without start/stop raises validation error."""
        with pytest.raises(ValueError, match="start and stop are required"):
            OfflinePredictionConfig(enabled=True, start="", stop="")

    def test_offline_enabled_with_window_accepted(self):
        """Offline mode enabled with start/stop succeeds."""
        cfg = OfflinePredictionConfig(
            enabled=True,
            start="2026-01-01 00:00:00",
            stop="2026-01-02 00:00:00",
        )
        assert cfg.enabled is True

    def test_unknown_preprocessor_type_detected(self, minimal_env, config_path):
        """Unknown preprocessor type is detected by config validator."""
        config = AppConfig.from_json(config_path)
        config.modules[0].preprocessor = PreprocessorConfig(type="nonexistent")
        errors = validate_config(config)
        assert any("unknown preprocessor type" in e for e in errors)

    def test_unknown_ml_algorithm_detected(self, minimal_env, config_path):
        """Unknown ML algorithm is detected by config validator."""
        config = AppConfig.from_json(config_path)
        config.modules[0].classification.algorithm = "neural_network"
        errors = validate_config(config)
        assert any("unknown ML algorithm" in e for e in errors)

    def test_unknown_stage_type_detected(self, minimal_env, config_path):
        """Unknown stage type is detected by config validator."""
        config = AppConfig.from_json(config_path)
        config.pipeline_post_processing.stages.append(StageConfig(type="unknown_stage"))
        errors = validate_config(config)
        assert any("unknown stage type" in e for e in errors)

    def test_valid_config_has_no_errors(self, minimal_env, config_path):
        """A valid config produces no validation errors."""
        config = AppConfig.from_json(config_path)
        errors = validate_config(config)
        assert errors == []

    def test_pydantic_rejects_invalid_quantile_type(self):
        """Pydantic rejects non-numeric quantile."""
        with pytest.raises(Exception):
            AppConfig.model_validate(
                {
                    "influx": {"url": "http://x", "token": "t"},
                    "postgres": {"dsn": "postgresql://x"},
                    "models": {"dir": "/tmp"},
                    "training": {"boundary": {"quantile": "not_a_number"}},
                }
            )

    def test_missing_required_field_rejected(self):
        """Missing required field raises validation error."""
        with pytest.raises(Exception):
            AppConfig.model_validate({"influx": {"url": "http://x"}})
