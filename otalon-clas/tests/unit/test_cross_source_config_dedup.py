"""CLAS-007 regression: cross-source delta tracks rule-based config.

Verifies the §7a D-b cross-source correlation window is sourced from the
same ``rule_based.gap_tolerance_seconds`` config value used by alarm
grouping, instead of a duplicated literal constant.
"""

from __future__ import annotations

from pathlib import Path

import pytest

import otalon_clas.main as main_module
from otalon_clas.common.settings import AppConfig
from otalon_clas.main import _get_rule_based_gap_tolerance

pytestmark = pytest.mark.unit

_CONFIG_PATH = Path(__file__).parent.parent.parent / "config" / "config.json"


@pytest.fixture()
def _minimal_env(monkeypatch: pytest.MonkeyPatch) -> None:
    """Set all environment variables required to load config.json."""
    env_vars = {
        "TRAINING_ENABLED": "false",
        "INFLUX_URL": "http://localhost:8181",
        "INFLUX_TOKEN": "test-token",
        "POSTGRES_DSN": "postgresql://user:pass@localhost:5432/otalon",
        "OTALON_CLAS_LOG_FILE": "/tmp/test.log",
        "MODEL_DIR": "/tmp/models",
        "PCAP_FLAGGING_ENABLED": "false",
        "PCAP_RECORDER_URL": "http://localhost:9090",
        "FREQUENCY_PERSISTENCE_ENABLED": "false",
        "SERIES_BLACKLIST": "[]",
        "PREDICTION_CLASSIFICATION_ENABLED": "false",
        "TRAINING_CLASSIFICATION_ENABLED": "false",
        "TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE": "",
        "TRAINING_BOUNDARY_TRAIN_WINDOW_START": "",
        "TRAINING_BOUNDARY_TRAIN_WINDOW_STOP": "",
        "GROUP_CLASSIFIER_MODEL_PATH": "",
        "TRAINING_GROUP_CLASSIFIER_ENABLED": "false",
        "GROUP_CLASSIFIER_TRAIN_WINDOW_START": "",
        "GROUP_CLASSIFIER_TRAIN_WINDOW_STOP": "",
        "GROUP_CLASSIFIER_GROUND_TRUTH_FILE": "",
    }
    for key, value in env_vars.items():
        monkeypatch.setenv(key, value)


@pytest.mark.usefixtures("_minimal_env")
def test_cross_source_gap_equals_rule_based_config_value() -> None:
    """Delta matches the rule_based stage's gap_tolerance_seconds."""
    config = AppConfig.from_json(_CONFIG_PATH)
    rule_based_stage = next(s for s in config.pipeline_post_processing.stages if s.type == "rule_based")
    rule_based_gap = getattr(rule_based_stage, "config")["gap_tolerance_seconds"]

    assert _get_rule_based_gap_tolerance(config) == rule_based_gap
    assert rule_based_gap == 10


@pytest.mark.usefixtures("_minimal_env")
def test_cross_source_gap_tracks_rule_based_config_change() -> None:
    """Changing only the rule_based config changes the delta."""
    config = AppConfig.from_json(_CONFIG_PATH)
    rule_based_stage = next(s for s in config.pipeline_post_processing.stages if s.type == "rule_based")
    getattr(rule_based_stage, "config")["gap_tolerance_seconds"] = 42

    assert _get_rule_based_gap_tolerance(config) == 42


def test_cross_source_constant_removed() -> None:
    """The duplicated literal constant is gone (CLAS-007)."""
    assert not hasattr(main_module, "CROSS_SOURCE_GAP_TOLERANCE_SECONDS")
