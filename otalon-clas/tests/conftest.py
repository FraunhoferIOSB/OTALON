"""Shared fixtures for otalon-clas golden and smoke tests.

Provides golden data loaders, directory paths, and convenience fixtures
for loading Parquet, JSONL, and JSON files from the golden_data directory.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, Callable, cast

import polars as pl
import pytest

GOLDEN_DATA_DIR = Path(__file__).parent / "golden_data"

# Environment variables that ``config/config.json`` references through
# ``$VAR`` placeholders. They are supplied by ``.env`` / ``.env.compose`` at
# runtime with container paths (``/app/logs/...``), which do not exist on a
# developer machine, so loading the real config in a test raised
# ``RuntimeError: Environment variable 'OTALON_CLAS_LOG_FILE' is not set``
# and 12 config tests were permanently red (SUITE-034). Providing a
# test-local value fixes the tests without weakening what they assert.
_CONFIG_ENV_DEFAULTS: dict[str, str] = {
    "OTALON_CLAS_LOG_FILE": "otalon-clas-test.log",
    "MODEL_DIR": "models",
    "TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE": "mitre_techniques_log.json",
    "INFLUX_URL": "http://localhost:8181",
    "INFLUX_TOKEN": "test-token",
    "POSTGRES_DSN": "postgresql://postgres:test@localhost:5432/test",
    "PCAP_RECORDER_URL": "http://localhost:9090",
    "SERIES_BLACKLIST": "[]",
    "FREQUENCY_PERSISTENCE_ENABLED": "true",
    "PCAP_FLAGGING_ENABLED": "false",
    "PREDICTION_CLASSIFICATION_ENABLED": "true",
}
"""Every ``$VAR`` placeholder in ``config/config.json``.

Values are test-local stand-ins, not the production ones: the point is
that loading and validating the config must not depend on a container
environment. Path-shaped entries are rewritten under a tmp dir by the
fixture below.
"""

_PATH_SHAPED: frozenset[str] = frozenset(
    {"OTALON_CLAS_LOG_FILE", "MODEL_DIR", "TRAINING_CLASSIFICATION_MITRE_TECHNIQUE_FILE"}
)


@pytest.fixture(autouse=True)
def _config_env_defaults(
    request: pytest.FixtureRequest,
    monkeypatch: pytest.MonkeyPatch,
    tmp_path_factory: pytest.TempPathFactory,
) -> None:
    """Supply config-referenced env vars that only exist inside containers.

    Only sets a variable that is not already present, so a real
    environment (CI with a full ``.env``) always wins.

    Tests that manage the config environment themselves — identified by
    requesting the ``minimal_env`` fixture — are left completely alone,
    so this cannot mask what they assert about env-var handling.
    """

    base = tmp_path_factory.mktemp("clas-config-env")
    for name, value in _CONFIG_ENV_DEFAULTS.items():
        if os.environ.get(name):
            continue
        monkeypatch.setenv(name, str(base / value) if name in _PATH_SHAPED else value)


@pytest.fixture(scope="session")
def golden_data_dir() -> Path:
    """Return the path to the golden data directory."""
    assert GOLDEN_DATA_DIR.is_dir(), f"Golden data directory not found: {GOLDEN_DATA_DIR}"
    return GOLDEN_DATA_DIR


@pytest.fixture
def load_golden_parquet(golden_data_dir: Path) -> Callable[[str], pl.DataFrame]:
    """Return a callable that loads a Parquet file from golden_data/ as a Polars DataFrame."""

    def _loader(filename: str) -> pl.DataFrame:
        path = golden_data_dir / filename
        assert path.exists(), f"Golden Parquet not found: {path}"
        return pl.read_parquet(path)

    return _loader


@pytest.fixture
def load_golden_jsonl(golden_data_dir: Path) -> Callable[[str], list[dict[str, Any]]]:
    """Return a callable that loads a JSONL file from golden_data/ as a list of dicts."""

    def _loader(filename: str) -> list[dict[str, Any]]:
        path = golden_data_dir / filename
        assert path.exists(), f"Golden JSONL not found: {path}"
        records: list[dict[str, Any]] = []
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line:
                    loaded: dict[str, Any] = json.loads(line)
                    records.append(loaded)
        return records

    return _loader


@pytest.fixture
def load_golden_json(golden_data_dir: Path) -> Callable[[str], Any]:
    """Return a callable that loads a JSON file from golden_data/."""

    def _loader(filename: str) -> Any:
        path = golden_data_dir / filename
        assert path.exists(), f"Golden JSON not found: {path}"
        with open(path) as f:
            return json.load(f)

    return _loader


@pytest.fixture
def golden_bounds(load_golden_jsonl: Callable[[str], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Load golden bounds from bounds_expected.jsonl."""
    return load_golden_jsonl("bounds_expected.jsonl")


@pytest.fixture
def golden_port_collapse_rules(load_golden_jsonl: Callable[[str], list[dict[str, Any]]]) -> pl.DataFrame:
    """Load golden port-collapse rules as a Polars DataFrame."""
    records = load_golden_jsonl("port_collapse_rules_expected.jsonl")
    return pl.DataFrame(records)


@pytest.fixture
def golden_anomalies(load_golden_jsonl: Callable[[str], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Load golden anomalies from anomalies_window.jsonl."""
    return load_golden_jsonl("anomalies_window.jsonl")


@pytest.fixture
def golden_alarms(load_golden_jsonl: Callable[[str], list[dict[str, Any]]]) -> list[dict[str, Any]]:
    """Load golden alarms from alarms_window.jsonl."""
    return load_golden_jsonl("alarms_window.jsonl")


@pytest.fixture
def golden_ground_truth(load_golden_json: Callable[[str], Any]) -> list[dict[str, Any]]:
    """Load golden ground truth from ground_truth_window.json."""
    records = cast("list[dict[str, Any]]", load_golden_json("ground_truth_window.json"))
    return records


@pytest.fixture
def golden_model_path(golden_data_dir: Path) -> Path:
    """Return the path to the golden ML model file."""
    path = golden_data_dir / "netcap_classifier.pkl"
    assert path.exists(), f"Golden model not found: {path}"
    return path
