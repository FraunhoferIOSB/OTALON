"""Shared fixtures for otalon-common golden and smoke tests."""

import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import polars as pl
import pytest


@pytest.fixture(scope="session")
def golden_data_dir() -> Path:
    """Return the path to the golden_data directory."""
    return Path(__file__).parent / "golden_data"


@pytest.fixture
def load_golden_parquet(golden_data_dir: Path) -> Callable[[str], pl.DataFrame]:
    """Return a callable that loads a Parquet file from golden_data by filename."""

    def _loader(filename: str) -> pl.DataFrame:
        return pl.read_parquet(golden_data_dir / filename)

    return _loader


@pytest.fixture
def load_golden_jsonl(golden_data_dir: Path) -> Callable[[str], list[dict]]:
    """Return a callable that loads a JSONL file from golden_data by filename."""

    def _loader(filename: str) -> list[dict]:
        records = []
        with open(golden_data_dir / filename) as f:
            for line in f:
                records.append(json.loads(line))
        return records

    return _loader


@pytest.fixture
def load_golden_json(golden_data_dir: Path) -> Callable[[str], Any]:
    """Return a callable that loads a JSON file from golden_data by filename."""

    def _loader(filename: str) -> Any:
        with open(golden_data_dir / filename) as f:
            return json.load(f)

    return _loader


@pytest.fixture
def baseline_df(load_golden_parquet: Callable[[str], pl.DataFrame]) -> pl.DataFrame:
    """Load the 10-minute baseline DataFrame."""
    return load_golden_parquet("conn_baseline_10min.parquet")


@pytest.fixture
def attack_df(load_golden_parquet: Callable[[str], pl.DataFrame]) -> pl.DataFrame:
    """Load the 5-minute attack DataFrame."""
    return load_golden_parquet("conn_attack_5min.parquet")


@pytest.fixture
def golden_rules(load_golden_jsonl: Callable[[str], list[dict]]) -> list[dict]:
    """Load production port-collapse rules as a list of dicts."""
    return load_golden_jsonl("port_collapse_rules_expected.jsonl")


@pytest.fixture
def golden_bounds(load_golden_jsonl: Callable[[str], list[dict]]) -> list[dict]:
    """Load production bounds as a list of dicts."""
    return load_golden_jsonl("bounds_expected.jsonl")


@pytest.fixture
def golden_anomalies(load_golden_jsonl: Callable[[str], list[dict]]) -> list[dict]:
    """Load sample anomalies as a list of dicts."""
    return load_golden_jsonl("anomalies_sample.jsonl")


@pytest.fixture
def uci_samples(load_golden_json: Callable[[str], Any]) -> list[str]:
    """Load 50 sample UCI strings."""
    return load_golden_json("uci_samples.json")
