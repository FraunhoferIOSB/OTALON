"""Shared pytest fixtures for the OTALON API test suite."""

# mypy: disable-error-code="no-untyped-def,no-any-return,call-arg"

from __future__ import annotations

import hashlib
import json
import os
import uuid
from collections.abc import Iterator
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import polars as pl
import pytest
from fastapi.testclient import TestClient


def _postgres_available() -> bool:
    """Return whether the database these tests target can be opened.

    Probed once per session, and deliberately a real connect rather than a
    port check: PostgreSQL may well be listening while the database the
    tests address does not exist (the suite defaults to ``otalon-clas``,
    which is absent on a developer box that hosts ``cyberclas``). A port
    probe would report "available" and the tests would still error.

    Tests needing a real database are skipped rather than left permanently
    red: an always-red suite hides regressions, and these assert real SQL
    behaviour a mock would not exercise honestly (SUITE-034).
    """
    import os

    try:
        import psycopg2
    except ImportError:  # pragma: no cover - psycopg2 is a hard dependency
        return False

    try:
        conn = psycopg2.connect(
            host=os.environ.get("POSTGRES_HOST", "localhost"),
            port=int(os.environ.get("POSTGRES_PORT", "5432")),
            dbname=os.environ.get("POSTGRES_DATABASE", "otalon-clas"),
            user=os.environ.get("POSTGRES_USER", "postgres"),
            password=os.environ.get("POSTGRES_PASSWORD", ""),
            connect_timeout=2,
        )
    except Exception:
        return False
    conn.close()
    return True


POSTGRES_AVAILABLE: bool = os.environ.get("OTALON_TEST_DB_PROBE", "0") == "1" and _postgres_available()

requires_postgres = pytest.mark.skipif(
    not POSTGRES_AVAILABLE,
    reason=(
        "needs a reachable PostgreSQL holding the target database "
        "(POSTGRES_HOST/PORT/DATABASE, default localhost:5432/otalon-clas). "
        "Start it with `docker compose --profile core-db up -d`. "
        "Tracked in SUITE-034."
    ),
)
"""Skip marker for tests that require a live database."""


# API-020 — test isolation. ``src/otalon_api/settings.py`` loads the repo-root ``.env`` as a
# pydantic ``env_file``. On a developer or deployment host that file defines
# ADMIN_API_KEY / OTALON_API_ALLOWED_KEYS, which arms the fail-closed auth
# registry in ``src/otalon_api/middleware/auth.py`` and makes tests that expect an
# unauthenticated 200 receive 401 instead. The same commit therefore passed on a
# clean checkout and failed on a configured host. Neutralise the auth-relevant
# variables before importing ``otalon_api.main`` so the suite depends only on what each
# test configures explicitly. Tests that need auth armed set it themselves.
for _auth_env_key in ("ADMIN_API_KEY", "OTALON_API_ALLOWED_KEYS"):
    os.environ[_auth_env_key] = ""

from otalon_api.main import app  # noqa: E402
from otalon_api.services.aggregation_service import NetcapAggregationService  # noqa: E402
from otalon_api.services.anomaly_details_service import AnomalyDetailsService  # noqa: E402
from otalon_api.services.anomaly_service import AnomalyService  # noqa: E402
from otalon_api.services.bounds_service import BoundsService  # noqa: E402
from otalon_api.services.dashboard_kpi_service import DashboardKpiService  # noqa: E402
from otalon_api.services.timeseries_service import TimeseriesService  # noqa: E402
from otalon_api.settings import Settings  # noqa: E402

GOLDEN_DATA_DIR = Path(__file__).parent / "golden_data"
PRODUCTION_GOLDEN_DIR = GOLDEN_DATA_DIR / "production"


@pytest.fixture()
def api_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    """Provide a synchronous FastAPI test client with a valid operator key armed.

    Business-logic tests overwhelmingly care about behavior behind the
    deny-by-default ``ApiKeyAuthMiddleware`` (see ``src/otalon_api/middleware/auth.py``),
    not about auth itself. This fixture patches ``get_settings`` as seen by
    the auth middleware to a fixed test key and sends that key by default so
    such tests don't need per-test auth wiring. Dedicated auth-semantic tests
    (``test_auth_middleware.py``, ``test_auth_env_isolation.py``,
    ``test_operations_router.py``, etc.) build their own raw
    ``TestClient(app, ...)`` and their own ``patch("otalon_api.middleware.auth.get_settings", ...)``
    and never use this fixture, so they are unaffected.

    Returns:
        A ``TestClient`` instance bound to the application, pre-authenticated
        with a fixed test-only operator API key.
    """
    test_settings = Settings(admin_api_key=_API_CLIENT_TEST_KEY)
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: test_settings)
    return TestClient(app, headers={"X-API-Key": _API_CLIENT_TEST_KEY})


_API_CLIENT_TEST_KEY = "test-suite-key-do-not-use-in-prod"  # noqa: S105 - test-only fixture constant


@pytest.fixture()
def golden_data() -> dict[str, Any]:
    """Load all JSON files from the ``golden_data/`` directory.

    Returns:
        A dictionary mapping filenames (without extension) to parsed JSON.
    """
    result: dict[str, Any] = {}
    if GOLDEN_DATA_DIR.exists():
        for path in sorted(GOLDEN_DATA_DIR.glob("*.json")):
            with open(path, encoding="utf-8") as fh:
                result[path.stem] = json.load(fh)
    return result


@pytest.fixture()
def golden_data_dir() -> Path:
    """Return the path to the golden_data directory.

    Returns:
        Absolute path to the golden_data directory.
    """
    return GOLDEN_DATA_DIR


@pytest.fixture()
def load_golden():
    """Fixture that returns a loader function for individual golden-data files.

    Returns:
        A callable that accepts a filename (e.g. ``"gd01_ip_opcua.json"``)
        and returns the parsed JSON dictionary.
    """

    def _load(filename: str) -> dict[str, Any]:
        """Load and parse a single golden-data JSON file.

        Args:
            filename: Name of the file inside golden_data directory.

        Returns:
            Parsed JSON dictionary.

        Raises:
            FileNotFoundError: If the file does not exist.
        """
        path = GOLDEN_DATA_DIR / filename
        if not path.exists():
            raise FileNotFoundError(f"Golden data file not found: {path}")
        with open(path, encoding="utf-8") as fh:
            return json.load(fh)

    return _load


@pytest.fixture()
def verify_checksum():
    """Fixture that returns a checksum verification function.

    Returns:
        A callable that verifies the SHA256 checksum of a golden-data file's
        ``data`` field matches the ``checksum_sha256`` field.
    """

    def _verify(gd: dict[str, Any]) -> bool:
        """Verify SHA256 checksum of a golden data dict's data field.

        Args:
            gd: Parsed golden data dictionary with ``data`` and
                ``checksum_sha256`` keys.

        Returns:
            ``True`` if the checksum matches.

        Raises:
            AssertionError: If the checksum does not match.
        """
        expected = gd.get("checksum_sha256", "")
        data_json = json.dumps(gd["data"], separators=(", ", ": "), sort_keys=True)
        actual = hashlib.sha256(data_json.encode("utf-8")).hexdigest()
        assert actual == expected, f"Checksum mismatch: computed={actual}, expected={expected}"
        return True

    return _verify


@pytest.fixture()
def mock_influx_repo() -> MagicMock:
    """Create a MagicMock of InfluxRepository with key methods pre-configured.

    The mock provides ``query_timeseries``, ``list_ids_between``, and
    ``query_timeseries_multi_ids_chunked`` as magic-mock methods whose
    return values can be configured per test.

    Returns:
        A ``MagicMock`` instance mimicking ``InfluxRepository``.
    """
    repo = MagicMock()
    repo.query_timeseries = MagicMock()
    repo.list_ids_between = MagicMock()
    repo.query_timeseries_multi_ids_chunked = MagicMock()
    repo.query_top_connections = MagicMock(return_value=[])
    repo.query_network_throughput = MagicMock(return_value=([], 60))
    repo.query_connection_sparklines = MagicMock(return_value={})
    repo.query_collapsed_port_counts = MagicMock(return_value={})
    repo.query_protocol_count = MagicMock(return_value=0)
    return repo


@pytest.fixture()
def mock_settings() -> Settings:
    """Create a Settings instance suitable for testing without real DB connections.

    All connection-related fields use harmless defaults.

    Returns:
        A ``Settings`` instance with test-safe configuration.
    """
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influxdb_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key="test-key",
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        utc_offset_hours=1,
        default_sample_max_points=500,
    )


@pytest.fixture()
def timeseries_service(mock_influx_repo: MagicMock, mock_settings: Settings) -> TimeseriesService:
    """Create a TimeseriesService with a mock repository.

    Args:
        mock_influx_repo: Mocked InfluxRepository fixture.
        mock_settings: Test settings fixture.

    Returns:
        A ``TimeseriesService`` instance backed by mock objects.
    """
    return TimeseriesService(mock_influx_repo, mock_settings)


@pytest.fixture()
def aggregation_service(mock_influx_repo: MagicMock, mock_settings: Settings) -> NetcapAggregationService:
    """Create a NetcapAggregationService with a mock repository.

    Args:
        mock_influx_repo: Mocked InfluxRepository fixture.
        mock_settings: Test settings fixture.

    Returns:
        A ``NetcapAggregationService`` instance backed by mock objects.
    """
    return NetcapAggregationService(mock_influx_repo, mock_settings, port_collapse_repo=None)


@pytest.fixture()
def mock_postgres_repo() -> MagicMock:
    """Create a MagicMock of PostgresRepository with key methods pre-configured.

    The mock provides all public query and mutation methods as magic-mock
    methods whose return values can be configured per test.

    Returns:
        A ``MagicMock`` instance mimicking ``PostgresRepository``.
    """
    repo = MagicMock()
    repo.query_bounds = MagicMock(return_value=[])
    repo.query_anomalies = MagicMock(return_value=[])
    repo.query_anomaly_groups = MagicMock(return_value=[])
    repo.count_anomaly_groups = MagicMock(return_value=0)
    repo.query_anomaly_group_series = MagicMock(return_value=[])
    repo.query_alarm_details_since = MagicMock(return_value=[])
    repo.query_dashboard_kpis = MagicMock(
        return_value={
            "active_alarm_groups": 0,
            "total_alarm_groups": 0,
            "total_anomalies": 0,
            "affected_series_count": 0,
            "last_alarm_timestamp": None,
        }
    )
    repo.get_anomaly_group_by_id = MagicMock(return_value=None)
    repo.update_alarm_group_confirmed = MagicMock(return_value=True)
    repo.query_device_count = MagicMock(return_value=0)
    repo.query_connection_count = MagicMock(return_value=0)
    return repo


@pytest.fixture()
def anomaly_service(mock_postgres_repo: MagicMock, mock_settings: Settings) -> AnomalyService:
    """Create an AnomalyService with a mock repository.

    Args:
        mock_postgres_repo: Mocked PostgresRepository fixture.
        mock_settings: Test settings fixture.

    Returns:
        An ``AnomalyService`` instance backed by mock objects.
    """
    return AnomalyService(mock_postgres_repo, mock_settings)


@pytest.fixture()
def anomaly_details_service(mock_postgres_repo: MagicMock, mock_settings: Settings) -> AnomalyDetailsService:
    """Create an AnomalyDetailsService with a mock repository.

    Args:
        mock_postgres_repo: Mocked PostgresRepository fixture.
        mock_settings: Test settings fixture.

    Returns:
        An ``AnomalyDetailsService`` instance backed by mock objects.
    """
    return AnomalyDetailsService(mock_postgres_repo, mock_settings)


@pytest.fixture()
def bounds_service(
    mock_influx_repo: MagicMock,
    mock_postgres_repo: MagicMock,
    mock_settings: Settings,
) -> BoundsService:
    """Create a BoundsService with mock repositories.

    Args:
        mock_influx_repo: Mocked InfluxRepository fixture.
        mock_postgres_repo: Mocked PostgresRepository fixture.
        mock_settings: Test settings fixture.

    Returns:
        A ``BoundsService`` instance backed by mock objects.
    """
    return BoundsService(mock_influx_repo, mock_postgres_repo, mock_settings)


@pytest.fixture()
def dashboard_kpi_service(
    mock_postgres_repo: MagicMock, mock_influx_repo: MagicMock, mock_settings: Settings
) -> DashboardKpiService:
    """Create a DashboardKpiService with mock repositories.

    Args:
        mock_postgres_repo: Mocked PostgresRepository fixture.
        mock_influx_repo: Mocked InfluxRepository fixture.
        mock_settings: Test settings fixture.

    Returns:
        A ``DashboardKpiService`` instance backed by mock objects.
    """
    return DashboardKpiService(mock_postgres_repo, mock_influx_repo, mock_settings)


@pytest.fixture(scope="session")
def production_golden_dir() -> Path:
    """Return the path to the production golden data directory.

    Returns:
        Absolute path to ``tests/golden_data/production/``.

    Raises:
        FileNotFoundError: If the directory does not exist.
    """
    if not PRODUCTION_GOLDEN_DIR.exists():
        raise FileNotFoundError(
            f"Production golden data directory not found: {PRODUCTION_GOLDEN_DIR}. "
            "Run tests/scripts/prepare_api_golden_data.py first."
        )
    return PRODUCTION_GOLDEN_DIR


def _load_jsonl(path: Path) -> list[dict[str, Any]]:
    """Load a JSONL file into a list of dictionaries.

    Args:
        path: Path to the ``.jsonl`` file.

    Returns:
        A list of parsed JSON dictionaries.

    Raises:
        FileNotFoundError: If the file does not exist.
    """
    if not path.exists():
        raise FileNotFoundError(f"Golden data file not found: {path}")
    rows: list[dict[str, Any]] = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                rows.append(json.loads(line))
    return rows


@pytest.fixture()
def prod_timeseries_df(production_golden_dir: Path) -> pl.DataFrame:
    """Load the 1-hour attack window timeseries as a Polars DataFrame.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A ``pl.DataFrame`` with all timeseries rows.
    """
    return pl.read_parquet(production_golden_dir / "conn_timeseries_1h.parquet")


@pytest.fixture()
def prod_baseline_df(production_golden_dir: Path) -> pl.DataFrame:
    """Load the 10-minute baseline timeseries as a Polars DataFrame.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A ``pl.DataFrame`` with baseline timeseries rows.
    """
    return pl.read_parquet(production_golden_dir / "conn_baseline_10min.parquet")


@pytest.fixture()
def prod_bounds(production_golden_dir: Path) -> list[dict[str, Any]]:
    """Load production bounds data from JSONL.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A list of bounds row dictionaries (20 rows).
    """
    return _load_jsonl(production_golden_dir / "bounds.jsonl")


@pytest.fixture()
def prod_anomalies(production_golden_dir: Path) -> list[dict[str, Any]]:
    """Load production anomaly data from JSONL.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A list of anomaly row dictionaries.
    """
    return _load_jsonl(production_golden_dir / "anomalies_1h.jsonl")


@pytest.fixture()
def prod_alarms(production_golden_dir: Path) -> list[dict[str, Any]]:
    """Load production alarm data from JSONL.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A list of alarm group row dictionaries.
    """
    return _load_jsonl(production_golden_dir / "alarms_1h.jsonl")


@pytest.fixture()
def prod_port_collapse_rules(production_golden_dir: Path) -> pl.DataFrame:
    """Load production port-collapse rules as a Polars DataFrame.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A ``pl.DataFrame`` with 279 rule rows.
    """
    rows = _load_jsonl(production_golden_dir / "port_collapse_rules.jsonl")
    return pl.DataFrame(rows)


@pytest.fixture()
def prod_ground_truth(production_golden_dir: Path) -> list[dict[str, Any]]:
    """Load production ground truth data from JSON.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A list of ground truth entry dictionaries.
    """
    path = production_golden_dir / "ground_truth_1h.json"
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


@pytest.fixture()
def prod_devices(production_golden_dir: Path) -> list[dict[str, Any]]:
    """Load production device data from JSONL.

    Args:
        production_golden_dir: Path to the production golden data directory.

    Returns:
        A list of device row dictionaries (4 rows).
    """
    return _load_jsonl(production_golden_dir / "devices.jsonl")


@pytest.fixture()
def audit_ownership_marker() -> Iterator[str]:
    """Yield a deterministic, unique ``source`` marker for test-created rows.

    Tests that seed ``operations_audit`` rows against a real database should
    import them with this marker as their provenance ``source`` (never the
    native ``"operations"`` source). Cleanup is then scoped to exactly the
    marker via :meth:`OperationsAuditRepository.delete_by_source`, so no live
    operator history is ever touched. The marker is stable within a test and
    unique across tests, keeping systemtest/audit data isolated.
    """
    marker = f"systemtest-{uuid.uuid4().hex}"
    yield marker
