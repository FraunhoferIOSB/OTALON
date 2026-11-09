"""Regression tests for SUITE-045 — readiness N+1 query fan-out.

``DetectionReadinessService.readiness`` ran four synchronous PostgreSQL
queries **per module**, sequentially — 12 round-trips for the three modules.
Two of the four were anti-joins over the ~1.4M-row ``anomalies`` table and
accounted for 3.93s of the endpoint's measured 3.99s.

These tests pin both halves of the fix:

* **behaviour is unchanged** — same modules, same states, same counts, from
  identical repository data (the readiness semantics must not shift);
* **the query pattern is batched** — the per-module fan-out is gone, so a
  future refactor cannot silently reintroduce it.

A fake repository records every query, so the assertions are about observed
call counts rather than source text. No database is required.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

from otalon_api.services.detection_readiness_service import MODULES, DetectionReadinessService

pytestmark = pytest.mark.unit


class _RecordingRepo:
    """Repository double that records queries and serves fixed rows."""

    def __init__(
        self,
        bounds: dict[str, list[dict[str, Any]]] | None = None,
        frequency: dict[str, int] | None = None,
        no_bounds: dict[str, tuple[int, int]] | None = None,
    ) -> None:
        self._bounds = bounds or {}
        self._frequency = frequency or {}
        self._no_bounds = no_bounds or {}
        self.bounds_calls: list[str] = []
        self.queries: list[str] = []

    def query_bounds(self, module: str, series_id: str | None = None) -> list[dict[str, Any]]:
        self.bounds_calls.append(module)
        return list(self._bounds.get(module, []))

    def _execute_query(self, sql: str, params: dict[str, Any] | None = None) -> list[dict[str, Any]]:
        self.queries.append(sql)
        params = params or {}
        modules = params.get("modules")

        if "frequency_profiles" in sql:
            assert modules is not None, "frequency count must be batched over modules"
            return [{"module": m, "count": self._frequency.get(m, 0)} for m in modules if m in self._frequency]

        if "per_series" in sql or "anomalies" in sql:
            assert modules is not None, "no-bounds counts must be batched over modules"
            return [
                {
                    "module": m,
                    "series_count": self._no_bounds[m][0],
                    "event_count": self._no_bounds[m][1],
                }
                for m in modules
                if m in self._no_bounds
            ]

        return []

    @property
    def anomaly_queries(self) -> list[str]:
        return [q for q in self.queries if "anomalies" in q]

    @property
    def frequency_queries(self) -> list[str]:
        return [q for q in self.queries if "frequency_profiles" in q]


BOUNDS_ROW = {
    "module": "conn",
    "series_id": "s1",
    # A real datetime: _as_datetime accepts only datetime instances, which is
    # what psycopg2 returns for a timestamptz column.
    "trained_at": datetime(2026, 8, 30, 12, 0, tzinfo=timezone.utc),
    "lower_bounds": {},
    "upper_bounds": {},
}


@pytest.fixture()
def config_file(tmp_path: Path) -> str:
    path = tmp_path / "config.json"
    path.write_text(
        json.dumps({"modules": [{"name": m, "enabled": True} for m in MODULES]}),
        encoding="utf-8",
    )
    return str(path)


def _service(repo: _RecordingRepo, config_file: str, tmp_path: Path) -> DetectionReadinessService:
    return DetectionReadinessService(repo, config_file, str(tmp_path))


class TestQueryFanOutIsBatched:
    """The N+1 pattern must not come back."""

    def test_anomalies_is_queried_once_not_twice_per_module(self, config_file: str, tmp_path: Path) -> None:
        """Was 2N (6) anti-join queries; now a single grouped statement."""
        repo = _RecordingRepo(no_bounds={m: (1, 2) for m in MODULES})

        _service(repo, config_file, tmp_path).readiness(set())

        assert len(repo.anomaly_queries) == 1, f"expected 1 batched anomalies query, got {len(repo.anomaly_queries)}"

    def test_frequency_is_queried_once_not_once_per_module(self, config_file: str, tmp_path: Path) -> None:
        repo = _RecordingRepo(frequency={m: 3 for m in MODULES})

        _service(repo, config_file, tmp_path).readiness(set())

        assert len(repo.frequency_queries) == 1

    def test_heavy_queries_total_two(self, config_file: str, tmp_path: Path) -> None:
        """Two grouped statements replace the eight per-module heavy ones.

        The per-module ``runtime_config`` point lookups from the state
        helpers are deliberately NOT batched: nine of them cost ~2.5ms in
        total against an indexed key, so restructuring the state helpers
        would add coupling for no measurable gain.
        """
        repo = _RecordingRepo()

        _service(repo, config_file, tmp_path).readiness(set())

        heavy = repo.anomaly_queries + repo.frequency_queries
        assert len(heavy) == 2

    def test_query_count_does_not_scale_with_module_count(
        self, config_file: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The whole point: adding a module must not add round-trips."""
        import otalon_api.services.detection_readiness_service as svc_mod

        repo = _RecordingRepo()
        monkeypatch.setattr(svc_mod, "MODULES", MODULES + ("extra_module",))

        _service(repo, config_file, tmp_path).readiness(set())

        heavy = repo.anomaly_queries + repo.frequency_queries
        assert len(heavy) == 2

    def test_bounds_stays_per_module_for_alias_fallback(self, config_file: str, tmp_path: Path) -> None:
        """query_bounds carries conn<->netcap alias semantics; keep it per module."""
        repo = _RecordingRepo()

        _service(repo, config_file, tmp_path).readiness(set())

        assert repo.bounds_calls == list(MODULES)


class TestOutputUnchanged:
    """Readiness semantics must be identical to the per-module implementation."""

    def _readiness(self, config_file: str, tmp_path: Path) -> list[dict[str, Any]]:
        repo = _RecordingRepo(
            bounds={"conn": [BOUNDS_ROW]},
            frequency={"conn": 7, "mac_traffic": 5},
            no_bounds={"conn": (11, 42), "proto_traffic": (2, 3)},
        )
        return _service(repo, config_file, tmp_path).readiness(set())

    def test_one_item_per_module_in_order(self, config_file: str, tmp_path: Path) -> None:
        items = self._readiness(config_file, tmp_path)

        assert [i["module"] for i in items] == list(MODULES)

    def test_counts_are_taken_from_the_batched_rows(self, config_file: str, tmp_path: Path) -> None:
        items = {i["module"]: i for i in self._readiness(config_file, tmp_path)}

        assert items["conn"]["frequency_profile_count"] == 7
        assert items["conn"]["no_bounds_count"] == 11
        assert items["conn"]["no_bounds_event_count"] == 42
        assert items["conn"]["bounds_series_count"] == 1

    def test_missing_module_defaults_to_zero(self, config_file: str, tmp_path: Path) -> None:
        """A module absent from the grouped result must read 0, as before."""
        items = {i["module"]: i for i in self._readiness(config_file, tmp_path)}

        assert items["proto_traffic"]["frequency_profile_count"] == 0
        assert items["mac_traffic"]["no_bounds_count"] == 0
        assert items["mac_traffic"]["no_bounds_event_count"] == 0

    def test_no_bounds_series_mirrors_no_bounds_count(self, config_file: str, tmp_path: Path) -> None:
        for item in self._readiness(config_file, tmp_path):
            assert item["no_bounds_series_count"] == item["no_bounds_count"]

    def test_response_keys_are_unchanged(self, config_file: str, tmp_path: Path) -> None:
        expected = {
            "module",
            "state",
            "detection_mode",
            "bounds_series_count",
            "no_bounds_count",
            "no_bounds_event_count",
            "no_bounds_series_count",
            "frequency_profile_count",
            "last_training",
            "schema_version",
            "schema_compatible",
            "classification_state",
            "bounds_state",
            "frequency_state",
        }

        for item in self._readiness(config_file, tmp_path):
            assert set(item) == expected

    def test_last_training_derived_from_bounds_rows(self, config_file: str, tmp_path: Path) -> None:
        items = {i["module"]: i for i in self._readiness(config_file, tmp_path)}

        assert items["conn"]["last_training"] is not None
        assert items["mac_traffic"]["last_training"] is None


class TestQueryFailureDegradesToZero:
    """A failing grouped query must not break the page, as before."""

    def test_execute_query_exception_yields_zero_counts(self, config_file: str, tmp_path: Path) -> None:
        class _BrokenRepo(_RecordingRepo):
            def _execute_query(self, sql: str, params: dict[str, Any] | None = None) -> Any:
                raise RuntimeError("database unavailable")

        items = _service(_BrokenRepo(), config_file, tmp_path).readiness(set())

        assert len(items) == len(MODULES)
        for item in items:
            assert item["frequency_profile_count"] == 0
            assert item["no_bounds_count"] == 0
            assert item["no_bounds_event_count"] == 0
