"""Unit tests for deterministic, read-only bound suggestions."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pandas as pd
import pytest

from otalon_api.domain.netcap.models import proto_series_hash
from otalon_api.services.detection_readiness_service import DetectionReadinessService
from otalon_api.settings import Settings


class _Postgres:
    def __init__(self, has_bounds: bool = True) -> None:
        self.writes = 0
        self.has_bounds = has_bounds

    def query_bounds(self, module: str, series_id: str | None = None) -> list[dict[str, object]]:
        if not self.has_bounds:
            return []
        return [
            {
                "module": module,
                "series_id": series_id,
                "lower_bounds": {"packet_count": 10.0},
                "upper_bounds": {"packet_count": 20.0},
            }
        ]


class _Influx:
    def __init__(self) -> None:
        self.calls: list[dict[str, object]] = []
        self.distinct_calls: list[tuple[str, str]] = []

    def query_timeseries(self, **kwargs: object) -> pd.DataFrame:
        self.calls.append(kwargs)
        return pd.DataFrame(
            {
                "time": [
                    "2026-07-01T00:00:00Z",
                    "2026-07-01T00:05:00Z",
                    "2026-07-01T00:10:00Z",
                ],
                "packet_count": [8.0, 15.0, 24.0],
            }
        )

    def query_distinct_tags(self, measurement: str, tag: str) -> list[str]:
        self.distinct_calls.append((measurement, tag))
        return ["Ethernet:ARP"]


class _NoTimeInflux(_Influx):
    def query_timeseries(self, **kwargs: object) -> pd.DataFrame:
        self.calls.append(kwargs)
        return pd.DataFrame({"packet_count": [8.0, 15.0]})


def _config(path: Path, features: list[str] | None = None) -> Path:
    modules = [
        {"name": "conn", "measurement": "conn_actual", "tag_key": "conn_tag", "features": features or ["packet_count"]},
        {"name": "mac_traffic", "measurement": "mac_actual", "tag_key": "mac_tag", "features": ["mac_feature"]},
        {"name": "proto_traffic", "measurement": "proto_actual", "tag_key": "proto_tag", "features": ["proto_feature"]},
    ]
    path.write_text(json.dumps({"modules": modules}), encoding="utf-8")
    return path


def _service(
    tmp_path: Path, has_bounds: bool = True, features: list[str] | None = None
) -> tuple[DetectionReadinessService, _Postgres, _Influx]:
    postgres = _Postgres(has_bounds)
    influx = _Influx()
    service = DetectionReadinessService(
        postgres,
        str(_config(tmp_path / "otalon-clas.json", features)),
        "/missing",
        influx=influx,  # type: ignore[arg-type]
        settings=Settings(),
    )
    return service, postgres, influx


def test_suggestion_uses_strict_window_and_expand_is_widen_only(tmp_path: Path) -> None:
    service, postgres, influx = _service(tmp_path)
    result = service.suggest_bounds(
        "conn",
        "uci-1",
        "expand",
        datetime(2026, 7, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc),
    )
    assert result["status"] == "available"
    assert result["proposed"] == {"lower_bounds": {"packet_count": 8.0}, "upper_bounds": {"packet_count": 20.0}}
    assert len(influx.calls) == 1
    assert postgres.writes == 0
    assert influx.calls[0]["start"] < influx.calls[0]["stop"]


@pytest.mark.parametrize(
    ("module", "series_id", "measurement", "tag", "feature"),
    [
        ("conn", "uci-1", "conn_actual", "conn_tag", "packet_count"),
        ("mac_traffic", "mac-1", "mac_actual", "mac_tag", "mac_feature"),
        ("proto_traffic", proto_series_hash("Ethernet:ARP"), "proto_actual", "proto_tag", "proto_feature"),
    ],
)
def test_suggestion_maps_all_sources_from_module_config(
    tmp_path: Path, module: str, series_id: str, measurement: str, tag: str, feature: str
) -> None:
    service, _, influx = _service(tmp_path)
    influx.query_timeseries = lambda **kwargs: (
        influx.calls.append(kwargs) or pd.DataFrame({"time": ["2026-07-01T00:00:00Z"], feature: [1.0]})
    )
    service.suggest_bounds(module, series_id, "replace", START, END)
    assert influx.calls[-1]["measurement"] == measurement
    assert influx.calls[-1]["id_tag"] == tag
    assert influx.calls[-1]["fields"] == [feature]
    assert influx.calls[-1]["tags"] == {tag: "Ethernet:ARP" if module == "proto_traffic" else series_id}
    if module == "proto_traffic":
        assert influx.distinct_calls == [(measurement, tag)]


def test_suggestion_replace_has_different_semantics_and_zero_mutation(tmp_path: Path) -> None:
    service, postgres, _ = _service(tmp_path)
    result = service.suggest_bounds(
        "conn",
        "uci-1",
        "replace",
        datetime(2026, 7, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc),
    )
    assert result["action"] == "replace"
    assert result["proposed"]["lower_bounds"]["packet_count"] == 7.65
    assert result["proposed"]["upper_bounds"]["packet_count"] == 15.35
    assert "5% of observed span" in result["rationale"]["packet_count"]["lower_rationale"]
    assert postgres.writes == 0


def test_replace_margin_uses_magnitude_fallback_for_singleton_observation(tmp_path: Path) -> None:
    service, _, influx = _service(tmp_path)
    influx.query_timeseries = lambda **_kwargs: pd.DataFrame({"time": ["2026-07-01T00:00:00Z"], "packet_count": [20.0]})
    result = service.suggest_bounds(
        "conn",
        "uci-1",
        "replace",
        datetime(2026, 7, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc),
    )
    assert result["proposed"]["lower_bounds"]["packet_count"] == 19.0
    assert result["proposed"]["upper_bounds"]["packet_count"] == 21.0


def test_replace_margin_uses_nonzero_fallback_for_zero_observation(tmp_path: Path) -> None:
    service, _, influx = _service(tmp_path)
    influx.query_timeseries = lambda **_kwargs: pd.DataFrame({"time": ["2026-07-01T00:00:00Z"], "packet_count": [0.0]})
    result = service.suggest_bounds(
        "conn",
        "uci-1",
        "replace",
        datetime(2026, 7, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc),
    )
    assert result["proposed"]["lower_bounds"]["packet_count"] == -1.0
    assert result["proposed"]["upper_bounds"]["packet_count"] == 1.0


def test_suggestion_without_time_column_fails_closed(tmp_path: Path) -> None:
    postgres = _Postgres()
    influx = _NoTimeInflux()
    service = DetectionReadinessService(
        postgres,
        str(_config(tmp_path / "otalon-clas.json")),
        "/missing",
        influx=influx,
        settings=Settings(),
    )
    result = service.suggest_bounds(
        "conn",
        "uci-1",
        "expand",
        datetime(2026, 7, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc),
    )
    assert result["status"] == "unavailable"
    assert result["evidence_count"] == 0
    assert result["proposed"] == result["current"]


def test_suggestion_reports_unavailable_without_values(tmp_path: Path) -> None:
    service, _, influx = _service(tmp_path)
    influx.query_timeseries = lambda **_kwargs: pd.DataFrame({"time": [], "packet_count": []})
    result = service.suggest_bounds(
        "conn",
        "uci-1",
        "expand",
        datetime(2026, 7, 1, tzinfo=timezone.utc),
        datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc),
    )
    assert result["status"] == "unavailable"
    assert result["evidence_count"] == 0


def test_create_reports_available_partial_and_unavailable_with_complete_envelope(tmp_path: Path) -> None:
    service, postgres, influx = _service(tmp_path, has_bounds=False, features=["packet_count", "total_volume"])
    influx.query_timeseries = lambda **_kwargs: pd.DataFrame(
        {"time": ["2026-07-01T00:00:00Z"], "packet_count": [10.0], "total_volume": [20.0]}
    )
    available = service.suggest_bounds("conn", "new", "create", START, END)
    influx.query_timeseries = lambda **_kwargs: pd.DataFrame(
        {"time": ["2026-07-01T00:00:00Z"], "packet_count": [10.0], "total_volume": [float("inf")]}
    )
    partial = service.suggest_bounds("conn", "new", "create", START, END)
    influx.query_timeseries = lambda **_kwargs: pd.DataFrame(
        {"time": ["2026-07-01T00:00:00Z"], "packet_count": [float("nan")], "total_volume": ["bad"]}
    )
    unavailable = service.suggest_bounds("conn", "new", "create", START, END)
    assert [available["status"], partial["status"], unavailable["status"]] == ["available", "partial", "unavailable"]
    assert available["current"] == {"lower_bounds": {}, "upper_bounds": {}}
    assert available["proposed"] == {
        "lower_bounds": {"packet_count": 9.0, "total_volume": 19.0},
        "upper_bounds": {"packet_count": 11.0, "total_volume": 21.0},
    }
    assert partial["proposed"]["lower_bounds"]["total_volume"] is None
    assert unavailable["proposed"] == {
        "lower_bounds": {"packet_count": None, "total_volume": None},
        "upper_bounds": {"packet_count": None, "total_volume": None},
    }
    assert set(unavailable["rationale"]) == {"packet_count", "total_volume"}
    assert postgres.writes == 0


def test_action_rejects_current_state_conflicts_without_query(tmp_path: Path) -> None:
    existing, _, existing_influx = _service(tmp_path)
    missing, _, missing_influx = _service(tmp_path, has_bounds=False)
    create = existing.suggest_bounds("conn", "uci-1", "create", START, END)
    expand = missing.suggest_bounds("conn", "uci-1", "expand", START, END)
    replace = missing.suggest_bounds("conn", "uci-1", "replace", START, END)
    assert [create["status"], expand["status"], replace["status"]] == ["unavailable"] * 3
    assert existing_influx.calls == missing_influx.calls == []


START = datetime(2026, 7, 1, tzinfo=timezone.utc)
END = datetime(2026, 7, 1, 0, 10, tzinfo=timezone.utc)
