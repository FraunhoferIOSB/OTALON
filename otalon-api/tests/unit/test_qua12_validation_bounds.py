"""Regression tests for QUA-12 — unbounded query/filter parameters.

The audit found free-text filters reaching a double-wildcard ``ILIKE`` over
two ``operations_audit`` columns, per-request list parameters with no
cardinality cap, and identifier/range parameters carried unchecked into the
Influx query. A megabyte-long pattern or a thousand-member list is a cheap
per-request CPU/IO amplifier — availability, not integrity, since every
value is correctly parameterised.

Each test asserts two things: an over-limit request is rejected with 422
before any service is reached, and a realistically-sized request still
passes validation. The "still accepted" half is what proves the caps do not
break live traffic; the live database holds a 113-character series id, a
130-character audit target and 88 frequency profiles, all far below the
caps.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime
from typing import Any

import pandas as pd
import pytest
from fastapi.testclient import TestClient

from otalon_api.api.v1 import (
    anomalies as anomalies_module,
    operations as operations_module,
    timeseries as timeseries_module,
    timeseries_mac_proto as mac_proto_module,
)
from otalon_api.dependencies import (
    get_aggregation_service,
    get_detection_readiness_service,
    get_mac_timeseries_service,
    get_operations_jobs_service,
    get_proto_hash_resolver,
    get_proto_timeseries_service,
    get_timeseries_service,
)
from otalon_api.domain.netcap.models import ALL_FEATURES, MAC_FEATURES
from otalon_api.main import app

pytestmark = pytest.mark.unit

START_STR = "2026-03-06T21:08:00Z"
STOP_STR = "2026-03-06T22:08:00Z"
SAMPLE_UCI = "aa:bb:cc:dd:ee:ff/11:22:33:44:55:66/0/6/192.168.0.1/192.168.0.2/12345/80/PROFINET_DCE_RPC"
SAMPLE_MAC = "aa:bb:cc:dd:ee:ff"
SAMPLE_PROTO = "Ethernet:IPv4:TCP"


def _sample_df() -> pd.DataFrame:
    return pd.DataFrame({"time": pd.to_datetime(["2026-03-06T21:10:00"]), "packet_count": [10]})


class _StubTimeseriesService:
    """Conn timeseries stub; a bounded request must still reach these."""

    def get_between(self, **kwargs: Any) -> tuple[pd.DataFrame, int | None]:
        return _sample_df(), None

    def get_plot_data(self, **kwargs: Any) -> tuple[pd.DataFrame, int | None]:
        return _sample_df(), None

    def list_ids(self, **kwargs: Any) -> list[str]:
        return [SAMPLE_UCI]

    def find_active_siblings(self, **kwargs: Any) -> list[dict[str, str]]:
        return []


class _StubAggregationService:
    """Aggregation stub for the deprecated wildcard route."""

    def resolve_and_aggregate(self, **kwargs: Any) -> pd.DataFrame:
        return _sample_df()

    def aggregate_wildcard_timeseries(self, **kwargs: Any) -> pd.DataFrame:
        return _sample_df()

    def build_wildcard_groups(self, ucis: list[str]) -> dict[str, tuple[list[str], bool]]:
        return {SAMPLE_UCI: ([SAMPLE_UCI], True)}


class _StubSourceTimeseriesService:
    """MAC/Proto timeseries stub."""

    def get_between(self, **kwargs: Any) -> tuple[pd.DataFrame, int | None]:
        return _sample_df(), None

    def get_plot_data(self, **kwargs: Any) -> tuple[pd.DataFrame, int | None]:
        return _sample_df(), None

    def list_ids(self, **kwargs: Any) -> list[str]:
        return [SAMPLE_MAC]


class _StubProtoResolver:
    """Proto hash resolver stub returning the id unchanged."""

    def resolve(self, series_id: str) -> str:
        return series_id

    def resolve_many(self, series_ids: list[str]) -> list[str]:
        return list(series_ids)


class _StubDetectionReadinessService:
    """Detection-readiness stub for the bound-review filter route."""

    def bounds(
        self,
        module: str | None,
        state: str | None,
        since: datetime | None,
        query: str | None,
        until: datetime | None = None,
    ) -> list[dict[str, Any]]:
        return []


class _StubJobsService:
    """Operations jobs/audit stub for the filter routes."""

    async def list_jobs(self, **kwargs: Any) -> list[Any]:
        return []

    async def query_audit(self, **kwargs: Any) -> list[Any]:
        return []


@pytest.fixture()
def bounds_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient with every service touched by a bounded route stubbed."""
    app.dependency_overrides[get_timeseries_service] = _StubTimeseriesService
    app.dependency_overrides[get_aggregation_service] = _StubAggregationService
    app.dependency_overrides[get_mac_timeseries_service] = _StubSourceTimeseriesService
    app.dependency_overrides[get_proto_timeseries_service] = _StubSourceTimeseriesService
    app.dependency_overrides[get_proto_hash_resolver] = _StubProtoResolver
    app.dependency_overrides[get_detection_readiness_service] = _StubDetectionReadinessService
    app.dependency_overrides[get_operations_jobs_service] = _StubJobsService
    test_key = "test-suite-key-do-not-use-in-prod"
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: _test_settings(test_key))
    client = TestClient(app, headers={"X-API-Key": test_key})
    yield client
    app.dependency_overrides.clear()


def _test_settings(api_key: str) -> Any:
    from otalon_api.settings import Settings

    return Settings(admin_api_key=api_key)


class TestAuditFilterLengthBounds:
    """``q``/``actor`` reach ``ILIKE '%…%'`` and must be length-capped."""

    def test_audit_q_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """A pattern longer than the cap never reaches the ILIKE."""
        over = "a" * (operations_module.MAX_SEARCH_LENGTH + 1)

        resp = bounds_client.get("/api/v1/operations/audit", params={"q": over})

        assert resp.status_code == 422

    def test_audit_q_at_limit_is_accepted(self, bounds_client: TestClient) -> None:
        """A realistic search string is still served."""
        at_limit = "a" * operations_module.MAX_SEARCH_LENGTH

        resp = bounds_client.get("/api/v1/operations/audit", params={"q": at_limit})

        assert resp.status_code == 200

    def test_audit_actor_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """``actor`` also reaches a double-wildcard ILIKE."""
        over = "a" * (operations_module.MAX_FILTER_LENGTH + 1)

        resp = bounds_client.get("/api/v1/operations/audit", params={"actor": over})

        assert resp.status_code == 422

    def test_bound_review_q_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """The bound-review needle is bounded on the same grounds."""
        over = "a" * (operations_module.MAX_SEARCH_LENGTH + 1)

        resp = bounds_client.get("/api/v1/operations/bounds", params={"q": over})

        assert resp.status_code == 422

    def test_bound_review_realistic_filters_are_accepted(self, bounds_client: TestClient) -> None:
        """Live filter values pass unchanged."""
        resp = bounds_client.get(
            "/api/v1/operations/bounds",
            params={"module": "conn", "state": "Violation", "q": SAMPLE_UCI},
        )

        assert resp.status_code == 200

    def test_jobs_filters_over_limit_are_rejected(self, bounds_client: TestClient) -> None:
        """Job filters are equality-matched but still bounded."""
        over = "a" * (operations_module.MAX_FILTER_LENGTH + 1)

        resp = bounds_client.get("/api/v1/operations/jobs", params={"state": over})

        assert resp.status_code == 422


class TestAuditQueryFiltersModelBounds:
    """The domain model is the backstop for non-HTTP callers."""

    def test_q_over_limit_raises(self) -> None:
        """``AuditQueryFilters`` rejects an oversized needle itself."""
        from pydantic import ValidationError

        from otalon_api.domain.operations import AuditQueryFilters

        with pytest.raises(ValidationError):
            AuditQueryFilters(q="a" * 201)

    def test_realistic_q_is_accepted(self) -> None:
        """A real search term validates."""
        from otalon_api.domain.operations import AuditQueryFilters

        filters = AuditQueryFilters(q="bounds", actor="operator")

        assert filters.q == "bounds"


class TestTimeseriesListCardinalityBounds:
    """Every extra list member expands the per-request aggregation work."""

    def test_features_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """More feature names than the catalog can ever hold is rejected."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("uci", SAMPLE_UCI),
            ("start", START_STR),
            ("stop", STOP_STR),
        ]
        params += [("features", "packet_count")] * (timeseries_module.MAX_FEATURES + 1)

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 422

    def test_real_feature_selection_is_accepted(self, bounds_client: TestClient) -> None:
        """The full conn feature catalog still fits under the cap."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("uci", SAMPLE_UCI),
            ("start", START_STR),
            ("stop", STOP_STR),
        ]
        params += [("features", name) for name in ALL_FEATURES]

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 200

    def test_members_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """Wildcard members are capped — each one costs an aggregation."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("wildcard_uci", SAMPLE_UCI),
            ("start", START_STR),
            ("stop", STOP_STR),
            ("features", "packet_count"),
        ]
        params += [("members", SAMPLE_UCI)] * (timeseries_module.MAX_MEMBERS + 1)

        resp = bounds_client.get("/api/v1/timeseries/wildcard", params=params)

        assert resp.status_code == 422

    def test_realistic_member_group_is_accepted(self, bounds_client: TestClient) -> None:
        """A plausible collapsed-port group passes."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("wildcard_uci", SAMPLE_UCI),
            ("start", START_STR),
            ("stop", STOP_STR),
            ("features", "packet_count"),
        ]
        params += [("members", SAMPLE_UCI)] * 8

        resp = bounds_client.get("/api/v1/timeseries/wildcard", params=params)

        assert resp.status_code == 200

    def test_ids_fields_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """The nonzero-filter field list is bounded too."""
        params: list[tuple[str, str | int | float | bool | None]] = [("start", START_STR), ("stop", STOP_STR)]
        params += [("fields", "packet_count")] * (timeseries_module.MAX_FEATURES + 1)

        resp = bounds_client.get("/api/v1/timeseries/ids", params=params)

        assert resp.status_code == 422

    def test_mac_features_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """The MAC subrouter carries the same cap."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("mac", SAMPLE_MAC),
            ("start", START_STR),
            ("stop", STOP_STR),
        ]
        params += [("features", "out_conn_count")] * (mac_proto_module.MAX_FEATURES + 1)

        resp = bounds_client.get("/api/v1/timeseries/mac/data", params=params)

        assert resp.status_code == 422

    def test_proto_features_over_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """The Proto subrouter carries the same cap."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("protocol", SAMPLE_PROTO),
            ("start", START_STR),
            ("stop", STOP_STR),
        ]
        params += [("features", "proto_conn_count")] * (mac_proto_module.MAX_FEATURES + 1)

        resp = bounds_client.get("/api/v1/timeseries/proto/data", params=params)

        assert resp.status_code == 422

    def test_real_mac_feature_catalog_is_accepted(self, bounds_client: TestClient) -> None:
        """All 13 MAC features still fit under the cap."""
        params: list[tuple[str, str | int | float | bool | None]] = [
            ("mac", SAMPLE_MAC),
            ("start", START_STR),
            ("stop", STOP_STR),
        ]
        params += [("features", name) for name in MAC_FEATURES]

        resp = bounds_client.get("/api/v1/timeseries/mac/data", params=params)

        assert resp.status_code == 200


class TestIdentifierAndRangeBounds:
    """Identifier strings and sample sizes reach the Influx query."""

    def test_oversized_uci_is_rejected(self, bounds_client: TestClient) -> None:
        """A megabyte-long UCI never reaches the repository."""
        params = {
            "uci": "a" * (timeseries_module.MAX_UCI_LENGTH + 1),
            "start": START_STR,
            "stop": STOP_STR,
            "features": "packet_count",
        }

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 422

    def test_live_length_uci_is_accepted(self, bounds_client: TestClient) -> None:
        """The longest real UCI on the live database still passes."""
        params = {
            "uci": SAMPLE_UCI,
            "start": START_STR,
            "stop": STOP_STR,
            "features": "packet_count",
        }

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 200

    def test_absurd_sample_max_points_is_rejected(self, bounds_client: TestClient) -> None:
        """``sample_max_points`` sizes the DATE_BIN bucket and is capped."""
        params = {
            "uci": SAMPLE_UCI,
            "start": START_STR,
            "stop": STOP_STR,
            "features": "packet_count",
            "sample_max_points": str(timeseries_module.MAX_SAMPLE_POINTS + 1),
        }

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 422

    def test_zero_sample_max_points_is_rejected(self, bounds_client: TestClient) -> None:
        """Non-positive point counts were silently ignored before."""
        params = {
            "uci": SAMPLE_UCI,
            "start": START_STR,
            "stop": STOP_STR,
            "features": "packet_count",
            "sample_max_points": "0",
        }

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 422

    def test_ui_sample_max_points_is_accepted(self, bounds_client: TestClient) -> None:
        """The largest value the UI offers (2400 points) still passes."""
        params = {
            "uci": SAMPLE_UCI,
            "start": START_STR,
            "stop": STOP_STR,
            "features": "packet_count",
            "sample_max_points": "2400",
        }

        resp = bounds_client.get("/api/v1/timeseries/data", params=params)

        assert resp.status_code == 200


class TestAnomalyFilterBounds:
    """The anomaly routes carry the same identifier/scan bounds."""

    def test_oversized_interval_uci_is_rejected(self, bounds_client: TestClient) -> None:
        """``uci`` is matched against every group's ``series_ids``."""
        params = {"uci": "a" * (anomalies_module.MAX_SERIES_ID_LENGTH + 1)}

        resp = bounds_client.get("/api/v1/anomalies/intervals", params=params)

        assert resp.status_code == 422

    def test_absurd_interval_scan_limit_is_rejected(self, bounds_client: TestClient) -> None:
        """``limit`` sizes the group scan and was previously unbounded."""
        params = {
            "uci": SAMPLE_UCI,
            "limit": str(anomalies_module.MAX_INTERVAL_SCAN + 1),
        }

        resp = bounds_client.get("/api/v1/anomalies/intervals", params=params)

        assert resp.status_code == 422


class TestOperationsRequestModelBounds:
    """Operator free text is persisted verbatim into unbounded audit columns."""

    def test_correction_reason_over_limit_is_rejected(self) -> None:
        """A reason beyond the cap fails Pydantic validation."""
        from pydantic import ValidationError

        from otalon_api.api.schemas.operations import MAX_REASON_LENGTH, BoundsCorrectionRequest

        with pytest.raises(ValidationError):
            BoundsCorrectionRequest(
                module="conn",
                lower_bounds={},
                upper_bounds={},
                reason="a" * (MAX_REASON_LENGTH + 1),
            )

    def test_correction_series_id_over_limit_is_rejected(self) -> None:
        """An oversized series identifier is rejected before the audit write."""
        from pydantic import ValidationError

        from otalon_api.api.schemas.operations import MAX_SERIES_ID_LENGTH, BoundsCorrectionRequest

        with pytest.raises(ValidationError):
            BoundsCorrectionRequest(
                module="conn",
                lower_bounds={},
                upper_bounds={},
                reason="operator correction",
                series_id="a" * (MAX_SERIES_ID_LENGTH + 1),
            )

    def test_realistic_correction_is_accepted(self) -> None:
        """A real correction request validates unchanged."""
        from otalon_api.api.schemas.operations import BoundsCorrectionRequest

        request = BoundsCorrectionRequest(
            module="conn",
            lower_bounds={"packet_count": 0},
            upper_bounds={"packet_count": 100},
            reason="Widened after a verified maintenance window",
            series_id=SAMPLE_UCI,
        )

        assert request.series_id == SAMPLE_UCI
