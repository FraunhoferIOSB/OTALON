"""Unit tests for the UI-101 frequency-correction contract.

Covers ``api--frequency-profile-corrections`` at the schema, service and
router level:

* Preview returns a canonical diff, the ``before_snapshot`` conflict
  guard, and the detector-threshold impact without mutating anything.
* Uneditable cadence fields, non-finite/non-positive factors, and an
  unchanged payload are rejected.
* An explicit ``null`` clears an override and is reported as restoring
  the global default.
* Apply accepts an optional reason and requires the exact snapshot; a stale
  snapshot maps to HTTP 409 with no profile or history mutation.
* Suggestions carry ``observations`` / ``window_days`` / ``method`` and
  never write.
* History is scoped to exactly one series.

The repository is a mock throughout: what is under test is the contract
the router and service present, not psycopg2 behaviour. The atomic
transaction itself is covered in
``tests/integration/test_frequency_correction_transaction.py``.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import pytest
from fastapi.testclient import TestClient

from otalon_api.api.schemas.frequency import FactorSource
from otalon_api.dependencies import get_frequency_service
from otalon_api.main import app
from otalon_api.repositories.postgres_repo import (
    FrequencyProfileNotFound,
    RhythmCorrectionConflict,
)
from otalon_api.services.frequency_service import FrequencyService
from otalon_api.settings import Settings

NOW = datetime.now(timezone.utc)
SERIES = "aa:bb/cc:dd/0//////Ethernet:PROFINET_RT"
PATH_SEGMENT = "series"
"""Placeholder path segment used by the router tests.

Series identifiers are UCIs containing ``/``. Starlette decodes
percent-escapes before route matching, so a raw UCI cannot survive one
path segment; the authoritative identifier therefore travels in the
request body (POST) or the ``uci`` query parameter (GET), exactly like
the bounds-correction routes. The path segment stays a fallback.

This placeholder deliberately contains no ``/``, which is why it cannot
stand in for the real wire shape. ``TestSlashBearingSeriesRoundTrip``
covers that with :data:`REAL_CONN_SERIES` and the double-encoded segment
the browser actually sends.
"""

REAL_CONN_SERIES = (
    "7c:cb:e2:ea:0d:65/33:33:00:00:00:fb//IPv6/" "fe80::f6f7:3be0:3c8d:5089/ff02::fb/5353/5353/Ethernet:IPv6:UDP:DNS"
)
"""A verbatim production ``conn`` UCI, copied from the live database.

Eight literal ``/`` separators plus IPv6 colons — the ordinary shape of
a ``conn`` series id, not a contrived worst case.
"""


def _profile_row(
    mean_interval: float = 10.0,
    std_interval: float = 1.0,
    tolerance_override: float | None = None,
    absence_override: float | None = None,
) -> dict[str, Any]:
    """Build a ``frequency_profiles`` row as psycopg2 would return it."""
    return {
        "module": "conn",
        "series_id": SERIES,
        "mean_interval": mean_interval,
        "std_interval": std_interval,
        "last_seen": NOW - timedelta(seconds=5),
        "trained_at": NOW - timedelta(days=1),
        "tolerance_factor_override": tolerance_override,
        "absence_factor_override": absence_override,
    }


def _repo(row: dict[str, Any] | None = None) -> MagicMock:
    """Repository mock wired for the correction paths."""
    repo = MagicMock()
    profile = _profile_row() if row is None else row
    repo.query_frequency_profile_row = MagicMock(return_value=profile)
    repo.query_frequency_profiles = MagicMock(return_value=[profile] if profile else [])
    repo.query_open_frequency_anomaly = MagicMock(return_value=None)
    repo.query_frequency_events = MagicMock(return_value=[])
    repo.query_recent_frequency_events = MagicMock(return_value=[])
    repo.query_frequency_history = MagicMock(return_value=[])
    repo.correct_frequency_overrides = MagicMock(
        return_value={
            "history_id": "hist-1",
            "module": "conn",
            "series_id": SERIES,
            "action": "update",
            "tolerance_factor_override": 4.0,
            "absence_factor_override": None,
            "prior": {"tolerance_factor_override": None, "absence_factor_override": None},
            "notified": True,
        }
    )
    return repo


def _service(repo: MagicMock) -> FrequencyService:
    """Build the service under test with the shipped detector defaults."""
    return FrequencyService(
        repo,
        tolerance_default=2.0,
        absence_default=3.0,
        absence_timeout_floor_seconds=0.0,
        relative_floor_factor=0.5,
    )


OPERATOR_KEY = "test-secret"
HEADERS = {"X-API-Key": OPERATOR_KEY}


def _auth_settings() -> Settings:
    """Settings carrying an operator key so the write routes are reachable."""
    return Settings(
        influxdb_host="localhost",
        influxdb_port=8181,
        influx_token="test-token",
        influxdb_org="test-org",
        influxdb_database="netcap",
        postgres_host="localhost",
        postgres_port=5432,
        postgres_user="test",
        postgres_password="test",
        postgres_database="test",
        admin_api_key=OPERATOR_KEY,
        api_port=8090,
        netcap_measurement="network_metrics",
        netcap_id_tag="uci",
        netcap_sparse_port_threshold=10,
        default_sample_max_points=500,
    )


class UvicornPathClient(TestClient):
    """A TestClient whose path segments decode exactly once, as in production.

    ``TestClient`` transports the request through httpx's ASGI adapter,
    which fills ``scope["path"]`` from ``URL.path`` — already
    percent-decoded — while uvicorn builds it with a **single**
    ``unquote(raw_path)`` (``uvicorn/protocols/http/h11_impl.py:198``).
    The test transport therefore decodes one level more than the server
    does, so the double-encoded segment the browser sends arrives here as
    a raw UCI full of ``/`` and misses the route (404) even though the
    live API answers 200 for the identical bytes.

    Encoding each segment once more on the way out cancels that surplus
    decode, making the ASGI scope byte-identical to the one uvicorn
    produces. Without this the suite cannot express the real wire shape at
    all — which is precisely how the slash-bearing case shipped unverified.
    """

    def request(self, method: str, url: Any, *args: Any, **kwargs: Any) -> Any:
        """Re-encode the path once, then delegate to the real transport.

        Args:
            method: HTTP method.
            url: Request URL whose path is compensated.
            *args: Forwarded positionally to :meth:`TestClient.request`.
            **kwargs: Forwarded to :meth:`TestClient.request`.

        Returns:
            The httpx response.
        """
        path, _, query = str(url).partition("?")
        compensated = "/".join(quote(segment, safe="") for segment in path.split("/"))
        target = f"{compensated}?{query}" if query else compensated
        return super().request(method, target, *args, **kwargs)


@pytest.fixture()
def client_repo() -> Iterator[tuple[TestClient, MagicMock]]:
    """Provide a TestClient with the frequency service and operator key wired."""
    repo = _repo()
    app.dependency_overrides[get_frequency_service] = lambda: _service(repo)
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=_auth_settings()):
            yield TestClient(app), repo
    finally:
        app.dependency_overrides.pop(get_frequency_service, None)


@pytest.fixture()
def wire_client_repo() -> Iterator[tuple[TestClient, MagicMock]]:
    """Like :func:`client_repo`, but with production path-decoding semantics.

    See :class:`UvicornPathClient`: only this fixture reproduces the ASGI
    scope uvicorn builds for a double-encoded series-id segment.
    """
    repo = _repo()
    app.dependency_overrides[get_frequency_service] = lambda: _service(repo)
    try:
        with patch("otalon_api.middleware.auth.get_settings", return_value=_auth_settings()):
            yield UvicornPathClient(app), repo
    finally:
        app.dependency_overrides.pop(get_frequency_service, None)


class TestPreviewContract:
    """Preview returns diff, snapshot and impact and never mutates."""

    @pytest.mark.unit
    async def test_valid_preview_returns_diff_snapshot_and_impact(self) -> None:
        """A changed tolerance yields effective values, snapshot and impact."""
        repo = _repo()

        result = await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": 6.0})

        tolerance = next(entry for entry in result.diff if entry.field == "tolerance_factor.override")
        assert tolerance.old_override is None
        assert tolerance.new_override == pytest.approx(6.0)
        assert tolerance.old_effective == pytest.approx(2.0)
        assert tolerance.new_effective == pytest.approx(6.0)
        assert tolerance.old_source == FactorSource.GLOBAL_DEFAULT
        assert tolerance.new_source == FactorSource.OVERRIDE
        assert tolerance.changed is True
        assert result.before_snapshot.tolerance_factor_override is None
        assert result.impact.new_threshold_seconds == pytest.approx(6.0)
        repo.correct_frequency_overrides.assert_not_called()

    @pytest.mark.unit
    async def test_untouched_factor_is_reported_as_unchanged(self) -> None:
        """An omitted field keeps its persisted value and is flagged unchanged."""
        repo = _repo(_profile_row(absence_override=7.0))

        result = await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": 5.0})

        absence = next(entry for entry in result.diff if entry.field == "absence_factor.override")
        assert absence.changed is False
        assert absence.new_override == pytest.approx(7.0)
        assert absence.new_source == FactorSource.OVERRIDE

    @pytest.mark.unit
    async def test_explicit_null_restores_global_default(self) -> None:
        """Clearing an override reports the global default as the new source."""
        repo = _repo(_profile_row(tolerance_override=9.0))

        result = await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": None})

        tolerance = next(entry for entry in result.diff if entry.field == "tolerance_factor.override")
        assert tolerance.new_override is None
        assert tolerance.new_source == FactorSource.GLOBAL_DEFAULT
        assert tolerance.new_effective == pytest.approx(2.0)
        assert tolerance.changed is True

    @pytest.mark.unit
    async def test_unchanged_input_is_rejected(self) -> None:
        """Previewing the already-persisted value is not a correction."""
        repo = _repo(_profile_row(tolerance_override=4.0))

        with pytest.raises(ValueError, match="no override change"):
            await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": 4.0})

    @pytest.mark.unit
    @pytest.mark.parametrize("value", [0.0, -1.0, float("inf"), float("nan")])
    async def test_invalid_factor_is_rejected(self, value: float) -> None:
        """Non-finite or non-positive factors never reach the repository."""
        repo = _repo()

        with pytest.raises(ValueError, match="finite positive"):
            await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": value})
        repo.correct_frequency_overrides.assert_not_called()

    @pytest.mark.unit
    async def test_missing_profile_raises_not_found(self) -> None:
        """A series with no cadence has nothing to correct."""
        repo = _repo()
        repo.query_frequency_profile_row.return_value = None

        with pytest.raises(FrequencyProfileNotFound):
            await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": 3.0})


class TestThresholdImpact:
    """The detector's mean-interval floor must be named, not hidden."""

    @pytest.mark.unit
    async def test_floor_dominance_is_reported_with_crossover(self) -> None:
        """A tolerance under the floor is flagged with its crossover value."""
        repo = _repo(_profile_row(mean_interval=10.0, std_interval=0.2))

        result = await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": 3.0})

        assert result.impact.floor_seconds == pytest.approx(5.0)
        assert result.impact.new_threshold_seconds == pytest.approx(5.0)
        assert result.impact.floor_dominates is True
        assert result.impact.crossover_tolerance_factor == pytest.approx(25.0)

    @pytest.mark.unit
    async def test_tolerance_above_crossover_moves_the_threshold(self) -> None:
        """Past the crossover the tolerance term sets the threshold again."""
        repo = _repo(_profile_row(mean_interval=10.0, std_interval=0.2))

        result = await _service(repo).preview_override("conn", SERIES, {"tolerance_factor_override": 30.0})

        assert result.impact.floor_dominates is False
        assert result.impact.new_threshold_seconds == pytest.approx(6.0)

    @pytest.mark.unit
    async def test_absence_timeout_reflects_the_proposed_factor(self) -> None:
        """The proposed absence factor drives the reported grace period."""
        repo = _repo(_profile_row(mean_interval=10.0))

        result = await _service(repo).preview_override("conn", SERIES, {"absence_factor_override": 8.0})

        assert result.impact.absence_timeout_seconds == pytest.approx(80.0)


class TestApplyContract:
    """Apply is audited, snapshot-guarded and conflict-safe."""

    @pytest.mark.unit
    async def test_successful_apply_commits_and_reports_notification(self) -> None:
        """A matching snapshot commits overrides plus one audit row."""
        repo = _repo()

        result = await _service(repo).apply_override(
            "conn",
            SERIES,
            {"tolerance_factor_override": 4.0},
            {"tolerance_factor_override": None, "absence_factor_override": None},
            "PROFINET jitter is expected on this flow",
        )

        assert result.history_id == "hist-1"
        assert result.notified is True
        repo.correct_frequency_overrides.assert_called_once()
        args = repo.correct_frequency_overrides.call_args.args
        assert args[2] == pytest.approx(4.0)
        assert args[3] is None

    @pytest.mark.unit
    async def test_empty_reason_is_accepted_and_audited_as_empty(self) -> None:
        """An empty optional reason reaches the repository unchanged."""
        repo = _repo()

        await _service(repo).apply_override(
            "conn",
            SERIES,
            {"tolerance_factor_override": 4.0},
            {"tolerance_factor_override": None, "absence_factor_override": None},
            "",
        )

        assert repo.correct_frequency_overrides.call_args.args[5] == ""

    @pytest.mark.unit
    async def test_stale_snapshot_propagates_conflict(self) -> None:
        """The repository conflict is surfaced, not swallowed."""
        repo = _repo()
        repo.correct_frequency_overrides.side_effect = RhythmCorrectionConflict("stale")

        with pytest.raises(RhythmCorrectionConflict):
            await _service(repo).apply_override(
                "conn",
                SERIES,
                {"tolerance_factor_override": 4.0},
                {"tolerance_factor_override": 1.5, "absence_factor_override": None},
                "reason",
            )


class TestSuggestionProvenance:
    """Suggestions are advisory and always carry their evidence."""

    @pytest.mark.unit
    async def test_absence_suggestion_covers_worst_observed_gap(self) -> None:
        """The proposal exceeds the longest observed silence with margin."""
        repo = _repo(_profile_row(mean_interval=10.0, std_interval=1.0))
        repo.query_frequency_events.return_value = [
            {
                "anomaly_type": "AbsenceAnomaly",
                "start_ts": NOW - timedelta(seconds=400),
                "end_ts": NOW - timedelta(seconds=100),
            }
        ]

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.absence_factor_suggested is not None
        assert result.absence_factor_suggested * 10.0 >= 300.0
        assert result.evidence.observations == 1
        assert result.evidence.window_days == 14
        assert result.evidence.method

    @pytest.mark.unit
    async def test_suggestion_never_falls_below_the_global_default(self) -> None:
        """A short gap must not propose tightening below the shipped default."""
        repo = _repo(_profile_row(mean_interval=100.0, std_interval=1.0))
        repo.query_frequency_events.return_value = [
            {
                "anomaly_type": "AbsenceAnomaly",
                "start_ts": NOW - timedelta(seconds=20),
                "end_ts": NOW - timedelta(seconds=10),
            }
        ]

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.absence_factor_suggested is not None
        assert result.absence_factor_suggested >= 3.0

    @pytest.mark.unit
    async def test_no_evidence_yields_null_factors_with_provenance(self) -> None:
        """Zero observations produce no proposal but still report the window."""
        repo = _repo()

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.tolerance_factor_suggested is None
        assert result.absence_factor_suggested is None
        assert result.evidence.observations == 0

    @pytest.mark.unit
    async def test_suggestion_does_not_mutate(self) -> None:
        """Requesting a proposal writes nothing."""
        repo = _repo()

        await _service(repo).suggest_override("conn", SERIES)

        repo.correct_frequency_overrides.assert_not_called()


class TestSuggestionRespectsCurrentOverride:
    """A suggestion never tightens below the operator's current override.

    Regression for UI-180: ``_build_suggestion`` used to floor advisory
    factors only at the GLOBAL default, so with a looser per-profile
    override already applied it could propose a STRICTER factor —
    fighting false-positive reduction. The floor is now the current
    effective value (``override ?? default``): a suggestion only ever
    loosens or holds, never tightens below what the operator set.
    """

    @pytest.mark.unit
    async def test_absence_override_blocks_tightening_below_it(self) -> None:
        """An absence override of 5 is the floor; evidence for 3 cannot lower it."""
        repo = _repo(_profile_row(mean_interval=10.0, absence_override=5.0))
        repo.query_frequency_events.return_value = [
            {
                "anomaly_type": "AbsenceAnomaly",
                "start_ts": NOW - timedelta(seconds=26),
                "end_ts": NOW,
            }
        ]

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.absence_factor_suggested is not None
        assert result.absence_factor_suggested >= 5.0

    @pytest.mark.unit
    async def test_tolerance_override_blocks_tightening_below_it(self) -> None:
        """A tolerance override of 5 is the floor; evidence for 3 cannot lower it."""
        repo = _repo(_profile_row(mean_interval=12.0, std_interval=4.6, tolerance_override=5.0))
        repo.query_frequency_events.return_value = [
            {"anomaly_type": "FrequencyAnomaly", "start_ts": NOW, "end_ts": NOW}
        ]

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.tolerance_factor_suggested is not None
        assert result.tolerance_factor_suggested >= 5.0

    @pytest.mark.unit
    async def test_no_override_still_floors_at_global_default(self) -> None:
        """Without an override the floor stays the shipped default, not higher."""
        repo = _repo(_profile_row(mean_interval=100.0, std_interval=1.0))
        repo.query_frequency_events.return_value = [
            {
                "anomaly_type": "AbsenceAnomaly",
                "start_ts": NOW - timedelta(seconds=20),
                "end_ts": NOW - timedelta(seconds=10),
            }
        ]

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.absence_factor_suggested is not None
        assert result.absence_factor_suggested == pytest.approx(3.0)

    @pytest.mark.unit
    async def test_loosening_is_still_proposed_when_evidence_warrants(self) -> None:
        """An override below the evidence value loosens up to the evidence."""
        repo = _repo(_profile_row(mean_interval=11.5, absence_override=2.0))
        repo.query_frequency_events.return_value = [
            {
                "anomaly_type": "AbsenceAnomaly",
                "start_ts": NOW - timedelta(seconds=60),
                "end_ts": NOW,
            }
        ]

        result = await _service(repo).suggest_override("conn", SERIES)

        assert result.absence_factor_suggested is not None
        assert result.absence_factor_suggested == pytest.approx(6.0)


class TestHistoryScope:
    """History is per-series and chronological."""

    @pytest.mark.unit
    async def test_history_maps_audit_rows(self) -> None:
        """Every contract field survives the mapping."""
        repo = _repo()
        repo.query_frequency_history.return_value = [
            {
                "actor": "operator",
                "old_tolerance": 2.0,
                "new_tolerance": 5.0,
                "old_absence": None,
                "new_absence": 9.0,
                "reason": "documented maintenance window",
                "changed_at": NOW,
            }
        ]

        result = await _service(repo).get_history("conn", SERIES)

        assert result.count == 1
        record = result.data[0]
        assert record.actor == "operator"
        assert record.old_tolerance == pytest.approx(2.0)
        assert record.new_absence == pytest.approx(9.0)
        assert record.reason == "documented maintenance window"
        assert record.changed_at.startswith(NOW.isoformat()[:19])

    @pytest.mark.unit
    async def test_history_query_is_scoped_to_one_series(self) -> None:
        """The repository is asked for exactly this module and series."""
        repo = _repo()

        await _service(repo).get_history("conn", SERIES)

        repo.query_frequency_history.assert_called_once_with("conn", SERIES, 200)

    @pytest.mark.unit
    async def test_never_corrected_series_returns_empty_envelope(self) -> None:
        """An empty history is a normal state, not an error."""
        repo = _repo()

        result = await _service(repo).get_history("conn", SERIES)

        assert result.count == 0
        assert result.data == []


class TestRouterContract:
    """The HTTP surface enforces module, payload and status mapping."""

    @pytest.mark.unit
    def test_preview_route_returns_snapshot(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """The endpoint shape matches the published contract."""
        client, _ = client_repo

        response = client.post(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/preview",
            json={"series_id": SERIES, "tolerance_factor_override": 6.0},
            headers=HEADERS,
        )

        assert response.status_code == 200
        body = response.json()
        assert "before_snapshot" in body
        assert "impact" in body
        assert len(body["diff"]) == 2

    @pytest.mark.unit
    def test_cadence_field_in_payload_is_rejected(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """Learned cadence is not an editable correction field."""
        client, repo = client_repo

        response = client.post(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/preview",
            json={"series_id": SERIES, "tolerance_factor_override": 6.0, "mean_interval_seconds": 3.0},
            headers=HEADERS,
        )

        assert response.status_code == 422
        repo.correct_frequency_overrides.assert_not_called()

    @pytest.mark.unit
    def test_apply_without_reason_is_allowed(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """An Apply payload may omit the optional reason."""
        client, repo = client_repo

        response = client.post(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/apply",
            json={
                "series_id": SERIES,
                "tolerance_factor_override": 6.0,
                "before_snapshot": {"tolerance_factor_override": None, "absence_factor_override": None},
            },
            headers=HEADERS,
        )

        assert response.status_code == 200
        repo.correct_frequency_overrides.assert_called_once()

    @pytest.mark.unit
    def test_apply_without_snapshot_is_rejected(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """Apply cannot run unguarded."""
        client, repo = client_repo

        response = client.post(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/apply",
            json={"series_id": SERIES, "tolerance_factor_override": 6.0, "reason": "why"},
            headers=HEADERS,
        )

        assert response.status_code == 422
        repo.correct_frequency_overrides.assert_not_called()

    @pytest.mark.unit
    def test_stale_snapshot_maps_to_409(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """A conflict is a 409, not a 500."""
        client, repo = client_repo
        repo.correct_frequency_overrides.side_effect = RhythmCorrectionConflict("stale")

        response = client.post(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/apply",
            json={
                "series_id": SERIES,
                "tolerance_factor_override": 6.0,
                "before_snapshot": {"tolerance_factor_override": 1.0, "absence_factor_override": None},
                "reason": "documented",
            },
            headers=HEADERS,
        )

        assert response.status_code == 409

    @pytest.mark.unit
    def test_unknown_module_is_rejected(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """``netcap`` is a database name, never a profiled module."""
        client, _ = client_repo

        response = client.post(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/preview?module=netcap",
            json={"series_id": SERIES, "tolerance_factor_override": 6.0},
            headers=HEADERS,
        )

        assert response.status_code == 400

    @pytest.mark.unit
    def test_history_route_returns_scoped_envelope(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """The history endpoint echoes its module and series."""
        client, _ = client_repo

        response = client.get(
            f"/api/v1/frequency/{PATH_SEGMENT}/history?uci={quote(SERIES, safe='')}",
            headers=HEADERS,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["series_id"] == SERIES
        assert body["module"] == "conn"

    @pytest.mark.unit
    def test_events_route_returns_scoped_envelope(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """The event timeline echoes its module and series."""
        client, repo = client_repo
        repo.query_recent_frequency_events.return_value = [
            {"anomaly_type": "AbsenceAnomaly", "start_ts": NOW, "end_ts": NOW, "confidence": 1.0}
        ]

        response = client.get(
            f"/api/v1/frequency/{PATH_SEGMENT}/events?uci={quote(SERIES, safe='')}",
            headers=HEADERS,
        )

        assert response.status_code == 200
        body = response.json()
        assert body["series_id"] == SERIES
        assert body["module"] == "conn"
        assert body["data"][0]["anomaly_type"] == "AbsenceAnomaly"

    @pytest.mark.unit
    def test_events_route_requires_an_operator_key(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """The timeline is operator-scoped like every other per-series read."""
        client, _ = client_repo

        response = client.get(f"/api/v1/frequency/{PATH_SEGMENT}/events?uci={quote(SERIES, safe='')}")

        assert response.status_code == 401

    @pytest.mark.unit
    def test_events_route_rejects_an_unprofiled_module(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """`netcap` is a database name, never a profiled module."""
        client, _ = client_repo

        response = client.get(
            f"/api/v1/frequency/{PATH_SEGMENT}/events?module=netcap&uci={quote(SERIES, safe='')}",
            headers=HEADERS,
        )

        assert response.status_code == 400

    @pytest.mark.unit
    def test_events_route_caps_the_requested_limit(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """An unbounded limit would stream the whole anomalies table."""
        client, _ = client_repo

        response = client.get(
            f"/api/v1/frequency/{PATH_SEGMENT}/events?limit=5000&uci={quote(SERIES, safe='')}",
            headers=HEADERS,
        )

        assert response.status_code == 422

    @pytest.mark.unit
    def test_suggest_route_returns_evidence(self, client_repo: tuple[TestClient, MagicMock]) -> None:
        """Provenance travels with every suggestion."""
        client, _ = client_repo

        response = client.get(
            f"/api/v1/frequency/{PATH_SEGMENT}/override/suggest?uci={quote(SERIES, safe='')}",
            headers=HEADERS,
        )

        assert response.status_code == 200
        evidence = response.json()["evidence"]
        assert set(evidence) == {"observations", "window_days", "method"}


class TestSlashBearingSeriesRoundTrip:
    """The real ``conn`` UCI shape survives every correction route.

    A production ``conn`` series id carries eight or more literal ``/``
    separators — that is the normal case, not an edge case. The rest of
    the router tests use the ``PATH_SEGMENT`` placeholder, which never
    contains one, so nothing exercised what the browser actually sends:
    a **double**-encoded path segment (``%252F``), because Starlette
    percent-decodes once before route matching and a single-encoded
    ``%2F`` would decode to a real separator and miss the route (404).

    These tests pin the whole contract for that shape: the double-encoded
    segment matches the route, the authoritative body/query identifier
    reaches the repository un-mangled, a single-encoded segment is
    rejected rather than silently mis-resolved, and Preview → Apply
    round-trips for one and the same series.
    """

    @pytest.mark.unit
    def test_double_encoded_segment_previews_and_applies(self, wire_client_repo: tuple[TestClient, MagicMock]) -> None:
        """Preview then Apply both resolve the real slash-bearing series."""
        client, repo = wire_client_repo
        segment = quote(quote(REAL_CONN_SERIES, safe=""), safe="")

        preview = client.post(
            f"/api/v1/frequency/{segment}/override/preview?module=conn",
            json={"series_id": REAL_CONN_SERIES, "tolerance_factor_override": 6.0},
            headers=HEADERS,
        )

        assert preview.status_code == 200
        snapshot = preview.json()["before_snapshot"]

        applied = client.post(
            f"/api/v1/frequency/{segment}/override/apply?module=conn",
            json={
                "series_id": REAL_CONN_SERIES,
                "tolerance_factor_override": 6.0,
                "before_snapshot": snapshot,
                "reason": "slash-bearing round trip",
            },
            headers=HEADERS,
        )

        assert applied.status_code == 200
        assert repo.correct_frequency_overrides.call_args.args[1] == REAL_CONN_SERIES

    @pytest.mark.unit
    def test_path_segment_alone_resolves_the_series(self, wire_client_repo: tuple[TestClient, MagicMock]) -> None:
        """With no body override the double-encoded path is decoded once."""
        client, repo = wire_client_repo
        segment = quote(quote(REAL_CONN_SERIES, safe=""), safe="")

        response = client.post(
            f"/api/v1/frequency/{segment}/override/preview?module=conn",
            json={"tolerance_factor_override": 6.0},
            headers=HEADERS,
        )

        assert response.status_code == 200
        assert response.json()["series_id"] == REAL_CONN_SERIES
        assert repo.query_frequency_profile_row.call_args.args[1] == REAL_CONN_SERIES

    @pytest.mark.unit
    def test_single_encoded_segment_does_not_match_the_route(
        self, wire_client_repo: tuple[TestClient, MagicMock]
    ) -> None:
        """A single-encoded UCI decodes to separators and misses the route.

        This is the failure the double-encoding exists to prevent; pinning
        it keeps a future "simplification" back to one encode honest.
        """
        client, _ = wire_client_repo
        segment = quote(REAL_CONN_SERIES, safe="")

        response = client.post(
            f"/api/v1/frequency/{segment}/override/preview?module=conn",
            json={"series_id": REAL_CONN_SERIES, "tolerance_factor_override": 6.0},
            headers=HEADERS,
        )

        assert response.status_code == 404

    @pytest.mark.unit
    def test_history_and_suggest_accept_the_slash_bearing_series(
        self, wire_client_repo: tuple[TestClient, MagicMock]
    ) -> None:
        """Both GET routes echo the full identifier they were asked for."""
        client, _ = wire_client_repo
        segment = quote(quote(REAL_CONN_SERIES, safe=""), safe="")
        query = f"module=conn&uci={quote(REAL_CONN_SERIES, safe='')}"

        history = client.get(f"/api/v1/frequency/{segment}/history?{query}", headers=HEADERS)
        suggest = client.get(f"/api/v1/frequency/{segment}/override/suggest?{query}", headers=HEADERS)

        assert history.status_code == 200
        assert history.json()["series_id"] == REAL_CONN_SERIES
        assert suggest.status_code == 200
        assert suggest.json()["series_id"] == REAL_CONN_SERIES

    @pytest.mark.unit
    def test_correction_routes_require_an_operator_key(self, wire_client_repo: tuple[TestClient, MagicMock]) -> None:
        """Unkeyed correction traffic is refused, not served.

        ``/api/v1/frequency`` is not in the middleware's
        ``PROTECTED_PATH_PREFIXES``; the guard is the per-route
        ``Depends(require_operator_api_key)``. UI-101 shipped with the
        browser reaching this subtree through the transparent Nuxt proxy,
        which injects no key — every correction answered 401 and the
        drawer showed "Server preview failed". The UI now routes through
        `server/api/v1/frequency/[...path].ts`; this asserts the backend
        half of that contract stays enforced.
        """
        client, _ = wire_client_repo
        segment = quote(quote(REAL_CONN_SERIES, safe=""), safe="")

        response = client.post(
            f"/api/v1/frequency/{segment}/override/preview?module=conn",
            json={"series_id": REAL_CONN_SERIES, "tolerance_factor_override": 6.0},
        )

        assert response.status_code == 401
