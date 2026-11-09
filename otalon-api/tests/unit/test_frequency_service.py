"""Unit tests for FrequencyService and the /api/v1/frequency router.

Covers the derived quantities the RHYTHM lane depends on: effective
factor resolution with provenance, the absence deadline, the detector
state machine, and the contract that "no profile" is a first-class
non-error outcome rather than a 404.
"""

from __future__ import annotations

from collections.abc import Iterator
from datetime import datetime, timedelta, timezone
from typing import Any
from unittest.mock import MagicMock

import pytest
from fastapi.testclient import TestClient

from otalon_api.api.schemas.frequency import FactorSource, RhythmState
from otalon_api.dependencies import get_frequency_service
from otalon_api.main import app
from otalon_api.services.frequency_service import FrequencyService
from otalon_api.settings import Settings

NOW_ISH = datetime.now(timezone.utc)
SAMPLE_UCI = "a8:74:1d:02:99:8d/00:01:05:93:50:9b/0//////Ethernet:VLAN:PROFINET_RT:PROFINET_RT_IO"


def _profile_row(
    series_id: str = SAMPLE_UCI,
    module: str = "conn",
    mean_interval: float = 10.0,
    std_interval: float = 1.0,
    last_seen: datetime | None = None,
    tolerance_override: float | None = None,
    absence_override: float | None = None,
) -> dict[str, Any]:
    """Build a frequency_profiles row dict as psycopg2 would return it."""
    return {
        "module": module,
        "series_id": series_id,
        "mean_interval": mean_interval,
        "std_interval": std_interval,
        "last_seen": last_seen,
        "trained_at": NOW_ISH - timedelta(days=2),
        "tolerance_factor_override": tolerance_override,
        "absence_factor_override": absence_override,
    }


def _service(repo: MagicMock) -> FrequencyService:
    """Build the service under test with the shipped global defaults."""
    return FrequencyService(
        repo,
        tolerance_default=2.0,
        absence_default=3.0,
        absence_timeout_floor_seconds=0.0,
    )


def _proto_service(repo: MagicMock, resolver: MagicMock) -> FrequencyService:
    """Build a frequency service with protocol hash resolution enabled."""
    return FrequencyService(repo, proto_resolver=resolver, absence_timeout_floor_seconds=0.0)


@pytest.fixture()
def freq_repo() -> MagicMock:
    """Repository mock exposing the two frequency query methods."""
    repo = MagicMock()
    repo.query_frequency_profiles = MagicMock(return_value=[])
    repo.query_open_frequency_anomaly = MagicMock(return_value=None)
    repo.count_recent_absence_anomalies = MagicMock(return_value={})
    repo.count_recent_frequency_anomalies = MagicMock(return_value={})
    repo.query_recent_frequency_events = MagicMock(return_value=[])
    return repo


class TestNoProfileIsNotAnError:
    """A series without a trained cadence is an ordinary state."""

    @pytest.mark.unit
    async def test_missing_profile_returns_no_profile_state(self, freq_repo: MagicMock) -> None:
        """An unprofiled series yields has_profile=False, not an exception."""
        result = await _service(freq_repo).get_profile("conn", "unknown-series")

        assert result.has_profile is False
        assert result.state == RhythmState.NO_PROFILE
        assert result.series_id == "unknown-series"
        assert result.mean_interval_seconds is None
        assert result.absence_deadline is None

    @pytest.mark.unit
    async def test_wildcard_conn_resolves_to_profiled_sibling(self, freq_repo: MagicMock) -> None:
        """A port-collapsed UCI uses the concrete trained sibling's profile."""
        wildcard = "aa:bb:cc:dd:ee:01/aa:bb:cc:dd:ee:02/0/17/192.0.2.1/192.0.2.2/*/*/UDP"
        sibling = wildcard.replace("*/*", "50000/56247")
        freq_repo.query_all_profiled_series_ids.return_value = {sibling}
        freq_repo.query_frequency_profiles.return_value = [_profile_row(sibling, mean_interval=42.0)]

        result = await _service(freq_repo).get_profile("conn", wildcard)

        assert result.has_profile is True
        assert result.series_id == sibling
        assert result.mean_interval_seconds == 42.0


class TestProtoSeriesDisplay:
    """Protocol hash series receive a readable display value only."""

    @pytest.mark.unit
    async def test_get_profile_resolves_proto_series(self, freq_repo: MagicMock) -> None:
        resolver = MagicMock()
        resolver.resolve_many.return_value = ["PROFINET"]
        freq_repo.query_frequency_profiles.return_value = [_profile_row("481221027", "proto_traffic")]

        result = await _proto_service(freq_repo, resolver).get_profile("proto_traffic", "481221027")

        assert result.series_display == "PROFINET"
        resolver.resolve_many.assert_called_once_with(["481221027"])

    @pytest.mark.unit
    async def test_list_profiles_falls_back_for_unknown_proto_hash(self, freq_repo: MagicMock) -> None:
        resolver = MagicMock()
        resolver.resolve_many.return_value = ["481221027"]
        freq_repo.query_frequency_profiles.return_value = [_profile_row("481221027", "proto_traffic")]

        result = await _proto_service(freq_repo, resolver).list_profiles("proto_traffic")

        assert result[0].series_display == "481221027"

    @pytest.mark.unit
    async def test_non_proto_profile_has_no_series_display(self, freq_repo: MagicMock) -> None:
        resolver = MagicMock()
        freq_repo.query_frequency_profiles.return_value = [_profile_row("conn-1", "conn")]

        result = await _proto_service(freq_repo, resolver).get_profile("conn", "conn-1")

        assert result.series_display is None
        resolver.resolve_many.assert_not_called()

    @pytest.mark.unit
    async def test_requested_but_unprofiled_series_are_listed_explicitly(self, freq_repo: MagicMock) -> None:
        """list_profiles distinguishes 'not profiled' from 'not asked for'."""
        freq_repo.query_frequency_profiles.return_value = [_profile_row(series_id="known")]

        results = await _service(freq_repo).list_profiles("conn", ["known", "missing"])

        by_id = {r.series_id: r for r in results}
        assert by_id["known"].has_profile is True
        assert by_id["missing"].has_profile is False
        assert by_id["missing"].state == RhythmState.NO_PROFILE


class TestRecentAbsenceCount:
    """History counts are optional and never alter live rhythm state."""

    @pytest.mark.unit
    async def test_count_defaults_to_zero_without_since(self, freq_repo: MagicMock) -> None:
        """Existing callers receive zero and do not query anomaly history."""
        freq_repo.query_frequency_profiles.return_value = [_profile_row(last_seen=NOW_ISH)]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.recent_absence_count == 0
        assert result.recent_frequency_anomaly_count == 0
        freq_repo.count_recent_absence_anomalies.assert_not_called()
        freq_repo.count_recent_frequency_anomalies.assert_not_called()

    @pytest.mark.unit
    @pytest.mark.parametrize("count", [0, 1, 3])
    async def test_count_comes_from_absence_episodes_in_requested_window(
        self, freq_repo: MagicMock, count: int
    ) -> None:
        """The batched repository count is exposed per profile."""
        since = NOW_ISH - timedelta(hours=24)
        freq_repo.query_frequency_profiles.return_value = [_profile_row(last_seen=NOW_ISH)]
        freq_repo.count_recent_absence_anomalies.return_value = {SAMPLE_UCI: count}
        freq_repo.count_recent_frequency_anomalies.return_value = {SAMPLE_UCI: 2}

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI, since)

        assert result.recent_absence_count == count
        assert result.recent_frequency_anomaly_count == 2
        freq_repo.count_recent_absence_anomalies.assert_called_once_with("conn", [SAMPLE_UCI], since)
        freq_repo.count_recent_frequency_anomalies.assert_called_once_with("conn", [SAMPLE_UCI], since)

    @pytest.mark.unit
    async def test_fleet_count_is_batched_and_missing_series_is_zero(self, freq_repo: MagicMock) -> None:
        """Fleet loading uses one aggregate result and zero-fills absent keys."""
        since = NOW_ISH - timedelta(hours=24)
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(series_id="a", last_seen=NOW_ISH),
            _profile_row(series_id="b", last_seen=NOW_ISH),
        ]
        freq_repo.count_recent_absence_anomalies.return_value = {"a": 2}
        freq_repo.count_recent_frequency_anomalies.return_value = {"a": 4}

        results = await _service(freq_repo).list_profiles("conn", since=since)

        assert {item.series_id: item.recent_absence_count for item in results} == {"a": 2, "b": 0}
        assert {item.series_id: item.recent_frequency_anomaly_count for item in results} == {"a": 4, "b": 0}
        freq_repo.count_recent_absence_anomalies.assert_called_once_with("conn", ["a", "b"], since)
        freq_repo.count_recent_frequency_anomalies.assert_called_once_with("conn", ["a", "b"], since)


class TestRhythmEventTimeline:
    """Per-series episode timeline backing the Rhythm Review drawer."""

    @pytest.mark.unit
    async def test_episodes_are_mapped_with_derived_duration(self, freq_repo: MagicMock) -> None:
        """Duration comes from the persisted interval, not a fresh measurement."""
        start = NOW_ISH - timedelta(minutes=5)
        freq_repo.query_recent_frequency_events.return_value = [
            {
                "anomaly_type": "AbsenceAnomaly",
                "start_ts": start,
                "end_ts": start + timedelta(seconds=51),
                "confidence": 1.0,
            }
        ]

        result = await _service(freq_repo).get_events("conn", SAMPLE_UCI)

        assert result.count == 1
        assert result.data[0].anomaly_type == "AbsenceAnomaly"
        assert result.data[0].duration_seconds == 51.0
        assert result.truncated is False

    @pytest.mark.unit
    async def test_missing_end_instant_yields_no_invented_duration(self, freq_repo: MagicMock) -> None:
        """An open episode has no measured length and must not report zero."""
        freq_repo.query_recent_frequency_events.return_value = [
            {"anomaly_type": "FrequencyAnomaly", "start_ts": NOW_ISH, "end_ts": None, "confidence": 0.7}
        ]

        result = await _service(freq_repo).get_events("conn", SAMPLE_UCI)

        assert result.data[0].duration_seconds is None
        assert result.data[0].end_ts is None

    @pytest.mark.unit
    async def test_never_deviating_series_is_an_empty_envelope(self, freq_repo: MagicMock) -> None:
        """No episodes is a normal outcome, not an error."""
        result = await _service(freq_repo).get_events("conn", SAMPLE_UCI)

        assert result.count == 0
        assert result.data == []

    @pytest.mark.unit
    async def test_overflow_is_trimmed_and_declared(self, freq_repo: MagicMock) -> None:
        """More matches than the limit are cut and flagged, never silently dropped."""
        freq_repo.query_recent_frequency_events.return_value = [
            {"anomaly_type": "AbsenceAnomaly", "start_ts": NOW_ISH, "end_ts": NOW_ISH, "confidence": 1.0}
            for _ in range(4)
        ]

        result = await _service(freq_repo).get_events("conn", SAMPLE_UCI, limit=3)

        assert result.count == 3
        assert result.truncated is True
        # One extra row is fetched purely to detect the overflow.
        freq_repo.query_recent_frequency_events.assert_called_once_with("conn", SAMPLE_UCI, None, 4)

    @pytest.mark.unit
    async def test_unbounded_window_is_forwarded_as_none(self, freq_repo: MagicMock) -> None:
        """The All range has no lower bound and must not be faked into one."""
        await _service(freq_repo).get_events("conn", SAMPLE_UCI, since=None, limit=10)

        assert freq_repo.query_recent_frequency_events.call_args.args[2] is None


class TestEffectiveFactors:
    """``override ?? global_default`` with explicit provenance."""

    @pytest.mark.unit
    async def test_global_defaults_when_no_override(self, freq_repo: MagicMock) -> None:
        """Both factors report the global default and say so."""
        freq_repo.query_frequency_profiles.return_value = [_profile_row(last_seen=NOW_ISH)]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.tolerance_factor is not None
        assert result.tolerance_factor.value == pytest.approx(2.0)
        assert result.tolerance_factor.source == FactorSource.GLOBAL_DEFAULT
        assert result.tolerance_factor.override is None
        assert result.absence_factor is not None
        assert result.absence_factor.value == pytest.approx(3.0)
        assert result.absence_factor.source == FactorSource.GLOBAL_DEFAULT

    @pytest.mark.unit
    async def test_operator_override_wins_and_is_named(self, freq_repo: MagicMock) -> None:
        """An override supersedes the default and is reported as such."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(last_seen=NOW_ISH, tolerance_override=4.5, absence_override=8.0)
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.tolerance_factor is not None
        assert result.tolerance_factor.value == pytest.approx(4.5)
        assert result.tolerance_factor.source == FactorSource.OVERRIDE
        assert result.tolerance_factor.global_default == pytest.approx(2.0)
        assert result.absence_factor is not None
        assert result.absence_factor.value == pytest.approx(8.0)
        assert result.absence_factor.source == FactorSource.OVERRIDE


class TestAbsenceDeadline:
    """The deadline must mirror the detector's own arithmetic."""

    @pytest.mark.unit
    async def test_deadline_is_last_seen_plus_mean_times_absence_factor(self, freq_repo: MagicMock) -> None:
        """deadline = last_seen + mean_interval * effective_absence_factor."""
        last_seen = NOW_ISH - timedelta(seconds=5)
        freq_repo.query_frequency_profiles.return_value = [_profile_row(mean_interval=10.0, last_seen=last_seen)]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.absence_timeout_seconds == pytest.approx(30.0)
        assert result.absence_deadline == (last_seen + timedelta(seconds=30)).isoformat()

    @pytest.mark.unit
    async def test_short_timeout_uses_detector_floor(self, freq_repo: MagicMock) -> None:
        """API deadline matches detector floor for short-interval profile."""
        last_seen = NOW_ISH - timedelta(seconds=5)
        freq_repo.query_frequency_profiles.return_value = [_profile_row(mean_interval=1.0, last_seen=last_seen)]
        service = FrequencyService(freq_repo, absence_timeout_floor_seconds=45.0)
        result = await service.get_profile("conn", SAMPLE_UCI)
        assert result.absence_timeout_seconds == pytest.approx(45.0)
        assert result.absence_deadline == (last_seen + timedelta(seconds=45)).isoformat()

    @pytest.mark.unit
    async def test_override_changes_the_deadline(self, freq_repo: MagicMock) -> None:
        """An absence override moves the deadline the detector would use."""
        last_seen = NOW_ISH - timedelta(seconds=5)
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=last_seen, absence_override=6.0)
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.absence_timeout_seconds == pytest.approx(60.0)

    @pytest.mark.unit
    async def test_no_deadline_without_last_seen(self, freq_repo: MagicMock) -> None:
        """A profile never observed has nothing to count down from."""
        freq_repo.query_frequency_profiles.return_value = [_profile_row(last_seen=None)]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.absence_deadline is None
        assert result.seconds_until_deadline is None
        assert result.state == RhythmState.NO_LAST_SEEN

    @pytest.mark.unit
    async def test_countdown_goes_negative_once_exceeded(self, freq_repo: MagicMock) -> None:
        """seconds_until_deadline is signed, not clamped."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=NOW_ISH - timedelta(seconds=300))
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.seconds_until_deadline is not None
        assert result.seconds_until_deadline < 0

    @pytest.mark.unit
    async def test_above_interval_cap_no_deadline(self, freq_repo: MagicMock) -> None:
        """Mean interval above cap yields no deadline."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=86401.0, last_seen=NOW_ISH - timedelta(seconds=5))
        ]
        svc = FrequencyService(freq_repo, absence_interval_cap_seconds=86400.0)
        result = await svc.get_profile("conn", SAMPLE_UCI)

        assert result.absence_timeout_seconds is None
        assert result.absence_deadline is None
        assert result.seconds_until_deadline is None

    @pytest.mark.unit
    async def test_below_interval_cap_normal_deadline(self, freq_repo: MagicMock) -> None:
        """Mean interval below cap yields normal deadline."""
        last_seen = NOW_ISH - timedelta(seconds=5)
        freq_repo.query_frequency_profiles.return_value = [_profile_row(mean_interval=86400.0, last_seen=last_seen)]
        svc = FrequencyService(freq_repo, absence_interval_cap_seconds=86400.0)
        result = await svc.get_profile("conn", SAMPLE_UCI)

        assert result.absence_timeout_seconds == pytest.approx(86400.0 * 3.0)
        assert result.absence_deadline is not None


class TestRhythmState:
    """Detector-state resolution."""

    @pytest.mark.unit
    async def test_recent_observation_is_normal(self, freq_repo: MagicMock) -> None:
        """Fresh data inside the grace period reads normal."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=NOW_ISH - timedelta(seconds=2))
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.NORMAL

    @pytest.mark.unit
    async def test_exceeded_deadline_is_absence_even_without_a_row(self, freq_repo: MagicMock) -> None:
        """The deadline closes the window before otalon-clas writes the row."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=NOW_ISH - timedelta(seconds=600))
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.ABSENCE_ACTIVE

    @pytest.mark.unit
    async def test_open_frequency_anomaly_row_is_reported(self, freq_repo: MagicMock) -> None:
        """A live FrequencyAnomaly interval surfaces as the state."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=NOW_ISH - timedelta(seconds=2))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "FrequencyAnomaly",
            "start_ts": NOW_ISH - timedelta(seconds=90),
            "end_ts": NOW_ISH - timedelta(seconds=5),
            "confidence": 0.8,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.FREQUENCY_ANOMALY
        assert result.active_anomaly_type == "FrequencyAnomaly"
        assert result.active_anomaly_since is not None

    @pytest.mark.unit
    async def test_stale_anomaly_row_is_not_reported_as_active(self, freq_repo: MagicMock) -> None:
        """A long-finished episode must not masquerade as running."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=NOW_ISH - timedelta(seconds=2))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "FrequencyAnomaly",
            "start_ts": NOW_ISH - timedelta(days=3),
            "end_ts": NOW_ISH - timedelta(days=3) + timedelta(seconds=30),
            "confidence": 0.8,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.NORMAL
        assert result.active_anomaly_type is None

    @pytest.mark.unit
    async def test_fast_series_is_not_absent_from_write_back_lag_alone(self, freq_repo: MagicMock) -> None:
        """A live 1 s-cadence PROFINET flow must not read as absent.

        Regression for a defect found against the live stack: with
        mean_interval = 1 s the absence timeout is 3 s, while the
        detector flushes last_seen to PostgreSQL only every 60 s. The
        persisted value is therefore routinely "past the deadline" for a
        perfectly healthy connection, and otalon-clas correctly wrote
        no AbsenceAnomaly row for it.
        """
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(
                mean_interval=1.0,
                last_seen=datetime.now(timezone.utc) - timedelta(seconds=32),
            )
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.seconds_until_deadline is not None
        assert result.seconds_until_deadline < 0
        assert result.state == RhythmState.NORMAL

    @pytest.mark.unit
    async def test_silence_beyond_the_write_lag_budget_is_absence(self, freq_repo: MagicMock) -> None:
        """Past the write-lag budget the deadline is trusted again."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(
                mean_interval=1.0,
                last_seen=datetime.now(timezone.utc) - timedelta(seconds=600),
            )
        ]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.ABSENCE_ACTIVE

    @pytest.mark.unit
    async def test_persisted_absence_row_wins_inside_the_budget(self, freq_repo: MagicMock) -> None:
        """The detector's own verdict is authoritative, lag notwithstanding."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(
                mean_interval=1.0,
                last_seen=datetime.now(timezone.utc) - timedelta(seconds=20),
            )
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "AbsenceAnomaly",
            "start_ts": datetime.now(timezone.utc) - timedelta(seconds=17),
            "end_ts": datetime.now(timezone.utc) - timedelta(seconds=2),
            "confidence": 1.0,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.ABSENCE_ACTIVE

    @pytest.mark.unit
    async def test_recovered_series_is_normal_despite_a_past_absence_row(self, freq_repo: MagicMock) -> None:
        """A fresh last_seen beats a finished absence episode.

        Regression for a defect found against the live stack: after an
        ettercap MitM ended, the connection resumed (last_seen 32 s ago,
        deadline still ahead) while the AbsenceAnomaly row written during
        the disruption was still inside the open-anomaly grace window.
        The lane then read "Absence active · seen 32s ago", which is
        self-contradictory. An observation that postdates the episode's
        end_ts proves the series recovered.
        """
        now = datetime.now(timezone.utc)
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=4.2, last_seen=now - timedelta(seconds=32))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "AbsenceAnomaly",
            "start_ts": now - timedelta(seconds=240),
            "end_ts": now - timedelta(seconds=60),
            "confidence": 1.0,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.NORMAL
        assert result.active_anomaly_type is None
        assert result.seconds_since_last_seen is not None
        assert result.seconds_since_last_seen < 60

    @pytest.mark.unit
    async def test_currently_silent_series_stays_absent(self, freq_repo: MagicMock) -> None:
        """Silence past the deadline still reads absence_active.

        The recovery rule must not disarm the absence verdict for a
        series that is genuinely still quiet: here last_seen predates the
        episode's end_ts, so nothing has been observed since.
        """
        now = datetime.now(timezone.utc)
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=4.2, last_seen=now - timedelta(seconds=300))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "AbsenceAnomaly",
            "start_ts": now - timedelta(seconds=287),
            "end_ts": now - timedelta(seconds=5),
            "confidence": 1.0,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.ABSENCE_ACTIVE
        assert result.active_anomaly_type == "AbsenceAnomaly"

    @pytest.mark.unit
    async def test_recovery_never_contradicts_a_future_deadline(self, freq_repo: MagicMock) -> None:
        """A future deadline and absence_active can never coexist."""
        now = datetime.now(timezone.utc)
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=600.0, last_seen=now - timedelta(seconds=32))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "AbsenceAnomaly",
            "start_ts": now - timedelta(seconds=900),
            "end_ts": now - timedelta(seconds=90),
            "confidence": 1.0,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.seconds_until_deadline is not None
        assert result.seconds_until_deadline > 0
        assert result.state == RhythmState.NORMAL

    @pytest.mark.unit
    async def test_recovery_rule_does_not_disarm_a_frequency_verdict(self, freq_repo: MagicMock) -> None:
        """Only absence is recovery-gated; FrequencyAnomaly is unaffected.

        A frequency verdict is derived from observed intervals, so fresh
        arrivals are exactly what it is computed from and must not
        cancel it.
        """
        now = datetime.now(timezone.utc)
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=4.2, last_seen=now - timedelta(seconds=2))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "FrequencyAnomaly",
            "start_ts": now - timedelta(seconds=90),
            "end_ts": now - timedelta(seconds=30),
            "confidence": 0.8,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.FREQUENCY_ANOMALY

    @pytest.mark.unit
    async def test_absence_outranks_a_stale_frequency_verdict(self, freq_repo: MagicMock) -> None:
        """While silent, there are no intervals to judge — absence wins."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(mean_interval=10.0, last_seen=NOW_ISH - timedelta(seconds=600))
        ]
        freq_repo.query_open_frequency_anomaly.return_value = {
            "anomaly_type": "AbsenceAnomaly",
            "start_ts": NOW_ISH - timedelta(seconds=570),
            "end_ts": NOW_ISH - timedelta(seconds=5),
            "confidence": 1.0,
        }

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        assert result.state == RhythmState.ABSENCE_ACTIVE
        assert result.active_anomaly_type == "AbsenceAnomaly"


class TestSelfConsistentClock:
    """All derived instants must reconcile against one server clock."""

    @pytest.mark.unit
    async def test_now_reconciles_with_the_derived_durations(self, freq_repo: MagicMock) -> None:
        """seconds_since_last_seen equals now - last_seen exactly."""
        last_seen = NOW_ISH - timedelta(seconds=42)
        freq_repo.query_frequency_profiles.return_value = [_profile_row(mean_interval=10.0, last_seen=last_seen)]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        now = datetime.fromisoformat(result.now)
        assert result.seconds_since_last_seen == pytest.approx((now - last_seen).total_seconds())
        assert result.last_seen == last_seen.isoformat()

    @pytest.mark.unit
    async def test_naive_db_timestamps_are_treated_as_utc(self, freq_repo: MagicMock) -> None:
        """A naive timestamp must not silently shift by the local offset.

        Asserted against the response's own ``now`` rather than wall
        clock, so the check stays exact regardless of how long the
        surrounding suite runs.
        """
        aware = datetime.now(timezone.utc) - timedelta(seconds=30)
        naive = aware.replace(tzinfo=None)
        freq_repo.query_frequency_profiles.return_value = [_profile_row(mean_interval=10.0, last_seen=naive)]

        result = await _service(freq_repo).get_profile("conn", SAMPLE_UCI)

        now = datetime.fromisoformat(result.now)
        assert result.last_seen == aware.isoformat()
        assert result.seconds_since_last_seen == pytest.approx((now - aware).total_seconds())


@pytest.fixture()
def freq_client(freq_repo: MagicMock, monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    """TestClient with the frequency service overridden."""
    app.dependency_overrides[get_frequency_service] = lambda: _service(freq_repo)
    test_key = "test-suite-key-do-not-use-in-prod"
    monkeypatch.setattr("otalon_api.middleware.auth.get_settings", lambda: Settings(admin_api_key=test_key))
    yield TestClient(app, headers={"X-API-Key": test_key})
    app.dependency_overrides.pop(get_frequency_service, None)


class TestFrequencyRouter:
    """HTTP surface: validation, error mapping, module support."""

    @pytest.mark.unit
    def test_profile_endpoint_returns_200_for_unprofiled_series(
        self, freq_client: TestClient, freq_repo: MagicMock
    ) -> None:
        """ "No profile" is 200 with a state, never a 404."""
        response = freq_client.get("/api/v1/frequency/profile", params={"uci": "nope", "module": "conn"})

        assert response.status_code == 200
        assert response.json()["state"] == "no_profile"
        assert response.json()["has_profile"] is False

    @pytest.mark.unit
    def test_unknown_module_is_rejected(self, freq_client: TestClient) -> None:
        """A module without frequency profiles is a 400."""
        response = freq_client.get("/api/v1/frequency/profile", params={"uci": SAMPLE_UCI, "module": "netcap"})

        assert response.status_code == 400
        assert "netcap" in response.json()["detail"]

    @pytest.mark.unit
    def test_empty_uci_is_rejected(self, freq_client: TestClient) -> None:
        """An empty series identifier is a client error."""
        response = freq_client.get("/api/v1/frequency/profile", params={"uci": "", "module": "conn"})

        assert response.status_code == 400

    @pytest.mark.unit
    @pytest.mark.parametrize("module", ["conn", "mac_traffic", "proto_traffic"])
    def test_all_profiled_modules_are_supported(self, freq_client: TestClient, module: str) -> None:
        """Every module otalon-clas profiles is reachable."""
        response = freq_client.get("/api/v1/frequency/profile", params={"uci": "x", "module": module})

        assert response.status_code == 200
        assert response.json()["module"] == module

    @pytest.mark.unit
    def test_repository_failure_maps_to_500(self, freq_client: TestClient, freq_repo: MagicMock) -> None:
        """A database error is a server error, not a silent empty result."""
        freq_repo.query_frequency_profiles.side_effect = RuntimeError("db down")

        response = freq_client.get("/api/v1/frequency/profile", params={"uci": SAMPLE_UCI, "module": "conn"})

        assert response.status_code == 500

    @pytest.mark.unit
    def test_list_endpoint_returns_envelope(self, freq_client: TestClient, freq_repo: MagicMock) -> None:
        """The list route wraps entries with module and count."""
        freq_repo.query_frequency_profiles.return_value = [
            _profile_row(series_id="a", last_seen=NOW_ISH),
            _profile_row(series_id="b", last_seen=NOW_ISH),
        ]

        response = freq_client.get("/api/v1/frequency/profiles", params={"module": "conn"})

        assert response.status_code == 200
        body = response.json()
        assert body["module"] == "conn"
        assert body["count"] == 2
        assert [item["series_id"] for item in body["data"]] == ["a", "b"]


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
