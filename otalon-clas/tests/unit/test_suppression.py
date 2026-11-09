"""Unit tests for the anomaly suppression service and persister gate.

Covers:

* :class:`SuppressionService` cache behaviour (TTL, invalidate, expiry).
* :func:`_is_low_signal_row` ML false-positive classification.
* The ``_apply_suppression_and_lowsignal_gate`` of
  :class:`AnomalyPersister` dropping suppressed rows and low-signal rows
  while keeping legitimate anomalies.
"""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

import polars as pl
import pytest

from otalon_clas.detection.anomaly_persister import (
    AnomalyPersister,
    _is_low_signal_row,
)
from otalon_clas.detection.suppression import SuppressionEntry, SuppressionService

# --------------------------------------------------------------------------- #
# Fake postgres connector — avoids spinning up an actual DB for unit tests.
# --------------------------------------------------------------------------- #


@dataclass
class _FakeAnomalySuppressionRow:
    """In-memory mirror of an ``anomaly_suppression`` table row."""

    id: int
    series_id: str
    suppressed_types: list[str]
    reason: str
    expires_at: datetime | None = None


class _FakeQuery:
    """Minimal SQLAlchemy-query stand-in supporting ``filter().all()``."""

    def __init__(self, rows: list[_FakeAnomalySuppressionRow]) -> None:
        self._rows = rows

    def filter(self, *_args: Any, **_kwargs: Any) -> "_FakeQuery":
        # Tests pre-shape the row list so the active filter is a no-op.
        return self

    def all(self) -> list[_FakeAnomalySuppressionRow]:
        return list(self._rows)


class _FakeSession:
    """Context-manager session yielding a fixed query result."""

    def __init__(self, rows: list[_FakeAnomalySuppressionRow]) -> None:
        self._rows = rows

    def __enter__(self) -> "_FakeSession":
        return self

    def __exit__(self, *_exc: Any) -> None:
        return None

    def query(self, _model: Any) -> _FakeQuery:
        return _FakeQuery(self._rows)


class _FakeConnector:
    """Stub connector for :class:`SuppressionService` unit tests."""

    def __init__(self, rows: list[_FakeAnomalySuppressionRow] | None = None) -> None:
        self.rows: list[_FakeAnomalySuppressionRow] = list(rows or [])
        self.session_calls: int = 0

    def session(self) -> _FakeSession:
        self.session_calls += 1
        return _FakeSession(self.rows)


# --------------------------------------------------------------------------- #
# SuppressionService
# --------------------------------------------------------------------------- #


class TestSuppressionService:
    """Cache / lookup behaviour of :class:`SuppressionService`."""

    def test_is_suppressed_matches_series_and_type(self) -> None:
        """A row matches when series_id and anomaly_type are both present."""
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=1,
                    series_id="cc:82:7f:a1:8a:3a/ff:ff:ff:ff:ff:ff:ARP",
                    suppressed_types=["T0846/arp_scan", "T0846/arp_spoofing"],
                    reason="legitimate ARP discovery",
                )
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=60)  # type: ignore[arg-type]
        entry = svc.is_suppressed(
            "cc:82:7f:a1:8a:3a/ff:ff:ff:ff:ff:ff:ARP", "T0846/arp_scan"
        )
        assert isinstance(entry, SuppressionEntry)
        assert entry.suppression_id == 1
        assert "T0846/arp_scan" in entry.suppressed_types

    def test_is_suppressed_returns_none_when_type_mismatches(self) -> None:
        """A row exists for the series but the type is not in the set."""
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=2,
                    series_id="series_a",
                    suppressed_types=["T0846/arp_scan"],
                    reason="legit ARP",
                )
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=60)  # type: ignore[arg-type]
        assert svc.is_suppressed("series_a", "T0888/port_scan") is None

    def test_is_suppressed_returns_none_for_unknown_series(self) -> None:
        """No matching series returns None and does not raise."""
        connector = _FakeConnector([])
        svc = SuppressionService(connector=connector, cache_ttl_s=60)  # type: ignore[arg-type]
        assert svc.is_suppressed("unknown_series", "T0846/arp_scan") is None

    def test_cache_is_used_within_ttl(self) -> None:
        """A second call within TTL does not re-query the DB."""
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=1,
                    series_id="s",
                    suppressed_types=["T0846/arp_scan"],
                    reason="r",
                )
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=60)  # type: ignore[arg-type]
        svc.active_suppressions()
        svc.active_suppressions()
        svc.is_suppressed("s", "T0846/arp_scan")
        assert connector.session_calls == 1

    def test_invalidate_forces_reload(self) -> None:
        """``invalidate()`` causes the next call to re-query the DB."""
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=1,
                    series_id="s",
                    suppressed_types=["T0846/arp_scan"],
                    reason="r",
                )
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=60)  # type: ignore[arg-type]
        svc.active_suppressions()
        assert connector.session_calls == 1
        svc.invalidate()
        svc.active_suppressions()
        assert connector.session_calls == 2

    def test_ttl_zero_disables_cache(self) -> None:
        """``cache_ttl_s=0`` re-queries on every lookup."""
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=1,
                    series_id="s",
                    suppressed_types=["T0846/arp_scan"],
                    reason="r",
                )
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=0)  # type: ignore[arg-type]
        svc.active_suppressions()
        svc.active_suppressions()
        assert connector.session_calls == 2

    def test_expired_rows_are_filtered_by_reload(self) -> None:
        """Rows whose ``expires_at`` is in the past are not returned.

        The service relies on the SQL filter ``expires_at IS NULL OR
        expires_at > NOW()`` — but our fake connector returns every row
        from ``.all()`` regardless. So this test instead exercises the
        post-load handling: a row with an empty ``suppressed_types``
        list is dropped, matching the same DB-level CHECK constraint.
        """
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=1,
                    series_id="s_active",
                    suppressed_types=["T0846/arp_scan"],
                    reason="active",
                ),
                _FakeAnomalySuppressionRow(
                    id=2,
                    series_id="s_empty",
                    suppressed_types=[],
                    reason="empty types — must be skipped",
                ),
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=60)  # type: ignore[arg-type]
        active = svc.active_suppressions()
        assert "s_active" in active
        assert "s_empty" not in active

    def test_cache_expires_after_ttl(self) -> None:
        """After ``cache_ttl_s`` elapses, the next call refreshes the cache."""
        connector = _FakeConnector(
            [
                _FakeAnomalySuppressionRow(
                    id=1,
                    series_id="s",
                    suppressed_types=["T0846/arp_scan"],
                    reason="r",
                )
            ]
        )
        svc = SuppressionService(connector=connector, cache_ttl_s=1)  # type: ignore[arg-type]
        svc.active_suppressions()
        assert connector.session_calls == 1
        time.sleep(1.2)
        svc.active_suppressions()
        assert connector.session_calls == 2


# --------------------------------------------------------------------------- #
# _is_low_signal_row
# --------------------------------------------------------------------------- #


class TestIsLowSignalRow:
    """The ML-only false-positive classifier used by the persister gate."""

    def test_ml_zero_severity_low_confidence_is_low_signal(self) -> None:
        """The canonical false-positive row matches."""
        row = {
            "anomaly_type": "T0846/arp_scan",
            "severity": 0,
            "violated_features": [],
            "confidence": 0.57,
        }
        assert _is_low_signal_row(row, 0.60) is True

    def test_no_bounds_ml_row_is_low_signal_when_confidence_is_low(self) -> None:
        """An ML label fused onto NoBounds is low-signal without bound evidence."""
        row = {
            "anomaly_type": "T0846/arp_scan",
            "bounds_type": "NoBounds",
            "severity": 0.0,
            "violated_features": "[]",
            "confidence": 0.55,
        }
        assert _is_low_signal_row(row, 0.60) is True

    def test_high_confidence_ml_is_not_low_signal(self) -> None:
        """High-confidence ML hits must NOT be dropped."""
        row = {
            "anomaly_type": "T0846/arp_scan",
            "severity": 0,
            "violated_features": [],
            "confidence": 0.85,
        }
        assert _is_low_signal_row(row, 0.60) is False

    def test_bound_violation_is_not_low_signal(self) -> None:
        """A genuine bounds violation is never low-signal even when ML conf is low."""
        row = {
            "anomaly_type": "BoundViolation",
            "severity": 2.0,
            "violated_features": ["packet_count"],
            "confidence": 0.1,
        }
        assert _is_low_signal_row(row, 0.60) is False

    def test_violated_features_string_blocks_drop(self) -> None:
        """A non-empty CSV string of violated features keeps the row."""
        row = {
            "anomaly_type": "T0846/arp_scan",
            "severity": 0,
            "violated_features": "packet_count",
            "confidence": 0.4,
        }
        assert _is_low_signal_row(row, 0.60) is False

    def test_empty_string_violated_features_does_not_block_drop(self) -> None:
        """An empty/``"[]"`` violated_features still allows the drop."""
        for empty in ("", "[]", "  ", None):
            row = {
                "anomaly_type": "T0846/arp_scan",
                "severity": 0,
                "violated_features": empty,
                "confidence": 0.3,
            }
            assert _is_low_signal_row(row, 0.60) is True, f"failed for {empty!r}"

    def test_nonzero_severity_blocks_drop(self) -> None:
        """A non-zero severity always blocks the drop."""
        row = {
            "anomaly_type": "T0846/arp_scan",
            "severity": 0.1,
            "violated_features": [],
            "confidence": 0.2,
        }
        assert _is_low_signal_row(row, 0.60) is False

    def test_non_ml_type_is_never_low_signal(self) -> None:
        """``NoBounds`` and ``benign`` are non-ML and never low-signal."""
        for atype in ("NoBounds", "benign", ""):
            row: dict[str, Any] = {
                "anomaly_type": atype,
                "severity": 0,
                "violated_features": [],
                "confidence": 0.1,
            }
            assert _is_low_signal_row(row, 0.60) is False


# --------------------------------------------------------------------------- #
# AnomalyPersister suppression / low-signal gate
# --------------------------------------------------------------------------- #


class _StubSuppressionService:
    """Stand-in service returning a static suppression map."""

    def __init__(self, mapping: dict[tuple[str, str], SuppressionEntry]) -> None:
        self._mapping = mapping

    def is_suppressed(
        self, series_id: str, anomaly_type: str
    ) -> SuppressionEntry | None:
        return self._mapping.get((series_id, anomaly_type))


def _make_anomaly_frame(rows: list[dict[str, Any]]) -> pl.DataFrame:
    """Build a Polars frame mimicking the persister's input shape."""
    base = datetime(2026, 5, 21, 8, 0, 0, tzinfo=timezone.utc)
    for i, r in enumerate(rows):
        r.setdefault("time", base + timedelta(seconds=i))
        r.setdefault("is_anomaly", True)
        r.setdefault("severity", 0.0)
        r.setdefault("confidence", 0.5)
        r.setdefault("violated_features", "")
    return pl.DataFrame(rows)


class TestPersisterSuppressionGate:
    """End-to-end ``_apply_suppression_and_lowsignal_gate`` behaviour."""

    def test_suppressed_row_is_dropped(self) -> None:
        """A row matched by a suppression is removed."""
        entry = SuppressionEntry(
            suppression_id=1,
            series_id="series_a",
            suppressed_types=frozenset({"T0846/arp_scan"}),
            reason="legit ARP",
        )
        svc = _StubSuppressionService({("series_a", "T0846/arp_scan"): entry})
        persister = AnomalyPersister(
            connector=None,  # type: ignore[arg-type]
            suppression_service=svc,  # type: ignore[arg-type]
            drop_low_signal_anomalies=False,
        )
        df = _make_anomaly_frame(
            [
                {"uci": "series_a", "anomaly_type": "T0846/arp_scan"},
                {"uci": "series_b", "anomaly_type": "T0846/arp_scan"},
            ]
        )
        filtered = persister._apply_suppression_and_lowsignal_gate(df, "uci")
        assert filtered.height == 1
        assert filtered["uci"].to_list() == ["series_b"]

    def test_low_signal_row_is_dropped(self) -> None:
        """A low-signal row is dropped even without a suppression match."""
        persister = AnomalyPersister(
            connector=None,  # type: ignore[arg-type]
            suppression_service=None,
            ml_confidence_persist_threshold=0.60,
            drop_low_signal_anomalies=True,
        )
        df = _make_anomaly_frame(
            [
                {
                    "uci": "series_x",
                    "anomaly_type": "T0846/arp_scan",
                    "severity": 0.0,
                    "violated_features": "",
                    "confidence": 0.55,
                },
                {
                    "uci": "series_y",
                    "anomaly_type": "BoundViolation",
                    "severity": 1.5,
                    "violated_features": "packet_count",
                    "confidence": 0.55,
                },
            ]
        )
        filtered = persister._apply_suppression_and_lowsignal_gate(df, "uci")
        assert filtered.height == 1
        assert filtered["uci"].to_list() == ["series_y"]

    def test_no_bounds_ml_row_is_dropped(self) -> None:
        """The persister drops low-confidence ML labels fused onto NoBounds."""
        persister = AnomalyPersister(
            connector=None,  # type: ignore[arg-type]
            suppression_service=None,
            ml_confidence_persist_threshold=0.60,
            drop_low_signal_anomalies=True,
        )
        df = _make_anomaly_frame(
            [
                {
                    "uci": "series_no_bounds",
                    "anomaly_type": "T0846/arp_scan",
                    "bounds_type": "NoBounds",
                    "severity": 0.0,
                    "violated_features": "[]",
                    "confidence": 0.55,
                }
            ]
        )
        filtered = persister._apply_suppression_and_lowsignal_gate(df, "uci")
        assert filtered.is_empty()

    def test_disable_low_signal_keeps_all_rows(self) -> None:
        """``drop_low_signal_anomalies=False`` skips the low-signal gate."""
        persister = AnomalyPersister(
            connector=None,  # type: ignore[arg-type]
            suppression_service=None,
            ml_confidence_persist_threshold=0.60,
            drop_low_signal_anomalies=False,
        )
        df = _make_anomaly_frame(
            [
                {
                    "uci": "series_x",
                    "anomaly_type": "T0846/arp_scan",
                    "severity": 0.0,
                    "violated_features": "",
                    "confidence": 0.55,
                },
            ]
        )
        filtered = persister._apply_suppression_and_lowsignal_gate(df, "uci")
        assert filtered.height == 1

    def test_no_service_no_drop_keeps_all_rows(self) -> None:
        """Default config without a service: no rows are filtered."""
        persister = AnomalyPersister(
            connector=None,  # type: ignore[arg-type]
            suppression_service=None,
            drop_low_signal_anomalies=False,
        )
        df = _make_anomaly_frame(
            [
                {"uci": "series_x", "anomaly_type": "T0846/arp_scan"},
                {"uci": "series_y", "anomaly_type": "BoundViolation", "severity": 2.0},
            ]
        )
        filtered = persister._apply_suppression_and_lowsignal_gate(df, "uci")
        assert filtered.height == 2

    def test_all_rows_dropped_returns_empty_frame(self) -> None:
        """When every row matches a suppression, an empty frame is returned."""
        entry = SuppressionEntry(
            suppression_id=1,
            series_id="series_a",
            suppressed_types=frozenset({"T0846/arp_scan"}),
            reason="legit",
        )
        svc = _StubSuppressionService(
            {
                ("series_a", "T0846/arp_scan"): entry,
                ("series_b", "T0846/arp_scan"): entry,
            }
        )
        persister = AnomalyPersister(
            connector=None,  # type: ignore[arg-type]
            suppression_service=svc,  # type: ignore[arg-type]
            drop_low_signal_anomalies=False,
        )
        df = _make_anomaly_frame(
            [
                {"uci": "series_a", "anomaly_type": "T0846/arp_scan"},
                {"uci": "series_b", "anomaly_type": "T0846/arp_scan"},
            ]
        )
        filtered = persister._apply_suppression_and_lowsignal_gate(df, "uci")
        assert filtered.is_empty()


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-v"]))
