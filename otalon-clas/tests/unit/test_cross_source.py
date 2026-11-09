"""Unit tests for the x1 cross-source aggregation matching logic.

Covers the safety-critical §7a rules in isolation (no database):

* D-c MAC attachment (src OR dst match, per-alarm dedup).
* D-a PROTO attachment (one-way stack subset / prefix match).
* Solo rule (unmatched mac / proto anomaly is NOT attached).
* UCI parsing helpers and the proto-hash reverse map.
"""

from __future__ import annotations

import hashlib
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from otalon_clas.common.postgres_connector import (
    Alarm,
    AnomalyRecord,
    PostgresConnector,
)
from otalon_clas.detection.cross_source import (
    _AnomalyView,
    _ConnAlarmView,
    _match_alarm,
    aggregate_cross_source,
    build_protocol_hash_lookup,
    parse_uci_macs,
    parse_uci_protocol_stack,
    protocol_stack_subset_match,
)

pytestmark = pytest.mark.unit

_SRC_MAC = "aa:bb:cc:dd:ee:01"
_DST_MAC = "aa:bb:cc:dd:ee:02"
_OTHER_MAC = "aa:bb:cc:dd:ee:99"
_UCI = f"{_SRC_MAC}/{_DST_MAC}//IPv4/192.168.0.10/192.168.0.77/*/80/Ethernet:IPv4:TCP"
_BASE = datetime(2026, 4, 6, 5, 0, 0, tzinfo=timezone.utc)
_GAP = timedelta(seconds=10)


def _stable_hash(value: str) -> int:
    digest = hashlib.sha1(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % (2**31)


def _conn_view() -> _ConnAlarmView:
    return _ConnAlarmView(
        alarm_id="alarm-1",
        start_ts=_BASE,
        end_ts=_BASE + timedelta(seconds=30),
        macs=parse_uci_macs(_UCI),
        protocol_stacks=[parse_uci_protocol_stack(_UCI)],
        existing_enrichment=None,
    )


def _mac_anomaly(mac: str, offset: int = 5) -> _AnomalyView:
    ts = _BASE + timedelta(seconds=offset)
    return _AnomalyView(
        anomaly_id=f"mac-{mac}-{offset}",
        module="mac_traffic",
        series_id=mac,
        start_ts=ts,
        end_ts=ts,
        anomaly_type="BoundViolation",
        confidence=0.9,
    )


def _proto_anomaly(protocol: str, offset: int = 5) -> _AnomalyView:
    ts = _BASE + timedelta(seconds=offset)
    return _AnomalyView(
        anomaly_id=f"proto-{protocol}-{offset}",
        module="proto_traffic",
        series_id=str(_stable_hash(protocol)),
        start_ts=ts,
        end_ts=ts,
        anomaly_type="BoundViolation",
        confidence=0.8,
    )


class TestUciParsing:
    """UCI source/destination MAC and protocol-stack extraction."""

    def test_parse_uci_macs_returns_src_and_dst(self) -> None:
        assert parse_uci_macs(_UCI) == {_SRC_MAC, _DST_MAC}

    def test_parse_uci_protocol_stack(self) -> None:
        assert parse_uci_protocol_stack(_UCI) == "Ethernet:IPv4:TCP"

    def test_parse_uci_macs_short_uci_returns_empty(self) -> None:
        assert parse_uci_macs("only-one-token") == set()

    def test_parse_uci_protocol_stack_short_uci_returns_empty(self) -> None:
        assert parse_uci_protocol_stack("a/b/c") == ""


class TestProtocolStackSubsetMatch:
    """D-a one-way stack prefix matching."""

    def test_prefix_matches(self) -> None:
        assert protocol_stack_subset_match("Ethernet:IPv4", "Ethernet:IPv4:TCP")

    def test_exact_matches(self) -> None:
        assert protocol_stack_subset_match("Ethernet:IPv4:TCP", "Ethernet:IPv4:TCP")

    def test_non_prefix_does_not_match(self) -> None:
        assert not protocol_stack_subset_match("Ethernet:ARP", "Ethernet:IPv4:TCP")

    def test_longer_proto_does_not_match(self) -> None:
        assert not protocol_stack_subset_match("Ethernet:IPv4:TCP:SSL", "Ethernet:IPv4:TCP")

    def test_empty_inputs_do_not_match(self) -> None:
        assert not protocol_stack_subset_match("", "Ethernet:IPv4")
        assert not protocol_stack_subset_match("Ethernet", "")


class TestMacAttachment:
    """D-c MAC attachment: src OR dst match with per-alarm dedup."""

    def test_dst_mac_attached(self) -> None:
        enrichment = _match_alarm(_conn_view(), [_mac_anomaly(_DST_MAC)], [], {}, _GAP)
        payload = enrichment.to_payload()
        assert len(payload["mac"]) == 1
        assert payload["mac"][0]["series_id"] == _DST_MAC

    def test_src_mac_attached(self) -> None:
        enrichment = _match_alarm(_conn_view(), [_mac_anomaly(_SRC_MAC)], [], {}, _GAP)
        assert len(enrichment.to_payload()["mac"]) == 1

    def test_foreign_mac_not_attached(self) -> None:
        enrichment = _match_alarm(_conn_view(), [_mac_anomaly(_OTHER_MAC)], [], {}, _GAP)
        assert enrichment.to_payload()["mac"] == []

    def test_same_mac_deduplicated(self) -> None:
        anomalies = [_mac_anomaly(_SRC_MAC, 3), _mac_anomaly(_SRC_MAC, 7)]
        enrichment = _match_alarm(_conn_view(), anomalies, [], {}, _GAP)
        assert len(enrichment.to_payload()["mac"]) == 1

    def test_out_of_window_not_attached(self) -> None:
        far = _mac_anomaly(_DST_MAC, offset=300)
        enrichment = _match_alarm(_conn_view(), [far], [], {}, _GAP)
        assert enrichment.to_payload()["mac"] == []

    def test_within_gap_boundary_attached(self) -> None:
        edge = _mac_anomaly(_DST_MAC, offset=40)
        enrichment = _match_alarm(_conn_view(), [edge], [], {}, _GAP)
        assert len(enrichment.to_payload()["mac"]) == 1


class TestProtoAttachment:
    """D-a PROTO attachment: one-way stack subset match via hash lookup."""

    def test_proto_prefix_attached(self) -> None:
        proto = _proto_anomaly("Ethernet:IPv4")
        lookup = build_protocol_hash_lookup(["Ethernet:IPv4"])
        enrichment = _match_alarm(_conn_view(), [], [proto], lookup, _GAP)
        payload = enrichment.to_payload()
        assert len(payload["proto"]) == 1
        assert payload["proto"][0]["protocol"] == "Ethernet:IPv4"

    def test_proto_non_prefix_not_attached(self) -> None:
        proto = _proto_anomaly("Ethernet:ARP")
        lookup = build_protocol_hash_lookup(["Ethernet:ARP"])
        enrichment = _match_alarm(_conn_view(), [], [proto], lookup, _GAP)
        assert enrichment.to_payload()["proto"] == []

    def test_unresolvable_hash_not_attached(self) -> None:
        proto = _proto_anomaly("Ethernet:IPv4")
        enrichment = _match_alarm(_conn_view(), [], [proto], {}, _GAP)
        assert enrichment.to_payload()["proto"] == []


class TestSoloRule:
    """Unmatched anomalies are never attached to a foreign conn alarm."""

    def test_no_attachment_for_foreign_signals(self) -> None:
        mac = _mac_anomaly(_OTHER_MAC)
        proto = _proto_anomaly("Ethernet:ARP")
        lookup = build_protocol_hash_lookup(["Ethernet:ARP"])
        enrichment = _match_alarm(_conn_view(), [mac], [proto], lookup, _GAP)
        payload = enrichment.to_payload()
        assert payload["mac"] == []
        assert payload["proto"] == []


_PROTO_STACK = "Ethernet:IPv4:ICMP"
_ICMP_UCI = f"{_SRC_MAC}/{_DST_MAC}//IPv4/192.168.0.196/192.168.0.41/0/0/{_PROTO_STACK}"


def _make_sqlite_connector(tmp_path: Path) -> PostgresConnector:
    """Build a PostgresConnector backed by a fresh SQLite file.

    Only the ``alarms`` and ``anomalies`` tables are created; the rest of
    the schema is irrelevant to the cross-source enrichment loader and
    some sibling ORM models do not compile under the SQLite dialect.
    """
    db_path = tmp_path / "cross_source.sqlite"
    pg = PostgresConnector(dsn=f"sqlite:///{db_path}", pool_size=1, max_overflow=0)
    Alarm.__table__.create(pg.engine, checkfirst=True)
    AnomalyRecord.__table__.create(pg.engine, checkfirst=True)
    return pg


def _insert_alarm(session: object, alarm_id: str, module: str, uci: str = _UCI) -> None:
    """Insert one alarm row spanning the fixed test window."""
    session.add(  # type: ignore[attr-defined]
        Alarm(
            id=alarm_id,
            module=module,
            start_timestamp=_BASE,
            end_timestamp=_BASE + timedelta(seconds=30),
            primary_type="icmp_flood",
            multi_type=True,
            confirmed=False,
            is_active=True,
            series_ids=[uci],
            anomaly_type_stats={},
            enrichment=None,
        )
    )


def _insert_anomaly(session: object, anomaly_id: str, module: str, series_id: str, alarm_id: str) -> None:
    """Insert one anomaly row linked to an alarm inside the test window."""
    session.add(  # type: ignore[attr-defined]
        AnomalyRecord(
            id=anomaly_id,
            module=module,
            series_id=series_id,
            anomaly_type="BoundViolation",
            start_ts=_BASE + timedelta(seconds=5),
            end_ts=_BASE + timedelta(seconds=5),
            is_anomaly=True,
            confidence=0.9,
            violated_features=[],
            alarm_id=alarm_id,
        )
    )


class TestConnInvolvedAlarmEnrichment:
    """DB-level §7a loader: any conn-involved alarm gets enriched (CLAS-009)."""

    def test_proto_primary_alarm_with_conn_anomaly_is_enriched(self, tmp_path: Path) -> None:
        """A proto-PRIMARY multi-type alarm that contains conn anomalies
        must receive its mac + proto enrichment buckets.

        Reproduces the live defect: alarm rolled up as ``proto_traffic``
        primary, ``module != 'conn'``, but its grouping pulled in conn
        anomalies (and the conn UCIs live in ``series_ids``). Before the
        fix the conn-only loader skipped it and ``enrichment`` stayed
        NULL; after the fix both buckets are persisted.
        """
        pg = _make_sqlite_connector(tmp_path)
        alarm_id = "proto-primary-alarm"
        with pg.session() as session:
            _insert_alarm(session, alarm_id, module="proto_traffic", uci=_ICMP_UCI)
            _insert_anomaly(session, "conn-anom", "conn", _ICMP_UCI, alarm_id)
            _insert_anomaly(session, "mac-anom", "mac_traffic", _DST_MAC, alarm_id)
            _insert_anomaly(
                session,
                "proto-anom",
                "proto_traffic",
                str(_stable_hash(_PROTO_STACK)),
                alarm_id,
            )

        summary = aggregate_cross_source(pg, [_PROTO_STACK])

        assert summary["enriched_alarms"] == 1
        assert summary["mac_attachments"] == 1
        assert summary["proto_attachments"] == 1

        with pg.session() as session:
            alarm = session.query(Alarm).filter(Alarm.id == alarm_id).one()
            assert alarm.enrichment is not None
            assert len(alarm.enrichment["mac"]) == 1
            assert alarm.enrichment["mac"][0]["series_id"] == _DST_MAC
            assert len(alarm.enrichment["proto"]) == 1
            assert alarm.enrichment["proto"][0]["protocol"] == _PROTO_STACK

    def test_conn_primary_alarm_still_enriched(self, tmp_path: Path) -> None:
        """A conn-PRIMARY alarm keeps being enriched (no regression)."""
        pg = _make_sqlite_connector(tmp_path)
        alarm_id = "conn-primary-alarm"
        with pg.session() as session:
            _insert_alarm(session, alarm_id, module="conn")
            _insert_anomaly(session, "conn-anom2", "conn", _UCI, alarm_id)
            _insert_anomaly(session, "mac-anom2", "mac_traffic", _SRC_MAC, alarm_id)

        summary = aggregate_cross_source(pg, [_PROTO_STACK])

        assert summary["enriched_alarms"] == 1
        assert summary["mac_attachments"] == 1

    def test_proto_only_alarm_without_conn_anomaly_not_enriched(self, tmp_path: Path) -> None:
        """A proto-only alarm with no conn anomaly is left untouched."""
        pg = _make_sqlite_connector(tmp_path)
        alarm_id = "proto-only-alarm"
        with pg.session() as session:
            alarm = Alarm(
                id=alarm_id,
                module="proto_traffic",
                start_timestamp=_BASE,
                end_timestamp=_BASE + timedelta(seconds=30),
                primary_type="FrequencyAnomaly",
                multi_type=False,
                confirmed=False,
                is_active=True,
                series_ids=["1513662987"],
                anomaly_type_stats={},
                enrichment=None,
            )
            session.add(alarm)
            _insert_anomaly(
                session,
                "proto-anom-solo",
                "proto_traffic",
                str(_stable_hash(_PROTO_STACK)),
                alarm_id,
            )

        summary = aggregate_cross_source(pg, [_PROTO_STACK])

        assert summary["enriched_alarms"] == 0
        with pg.session() as session:
            alarm = session.query(Alarm).filter(Alarm.id == alarm_id).one()
            assert alarm.enrichment is None
