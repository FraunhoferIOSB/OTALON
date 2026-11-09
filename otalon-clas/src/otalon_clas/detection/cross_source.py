"""x1 cross-source aggregation: conn-anchored MAC/Proto enrichment.

Implements the authoritative §7a matching mechanism of the Multi-Source
Anomaly Pipeline. The aggregation is a strictly one-way, additive
post-step that runs AFTER the per-series rule-based grouping: it iterates
over conn alarms and attaches matching mac / proto anomalies as evidence,
without re-grouping or altering the identity of any conn alarm.

Matching rules (§7a, decided 2026-06-19):

* Direction is one-way conn -> {mac, proto}; a mac / proto alarm never
  reaches back toward conn alarms.
* Window per conn alarm A: ``[A.start - Δ, A.stop + Δ]`` with
  ``Δ = gap_tolerance_seconds`` (10s, reused from the rule-based config).
* MAC (D-c): attach a mac anomaly when its ``mac_address`` is the source
  OR destination MAC of any UCI of A, deduplicated to at most one attach
  per ``mac_address`` per alarm.
* PROTO (D-a, one-way): attach a proto anomaly when its ``protocol`` is a
  subset / prefix of the protocol stack of any UCI of A.
* Solo rule: an unmatched mac / proto anomaly becomes its own alarm
  (``alarms.module='mac_traffic'`` / ``'proto_traffic'``); it is never
  force-attached to a foreign conn alarm. The standalone alarm itself is
  produced by the existing per-series grouping; this module only refrains
  from attaching such anomalies to conn alarms.

The evidence attachment is persisted in the additive-nullable
``alarms.enrichment`` JSON column, leaving the conn alarm's identity,
count, ``series_ids`` and ``primary_type`` unchanged (E-B3).
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from loguru import logger
from sqlalchemy import or_

from otalon_clas.common.postgres_connector import (
    Alarm,
    AnomalyRecord,
    PostgresConnector,
)

DEFAULT_GAP_TOLERANCE_SECONDS: int = 10
"""Δ for the cross-source match window, reused from the rule-based config."""

_HASH_MODULUS: int = 2**31
"""Modulus mirroring ``preprocessing.passthrough._stable_hash``."""

_UCI_SRC_MAC_INDEX: int = 0
_UCI_DST_MAC_INDEX: int = 1
_UCI_PROTOCOL_STACK_INDEX: int = 8
_UCI_MIN_PARTS: int = 9


@dataclass
class _ConnAlarmView:
    """Read-only projection of a conn alarm used during aggregation."""

    alarm_id: str
    start_ts: datetime
    end_ts: datetime
    macs: set[str]
    protocol_stacks: list[str]
    existing_enrichment: dict[str, Any] | None


@dataclass
class _AnomalyView:
    """Read-only projection of a mac / proto anomaly used during matching."""

    anomaly_id: str
    module: str
    series_id: str
    start_ts: datetime
    end_ts: datetime
    anomaly_type: str
    confidence: float


@dataclass
class _AlarmEnrichment:
    """Accumulated evidence attachment for a single conn alarm."""

    mac_anomaly_ids: dict[str, dict[str, Any]] = field(default_factory=dict)
    proto_anomaly_ids: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_payload(self) -> dict[str, Any]:
        """Serialize the accumulated evidence to a JSON-ready payload."""
        return {
            "schema": 1,
            "mac": list(self.mac_anomaly_ids.values()),
            "proto": list(self.proto_anomaly_ids.values()),
        }


def _stable_hash(value: str) -> int:
    """Hash a protocol string exactly like the proto passthrough encoder.

    Args:
        value: Protocol-stack string (e.g. ``"Ethernet:ARP"``).

    Returns:
        Stable non-negative integer in ``[0, _HASH_MODULUS)``.
    """
    digest = hashlib.sha1(value.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % _HASH_MODULUS


def build_protocol_hash_lookup(protocols: list[str]) -> dict[str, str]:
    """Build a ``hashed-series-id -> protocol-string`` reverse map.

    The proto preprocessor hash-encodes the ``protocol`` tag, so a proto
    anomaly's ``series_id`` is the stringified stable hash of the
    protocol stack. This reverse map lets the aggregation resolve a proto
    series back to its protocol stack for the subset match. Protocols
    whose hash cannot be resolved (e.g. legacy non-deterministic hashes)
    simply never match and fall through to the solo rule.

    Args:
        protocols: Distinct protocol-stack strings (from InfluxDB).

    Returns:
        Mapping of the stringified hash to the protocol-stack string.
    """
    return {str(_stable_hash(proto)): proto for proto in protocols}


def parse_uci_macs(uci: str) -> set[str]:
    """Extract the source and destination MACs from a conn UCI.

    Args:
        uci: Connection UCI (slash-separated, src MAC at index 0,
            dst MAC at index 1).

    Returns:
        Lower-cased set of the source and destination MACs (empty
        entries dropped).
    """
    parts = uci.split("/")
    if len(parts) <= _UCI_DST_MAC_INDEX:
        return set()
    macs = {
        parts[_UCI_SRC_MAC_INDEX].strip().lower(),
        parts[_UCI_DST_MAC_INDEX].strip().lower(),
    }
    return {mac for mac in macs if mac}


def parse_uci_protocol_stack(uci: str) -> str:
    """Extract the protocol-stack token from a conn UCI.

    Args:
        uci: Connection UCI (protocol stack at index 8).

    Returns:
        Protocol-stack string (e.g. ``"Ethernet:IPv4:TCP"``) or an empty
        string when the UCI is too short.
    """
    parts = uci.split("/")
    if len(parts) < _UCI_MIN_PARTS:
        return ""
    return parts[_UCI_PROTOCOL_STACK_INDEX].strip()


def protocol_stack_subset_match(proto: str, conn_stack: str) -> bool:
    """Return whether ``proto`` is a stack subset / prefix of ``conn_stack``.

    A proto stack matches a conn stack when its colon-separated tokens are
    a contiguous prefix of the conn stack's tokens (D-a). For example
    ``Ethernet:IPv4`` matches ``Ethernet:IPv4:TCP`` but ``Ethernet:ARP``
    does not match ``Ethernet:IPv4:TCP``.

    Args:
        proto: Proto-anomaly protocol stack.
        conn_stack: Conn-UCI protocol stack.

    Returns:
        True when ``proto`` is a prefix of ``conn_stack``.
    """
    if not proto or not conn_stack:
        return False
    proto_tokens = proto.split(":")
    conn_tokens = conn_stack.split(":")
    if len(proto_tokens) > len(conn_tokens):
        return False
    return conn_tokens[: len(proto_tokens)] == proto_tokens


def aggregate_cross_source(
    connector: PostgresConnector,
    protocol_vocabulary: list[str],
    gap_tolerance_seconds: int = DEFAULT_GAP_TOLERANCE_SECONDS,
    window_start: datetime | None = None,
    window_stop: datetime | None = None,
) -> dict[str, int]:
    """Enrich conn-involved alarms with same-window mac / proto anomalies.

    Loads every alarm that involves conn anomalies (its own ``module`` is
    ``"conn"`` OR it references a linked conn ``AnomalyRecord``) plus the
    ungrouped-context mac / proto anomalies inside the optional
    ``[window_start, window_stop]`` bounds, attaches matching evidence to
    each such alarm's ``enrichment`` column, and returns a summary count
    dict. The alarm identity, ``series_ids`` and ``primary_type`` are
    never modified (E-B3). Multi-type alarms that rolled up as proto- or
    mac-primary but still contain conn anomalies are enriched too
    (CLAS-009).

    Args:
        connector: PostgreSQL connector.
        protocol_vocabulary: Distinct protocol-stack strings used to build
            the proto hash reverse map.
        gap_tolerance_seconds: Δ for the match window (default 10s).
        window_start: Optional lower bound on the conn alarm window.
        window_stop: Optional upper bound on the conn alarm window.

    Returns:
        Dict with ``enriched_alarms``, ``mac_attachments`` and
        ``proto_attachments`` counts.
    """
    proto_lookup = build_protocol_hash_lookup(protocol_vocabulary)
    gap = timedelta(seconds=gap_tolerance_seconds)

    with connector.session() as session:
        conn_alarms = _load_conn_involved_alarms(session, window_start, window_stop)
        if not conn_alarms:
            return {"enriched_alarms": 0, "mac_attachments": 0, "proto_attachments": 0}

        search_start, search_stop = _enrichment_search_bounds(conn_alarms, gap)
        mac_anomalies = _load_anomalies(session, "mac_traffic", search_start, search_stop)
        proto_anomalies = _load_anomalies(session, "proto_traffic", search_start, search_stop)

        if proto_anomalies and not proto_lookup:
            logger.warning(
                "Cross-source aggregation: {} proto anomalies in window but the "
                "protocol-hash reverse map is EMPTY (no protocol vocabulary). "
                "Every proto anomaly will silently fall through to the solo "
                "rule and NO proto evidence will be attached to any conn alarm. "
                "Check the proto_traffic InfluxDB vocabulary fetch / proto bundle.",
                len(proto_anomalies),
            )

        summary = {"enriched_alarms": 0, "mac_attachments": 0, "proto_attachments": 0}
        for view in conn_alarms:
            enrichment = _match_alarm(view, mac_anomalies, proto_anomalies, proto_lookup, gap)
            payload = enrichment.to_payload()
            if not payload["mac"] and not payload["proto"]:
                continue
            _persist_enrichment(session, view.alarm_id, payload)
            summary["enriched_alarms"] += 1
            summary["mac_attachments"] += len(payload["mac"])
            summary["proto_attachments"] += len(payload["proto"])

    logger.info(
        "Cross-source aggregation: enriched {} conn alarms " "({} mac, {} proto attachments)",
        summary["enriched_alarms"],
        summary["mac_attachments"],
        summary["proto_attachments"],
    )
    return summary


def _match_alarm(
    view: _ConnAlarmView,
    mac_anomalies: list[_AnomalyView],
    proto_anomalies: list[_AnomalyView],
    proto_lookup: dict[str, str],
    gap: timedelta,
) -> _AlarmEnrichment:
    """Match mac / proto anomalies to a single conn alarm view.

    Args:
        view: Conn alarm projection.
        mac_anomalies: Candidate mac anomalies.
        proto_anomalies: Candidate proto anomalies.
        proto_lookup: Hash -> protocol-stack reverse map.
        gap: Δ window tolerance.

    Returns:
        Accumulated enrichment for the alarm.
    """
    win_start = view.start_ts - gap
    win_stop = view.end_ts + gap
    enrichment = _AlarmEnrichment()

    for anomaly in mac_anomalies:
        if not _overlaps(anomaly, win_start, win_stop):
            continue
        if anomaly.series_id.lower() in view.macs:
            enrichment.mac_anomaly_ids.setdefault(anomaly.series_id.lower(), _evidence_entry(anomaly))

    for anomaly in proto_anomalies:
        if not _overlaps(anomaly, win_start, win_stop):
            continue
        proto_stack = proto_lookup.get(anomaly.series_id)
        if proto_stack is None:
            continue
        if any(protocol_stack_subset_match(proto_stack, stack) for stack in view.protocol_stacks):
            entry = _evidence_entry(anomaly)
            entry["protocol"] = proto_stack
            enrichment.proto_anomaly_ids.setdefault(anomaly.anomaly_id, entry)

    return enrichment


def _evidence_entry(anomaly: _AnomalyView) -> dict[str, Any]:
    """Build a JSON-ready evidence reference for an attached anomaly.

    Args:
        anomaly: The mac / proto anomaly being attached.

    Returns:
        Evidence dict with id, module, series, type, time window.
    """
    return {
        "anomaly_id": anomaly.anomaly_id,
        "module": anomaly.module,
        "series_id": anomaly.series_id,
        "anomaly_type": anomaly.anomaly_type,
        "confidence": anomaly.confidence,
        "start_ts": anomaly.start_ts.isoformat(),
        "end_ts": anomaly.end_ts.isoformat(),
    }


def _overlaps(anomaly: _AnomalyView, win_start: datetime, win_stop: datetime) -> bool:
    """Return whether an anomaly's interval overlaps the match window."""
    return anomaly.start_ts <= win_stop and anomaly.end_ts >= win_start


def _enrichment_search_bounds(
    conn_alarms: list[_ConnAlarmView],
    gap: timedelta,
) -> tuple[datetime, datetime]:
    """Compute the global anomaly-search window across all conn alarms."""
    earliest = min(view.start_ts for view in conn_alarms) - gap
    latest = max(view.end_ts for view in conn_alarms) + gap
    return earliest, latest


def _load_conn_involved_alarms(
    session: Any,
    window_start: datetime | None,
    window_stop: datetime | None,
) -> list[_ConnAlarmView]:
    """Load every alarm that involves conn anomalies as read-only views.

    The enrichment must attach mac / proto evidence to ANY alarm whose
    grouping pulled in conn anomalies, not only to alarms whose primary
    ``module`` tag is ``"conn"``. A multi-type alarm can roll up as
    ``proto_traffic``- or ``mac_traffic``-primary while still containing
    conn anomalies (CLAS-009); such an alarm would otherwise lose its
    mac + conn attribution because the conn-only filter skipped it.

    An alarm is considered conn-involved when its own ``module`` tag is
    ``"conn"`` OR it references at least one linked ``AnomalyRecord``
    with ``module == "conn"``. The mac / proto matching below operates on
    the conn UCIs carried in ``series_ids``, which are present regardless
    of which module won the primary tag.

    Args:
        session: Active SQLAlchemy session.
        window_start: Optional lower bound on the alarm window.
        window_stop: Optional upper bound on the alarm window.

    Returns:
        Read-only conn-alarm views for every conn-involved alarm.
    """
    conn_anomaly_alarm_ids = (
        session.query(AnomalyRecord.alarm_id)
        .filter(AnomalyRecord.module == "conn")
        .filter(AnomalyRecord.alarm_id.isnot(None))
        .distinct()
    )
    query = session.query(Alarm).filter(or_(Alarm.module == "conn", Alarm.id.in_(conn_anomaly_alarm_ids)))
    if window_start is not None:
        query = query.filter(Alarm.end_timestamp >= window_start)
    if window_stop is not None:
        query = query.filter(Alarm.start_timestamp <= window_stop)

    views: list[_ConnAlarmView] = []
    for alarm in query.all():
        series_ids = alarm.series_ids or []
        macs: set[str] = set()
        stacks: list[str] = []
        for uci in series_ids:
            macs |= parse_uci_macs(str(uci))
            stack = parse_uci_protocol_stack(str(uci))
            if stack:
                stacks.append(stack)
        views.append(
            _ConnAlarmView(
                alarm_id=str(alarm.id),
                start_ts=_ensure_utc(alarm.start_timestamp),
                end_ts=_ensure_utc(alarm.end_timestamp),
                macs=macs,
                protocol_stacks=stacks,
                existing_enrichment=alarm.enrichment,
            )
        )
    return views


def _load_anomalies(
    session: Any,
    module: str,
    search_start: datetime,
    search_stop: datetime,
) -> list[_AnomalyView]:
    """Load anomalous mac / proto records inside the search window."""
    rows = (
        session.query(AnomalyRecord)
        .filter(AnomalyRecord.module == module)
        .filter(AnomalyRecord.is_anomaly.is_(True))
        .filter(AnomalyRecord.end_ts >= search_start)
        .filter(AnomalyRecord.start_ts <= search_stop)
        .all()
    )
    return [
        _AnomalyView(
            anomaly_id=str(row.id),
            module=str(row.module),
            series_id=str(row.series_id),
            start_ts=_ensure_utc(row.start_ts),
            end_ts=_ensure_utc(row.end_ts),
            anomaly_type=str(row.anomaly_type),
            confidence=float(row.confidence or 0.0),
        )
        for row in rows
    ]


def _persist_enrichment(session: Any, alarm_id: str, payload: dict[str, Any]) -> None:
    """Write the enrichment payload onto an existing conn alarm row."""
    session.query(Alarm).filter(Alarm.id == alarm_id).update(
        {Alarm.enrichment: payload},
        synchronize_session=False,
    )


def _ensure_utc(dt: Any) -> datetime:
    """Ensure a datetime value carries UTC timezone info."""
    if dt is None:
        return datetime.now(tz=timezone.utc)
    if isinstance(dt, datetime):
        return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt
    return datetime.fromisoformat(str(dt)).replace(tzinfo=timezone.utc)
