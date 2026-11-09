"""Pydantic v2 request/response schemas for anomaly and bounds API endpoints.

Covers:
- GD-04: Anomaly bounds (per series_id)
- GD-05: Merged timeseries + bounds
- GD-06: Anomaly alarm groups
- GD-07: Alarm intervals for a UCI
- GD-08: Netcap entities for an alarm group
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel, ConfigDict


class BoundsDataRow(BaseModel):
    """A single row from the bounds table (GD-04).

    Contains module, series_id, and per-feature lower/upper bound columns
    with ``lb_`` and ``ub_`` prefixes.
    """

    model_config = ConfigDict(extra="allow")

    module: str
    series_id: str


class BoundsResponse(BaseModel):
    """Response envelope for bounds queries (GD-04)."""

    data: list[dict[str, Any]]
    row_count: int
    parameters: dict[str, Any]


class TimeseriesWithBoundsItem(BaseModel):
    """A single data point in a merged timeseries + bounds response (GD-05)."""

    time: str
    value: float | None = None
    value_min: float | None = None
    value_max: float | None = None
    lower_bound: float | None = None
    upper_bound: float | None = None
    violation_low: bool = False
    violation_high: bool = False


class TimeseriesWithBoundsResponse(BaseModel):
    """Response envelope for merged timeseries + bounds (GD-05)."""

    data: list[dict[str, Any]]
    row_count: int
    parameters: dict[str, Any]
    protocol: str | None = None


class NormRefs(BaseModel):
    """Reference values used for score normalization within anomaly type stats."""

    packet_rate_ref: float
    byte_rate_ref: float
    coverage_ref: float
    count_ref: float


class Weights(BaseModel):
    """Scoring weights used in anomaly type stat computation."""

    w_rate: float
    w_cov: float
    w_persist: float
    w_pr: float
    w_br: float
    gamma: float


class AnomalyTypeStatDetail(BaseModel):
    """Detailed statistics for a single anomaly type within an alarm group.

    Many fields are optional with defaults because the database may store
    either the full scoring pipeline output or a simplified summary
    (e.g. only ``interval_count``, ``count``, ``confidence_mean``,
    ``score_norm``, ``packet_rate_mean``, ``byte_rate_mean``).
    """

    interval_count: int
    count: int
    confidence_sum: float | None = None
    confidence_max: float | None = None
    confidence_min: float | None = None
    confidence_mean: float
    packet_rate_sum: float | None = None
    byte_rate_sum: float | None = None
    rate_count: int | None = None
    protocol_penalty_sum: float | None = None
    protocol_penalty_count: int | None = None
    severity_mean_sum: float | None = None
    severity_max_sum: float | None = None
    severity_count: int | None = None
    packet_rate_mean: float | None = None
    byte_rate_mean: float | None = None
    type_series_count: int | None = None
    severity_mean: float | None = None
    severity_max: float | None = None
    protocol_penalty_mean: float | None = None
    traffic_n: float | None = None
    coverage_n: float | None = None
    count_n: float | None = None
    conf_factor: float | None = None
    score_raw: float | None = None
    score: float | None = None
    norm_refs: NormRefs | None = None
    weights: Weights | None = None
    score_norm: float


class AnomalyGroupItem(BaseModel):
    """A single alarm group record (GD-06).

    The ``anomaly_type_stats`` field is a dict keyed by anomaly type name
    (e.g. ``"BoundViolation"``, ``"NoBounds"``, ``"T0846/pn_discovery"``).
    ``protocols`` is index-parallel with ``series_ids`` for every module;
    non-protocol entries are represented by ``null``.
    """

    id: str
    module: str
    start_timestamp: str
    end_timestamp: str
    primary_type: str | list[str]
    multi_type: bool
    confirmed: bool
    is_active: bool
    series_ids: list[str]
    protocols: list[str | None] | None = None
    anomaly_type_stats: dict[str, AnomalyTypeStatDetail]
    enrichment: dict[str, Any] | None = None


class AnomalyGroupsResponse(BaseModel):
    """Response envelope for anomaly alarm groups (GD-06)."""

    data: list[AnomalyGroupItem]
    row_count: int
    parameters: dict[str, Any]


class AlarmIntervalItem(BaseModel):
    """A single alarm interval for a UCI (GD-07)."""

    start_timestamp: str
    end_timestamp: str
    alarm_group_id: str
    anomaly_type: str | None = None


class AlarmIntervalsResponse(BaseModel):
    """Response envelope for alarm intervals (GD-07)."""

    data: list[AlarmIntervalItem]
    row_count: int
    parameters: dict[str, Any]


class NetcapEntityItem(BaseModel):
    """A single parsed UCI entity for display in the UI (GD-08).

    Column names use human-readable labels matching the Golden Data format.
    """

    model_config = ConfigDict(populate_by_name=True)

    source_mac: str
    destination_mac: str
    source_ip: str
    destination_ip: str
    source_port: str
    destination_port: str
    vlan: str
    ip_proto: str
    protocols: str
    uci: str


class GroupEntitiesResponse(BaseModel):
    """Response envelope for alarm group netcap entities (GD-08)."""

    data: list[dict[str, Any]]
    row_count: int
    parameters: dict[str, Any]
