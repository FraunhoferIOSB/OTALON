"""Pydantic v2 request/response schemas for time-series API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel


class TimeseriesQueryParams(BaseModel):
    """Query parameters for a single UCI timeseries query."""

    uci: str
    start: datetime
    stop: datetime
    features: list[str]
    aggregate: str | None = None
    sample_max_points: int | None = None
    preserve_extrema: bool = True


class TimeseriesDataRow(BaseModel):
    """A single data row in a timeseries response.

    Extra fields are allowed so that dynamic metric columns can be
    included without enumerating them upfront.
    """

    time: str

    model_config = {"extra": "allow"}


class TimeseriesResponse(BaseModel):
    """Response envelope for timeseries query endpoints."""

    uci: str
    start: str
    stop: str
    features: list[str]
    bucket_seconds: int | None = None
    row_count: int
    data: list[dict[str, Any]]


class DataExtentResponse(BaseModel):
    """Available time extent for the primary network metrics measurement."""

    has_data: bool
    first_ts: str | None = None
    last_ts: str | None = None


class IdsQueryParams(BaseModel):
    """Query parameters for UCI identifier listing."""

    start: datetime
    stop: datetime
    nonzero: bool = False
    fields: list[str] | None = None


class IdsResponseItem(BaseModel):
    """Single entry in the IDs response."""

    uci: str
    is_wildcard: bool = False
    member_count: int = 1
    collapsed_port_count: int | None = None
    rule_trained: bool = True
    profiled: bool = True


class IdsResponse(BaseModel):
    """Response envelope for UCI identifier listing."""

    start: str
    stop: str
    nonzero: bool
    count: int
    data: list[IdsResponseItem]


class SiblingItem(BaseModel):
    """A base-key sibling UCI that has non-zero data in the queried window."""

    uci: str
    src_port: str
    dst_port: str


class SiblingsResponse(BaseModel):
    """Response envelope for the base-key sibling lookup.

    Used by the connections page empty-metrics branch to distinguish a
    rotating-port connection (``has_active_sibling=True``) from a genuinely
    inactive one. Siblings share all 7 base-key fields with the queried UCI but
    differ in port, and are restricted to the same window with non-zero data.
    """

    uci: str
    start: str
    stop: str
    has_active_sibling: bool
    count: int
    siblings: list[SiblingItem]


class WildcardQueryParams(BaseModel):
    """Query parameters for wildcard aggregation."""

    wildcard_uci: str
    members: list[str]
    start: datetime
    stop: datetime
    features: list[str]


class FeaturesResponse(BaseModel):
    """Response for available features listing."""

    features: list[str]


class PlotQueryParams(BaseModel):
    """Query parameters for plot-ready timeseries (combined query + aggregate)."""

    uci: str
    start: datetime
    stop: datetime
    features: list[str]
    sample_max_points: int = 500
    preserve_extrema: bool = True


class SourceIdsResponseItem(BaseModel):
    """Single entry in a source-specific IDs response."""

    id: str
    protocol: str | None = None


class SourceIdsResponse(BaseModel):
    """Response envelope for source-specific identifier listing."""

    start: str
    stop: str
    nonzero: bool
    count: int
    data: list[SourceIdsResponseItem]


class SourceTimeseriesResponse(BaseModel):
    """Response envelope for source-specific timeseries query endpoints."""

    series_id: str
    protocol: str | None = None
    start: str
    stop: str
    features: list[str]
    bucket_seconds: int | None = None
    row_count: int
    data: list[dict[str, Any]]
