"""InfluxDB helper functions for MCP tools.

This module encapsulates logic for InfluxDB time series operations.
It is initialized via tools.__init__.init() which passes the InfluxRepo and Defaults.

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

from typing import Any, Dict, List, Optional

from loguru import logger

from otalon_mcp.repositories.influx_repo import InfluxRepo
from otalon_mcp.serialization import dataframe_to_table

from .utils import ensure_nonempty_ids, time_range_default

INFLUX_REPO: InfluxRepo | None = None
DEFAULTS: Any | None = None


def init(influx_repo: InfluxRepo, defaults: Any) -> None:
    """Initialize influx helpers with shared dependencies."""
    global INFLUX_REPO, DEFAULTS
    INFLUX_REPO = influx_repo
    DEFAULTS = defaults
    logger.debug("tools.influx.init: repo and defaults injected")


def list_recent_time_series_ids(
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    minutes: int = 10,
) -> Dict[str, Any]:
    """List distinct time series IDs observed in the last N minutes."""
    if INFLUX_REPO is None or DEFAULTS is None:
        err = {"ok": False, "error": "Influx helpers not initialized"}
        logger.error("tools.influx.list_recent_time_series_ids error: {err}", err=err)
        return err

    meas = measurement or DEFAULTS.measurement
    tag = id_tag or DEFAULTS.id_tag
    try:
        ids = INFLUX_REPO.list_ids(measurement=meas, id_tag=tag, minutes=max(1, int(minutes)))
        result = {"ok": True, "ids": ids, "count": len(ids)}
        logger.info("tools.influx.list_recent_time_series_ids({meas},{tag}) -> {n}", meas=meas, tag=tag, n=len(ids))
        return result
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.influx.list_recent_time_series_ids error: {err}", err=err)
        return err


def list_time_series(
    start: Optional[str] = None,
    stop: Optional[str] = None,
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    nonzero: bool = False,
    fields: Optional[List[str]] = None,
    threshold: Optional[float] = 0.0,
    default_window_minutes: int = 60,
) -> Dict[str, Any]:
    """List distinct time series IDs observed between two timestamps."""
    if INFLUX_REPO is None or DEFAULTS is None:
        err = {"ok": False, "error": "Influx helpers not initialized"}
        logger.error("tools.influx.list_time_series error: {err}", err=err)
        return err

    meas = measurement or DEFAULTS.measurement
    tag = id_tag or DEFAULTS.id_tag
    if start and stop:
        start_ts, stop_ts = start, stop
    else:
        start_ts, stop_ts = time_range_default(default_window_minutes)
    sum_fields = fields or list(DEFAULTS.fields)

    try:
        ids = INFLUX_REPO.list_ids_between(
            measurement=meas,
            id_tag=tag,
            start=start_ts,
            stop=stop_ts,
            nonzero=bool(nonzero),
            fields=sum_fields,
            threshold=threshold,
        )
        result = {"ok": True, "ids": ids, "count": len(ids), "start": start_ts, "stop": stop_ts}
        logger.info("tools.influx.list_time_series({meas},{tag}) -> {n}", meas=meas, tag=tag, n=len(ids))
        return result
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.influx.list_time_series error: {err}", err=err)
        return err


def read_single_time_series(
    series_id: str,
    fields: Optional[List[str]] = None,
    start: Optional[str] = None,
    stop: Optional[str] = None,
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    tags: Optional[Dict[str, str | int | float | bool]] = None,
    limit: Optional[int] = None,
    aggregate: Optional[str | Dict[str, str]] = "avg",
    sample_max_points: Optional[int] = 1000,
    preserve_extrema: bool = True,
    default_window_minutes: int = 60,
) -> Dict[str, Any]:
    """Read a single time series for the given series_id."""
    if INFLUX_REPO is None or DEFAULTS is None:
        err = {"ok": False, "error": "Influx helpers not initialized"}
        logger.error("tools.influx.read_single_time_series error: {err}", err=err)
        return err

    meas = measurement or DEFAULTS.measurement
    tag = id_tag or DEFAULTS.id_tag
    fs = fields or list(DEFAULTS.fields)

    tag_filters = dict(tags or {})
    if tag not in tag_filters:
        tag_filters[tag] = series_id

    if start and stop:
        start_ts, stop_ts = start, stop
    else:
        start_ts, stop_ts = time_range_default(default_window_minutes)

    try:
        df = INFLUX_REPO.query_timeseries(
            measurement=meas,
            id_tag=tag,
            fields=fs,
            start=start_ts,
            stop=stop_ts,
            tags=tag_filters,
            limit=limit,
            aggregate=aggregate,
            sample_max_points=sample_max_points,
            preserve_extrema=preserve_extrema,
        )
        table = dataframe_to_table(df, include_index=True, index_name="time")
        logger.info(
            "tools.influx.read_single_time_series({series_id}) -> {n} rows", series_id=series_id, n=table["rowcount"]
        )
        return {"ok": True, "series_id": series_id, "data": table}
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.influx.read_single_time_series error: {err}", err=err)
        return err


def read_multiple_time_series(
    ids: Optional[List[str]] = None,
    fields: Optional[List[str]] = None,
    start: Optional[str] = None,
    stop: Optional[str] = None,
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    limit: Optional[int] = None,
    initial_chunk_size: int = 5000,
    default_recent_minutes: int = 10,
    default_window_minutes: int = 60,
    fallback_k: int = 5,
) -> Dict[str, Any]:
    """Read multiple time series for a set of IDs. Uses recent IDs as fallback when `ids` omitted."""
    if INFLUX_REPO is None or DEFAULTS is None:
        err = {"ok": False, "error": "Influx helpers not initialized"}
        logger.error("tools.influx.read_multiple_time_series error: {err}", err=err)
        return err

    meas = measurement or DEFAULTS.measurement
    tag = id_tag or DEFAULTS.id_tag
    fs = fields or list(DEFAULTS.fields)

    if start and stop:
        start_ts, stop_ts = start, stop
    else:
        start_ts, stop_ts = time_range_default(default_window_minutes)

    try:
        recent_ids = INFLUX_REPO.list_ids(measurement=meas, id_tag=tag, minutes=default_recent_minutes)
        ids_chosen = ensure_nonempty_ids(ids, recent_ids, k=fallback_k)
        df = INFLUX_REPO.query_timeseries_multi_ids_chunked(
            measurement=meas,
            id_tag=tag,
            fields=fs,
            start=start_ts,
            stop=stop_ts,
            ids=ids_chosen,
            limit=limit,
            initial_chunk_size=initial_chunk_size,
        )
        table = dataframe_to_table(df, include_index=False)
        result = {"ok": True, "ids": ids_chosen, "data": table}
        logger.info(
            "tools.influx.read_multiple_time_series(ids={n}) -> {rows} rows", n=len(ids_chosen), rows=table["rowcount"]
        )
        return result
    except Exception as exc:
        err = {"ok": False, "error": str(exc)}
        logger.error("tools.influx.read_multiple_time_series error: {err}", err=err)
        return err
