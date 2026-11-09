"""Baseline-traffic MCP tools.

These tools mirror the paper's offline ``*_baseline_*`` tools but in the
live system they:
- resolve ``baseline_id`` (or the active baseline) via PostgreSQL,
- read InfluxDB time series with the baseline's time window using the
  same live bucket as the regular tools,
- list / sample PCAP chunks from the curated baseline directory written by
  ``otalon-api``'s :class:`BaselineService`.

The 5 exposed tools:
- ``influx.list_baseline_time_series``
- ``influx.get_baseline_single_time_series``
- ``influx.get_baseline_multiple_time_series``
- ``pcap.list_baseline_chunks``
- ``pcap.get_baseline_chunks``
"""

from __future__ import annotations

import json
import random
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import psycopg2
import psycopg2.extras
from loguru import logger

from . import influx as influx_tools

_state: Dict[str, Any] = {
    "dsn": "",
    "baseline_dir": "/app/pcap/baseline",
}


def init(dsn: str, baseline_dir: str = "/app/pcap/baseline") -> None:
    """Initialise the baseline tools with the PG DSN and baseline filesystem path."""
    _state["dsn"] = dsn
    _state["baseline_dir"] = baseline_dir or _state["baseline_dir"]
    logger.info(
        "tools.baseline.init: baseline_dir={} dsn_set={}",
        _state["baseline_dir"],
        bool(dsn),
    )


# ── Helpers ─────────────────────────────────────────────────────────────


def _connect():
    if not _state["dsn"]:
        raise RuntimeError("tools.baseline: POSTGRES_DSN not configured")
    return psycopg2.connect(_state["dsn"])


def _resolve_baseline(baseline_id: Optional[str]) -> Optional[Dict[str, Any]]:
    """Return a baselines row by id, or the active baseline if id is None.

    Returns None if no match and no active baseline is configured.
    """
    sql_active = "SELECT * FROM baselines WHERE is_active = TRUE LIMIT 1"
    sql_by_id = "SELECT * FROM baselines WHERE id = %s"
    try:
        with _connect() as conn:
            with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
                if baseline_id:
                    cur.execute(sql_by_id, (str(baseline_id),))
                else:
                    cur.execute(sql_active)
                row = cur.fetchone()
    except Exception as exc:
        logger.error("tools.baseline._resolve_baseline error: {}", exc)
        return None
    return dict(row) if row else None


def _to_iso(value: Any) -> Optional[str]:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value.isoformat()
    return str(value)


def _clamp_window(baseline: Dict[str, Any], start: Optional[str], stop: Optional[str]) -> Tuple[str, str]:
    """Return (start, stop) clamped to the baseline window."""
    bs = baseline["start_ts"]
    be = baseline["end_ts"]
    if isinstance(bs, str):
        bs_dt = datetime.fromisoformat(bs.replace("Z", "+00:00"))
    else:
        bs_dt = bs
    if isinstance(be, str):
        be_dt = datetime.fromisoformat(be.replace("Z", "+00:00"))
    else:
        be_dt = be

    def _parse(s: Optional[str]) -> Optional[datetime]:
        if not s:
            return None
        try:
            return datetime.fromisoformat(s.replace("Z", "+00:00"))
        except ValueError:
            return None

    s_dt = _parse(start)
    e_dt = _parse(stop)
    s_eff = max(bs_dt, s_dt) if s_dt else bs_dt
    e_eff = min(be_dt, e_dt) if e_dt else be_dt
    if e_eff <= s_eff:
        s_eff, e_eff = bs_dt, be_dt
    return s_eff.isoformat(), e_eff.isoformat()


def _baseline_index_path(baseline_id: str) -> Path:
    return Path(_state["baseline_dir"]) / baseline_id / "index.json"


def _load_baseline_index(baseline_id: str) -> List[Dict[str, Any]]:
    path = _baseline_index_path(baseline_id)
    if not path.is_file():
        return []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        logger.error("tools.baseline._load_baseline_index error: {}", exc)
        return []


# ── InfluxDB baseline tools ─────────────────────────────────────────────


def list_baseline_time_series(
    start: Optional[str] = None,
    stop: Optional[str] = None,
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    nonzero: bool = False,
    fields: Optional[List[str]] = None,
    threshold: Optional[float] = 0.0,
    baseline_id: Optional[str] = None,
) -> Dict[str, Any]:
    """List distinct UCIs observed in the active or specified baseline window.

    The optional ``start``/``stop`` clamp the query to a sub-range of the
    baseline window. Always returns ``baseline_id`` and the resolved
    ``start``/``stop`` for transparency.
    """
    baseline = _resolve_baseline(baseline_id)
    if baseline is None:
        return {"ok": False, "error": "no active baseline configured"}
    s, e = _clamp_window(baseline, start, stop)
    result = influx_tools.list_time_series(
        start=s,
        stop=e,
        measurement=measurement,
        id_tag=id_tag,
        nonzero=nonzero,
        fields=fields,
        threshold=threshold,
    )
    if isinstance(result, dict) and result.get("ok"):
        result["baseline_id"] = str(baseline["id"])
    return result


def _pick_chunk_window(
    baseline_id: str, chunk_filename: Optional[str]
) -> Tuple[Optional[str], Optional[str], Optional[str]]:
    """Return (start_iso, stop_iso, chunk_filename) for a baseline chunk.

    If ``chunk_filename`` is None, a random chunk is picked. Window is
    derived from the chunk's filename (assumed 30 s duration) and any
    metadata in the index file.
    """
    index = _load_baseline_index(baseline_id)
    if not index:
        return None, None, None
    if chunk_filename:
        entry = next((e for e in index if e.get("filename") == chunk_filename), None)
    else:
        entry = random.choice(index)
    if entry is None:
        return None, None, None
    start = entry.get("start_ts")
    if isinstance(start, datetime):
        start_dt = start
    else:
        try:
            start_dt = datetime.fromisoformat(str(start).replace("Z", "+00:00"))
        except Exception:
            return None, None, entry.get("filename")
    if start_dt.tzinfo is None:
        start_dt = start_dt.replace(tzinfo=timezone.utc)
    end_dt = start_dt.fromtimestamp(start_dt.timestamp() + 30, tz=timezone.utc)
    return start_dt.isoformat(), end_dt.isoformat(), entry.get("filename")


def get_baseline_single_time_series(
    series_id: str,
    baseline_id: Optional[str] = None,
    chunk_filename: Optional[str] = None,
    fields: Optional[List[str]] = None,
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    limit: Optional[int] = None,
    aggregate: Optional[str | Dict[str, str]] = "avg",
    sample_max_points: Optional[int] = 1000,
    preserve_extrema: bool = True,
) -> Dict[str, Any]:
    """Read one baseline UCI for a chosen (or random) baseline PCAP chunk window."""
    baseline = _resolve_baseline(baseline_id)
    if baseline is None:
        return {"ok": False, "error": "no active baseline configured"}
    start_iso, stop_iso, chunk = _pick_chunk_window(str(baseline["id"]), chunk_filename)
    if not start_iso:
        return {
            "ok": False,
            "error": "no baseline chunk available",
            "baseline_id": str(baseline["id"]),
        }
    result = influx_tools.read_single_time_series(
        series_id=series_id,
        fields=fields,
        start=start_iso,
        stop=stop_iso,
        measurement=measurement,
        id_tag=id_tag,
        limit=limit,
        aggregate=aggregate,
        sample_max_points=sample_max_points,
        preserve_extrema=preserve_extrema,
    )
    if isinstance(result, dict):
        result["baseline_id"] = str(baseline["id"])
        result["baseline_chunk"] = chunk
    return result


def get_baseline_multiple_time_series(
    series_ids: List[str],
    baseline_id: Optional[str] = None,
    chunk_filename: Optional[str] = None,
    fields: Optional[List[str]] = None,
    measurement: Optional[str] = None,
    id_tag: Optional[str] = None,
    limit: Optional[int] = None,
    initial_chunk_size: int = 5000,
) -> Dict[str, Any]:
    """Read multiple baseline UCIs for a single baseline PCAP chunk window."""
    baseline = _resolve_baseline(baseline_id)
    if baseline is None:
        return {"ok": False, "error": "no active baseline configured"}
    start_iso, stop_iso, chunk = _pick_chunk_window(str(baseline["id"]), chunk_filename)
    if not start_iso:
        return {
            "ok": False,
            "error": "no baseline chunk available",
            "baseline_id": str(baseline["id"]),
        }
    result = influx_tools.read_multiple_time_series(
        ids=series_ids,
        fields=fields,
        start=start_iso,
        stop=stop_iso,
        measurement=measurement,
        id_tag=id_tag,
        limit=limit,
        initial_chunk_size=initial_chunk_size,
    )
    if isinstance(result, dict):
        result["baseline_id"] = str(baseline["id"])
        result["baseline_chunk"] = chunk
    return result


# ── PCAP baseline tools ─────────────────────────────────────────────────


def list_baseline_chunks(
    baseline_id: Optional[str] = None,
    start_ts: Optional[str] = None,
    end_ts: Optional[str] = None,
    last_minutes: Optional[int] = None,
    last_hours: Optional[int] = None,
    last_chunks: Optional[int] = None,
) -> Dict[str, Any]:
    """List baseline PCAP chunks (optionally filtered by time / count)."""
    baseline = _resolve_baseline(baseline_id)
    if baseline is None:
        return {"ok": False, "error": "no active baseline configured"}
    bid = str(baseline["id"])
    index = _load_baseline_index(bid)
    if not index:
        return {"ok": True, "chunks": [], "count": 0, "baseline_id": bid}

    s_dt = datetime.fromisoformat(start_ts.replace("Z", "+00:00")) if start_ts else None
    e_dt = datetime.fromisoformat(end_ts.replace("Z", "+00:00")) if end_ts else None

    def _entry_dt(e: Dict[str, Any]) -> datetime:
        v = e.get("start_ts")
        if isinstance(v, datetime):
            return v if v.tzinfo else v.replace(tzinfo=timezone.utc)
        try:
            dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)
        except Exception:
            return datetime.fromtimestamp(0, tz=timezone.utc)

    chunks = list(index)
    if s_dt or e_dt:
        chunks = [c for c in chunks if (s_dt is None or _entry_dt(c) >= s_dt) and (e_dt is None or _entry_dt(c) < e_dt)]
    elif last_minutes is not None or last_hours is not None:
        # Relative to the baseline's end_ts (its "now")
        be = baseline["end_ts"]
        if isinstance(be, str):
            be = datetime.fromisoformat(be.replace("Z", "+00:00"))
        delta = (last_hours or 0) * 60 + (last_minutes or 0)
        cutoff = be.fromtimestamp(be.timestamp() - delta * 60, tz=timezone.utc)
        chunks = [c for c in chunks if _entry_dt(c) >= cutoff]
    chunks.sort(key=_entry_dt)
    if last_chunks:
        chunks = chunks[-int(last_chunks) :]
    enriched = [{**c, "source": "baseline", "baseline_id": bid} for c in chunks]
    return {
        "ok": True,
        "chunks": enriched,
        "count": len(enriched),
        "baseline_id": bid,
    }


def get_baseline_chunks(baseline_id: Optional[str] = None, limit: int = 5) -> Dict[str, Any]:
    """Return up to ``limit`` randomly sampled baseline chunks (quick lookup)."""
    baseline = _resolve_baseline(baseline_id)
    if baseline is None:
        return {"ok": False, "error": "no active baseline configured"}
    bid = str(baseline["id"])
    index = _load_baseline_index(bid)
    if not index:
        return {"ok": True, "chunks": [], "count": 0, "baseline_id": bid}
    n = max(1, int(limit))
    sample = random.sample(index, min(n, len(index)))
    enriched = [{**c, "source": "baseline", "baseline_id": bid} for c in sample]
    return {
        "ok": True,
        "chunks": enriched,
        "count": len(enriched),
        "baseline_id": bid,
    }
