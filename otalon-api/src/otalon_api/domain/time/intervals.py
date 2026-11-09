"""Canonical local-time interval normalization for training requests."""

from __future__ import annotations

from datetime import datetime, timezone
from zoneinfo import ZoneInfo

from otalon_api.domain.time.validation import RuntimeRetrainValidationError

_BERLIN = ZoneInfo("Europe/Berlin")


def normalize_intervals(
    intervals: list[tuple[str, str]] | None = None,
    *,
    window_start: str | None = None,
    window_stop: str | None = None,
) -> list[tuple[str, str]]:
    """Normalize local Europe/Berlin intervals to a sorted UTC union.

    The legacy ``window_start``/``window_stop`` pair is accepted as one
    interval. Adjacent and overlapping ranges are merged so downstream
    workers never double-count samples.
    """
    if (window_start is None) != (window_stop is None) and not intervals:
        raise RuntimeRetrainValidationError("window_start and window_stop must be provided together")
    raw = list(intervals or [])
    if not raw and (window_start is not None or window_stop is not None):
        if window_start is None or window_stop is None:
            raise RuntimeRetrainValidationError("window_start and window_stop must be provided together")
        raw.append((window_start, window_stop))
    if not raw:
        raise RuntimeRetrainValidationError("at least one training interval is required")
    parsed = sorted((_parse(start), _parse(stop)) for start, stop in raw)
    if any(start >= stop for start, stop in parsed):
        raise RuntimeRetrainValidationError("each training interval must have start before stop")
    merged: list[list[datetime]] = []
    for start, stop in parsed:
        if merged and start <= merged[-1][1]:
            merged[-1][1] = max(merged[-1][1], stop)
        else:
            merged.append([start, stop])
    return [(start.isoformat(), stop.isoformat()) for start, stop in merged]


def _parse(value: str) -> datetime:
    """Parse a wall-clock timestamp and return an aware UTC datetime."""
    try:
        parsed = datetime.fromisoformat(value.replace(" ", "T"))
    except (TypeError, ValueError) as exc:
        raise RuntimeRetrainValidationError(f"invalid training timestamp: {value!r}") from exc
    if parsed.tzinfo is None:
        parsed = _localize_berlin(parsed, value)
    return parsed.astimezone(timezone.utc)


def _localize_berlin(value: datetime, raw: str) -> datetime:
    """Reject ambiguous/nonexistent Berlin wall times deterministically."""
    candidates = [value.replace(tzinfo=_BERLIN, fold=fold) for fold in (0, 1)]
    round_trips = [
        candidate.astimezone(timezone.utc).astimezone(_BERLIN).replace(tzinfo=None) for candidate in candidates
    ]
    if any(round_trip != value for round_trip in round_trips):
        raise RuntimeRetrainValidationError(f"nonexistent Europe/Berlin wall time: {raw!r}")
    if candidates[0].utcoffset() != candidates[1].utcoffset():
        raise RuntimeRetrainValidationError(f"ambiguous Europe/Berlin wall time: {raw!r}; provide an offset")
    return candidates[0]
