"""Shared utility functions for MCP tool helpers.

This module provides common helpers for time range construction and
ID list handling across Influx and Postgres tool implementations.

Docstrings are written in English as per workspace rules.
"""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import List, Optional, Sequence, Tuple


def iso_now() -> str:
    """Return current UTC timestamp in ISO-8601 format with trailing 'Z'."""
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"


def iso_minus(minutes: int) -> str:
    """Return UTC ISO-8601 timestamp at `minutes` minutes ago (with trailing 'Z')."""
    mins = max(1, int(minutes))
    return (datetime.utcnow().replace(microsecond=0) - timedelta(minutes=mins)).isoformat() + "Z"


def time_range_default(minutes: int) -> Tuple[str, str]:
    """Build a default (start, stop) ISO-8601 Z time range ending at now."""
    stop = iso_now()
    start = iso_minus(minutes)
    return start, stop


def ensure_nonempty_ids(ids: Optional[Sequence[str]], fallback_ids: Sequence[str], k: int = 5) -> List[str]:
    """Return `ids` if provided and non-empty, otherwise top-k from `fallback_ids`.

    Parameters
    ----------
    ids : Sequence[str], optional
        Explicit IDs to use if provided and non-empty after trimming.
    fallback_ids : Sequence[str]
        Fallback ID sequence from which the top-k will be used.
    k : int
        Number of fallback IDs to select when `ids` is empty (default: 5).

    Returns
    -------
    list[str]
        The chosen ID list.
    """
    if ids:
        cleaned = [str(i).strip() for i in ids if str(i).strip()]
        if cleaned:
            return cleaned
    return list(fallback_ids[: max(1, k)])
