"""Anomaly domain: UCI parsing, bounds merging, and signal-color computation."""

from otalon_api.domain.anomaly.processing import compute_signal_color, parse_uci, prepare_timeseries_with_bounds

__all__ = [
    "compute_signal_color",
    "parse_uci",
    "prepare_timeseries_with_bounds",
]
