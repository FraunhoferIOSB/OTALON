"""MITRE labeling per data source using CISF ground-truth files.

Provides dedicated labeler classes for each data source module:
``ConnectionLabeler``, ``MacLabeler``, and ``ProtoLabeler``.
"""

from __future__ import annotations

import ipaddress
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import timezone
from pathlib import Path
from typing import Any
from zoneinfo import ZoneInfo

import pandas as pd
import polars as pl
from loguru import logger

LABEL_TIME_MARGIN_SECONDS: int = 30
"""Default time margin (±seconds) for matching labels to data rows.

Time-bucketed training data may aggregate up to ``bucket_seconds``
worth of packets into a single row whose timestamp falls anywhere
inside the bucket. The margin must therefore be at least one bucket
plus the typical attack duration to capture all attack rows reliably.
"""

DEFAULT_GROUND_TRUTH_TIMEZONE: str = "Europe/Berlin"
"""Timezone assumed for naive timestamps in CISF ground-truth files.

The CISF files record local wall-clock time (``"2026-04-18 22:35:59"``,
no offset), while the measurement timestamps in InfluxDB are true UTC —
``otalon-capture`` writes them via
``datetime.fromtimestamp(..., tz=timezone.utc)``.

These bounds used to be built as naive ``pd.Timestamp`` and compared
directly against the UTC data column, applying a silent 1-2 hour shift
that dwarfs :data:`LABEL_TIME_MARGIN_SECONDS` and mislabels every row at
the edges of an attack window. The group-alarm labeler already localized
correctly; this module did not, so the two disagreed on the same file
(audit CLAS-04). Matches
``otalon_clas.ml.group_classifier.labeler.DEFAULT_GROUND_TRUTH_TIMEZONE``.
"""


def _row_timestamp_utc(value: Any) -> pd.Timestamp:
    """Normalize a measurement timestamp to UTC.

    Measurement timestamps originate from InfluxDB and are true UTC;
    naive values (e.g. a parquet column that lost its tzinfo) are
    therefore localized as UTC, not as the ground-truth timezone. Both
    sides of the label comparison must be tz-aware or pandas raises on
    the comparison (audit CLAS-04).

    Args:
        value: Timestamp-like value from the data frame's ``time`` column.

    Returns:
        A timezone-aware ``pd.Timestamp`` in UTC.
    """
    return _to_utc_timestamp(value, None)


def _to_utc_timestamp(value: Any, default_tz: ZoneInfo | None) -> pd.Timestamp:
    """Normalize a timestamp to UTC, localizing naive input to ``default_tz``.

    Args:
        value: Timestamp-like value (string, ``datetime`` or
            ``pd.Timestamp``).
        default_tz: Timezone assumed for naive input; ``None`` treats
            naive input as already-UTC.

    Returns:
        A timezone-aware ``pd.Timestamp`` in UTC.
    """
    ts = pd.Timestamp(value)
    if ts.tzinfo is None:
        ts = ts.tz_localize(default_tz if default_tz is not None else timezone.utc)
    return ts.tz_convert(timezone.utc)

PROTOCOL_ALIAS_MAP: dict[str, list[str]] = {
    "pn_dcp": ["PROFINET_RT_DCP", "PROFINET-RT-DCP", "profinet_rt_dcp"],
    "opcua": ["OPC-UA", "OPC_UA", "opcua"],
    "arp": ["ARP", "arp"],
    "tcp": ["TCP", "tcp"],
    "udp": ["UDP", "udp"],
    "icmp": ["ICMP", "icmp"],
    "snmp": ["SNMP", "snmp"],
}
"""Mapping from CISF short protocol names to InfluxDB protocol tag substrings."""


@dataclass
class MitreLabel:
    """A single MITRE technique label entry from a ground-truth file."""

    module_name: str
    technical_method: str
    start_time: pd.Timestamp
    end_time: pd.Timestamp
    target_ip: list[str]
    target_mac: list[str]
    protocol: str
    source_ip: str
    source_mac: str

    def label_for(self, field: str) -> str:
        """Return the label string corresponding to ``field``.

        Args:
            field: Either ``"module_name"`` (e.g. ``"T0846/arp_scan"``)
                or ``"technical_method"`` (e.g. ``"arp_scan"``).

        Returns:
            The label value; falls back to ``module_name`` when an
            unknown ``field`` is requested or when the requested field
            is empty.
        """
        if field == "technical_method" and self.technical_method:
            return self.technical_method
        return self.module_name


def load_labels(
    path: str | Path,
    time_margin_seconds: int = LABEL_TIME_MARGIN_SECONDS,
    ground_truth_timezone: str | None = DEFAULT_GROUND_TRUTH_TIMEZONE,
) -> list[MitreLabel]:
    """Load MITRE labels from a JSON ground-truth file.

    Naive timestamps in the file are interpreted in
    ``ground_truth_timezone`` and converted to UTC, so the resulting
    bounds compare correctly against the UTC measurement timestamps
    (audit CLAS-04).

    Args:
        path: Path to the JSON label file.
        time_margin_seconds: Time margin applied to start/end times.
        ground_truth_timezone: IANA timezone assumed for naive
            timestamps. Pass ``None`` when the file already records UTC.

    Returns:
        List of parsed MitreLabel entries with UTC-aware, expanded time windows.
    """
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if isinstance(raw, dict):
        raw = [raw]

    default_tz = ZoneInfo(ground_truth_timezone) if ground_truth_timezone else None
    margin = pd.Timedelta(seconds=time_margin_seconds)
    labels: list[MitreLabel] = []
    skipped = 0
    for entry in raw:
        if not _has_host_selector(entry):
            # Both _ip_match and _mac_match return True when their field is
            # empty, so an entry with no IP *and* no MAC selector matches
            # EVERY row inside its time window — one malformed entry would
            # relabel the whole window as an attack. That is a ground-truth
            # configuration error, not a wildcard (audit QUA-09).
            logger.error(
                "Ground-truth entry {!r} in {} has no target/source IP and no "
                "target/source MAC; it would match every row in its window. Skipping it.",
                entry.get("module_name", "<unnamed>"),
                path,
            )
            skipped += 1
            continue
        labels.append(
            MitreLabel(
                module_name=entry["module_name"],
                technical_method=str(entry.get("technical_method", "")),
                start_time=_to_utc_timestamp(entry["start_time"], default_tz) - margin,
                end_time=_to_utc_timestamp(entry["end_time"], default_tz) + margin,
                target_ip=entry.get("target_ip", []),
                target_mac=[m.lower() for m in entry.get("target_mac", [])],
                protocol=entry.get("protocol", ""),
                source_ip=entry.get("source_ip", ""),
                source_mac=entry.get("source_mac", "").lower(),
            )
        )
    if skipped:
        logger.warning(
            "Skipped {} malformed ground-truth entr{} from {}",
            skipped,
            "y" if skipped == 1 else "ies",
            path,
        )
    logger.info("Loaded {} MITRE labels from {}", len(labels), path)
    return labels


def _has_host_selector(entry: dict[str, Any]) -> bool:
    """Return whether a ground-truth entry identifies specific hosts.

    An entry must narrow by at least one of target/source IP or MAC;
    otherwise it degenerates into "everything in this time window".

    Args:
        entry: Raw ground-truth entry as parsed from JSON.

    Returns:
        Whether at least one host selector is present and non-empty.
    """
    return bool(
        entry.get("target_ip")
        or entry.get("source_ip")
        or entry.get("target_mac")
        or entry.get("source_mac")
    )


class BaseLabeler(ABC):
    """Abstract base class for per-data-source MITRE labelers."""

    def __init__(
        self,
        labels: list[MitreLabel],
        label_field: str = "module_name",
    ) -> None:
        """Initialize with pre-loaded labels.

        Args:
            labels: List of MitreLabel entries.
            label_field: Name of the :class:`MitreLabel` attribute
                used as the row's class label. Either
                ``"module_name"`` (e.g. ``T0846/arp_scan``) or
                ``"technical_method"`` (e.g. ``arp_scan``). Defaults
                to ``"module_name"`` for backward compatibility.
        """
        self._labels = labels
        self._label_field = label_field

    @abstractmethod
    def apply_labels(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply MITRE labels to a data DataFrame.

        Adds a ``label`` column containing the MITRE technique name
        (e.g., ``"T0846/pn_discovery"``) or ``"benign"`` for non-matching rows.

        Args:
            df: Data DataFrame with ``time`` and tag columns.

        Returns:
            DataFrame with an added ``label`` column.
        """


class ConnectionLabeler(BaseLabeler):
    """Labeler for connection/UCI data.

    Matches UCI fields (IP + MAC) and protocol against ground-truth entries.
    """

    def apply_labels(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply labels by matching UCI components against ground-truth.

        Matches ``target_ip``/``source_ip`` against IP fields from UCI,
        ``target_mac``/``source_mac`` against MAC fields from UCI, and
        ``protocol`` as a partial match against the UCI protocol stack.

        Args:
            df: DataFrame with ``time`` and ``uci`` columns.

        Returns:
            DataFrame with added ``label`` column.
        """
        if "uci" not in df.columns:
            return df.with_columns(pl.lit("benign").alias("label"))

        pdf = df.to_pandas()
        labels_col = ["benign"] * len(pdf)

        for idx, row in pdf.iterrows():
            uci = str(row.get("uci", ""))
            ts = _row_timestamp_utc(row["time"])
            parts = uci.split("/")
            if len(parts) < 9:
                continue

            src_mac = parts[0].lower()
            dst_mac = parts[1].lower()
            src_ip = parts[4].lower()
            dst_ip = parts[5].lower()
            proto_stack = parts[8].lower() if len(parts) > 8 else ""

            for lbl in self._labels:
                if not (lbl.start_time <= ts <= lbl.end_time):
                    continue
                ip_match = _ip_match(src_ip, dst_ip, lbl)
                mac_match = _mac_match(src_mac, dst_mac, lbl)
                proto_match = _proto_partial_match(proto_stack, lbl.protocol)
                if ip_match and mac_match and proto_match:
                    labels_col[idx] = lbl.label_for(self._label_field)
                    break

        pdf["label"] = labels_col
        return pl.from_pandas(pdf)


class MacLabeler(BaseLabeler):
    """Labeler for MAC traffic data.

    Matches ``mac_address`` tag directly against ``target_mac``/``source_mac``.
    """

    def apply_labels(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply labels by matching mac_address tag against ground-truth.

        Args:
            df: DataFrame with ``time`` and ``mac_address`` columns.

        Returns:
            DataFrame with added ``label`` column.
        """
        if "mac_address" not in df.columns:
            return df.with_columns(pl.lit("benign").alias("label"))

        pdf = df.to_pandas()
        labels_col = ["benign"] * len(pdf)

        for idx, row in pdf.iterrows():
            mac = str(row.get("mac_address", "")).lower()
            ts = _row_timestamp_utc(row["time"])

            for lbl in self._labels:
                if not (lbl.start_time <= ts <= lbl.end_time):
                    continue
                if mac in lbl.target_mac or mac == lbl.source_mac:
                    labels_col[idx] = lbl.label_for(self._label_field)
                    break

        pdf["label"] = labels_col
        return pl.from_pandas(pdf)


class ProtoLabeler(BaseLabeler):
    """Labeler for protocol traffic data.

    Matches ``protocol`` tag using partial/case-insensitive string matching.
    """

    def apply_labels(self, df: pl.DataFrame) -> pl.DataFrame:
        """Apply labels by partial-matching protocol tags against ground-truth.

        Args:
            df: DataFrame with ``time`` and ``protocol`` columns.

        Returns:
            DataFrame with added ``label`` column.
        """
        if "protocol" not in df.columns:
            return df.with_columns(pl.lit("benign").alias("label"))

        pdf = df.to_pandas()
        labels_col = ["benign"] * len(pdf)

        for idx, row in pdf.iterrows():
            proto = str(row.get("protocol", "")).lower()
            ts = _row_timestamp_utc(row["time"])

            for lbl in self._labels:
                if not (lbl.start_time <= ts <= lbl.end_time):
                    continue
                if _proto_partial_match(proto, lbl.protocol):
                    labels_col[idx] = lbl.label_for(self._label_field)
                    break

        pdf["label"] = labels_col
        return pl.from_pandas(pdf)


def _ip_selector_matches(selector: str, candidates: tuple[str, ...]) -> bool:
    """Match one ground-truth IP selector against observed addresses.

    A selector carrying a prefix (``"192.168.0.0/24"``) is treated as a
    network and tested by containment; a plain address is compared
    exactly. Ground truth is written by humans and CIDR is the natural way
    to express a scan target, but the comparison was pure string equality,
    so every subnet selector silently matched nothing — 50 entries in the
    live CISF ground truth, i.e. every ``arp_scan`` label (audit QUA-09).

    Args:
        selector: A ground-truth IP or CIDR string.
        candidates: Observed addresses from the record's UCI.

    Returns:
        Whether any candidate satisfies the selector.
    """
    cleaned = selector.strip().lower()
    if not cleaned:
        return False
    if "/" not in cleaned:
        return cleaned in candidates

    try:
        network = ipaddress.ip_network(cleaned, strict=False)
    except ValueError:
        logger.warning(
            "Ground-truth IP selector {!r} is neither an address nor a network; ignoring it",
            selector,
        )
        return False

    for candidate in candidates:
        if not candidate:
            continue
        try:
            if ipaddress.ip_address(candidate) in network:
                return True
        except ValueError:
            continue
    return False


def _ip_match(src_ip: str, dst_ip: str, label: MitreLabel) -> bool:
    """Check if source/destination IP matches the label's target/source IPs.

    For non-IP traffic (ARP, raw Ethernet, etc.) ``src_ip`` and ``dst_ip``
    are both empty strings. In that case the IP check is skipped and
    matching falls back to MAC + protocol.

    Selectors may be plain addresses or CIDR networks; see
    :func:`_ip_selector_matches`.
    """
    if not src_ip and not dst_ip:
        return True
    if not label.target_ip and not label.source_ip:
        return True
    candidates = (src_ip, dst_ip)
    target_match = any(_ip_selector_matches(ip, candidates) for ip in label.target_ip)
    source_match = _ip_selector_matches(label.source_ip, candidates) if label.source_ip else False
    return target_match or source_match


def _mac_match(src_mac: str, dst_mac: str, label: MitreLabel) -> bool:
    """Check if source/destination MAC matches the label's target/source MACs."""
    if not label.target_mac and not label.source_mac:
        return True
    target_match = any(mac in (src_mac, dst_mac) for mac in label.target_mac)
    source_match = label.source_mac in (src_mac, dst_mac) if label.source_mac else False
    return target_match or source_match


def _proto_partial_match(data_protocol: str, label_protocol: str) -> bool:
    """Check if a protocol tag partially matches the label's protocol field.

    Uses the ``PROTOCOL_ALIAS_MAP`` for normalized matching.

    Args:
        data_protocol: Protocol string from data (e.g., ``"ethernet:vlan:profinet_rt_dcp"``).
        label_protocol: Protocol name from label file (e.g., ``"pn_dcp"``).

    Returns:
        True if a partial match is found.
    """
    if not label_protocol:
        return True

    label_lower = label_protocol.lower()

    if label_lower in data_protocol:
        return True

    aliases = PROTOCOL_ALIAS_MAP.get(label_lower, [])
    for alias in aliases:
        if alias.lower() in data_protocol:
            return True

    return False
