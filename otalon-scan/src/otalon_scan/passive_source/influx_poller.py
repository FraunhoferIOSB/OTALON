"""Single-cycle Influx reader for the passive asset seeder.

Implements the two ``SELECT DISTINCT …`` queries pinned by design.md
decision ``D-INFLUX-QUERY`` and the UCI-splitting logic that derives
``(MAC, IPv4)`` pairs from the ``network_metrics.uci`` tag. No PCAP
parsing happens here; this module exists strictly to consume the tags
``otalon-capture`` already writes.

The poller is intentionally stateless — every call to
:meth:`InfluxPoller.poll_once` builds its own SQL strings against the
configured lookback window and returns a fresh :class:`PollResult`.
The poll-loop scheduler (the package's entry point) is responsible for
cadence, MAC filtering, and upserts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

import pandas as pd
from loguru import logger


class InfluxUnreachableError(RuntimeError):
    """Raised when the InfluxDB instance cannot serve the cycle's queries.

    Wraps any underlying transport-level / 5xx / timeout exception so
    the poll loop catches a single, typed signal and applies the
    graceful-degradation rule from spec requirement
    ``Influx Outage Graceful Degradation``.
    """


@dataclass(slots=True)
class PollResult:
    """Outcome of a single Influx poll cycle.

    Attributes:
        macs: Set of distinct lowercase MAC strings observed in the
            ``mac_traffic`` measurement within the lookback window.
        mac_to_ipv4: Mapping from MAC to one IPv4 string seen paired
            with it in a UCI tag. Only MACs that appear in at least one
            well-formed UCI row are present; ``mac_to_ipv4`` MAY be a
            strict subset of ``macs``.
        uci_malformed: Count of UCI tag values that did not split into
            the expected 9 slash-separated components and were
            therefore skipped.
    """

    macs: set[str] = field(default_factory=set)
    mac_to_ipv4: dict[str, str] = field(default_factory=dict)
    uci_malformed: int = 0


class _Queryable(Protocol):
    """Minimal protocol the poller needs from its Influx client.

    Implementing this Protocol (rather than typing the concrete
    ``influxdb_client_3.InfluxDBClient3``) keeps the unit tests free
    of the heavy real client and matches the AGENTS.md guidance
    ``Mock at the boundary, not internals``.
    """

    def query(self, query: str, database: str, language: str = ...) -> Any: ...


def _result_to_dataframe(result: Any) -> pd.DataFrame:
    """Normalise an Influx ``query()`` return value into a DataFrame.

    The Influx v3 client may return an Arrow table, a list of dicts,
    or — in tests — a pre-built DataFrame. This helper coerces all
    three into a DataFrame so the rest of the poller can operate on
    a single representation.
    """
    if isinstance(result, pd.DataFrame):
        return result
    if hasattr(result, "to_pandas"):
        df = result.to_pandas()
        return df if isinstance(df, pd.DataFrame) else pd.DataFrame()
    if isinstance(result, list):
        return pd.DataFrame(result)
    return pd.DataFrame()


def _parse_uci(uci: str) -> tuple[str, str | None] | None:
    """Parse a UCI tag value into a ``(mac, ipv4_or_None)`` pair.

    The UCI string assembled by ``otalon-capture/aggregation.py`` is
    ``src_mac/dst_mac/vlan/ip_proto/src_ip/dst_ip/sport/dport/protos``
    — exactly 9 slash-separated components. **Empty fields are
    valid** whenever a layer is absent: pure ARP/LLDP/PROFINET frames
    have no L3 and therefore an empty ``src_ip``; VLAN-tagged frames
    have a numeric ``vlan`` but still no L3.

    This parser:

    - rejects any UCI whose ``split('/')`` length is not 9 (the
      design.md `Risk` row "UCI tag parsing fragility" mitigation);
    - returns ``(src_mac, src_ip)`` lowercased, where ``src_ip`` is
      ``None`` if the position is empty or the placeholder ``-``;
    - returns ``None`` only when ``src_mac`` itself is missing /
      placeholder — without a MAC the row is useless for the passive
      seeder.

    Bug-cluster 2026-05-21 fix: the previous implementation also
    rejected rows with an empty ``src_ip``, which discarded roughly
    80 % of real netcap UCI tags (ARP, LLDP, PROFINET, VLAN-only).
    The passive seeder only needs the MAC; the IPv4, if present,
    enriches the resulting ``network_interfaces`` row but is not
    mandatory.
    """
    parts = uci.split("/")
    if len(parts) != 9:
        return None
    src_mac = parts[0].strip().lower()
    if not src_mac or src_mac == "-":
        return None
    src_ip_raw = parts[4].strip()
    src_ip: str | None = src_ip_raw if src_ip_raw and src_ip_raw != "-" else None
    return src_mac, src_ip


class InfluxPoller:
    """Read MAC and UCI tags from a single InfluxDB v3 instance.

    The poller wraps an :class:`influxdb_client_3.InfluxDBClient3`
    (or any duck-typed object that exposes the
    :meth:`_Queryable.query` shape) and exposes a single
    :meth:`poll_once` coroutine that the seeder's poll loop invokes
    every ``PASSIVE_SEEDER_POLL_INTERVAL_S`` seconds.
    """

    def __init__(
        self,
        *,
        client: _Queryable,
        database: str,
        lookback_window_s: int,
    ) -> None:
        """Initialise the poller.

        Args:
            client: An object implementing the :class:`_Queryable`
                shape (typically an ``InfluxDBClient3``). Injected so
                tests can pass a mock without touching the network.
            database: Influx v3 database/bucket name carrying the
                ``mac_traffic`` and ``network_metrics`` measurements.
            lookback_window_s: Seconds the SQL queries look back from
                ``now()``; renders as ``INTERVAL '<n> seconds'``.
        """
        self._client = client
        self._database = database
        self._lookback_window_s = int(lookback_window_s)

    @property
    def lookback_window_s(self) -> int:
        """Configured lookback window in seconds (read-only)."""
        return self._lookback_window_s

    def _query_macs_sql(self) -> str:
        """Build the SQL string for the ``mac_traffic`` query."""
        return (
            "SELECT DISTINCT mac_address "
            "FROM mac_traffic "
            f"WHERE time > now() - INTERVAL '{self._lookback_window_s} seconds'"
        )

    def _query_uci_sql(self) -> str:
        """Build the SQL string for the ``network_metrics`` query."""
        return (
            "SELECT DISTINCT uci "
            "FROM network_metrics "
            f"WHERE time > now() - INTERVAL '{self._lookback_window_s} seconds'"
        )

    async def poll_once(self) -> PollResult:
        """Execute one Influx poll cycle and return a :class:`PollResult`.

        Issues two ``SELECT DISTINCT`` queries (one per measurement),
        materialises both into pandas DataFrames, builds the set of
        MACs and the MAC→IPv4 mapping, and counts malformed UCI rows.

        Raises:
            InfluxUnreachableError: When either query raises any
                exception. The wrapped exception is attached via
                ``raise … from exc`` so the caller can correlate.
        """
        result = PollResult()
        try:
            mac_raw = self._client.query(
                query=self._query_macs_sql(),
                database=self._database,
                language="sql",
            )
            uci_raw = self._client.query(
                query=self._query_uci_sql(),
                database=self._database,
                language="sql",
            )
        except Exception as exc:
            raise InfluxUnreachableError(f"Influx query failed: {exc}") from exc

        mac_df = _result_to_dataframe(mac_raw)
        uci_df = _result_to_dataframe(uci_raw)

        if not mac_df.empty and "mac_address" in mac_df.columns:
            for value in mac_df["mac_address"].dropna().tolist():
                mac = str(value).strip().lower()
                if mac:
                    result.macs.add(mac)

        if not uci_df.empty and "uci" in uci_df.columns:
            for value in uci_df["uci"].dropna().tolist():
                parsed = _parse_uci(str(value))
                if parsed is None:
                    result.uci_malformed += 1
                    logger.warning(
                        "passive_seeder: malformed uci skipped uci={!r}",
                        value,
                    )
                    continue
                mac, ipv4 = parsed
                result.macs.add(mac)
                if ipv4 is not None:
                    result.mac_to_ipv4.setdefault(mac, ipv4)

        return result
