"""Tests for InfluxModule, MITRE labeling, and data source abstractions."""

import json
from pathlib import Path

import pandas as pd  # type: ignore[import-untyped]  # pandas stubs not installed in this environment
import polars as pl
import pytest

from otalon_clas.common.influx_connector import (
    InfluxModule,
    InfluxUnavailableError,
    _empty_frame,
    _parse_duration_to_seconds,
    _validate_iso_timestamp,
)
from otalon_clas.ml.labeling import (
    ConnectionLabeler,
    MacLabeler,
    MitreLabel,
    ProtoLabeler,
    _proto_partial_match,
    load_labels,
)


class TestDurationParsing:
    """Tests for the duration string parser."""

    def test_parse_hours(self) -> None:
        """Parse hours duration."""
        assert _parse_duration_to_seconds("8h") == 28800

    def test_parse_minutes(self) -> None:
        """Parse minutes duration."""
        assert _parse_duration_to_seconds("30m") == 1800

    def test_parse_seconds(self) -> None:
        """Parse seconds duration."""
        assert _parse_duration_to_seconds("300s") == 300

    def test_invalid_format_raises(self) -> None:
        """Invalid duration format raises ValueError."""
        with pytest.raises(ValueError, match="Unrecognized duration format"):
            _parse_duration_to_seconds("5d")


class TestEmptyFrame:
    """Tests for empty DataFrame creation."""

    def test_polars_empty_frame(self) -> None:
        """Empty Polars frame has expected columns."""
        df = _empty_frame("uci", ["packet_count", "total_volume"], use_polars=True)
        assert isinstance(df, pl.DataFrame)
        assert df.columns == ["time", "uci", "packet_count", "total_volume"]
        assert len(df) == 0

    def test_pandas_empty_frame(self) -> None:
        """Empty Pandas frame has expected columns."""
        df = _empty_frame("mac_address", ["out_conn_count"], use_polars=False)
        assert isinstance(df, pd.DataFrame)
        assert list(df.columns) == ["time", "mac_address", "out_conn_count"]
        assert len(df) == 0


class TestProtocolPartialMatch:
    """Tests for the protocol partial-match logic."""

    def test_pn_dcp_matches_profinet(self) -> None:
        """'pn_dcp' label matches PROFINET_RT_DCP tag."""
        assert _proto_partial_match("ethernet:vlan:profinet_rt_dcp", "pn_dcp") is True

    def test_opcua_matches_opc_ua(self) -> None:
        """'opcua' label matches OPC-UA tag."""
        assert _proto_partial_match("ethernet:ipv4:tcp:opc-ua", "opcua") is True

    def test_arp_matches_arp(self) -> None:
        """'arp' label matches ARP tag."""
        assert _proto_partial_match("ethernet:arp", "arp") is True

    def test_empty_label_always_matches(self) -> None:
        """Empty label protocol always matches."""
        assert _proto_partial_match("any_protocol", "") is True

    def test_no_match_returns_false(self) -> None:
        """Non-matching protocol returns False."""
        assert _proto_partial_match("ethernet:ipv4:tcp", "pn_dcp") is False


class TestLoadLabels:
    """Tests for loading MITRE labels from JSON files."""

    def test_load_single_label(self, tmp_path: Path) -> None:
        """Single label entry is loaded correctly."""
        label_data = {
            "module_name": "T0846/pn_discovery",
            "start_time": "2026-03-06 21:08:31",
            "end_time": "2026-03-06 21:08:33",
            "target_ip": ["192.168.1.10"],
            "target_mac": ["aa:bb:cc:dd:ee:ff"],
            "protocol": "pn_dcp",
            "source_ip": "192.168.1.1",
            "source_mac": "11:22:33:44:55:66",
        }
        path = tmp_path / "labels.json"
        path.write_text(json.dumps([label_data]))

        labels = load_labels(path)
        assert len(labels) == 1
        assert labels[0].module_name == "T0846/pn_discovery"
        assert labels[0].source_mac == "11:22:33:44:55:66"

    def test_time_margin_applied(self, tmp_path: Path) -> None:
        """Time margin is applied to start/end times."""
        label_data = {
            "module_name": "T0846/test",
            "start_time": "2026-03-06 21:08:31",
            "end_time": "2026-03-06 21:08:33",
            "target_ip": ["192.168.0.20"],
            "target_mac": [],
            "protocol": "",
            "source_ip": "",
            "source_mac": "",
        }
        path = tmp_path / "labels.json"
        path.write_text(json.dumps([label_data]))

        labels = load_labels(path, time_margin_seconds=5)
        # Naive ground-truth timestamps are CISF local wall-clock and are
        # normalized to UTC, so they compare correctly against the UTC
        # measurement timestamps (audit CLAS-04). 21:08:31 CET = 20:08:31Z.
        expected_start = pd.Timestamp("2026-03-06 20:08:26", tz="UTC")
        expected_end = pd.Timestamp("2026-03-06 20:08:38", tz="UTC")
        assert labels[0].start_time == expected_start
        assert labels[0].end_time == expected_end

    def test_naive_ground_truth_is_localized_then_converted(self, tmp_path: Path) -> None:
        """A naive entry is read as Europe/Berlin and stored as UTC."""
        label_data = {
            "module_name": "T0846/test",
            "start_time": "2026-03-06 21:08:31",
            "end_time": "2026-03-06 21:08:33",
            "target_ip": ["192.168.0.20"],
            "target_mac": [],
            "protocol": "",
            "source_ip": "",
            "source_mac": "",
        }
        path = tmp_path / "labels.json"
        path.write_text(json.dumps([label_data]))

        labels = load_labels(path, time_margin_seconds=0)

        assert labels[0].start_time.tzinfo is not None
        assert labels[0].start_time == pd.Timestamp("2026-03-06T20:08:31Z")

    def test_utc_ground_truth_is_left_alone(self, tmp_path: Path) -> None:
        """An entry that already carries an offset is not shifted again."""
        label_data = {
            "module_name": "T0846/test",
            "start_time": "2026-03-06T20:08:31+00:00",
            "end_time": "2026-03-06T20:08:33+00:00",
            "target_ip": ["192.168.0.20"],
            "target_mac": [],
            "protocol": "",
            "source_ip": "",
            "source_mac": "",
        }
        path = tmp_path / "labels.json"
        path.write_text(json.dumps([label_data]))

        labels = load_labels(path, time_margin_seconds=0)

        assert labels[0].start_time == pd.Timestamp("2026-03-06T20:08:31Z")

    def test_timezone_override_is_honoured(self, tmp_path: Path) -> None:
        """Passing ``None`` treats naive input as already-UTC."""
        label_data = {
            "module_name": "T0846/test",
            "start_time": "2026-03-06 21:08:31",
            "end_time": "2026-03-06 21:08:33",
            "target_ip": ["192.168.0.20"],
            "target_mac": [],
            "protocol": "",
            "source_ip": "",
            "source_mac": "",
        }
        path = tmp_path / "labels.json"
        path.write_text(json.dumps([label_data]))

        labels = load_labels(path, time_margin_seconds=0, ground_truth_timezone=None)

        assert labels[0].start_time == pd.Timestamp("2026-03-06T21:08:31Z")


class TestConnectionLabeler:
    """Tests for the ConnectionLabeler."""

    @pytest.fixture()
    def labels(self) -> list[MitreLabel]:
        """Create test labels."""
        return [
            MitreLabel(
                module_name="T0846/arp_scan",
                technical_method="",
                start_time=pd.Timestamp("2026-03-06 21:08:28", tz="UTC"),
                end_time=pd.Timestamp("2026-03-06 21:08:36", tz="UTC"),
                target_ip=["192.168.1.10"],
                target_mac=["aa:bb:cc:dd:ee:ff"],
                protocol="arp",
                source_ip="192.168.1.1",
                source_mac="11:22:33:44:55:66",
            )
        ]

    def test_matching_uci_gets_labeled(self, labels: list[MitreLabel]) -> None:
        """UCI matching IP, MAC, and protocol gets labeled."""
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06 21:08:31")],
                "uci": ["11:22:33:44:55:66/aa:bb:cc:dd:ee:ff/0/2054/192.168.1.1/192.168.1.10/0/0/Ethernet:ARP"],
            }
        )
        labeler = ConnectionLabeler(labels)
        result = labeler.apply_labels(df)
        assert result["label"][0] == "T0846/arp_scan"

    def test_non_matching_uci_is_benign(self, labels: list[MitreLabel]) -> None:
        """Non-matching UCI stays benign."""
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06 21:08:31")],
                "uci": ["ff:ff:ff:ff:ff:ff/00:00:00:00:00:00/0/6/10.0.0.1/10.0.0.2/80/443/Ethernet:IPv4:TCP"],
            }
        )
        labeler = ConnectionLabeler(labels)
        result = labeler.apply_labels(df)
        assert result["label"][0] == "benign"


class TestMacLabeler:
    """Tests for the MacLabeler."""

    @pytest.fixture()
    def labels(self) -> list[MitreLabel]:
        """Create test labels."""
        return [
            MitreLabel(
                module_name="T0846/arp_scan",
                technical_method="",
                start_time=pd.Timestamp("2026-03-06 21:08:28", tz="UTC"),
                end_time=pd.Timestamp("2026-03-06 21:08:36", tz="UTC"),
                target_ip=[],
                target_mac=["aa:bb:cc:dd:ee:ff"],
                protocol="",
                source_ip="",
                source_mac="11:22:33:44:55:66",
            )
        ]

    def test_target_mac_matches(self, labels: list[MitreLabel]) -> None:
        """MAC matching target_mac gets labeled."""
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06 21:08:31")],
                "mac_address": ["aa:bb:cc:dd:ee:ff"],
            }
        )
        labeler = MacLabeler(labels)
        result = labeler.apply_labels(df)
        assert result["label"][0] == "T0846/arp_scan"

    def test_source_mac_matches(self, labels: list[MitreLabel]) -> None:
        """MAC matching source_mac gets labeled."""
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06 21:08:31")],
                "mac_address": ["11:22:33:44:55:66"],
            }
        )
        labeler = MacLabeler(labels)
        result = labeler.apply_labels(df)
        assert result["label"][0] == "T0846/arp_scan"


class TestProtoLabeler:
    """Tests for the ProtoLabeler."""

    @pytest.fixture()
    def labels(self) -> list[MitreLabel]:
        """Create test labels."""
        return [
            MitreLabel(
                module_name="T0846/pn_discovery",
                technical_method="",
                start_time=pd.Timestamp("2026-03-06 21:08:28", tz="UTC"),
                end_time=pd.Timestamp("2026-03-06 21:08:36", tz="UTC"),
                target_ip=[],
                target_mac=[],
                protocol="pn_dcp",
                source_ip="",
                source_mac="",
            )
        ]

    def test_proto_partial_match_labels(self, labels: list[MitreLabel]) -> None:
        """Protocol partial match gets labeled."""
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06 21:08:31")],
                "protocol": ["Ethernet:VLAN:PROFINET_RT_DCP"],
            }
        )
        labeler = ProtoLabeler(labels)
        result = labeler.apply_labels(df)
        assert result["label"][0] == "T0846/pn_discovery"

    def test_non_matching_proto_is_benign(self, labels: list[MitreLabel]) -> None:
        """Non-matching protocol stays benign."""
        df = pl.DataFrame(
            {
                "time": [pd.Timestamp("2026-03-06 21:08:31")],
                "protocol": ["Ethernet:IPv4:TCP"],
            }
        )
        labeler = ProtoLabeler(labels)
        result = labeler.apply_labels(df)
        assert result["label"][0] == "benign"


class TestValidateIsoTimestamp:
    """Tests for ISO-8601 timestamp validation before SQL interpolation."""

    def test_valid_iso_timestamps_accepted(self) -> None:
        """Common ISO-8601 formats pass validation unchanged."""
        assert _validate_iso_timestamp("2026-03-06T21:08:31") == "2026-03-06T21:08:31"
        assert _validate_iso_timestamp("2026-03-06T21:08:31Z") == "2026-03-06T21:08:31Z"
        assert _validate_iso_timestamp("2026-03-06 21:08:31+00:00") == "2026-03-06 21:08:31+00:00"

    def test_malformed_timestamp_rejected(self) -> None:
        """Malformed timestamp is rejected before interpolation into SQL."""
        with pytest.raises(ValueError, match="Invalid ISO-8601 timestamp"):
            _validate_iso_timestamp("2026-03-06T21:08:31'; DROP MEASUREMENT network_metrics; --")


class TestInfluxModuleWindowValidation:
    """Tests that InfluxModule rejects malformed time windows."""

    def test_build_query_rejects_injected_timestamp(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A malicious stop value is rejected before the query is built."""
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: object(),
        )
        module = InfluxModule("http://localhost:8086", "token", "db", "network_metrics", "uci", ["packet_count"])
        with pytest.raises(ValueError, match="Invalid ISO-8601 timestamp"):
            module._build_query(
                "2026-01-01T00:00:00",
                "2026-01-01T00:00:00' OR '1'='1",
            )

    def test_execute_query_recreates_client_and_retries_once(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A stale client is replaced once and a successful retry is returned."""
        first = type("Client", (), {})()
        second = type("Client", (), {})()
        first.query = lambda *args, **kwargs: (_ for _ in ()).throw(RuntimeError("stale"))
        second.query = lambda *args, **kwargs: pl.DataFrame({"time": [], "uci": []})
        clients = iter([first, second])
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: next(clients),
        )
        module = InfluxModule("http://localhost:8086", "token", "db", "network_metrics", "uci", [])
        assert module._execute_query("SELECT 1").is_empty()

    def test_fetch_chunks_rejects_partial_source_failure(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A failed middle chunk is unavailable, not misleading partial data."""
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: object(),
        )
        module = InfluxModule("http://localhost:8086", "token", "db", "network_metrics", "uci", [])
        calls = iter([pl.DataFrame({"time": [1], "uci": ["a"]}), RuntimeError("down")])
        monkeypatch.setattr(module, "_execute_query", lambda *args, **kwargs: next(calls))
        with pytest.raises(InfluxUnavailableError):
            module.fetch_in_chunks("2026-01-01T00:00:00", "2026-01-01T16:00:00", chunk_size="8h")


class _FlightInternalError(Exception):
    """Stub whose ``__name__`` matches the pyarrow oversized-response signal."""


_FlightInternalError.__name__ = "FlightInternalError"


class _ArrowInvalid(Exception):
    """Stub whose ``__name__`` matches the pyarrow ArrowInvalid signal."""


_ArrowInvalid.__name__ = "ArrowInvalid"


class TestInfluxOversizedResponseFallback:
    """Audit B-4: an oversized response must reach the chunked fetch fallback.

    The reconnect-retry in ``_execute_query`` must not swallow
    ``FlightInternalError``/``ArrowInvalid`` and re-type them as
    ``InfluxUnavailableError`` before ``fetch`` can fall back to
    ``fetch_in_chunks``; and a genuine second transport failure must still
    surface a typed, target-free unavailable error.
    """

    def _module(self, monkeypatch: pytest.MonkeyPatch) -> InfluxModule:
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: object(),
        )
        return InfluxModule("http://influx-host.internal:8181", "secret-token", "db", "network_metrics", "uci", ["c"])

    def test_direct_fetch_flight_internal_error_falls_back_to_chunks(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A FlightInternalError on the direct query yields the chunked result."""
        module = self._module(monkeypatch)
        chunked = pl.DataFrame({"time": [1], "uci": ["a"], "c": [1.0]})

        def _direct(sql: str, use_polars: bool = True) -> pl.DataFrame:
            raise _FlightInternalError("response exceeded 4MB")

        # _execute_query raises the size signal untouched; fetch() must fall
        # back to fetch_in_chunks (patched to return a marker frame).
        monkeypatch.setattr(module, "_execute_query", _direct)
        monkeypatch.setattr(module, "fetch_in_chunks", lambda *a, **k: chunked)

        result = module.fetch("2026-07-23T10:00:00", "2026-07-23T13:00:00")
        assert result.equals(chunked)

    def test_execute_query_reraises_size_signal_untouched(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """_execute_query must NOT convert a size signal into unavailable."""
        module = self._module(monkeypatch)
        client = type("Client", (), {})()
        client.query = lambda *a, **k: (_ for _ in ()).throw(_ArrowInvalid("too large"))  # type: ignore[attr-defined]
        module._client = client  # type: ignore[attr-defined]

        # The size signal propagates as-is (so fetch can chunk); it is NOT
        # wrapped in InfluxUnavailableError and does NOT trigger a reconnect.
        with pytest.raises(_ArrowInvalid):
            module._execute_query("SELECT 1")

    def test_second_transport_failure_raises_typed_unavailable(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Two transport failures (not size signals) surface typed unavailable."""
        first = type("Client", (), {})()
        second = type("Client", (), {})()
        first.query = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stale gRPC channel"))
        second.query = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("still down"))
        clients = iter([first, second])
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: next(clients),
        )
        module = InfluxModule("http://influx-host.internal:8181", "secret-token", "db", "m", "uci", [])
        with pytest.raises(InfluxUnavailableError):
            module.fetch("2026-07-23T10:00:00", "2026-07-23T13:00:00")

    def test_persisted_unavailable_error_is_target_free(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """The typed error must not leak host/port/token into job evidence (B-7)."""

        def _raise_target(*_a: object, **_k: object) -> None:
            raise RuntimeError("connect to influx-host.internal:8181 failed")

        first = type("Client", (), {})()
        second = type("Client", (), {})()
        first.query = _raise_target
        second.query = _raise_target
        clients = iter([first, second])
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: next(clients),
        )
        module = InfluxModule("http://influx-host.internal:8181", "secret-token", "db", "m", "uci", [])
        with pytest.raises(InfluxUnavailableError) as excinfo:
            module.fetch("2026-07-23T10:00:00", "2026-07-23T13:00:00")
        message = str(excinfo.value)
        # No host, port, token, or DNS target in the persisted message.
        assert "influx-host.internal" not in message
        assert "8181" not in message
        assert "secret-token" not in message

    def test_chunk_fallback_after_retry_still_reaches_chunking(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """A size signal surfaced by the reconnected client still chunks.

        Transport failure on attempt 1 triggers a reconnect; the reconnected
        client raises a size signal on attempt 2. That must propagate to
        ``fetch`` and drive the chunk fallback, not be typed unavailable.
        """
        first = type("Client", (), {})()
        second = type("Client", (), {})()
        first.query = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("stale channel"))
        second.query = lambda *a, **k: (_ for _ in ()).throw(_FlightInternalError("too large"))
        clients = iter([first, second])
        monkeypatch.setattr(
            "otalon_clas.common.influx_connector.create_influx_client",
            lambda **kwargs: next(clients),
        )
        module = InfluxModule("http://influx-host.internal:8181", "secret-token", "db", "m", "uci", [])
        chunked = pl.DataFrame({"time": [1], "uci": ["a"]})
        monkeypatch.setattr(module, "fetch_in_chunks", lambda *a, **k: chunked)
        result = module.fetch("2026-07-23T10:00:00", "2026-07-23T13:00:00")
        assert result.equals(chunked)
