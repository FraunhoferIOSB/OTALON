"""Independent synthetic E1 producer regressions; no live service qualification."""

from __future__ import annotations

import hashlib
import json
import re
import struct
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import pytest
from influxdb_client_3 import InfluxDBError
from influxdb_client_3.write_client.rest import ApiException
from network_capture import NetworkCaptureSession
from pydantic import ValidationError
from urllib3 import HTTPResponse

from capture_runtime import CaptureBackend, CaptureIntent, CaptureSnapshot, SourceState, resolve_capture_intent
from desktop_ingest.codec import decode
from desktop_ingest.ledger import Ledger
from desktop_ingest.main import Status
from desktop_ingest.pipeline import ContinuousPipeline
from desktop_ingest.processor_lifecycle import ProcessorOwner
from desktop_ingest.settings import ReliablePipelineSettings
from otalon_capture import influxdb_writer as writer_module
from otalon_capture.influxdb_writer import InfluxDBWriter
from otalon_capture.netcap import Netcap
from otalon_capture.settings import CaptureType, Settings, WriteOptionsConfig
from otalon_capture.write_failure import TerminalWriteError, permanent_auth_status
from pcap_import.models import ImportRequest, ImportState
from pcap_import.runner import PipelineImportRunner
from pcap_import.service import ImportService
from pcap_recorder.api import CaptureStatusProvider

SRC = "02:19:27:35:43:51"
DST = "02:62:70:88:96:a4"
BASE_NS = 17_123_456_789
# Each row is (packet count, captured Ethernet bytes, smallest, largest).
WINDOWS = ((2, 140, 61, 79), (2, 158, 61, 97), (2, 176, 79, 97), (2, 122, 61, 61))
SIZES = (61, 79, 97, 61, 79, 97, 61, 61, 79)


def frame(size: int) -> bytes:
    """Construct a complete UDP datagram, including an independently computed IP checksum."""
    ethernet = bytes.fromhex(DST.replace(":", "") + SRC.replace(":", "") + "0800")
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, size - 14, 19, 0, 64, 17, 0, b"\xc0\x00\x02\x13", b"\xc6\x33\x64\x1d")
    checksum = sum(struct.unpack("!10H", ip))
    while checksum >> 16:
        checksum = (checksum & 65535) + (checksum >> 16)
    ip = ip[:10] + struct.pack("!H", checksum ^ 65535) + ip[12:]
    udp = struct.pack("!HHHH", 32119, 29017, size - 34, 0)
    return ethernet + ip + udp + bytes((i * 13 + 7) % 256 for i in range(size - 42))


def packets(interval: int) -> list[tuple[bytes, int]]:
    values = []
    for index, size in enumerate(SIZES):
        offset = (index // 2) * interval * 1_000_000 + (index % 2) * 125_000_000
        values.append((frame(size), BASE_NS + offset + (1_000_000 if index >= 2 else 0)))
    return values


def pcap(values: list[tuple[bytes, int]]) -> bytes:
    # Nanosecond classic PCAP, not the existing millisecond/ARP fixture.
    header = struct.pack("<IHHIIII", 0xA1B23C4D, 2, 4, 0, 0, 65535, 1)
    return header + b"".join(
        struct.pack("<IIII", instant // 1_000_000_000, instant % 1_000_000_000, len(data), len(data)) + data
        for data, instant in values
    )


def iso(ms: int) -> str:
    return (datetime(1970, 1, 1, tzinfo=timezone.utc) + timedelta(milliseconds=ms)).isoformat()


def settings(interval: int = 375, sparse: bool = False, precision: str = "ms") -> ReliablePipelineSettings:
    def measurement(name: str, tags: list[str], fields: dict[str, str]) -> dict[str, Any]:
        return dict(
            host="http://e1-capture.invalid:8181",
            token="synthetic-unused-e1",
            database="e1_synthetic",
            measurement_name=name,
            tags=tags,
            fields=fields,
        )

    return ReliablePipelineSettings.model_validate(
        dict(
            interval_ms=interval,
            influx=measurement(
                "network_metrics",
                ["uci"],
                {
                    "packet_count": "get_total_packet_count",
                    "total_volume": "get_total_volume",
                    "mean_packet_size": "get_mean_packet_size",
                    "min_packet_size": "get_min_packet_size",
                    "max_packet_size": "get_max_packet_size",
                },
            ),
            mac_influx=measurement(
                "mac_traffic",
                ["mac_address"],
                {
                    name: "get_" + name
                    for name in ("out_total_packets", "out_total_volume", "in_total_packets", "in_total_volume")
                },
            ),
            proto_influx=measurement(
                "proto_traffic",
                ["protocol"],
                {name: "get_" + name for name in ("proto_total_packets", "proto_total_volume", "proto_conn_count")},
            ),
            write_options=dict(batch_size=100, flush_interval=1_000_000, jitter_interval=0, precision=precision),
            preprocess=dict(aggregate_sparse_ports=sparse),
            mac_aggregation=dict(enabled=True),
            proto_aggregation=dict(enabled=True),
            protocol_map={17: "E1-UDP"},
        )
    )


class LocalClient:
    """Narrow write/readback double: parses emitted lines, never opens a connection."""

    def __init__(self, failure: Exception | None = None) -> None:
        self.failure = failure
        self.attempts: list[list[str]] = []
        self.rows: dict[tuple[str, str, tuple[tuple[str, str], ...]], dict[str, Any]] = {}
        self.closes = 0
        self.queries = 0

    def write(self, record: Any, write_precision: str = "ms") -> None:
        lines = [value if isinstance(value, str) else value.to_line_protocol() for value in record]
        self.attempts.append(lines)
        if self.failure is not None:
            raise self.failure
        for line in lines:
            series, fields, timestamp = line.split(" ")
            measurement, *tag_values = re.split(r"(?<!\\),", series)
            tags = {key: value.replace("\\,", ",") for key, value in (tag.split("=", 1) for tag in tag_values)}
            divisor = {"ms": 1, "us": 1000, "ns": 1_000_000}[write_precision]
            row: dict[str, Any] = {"time": iso(int(timestamp) // divisor), **tags}
            for field_value in fields.split(","):
                name, raw = field_value.split("=", 1)
                row[name] = int(raw[:-1]) if raw.endswith("i") else float(raw)
            self.rows[(measurement, row["time"], tuple(sorted(tags.items())))] = row

    def query(self, *, query: str, mode: str) -> list[dict[str, Any]]:
        assert mode == "pandas"
        self.queries += 1
        measurement = re.search(r'SELECT \* FROM "([^"]+)"', query)
        instant = re.search(r"time='([^']+)'", query)
        assert measurement is not None and instant is not None
        tags = tuple(sorted(re.findall(r'"([^"]+)"=\x27([^\x27]*)\x27', query)))
        key = (measurement.group(1), instant.group(1), tags)
        return [dict(self.rows[key])] if key in self.rows else []

    def close(self) -> None:
        self.closes += 1


def client_factory(monkeypatch: pytest.MonkeyPatch, client: LocalClient) -> None:
    monkeypatch.setattr(writer_module, "InfluxDBClient3", lambda **kwargs: client)


def expected_network(index: int, interval: int) -> dict[str, Any]:
    count, volume, smallest, largest = WINDOWS[index]
    return dict(
        time=iso(17_123 + index * interval),
        packet_count=count,
        total_volume=volume,
        mean_packet_size=volume / count,
        min_packet_size=smallest,
        max_packet_size=largest,
    )


def assert_payload(parts: list[dict[str, Any]], interval: int, sparse: bool, precision: str) -> None:
    rows = {name: [] for name in ("network", "mac", "proto")}
    measurements = {"network": "network_metrics", "mac": "mac_traffic", "proto": "proto_traffic"}
    tag_keys = {"network": ["uci"], "mac": ["mac_address"], "proto": ["protocol"]}
    multiplier = {"ms": 1, "us": 1000, "ns": 1_000_000}[precision]
    for part in parts:
        assert part["measurement"] == measurements[part["writer"]]
        assert part["database"] == "e1_synthetic"
        assert part["tag_keys"] == tag_keys[part["writer"]]
        for line, row in zip(part["lines"], part["records"], strict=True):
            assert int(line.rsplit(" ", 1)[1]) % multiplier == 0
            assert iso(int(line.rsplit(" ", 1)[1]) // multiplier) == row["time"]
            if part["writer"] == "network":
                assert "packet_count=2i" in line
                assert "total_volume=" in line
            rows[part["writer"]].append(row)
    expected = [expected_network(i, interval) for i in range(3 if sparse else 4)]
    assert [{key: value for key, value in row.items() if key != "uci"} for row in rows["network"]] == expected
    for row in rows["network"]:
        assert row["uci"] == f"{SRC}/{DST}//IPv4/192.0.2.19/198.51.100.29/32119/29017/Ethernet:IPv4:UDP"
    assert len(rows["mac"]) == 6
    assert len(rows["proto"]) == 3
    for index in range(3):
        count, volume, _, _ = WINDOWS[index]
        assert rows["mac"][index * 2 : index * 2 + 2] == [
            dict(
                time=iso(17_123 + index * interval),
                mac_address=SRC,
                out_total_packets=count,
                out_total_volume=volume,
                in_total_packets=0.0,
                in_total_volume=0.0,
            ),
            dict(
                time=iso(17_123 + index * interval),
                mac_address=DST,
                out_total_packets=0.0,
                out_total_volume=0.0,
                in_total_packets=count,
                in_total_volume=volume,
            ),
        ]
        proto = rows["proto"][index]
        assert proto["protocol"] == "Ethernet:IPv4:UDP"
        assert {key: value for key, value in proto.items() if key != "protocol"} == dict(
            time=iso(17_123 + index * interval),
            proto_total_packets=count,
            proto_total_volume=volume,
            proto_conn_count=1.0,
        )


@pytest.mark.parametrize("interval", [375, 1000])
def test_real_native_windows_have_independent_counters(interval: int) -> None:
    native = NetworkCaptureSession(interval, 64, 65536)
    emitted = []
    for data, instant in packets(interval):
        result = native.push_packet(data, instant // 1_000_000_000, instant % 1_000_000_000)
        if result is not None:
            emitted.append(result)
    assert len(emitted) == 4
    for index, window in enumerate(emitted):
        assert window["record_start_ms"] == 17_123 + index * interval
        assert len(window["metrics"]) == 1
        metric = window["metrics"][0]
        assert metric["time"] == 17_123 + index * interval
        actual = {
            key: metric[key]
            for key in ("packet_count", "total_volume", "mean_packet_size", "min_packet_size", "max_packet_size")
        }
        assert actual == {key: value for key, value in expected_network(index, interval).items() if key != "time"}


@pytest.mark.parametrize("interval", [375, 1000])
@pytest.mark.parametrize("sparse", [False, True])
@pytest.mark.parametrize("precision", ["ms", "us", "ns"])
@pytest.mark.parametrize("ends", [(9,), (1, 3, 5, 7, 9), (2, 4, 6, 8, 9)])
def test_real_custody_multisplit_restores_native_and_python_carry(
    tmp_path: Path, interval: int, sparse: bool, precision: str, ends: tuple[int, ...]
) -> None:
    root = tmp_path / "custody"
    ledger = Ledger(root)
    ledger.register_run("e1", None, "synthetic-no-interface")
    values = packets(interval)
    parts = []
    start = 0
    try:
        for ordinal, end in enumerate(ends):
            data = pcap(values[start:end])
            receipt = ledger.receive("e1", ordinal, data)
            assert receipt["accepted"] is True
            assert receipt["hash"] == hashlib.sha256(data).hexdigest()
            pipe = ContinuousPipeline(settings(interval, sparse, precision), ledger, write_enabled=False)
            try:
                assert pipe.process_one() is True
                state = ledger.load_checkpoint()
                assert state["version"] == 2
                assert state["timestamp_contract"] == "native-window-start-ms-v1"
                assert pipe.native.export_state() == decode(state["native"])
                batch = ledger.pending_batches()[0]
                parts.extend(batch["payload"])
                # Drain the bounded outbox through its public API, not a publication claim.
                ledger.commit_batch(batch["id"])
            finally:
                pipe.close()
                pipe.close()
            assert ledger.load_checkpoint() == state
            assert ledger.receipt("e1", ordinal)["processing"] == "carry_or_published"
            ledger.close()
            ledger = Ledger(root)
            assert ledger.load_checkpoint() == state
            start = end
        assert_payload(parts, interval, sparse, precision)
        assert ledger.next_chunk() is None
        assert len(ledger.committed_batches(0)) == len(ends)
    finally:
        ledger.close()


def import_config(tmp_path: Path, *, batch: int = 100) -> Path:
    raw = settings().model_dump(mode="json")
    for name in ("influx", "mac_influx", "proto_influx"):
        raw[name]["token"] = "synthetic-unused-e1"
    raw.pop("interval_ms")
    raw["capture"] = dict(source="$CAPTURE_SOURCE", type="$CAPTURE_TYPE", interval=375)
    raw["log"] = dict(level="INFO", file=str(tmp_path / "unused.log"))
    raw["mac_aggregation"]["enabled"] = False
    raw["proto_aggregation"]["enabled"] = False
    raw["write_options"]["batch_size"] = batch
    raw["pcap"] = dict(unused="$E1_UNUSED_RECORDER_PLACEHOLDER")
    path = tmp_path / "synthetic.json"
    path.write_text(json.dumps(raw))
    return path


@pytest.mark.parametrize("unused_source", [None, ""])
def test_none_public_import_replays_real_pcap_without_unused_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, unused_source: str | None
) -> None:
    monkeypatch.setenv("CAPTURE_TYPE", "NONE")
    if unused_source is None:
        monkeypatch.delenv("CAPTURE_SOURCE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_SOURCE", unused_source)
    monkeypatch.delenv("E1_UNUSED_RECORDER_PLACEHOLDER", raising=False)
    source = tmp_path / "e1.pcap"
    data = pcap(packets(375))
    source.write_bytes(data)
    config = import_config(tmp_path)
    resolved = Settings.for_import_file(config, source)
    assert resolved.capture.source == str(source)
    assert resolved.capture.type is CaptureType.PCAP
    assert resolve_capture_intent() is CaptureIntent.NONE
    assert Netcap._map_capture_type(CaptureType.PCAP) != Netcap._map_capture_type(CaptureType.LIVE)
    assert resolved.influx == settings().influx
    assert resolved.write_options == settings().write_options
    client = LocalClient()
    client_factory(monkeypatch, client)
    result = PipelineImportRunner(str(config), import_dir=str(tmp_path)).run(
        ImportRequest(display_id="e1-none", file_path=str(source)), lambda phase, event: None, threading.Event()
    )
    assert result["records_processed"] == result["points_written"] == 5
    assert result["time_start"] == iso(17_123)
    assert result["time_end"] == iso(18_623)
    rows = sorted(client.rows.values(), key=lambda row: row["time"])
    assert [row["packet_count"] for row in rows] == [2, 2, 2, 2, 1]
    assert [row["total_volume"] for row in rows] == [140, 158, 176, 122, 79]
    assert client.closes == 1
    assert source.read_bytes() == data
    raw = json.loads(config.read_text())
    raw["influx"]["host"] = "invalid-url"
    config.write_text(json.dumps(raw))
    with pytest.raises(ValidationError):
        Settings.for_import_file(config, source)


@pytest.mark.parametrize("selection,expected", [(None, "NONE"), (" NONE ", "NONE"), (" LIVE ", "LIVE")])
def test_public_boot_intent_exact_domain(monkeypatch: pytest.MonkeyPatch, selection: str | None, expected: str) -> None:
    if selection is None:
        monkeypatch.delenv("CAPTURE_TYPE", raising=False)
    else:
        monkeypatch.setenv("CAPTURE_TYPE", selection)
    assert resolve_capture_intent().value == expected
    assert {mode.value for mode in CaptureType} == {"PCAP", "LIVE"}


@pytest.mark.parametrize("selection", ["", "live", "none", "AUTO", "PCAP"])
def test_public_boot_rejects_unknown_and_retired_exactly(monkeypatch: pytest.MonkeyPatch, selection: str) -> None:
    monkeypatch.setenv("CAPTURE_TYPE", selection)
    expected = (
        "CAPTURE_TYPE=PCAP is retired for service startup; use CAPTURE_TYPE=NONE "
        "and import PCAP/PCAPNG through Operations / Data Sources."
        if selection == "PCAP"
        else "CAPTURE_TYPE must be NONE or LIVE for service startup."
    )
    with pytest.raises(ValueError) as caught:
        resolve_capture_intent()
    assert str(caught.value) == expected


def test_actual_status_producers_distinguish_local_none_remote_none_and_live(tmp_path: Path) -> None:
    class Recorder:
        interface = ""
        is_running = True

    disabled = CaptureSnapshot(
        CaptureIntent.NONE, CaptureBackend.NATIVE, SourceState.DISABLED, "none_selected", 0, 5, None, False
    )
    native = CaptureStatusProvider(Recorder(), snapshot=lambda: disabled).get_status().model_dump(mode="json")
    with_ledger = Ledger(tmp_path / "custody")
    try:
        with_ledger.observe(dict(interface="synthetic-no-interface", recording=False))
        remote = Status(with_ledger, intent=CaptureIntent.NONE).get_status().model_dump(mode="json")
        assert native == {**remote, "backend": "native", "recording": False}
        assert remote == dict(
            interface=None,
            link_up=None,
            recording=None,
            drops_24h_pct=None,
            overflows=None,
            capture_type="NONE",
            backend="wsl",
            source_state="disabled",
            reason_code="none_selected",
            retry_attempt=0,
            retry_limit=5,
            retry_in_seconds=None,
            retry_exhausted=False,
            observation_age_seconds=None,
        )
        processor = ProcessorOwner(settings(), with_ledger, lambda: None)
        live = Status(with_ledger, intent=CaptureIntent.LIVE, processor=lambda: processor).get_status()
        assert live.capture_type is CaptureIntent.LIVE
        assert live.backend is CaptureBackend.WSL
        assert live.recording is False and live.source_state is SourceState.WAITING
        assert live.interface == "synthetic-no-interface"
        assert live.observation_age_seconds is not None
        native_live = CaptureStatusProvider(
            Recorder(), snapshot=lambda: CaptureSnapshot(CaptureIntent.LIVE, CaptureBackend.NATIVE, SourceState.WAITING)
        ).get_status()
        assert native_live.recording is True and native_live.source_state is SourceState.WAITING
        assert native_live.interface is None and native_live.link_up is None
    finally:
        with_ledger.close()


@pytest.mark.parametrize("phase", ["prepare", "commit"])
def test_stop_at_real_ledger_return_preserves_effects_and_new_owner_retry(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, phase: str
) -> None:
    stop = threading.Event()

    class PhaseLedger(Ledger):
        armed = False

        def prepare(self, ident: str, state: Any, payload: Any) -> None:
            super().prepare(ident, state, payload)
            if self.armed and phase == "prepare":
                stop.set()

        def commit_batch(self, ident: int) -> None:
            super().commit_batch(ident)
            if self.armed and phase == "commit":
                stop.set()

    ledger = PhaseLedger(tmp_path / "custody")
    ledger.register_run("e1-stop", None)
    values = packets(375)
    original = [pcap(values[:5]), pcap(values[5:]), pcap([(frame(97), BASE_NS + 5 * 375_000_000)])]
    for ordinal, data in enumerate(original):
        ledger.receive("e1-stop", ordinal, data)
    client = LocalClient()
    client_factory(monkeypatch, client)
    pipe = ContinuousPipeline(settings(sparse=True), ledger)
    pipe.bind_stop(stop.is_set)
    try:
        assert pipe.process_one() is True
        completed = ledger.committed_batches(0)
        assert len(completed) == 1
        ledger.armed = True
        assert pipe.process_one() is False
        durable = ledger.load_checkpoint()
        pending = ledger.pending_batches()
        assert len(pending) == (1 if phase == "prepare" else 0)
        expected_processing = "prepared" if phase == "prepare" else "carry_or_published"
        assert ledger.receipt("e1-stop", 1)["processing"] == expected_processing
        assert ledger.receipt("e1-stop", 2)["processing"] == "pending"
        assert ledger.committed_batches(0)[:1] == completed
        before_close = list(client.attempts)
        retained_rows = dict(client.rows)
        assert len(before_close) == (1 if phase == "prepare" else 2)
    finally:
        pipe.close()
        pipe.close()
    assert client.attempts == before_close and client.rows == retained_rows
    assert ledger.load_checkpoint() == durable and ledger.pending_batches() == pending
    assert pipe.native is None
    ledger.close()
    restored = Ledger(tmp_path / "custody")
    replacement_client = LocalClient()
    replacement_client.rows.update(retained_rows)
    client_factory(monkeypatch, replacement_client)
    replacement = ContinuousPipeline(settings(sparse=True), restored)
    replacement.bind_stop(threading.Event().is_set)
    try:
        assert replacement is not pipe
        assert replacement.checkpoint() == durable
        replacement.publish_pending()
        assert restored.pending_batches() == []
        assert len(replacement_client.attempts) == (1 if phase == "prepare" else 0)
        assert restored.receipt("e1-stop", 2)["processing"] == "pending"
        assert restored.load_checkpoint() == durable
        assert restored.committed_batches(0)[:1] == completed
        new_rows = [row for row in replacement_client.rows.values() if row not in retained_rows.values()]
        assert all(row["time"] != iso(17_123) for row in new_rows)
        assert_payload([part for batch in restored.committed_batches(0) for part in batch["payload"]], 375, True, "ms")
        for ordinal, data in enumerate(original):
            receipt = restored.receipt("e1-stop", ordinal)
            assert receipt["hash"] == hashlib.sha256(data).hexdigest()
            assert receipt["size_bytes"] == len(data)
            path = restored.db.execute("SELECT path FROM chunks WHERE id=?", (receipt["id"],)).fetchone()[0]
            assert Path(path).read_bytes() == data
        assert len(replacement_client.rows) == 12
    finally:
        replacement.close()
        restored.close()


@pytest.mark.parametrize("shape", ["influx", "api"])
@pytest.mark.parametrize("status", [401, 403])
@pytest.mark.parametrize("batch", [1, 100])
def test_real_import_eof_numeric_refusal_is_failed_and_never_repeated(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, shape: str, status: int, batch: int
) -> None:
    refusal = (
        InfluxDBError(response=HTTPResponse(status=status, body=b"synthetic-e1-diagnostic"))
        if shape == "influx"
        else ApiException(status=status, reason="synthetic-e1-diagnostic")
    )
    assert permanent_auth_status(refusal) == status
    client = LocalClient(refusal)
    client_factory(monkeypatch, client)
    source = tmp_path / "e1-refused.pcap"
    data = pcap(packets(375))
    source.write_bytes(data)
    config = import_config(tmp_path, batch=batch)
    reports = []

    class Reporter:
        def report(self, display_id: str, update: Any) -> None:
            reports.append(update)

    service = ImportService(PipelineImportRunner(str(config), import_dir=str(tmp_path)), Reporter())
    service.submit(ImportRequest(display_id="e1-refusal", file_path=str(source)))
    assert service.wait_for_idle(timeout=3.0)
    final = service.status
    assert final.state is ImportState.FAILED
    assert final.result is None
    assert final.error == f"TerminalWriteError: InfluxDB write refused: permanent_auth_refusal (HTTP {status})."
    assert any(update.state is ImportState.FAILED for update in reports)
    assert all(update.state is not ImportState.COMPLETED and update.result is None for update in reports)
    assert len(client.attempts) == client.closes == 1
    assert len(client.attempts[0]) == (1 if batch == 1 else 5)
    assert client.rows == {} and client.queries == 0
    assert source.read_bytes() == data


@pytest.mark.parametrize("failure", [ApiException(status=503, reason="synthetic 401 text"), RuntimeError("403 text")])
def test_transient_buffer_retries_exact_original_points_without_auth_latch(
    monkeypatch: pytest.MonkeyPatch, failure: Exception
) -> None:
    client = LocalClient(failure)
    client_factory(monkeypatch, client)
    config = settings()
    options = WriteOptionsConfig(batch_size=1, flush_interval=1_000_000, jitter_interval=0, precision="ms")
    writer = InfluxDBWriter(config.influx, options, 375)
    raw = dict(
        time=17_123,
        uci="e1",
        packet_count=2,
        total_volume=140,
        mean_packet_size=70,
        min_packet_size=61,
        max_packet_size=79,
    )
    try:
        writer.write(raw)
        assert writer._terminal_status is None
        assert len(writer._buffer) == 1
        assert len(client.attempts) == 1 and client.rows == {}
        client.failure = None
        writer.flush(force=True)
        assert client.attempts[1] == client.attempts[0]
        assert writer._buffer == []
        writer.close()
        writer.close()
        assert len(client.attempts) == 2 and client.closes == 1
    finally:
        writer.close()


@pytest.mark.parametrize("status", [401, 403])
def test_installed_numeric_refusal_latches_through_flush_close_and_later_enqueue(
    monkeypatch: pytest.MonkeyPatch, status: int
) -> None:
    class NonRenderingRefusal(InfluxDBError):
        def __str__(self) -> str:
            raise AssertionError("numeric refusal must not render the transport exception")

    client = LocalClient(NonRenderingRefusal(response=HTTPResponse(status=status, body=b"synthetic-e1")))
    client_factory(monkeypatch, client)
    config = settings()
    writer = InfluxDBWriter(
        config.influx,
        WriteOptionsConfig(batch_size=1, flush_interval=1_000_000, jitter_interval=0, precision="ms"),
        375,
    )
    native = NetworkCaptureSession(375, 64, 65536)
    metrics = []
    for data, instant in packets(375):
        window = native.push_packet(data, instant // 1_000_000_000, instant % 1_000_000_000)
        if window is not None:
            metrics.extend(window["metrics"])
    for action in (
        lambda: writer.write(metrics[0]),
        writer.flush,
        lambda: writer.flush(force=True),
        writer.close,
        writer.close,
        lambda: writer.write(metrics[1]),
    ):
        with pytest.raises(TerminalWriteError) as caught:
            action()
        assert caught.value.status == status
        assert caught.value.category == "permanent_auth_refusal"
        assert caught.value.__context__ is None and caught.value.__cause__ is None
        assert str(caught.value) == f"InfluxDB write refused: permanent_auth_refusal (HTTP {status})."
    assert len(client.attempts) == client.closes == 1
    assert len(writer._buffer) == 1
    assert writer._buffer[0].to_line_protocol() == client.attempts[0][0]
    assert "packet_count=2i" in client.attempts[0][0]
    assert "total_volume=140i" in client.attempts[0][0]
    assert client.attempts[0][0].endswith(" 17123")
    assert client.rows == {} and client.queries == 0


def test_actual_python_protocol_mapping_and_accessor_precedence(tmp_path: Path) -> None:
    ledger = Ledger(tmp_path / "mapping")
    pipe = ContinuousPipeline(settings(sparse=True), ledger, write_enabled=False)
    try:

        def window(start: int) -> dict[str, Any]:
            return dict(
                record_start_ms=start,
                metrics=[
                    dict(
                        time=start,
                        uci=f"{SRC}/{DST}/0/17/192.0.2.19/198.51.100.29/{port}/29017/UDP",
                        protocols=17,
                        packet_count=count,
                        total_volume=volume,
                        min_packet_size=61,
                        max_packet_size=97,
                        mean_packet_size=volume / count,
                    )
                    for port, count, volume in [(32119, 2, 140), (32120, 3, 237)]
                ],
            )

        assert pipe.points(window(17_123)) == []
        parts = pipe.points(window(17_498))
        network = next(part for part in parts if part["writer"] == "network")["records"][0]
        assert network["packet_count"] == 5 and network["total_volume"] == 377
        assert network["mean_packet_size"] == 75.4
        assert network["uci"] == f"{SRC}/{DST}/0/17/192.0.2.19/198.51.100.29/*/29017/UDP"
        proto = next(part for part in parts if part["writer"] == "proto")["records"]
        assert proto == [
            dict(
                time=iso(17_123),
                protocol="E1-UDP",
                proto_total_packets=5.0,
                proto_total_volume=377.0,
                proto_conn_count=2.0,
            )
        ]
        writer = pipe.writers["network"]
        assert writer._extract_attribute(dict(packet_count=7), "get_total_packet_count") == 7
        assert writer._extract_attribute(dict(packet_count=7, total_packet_count=11), "get_total_packet_count") == 11
        assert (
            writer._extract_attribute(dict(packet_count=7, get_total_packet_count=None), "get_total_packet_count")
            is None
        )
        with pytest.raises(ValueError, match="millisecond"):
            writer_module._map_precision("s")
    finally:
        pipe.close()
        ledger.close()
