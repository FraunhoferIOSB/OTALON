"""Continuous owner construction and release must never finalize custody."""

import gc
import hashlib
import struct
import traceback
import weakref
from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from desktop_ingest import pipeline as module
from desktop_ingest.ledger import Ledger
from desktop_ingest.settings import ReliablePipelineSettings
from otalon_capture.influxdb_writer import ClientReleaseError, InfluxDBWriter


class OwnerAbort(BaseException):
    pass


def settings():
    def measurement(name):
        return dict(
            host="http://owner.invalid",
            token="synthetic-only",
            database="owner_test",
            measurement_name=name,
            tags=["uci"],
            fields={"packet_count": "packet_count"},
        )

    return ReliablePipelineSettings.model_validate(
        dict(
            interval_ms=375,
            influx=measurement("network"),
            mac_influx=measurement("mac"),
            proto_influx=measurement("proto"),
            write_options=dict(batch_size=10, flush_interval=1000, jitter_interval=0, precision="ms"),
            mac_aggregation=dict(enabled=True),
            proto_aggregation=dict(enabled=True),
        )
    )


@pytest.fixture
def allocations(monkeypatch):
    refs = {}
    clients = []
    allocated = []
    fault = {"stage": None, "error": OwnerAbort("construction aborted"), "close_failure": None}
    forbidden = Mock(side_effect=AssertionError("release must not finalize or publish"))

    class Native:
        def restore_state(self, state):
            if fault["stage"] == "restore_native":
                raise fault["error"]

        finish_stream = seal = export_state = push_packet = forbidden

    class Agg:
        enabled = True

        def __init__(self, name):
            self.name = name
            self.buckets = {}

        def __setattr__(self, name, value):
            if name == "buckets" and fault["stage"] == "restore_" + self.name:
                raise fault["error"]
            object.__setattr__(self, name, value)

        flush = add = forbidden

    def allocate(name):
        if fault["stage"] == name:
            raise fault["error"]
        resource = Native() if name == "native" else Agg(name)
        refs[name] = weakref.ref(resource)
        allocated.append(name)
        return resource

    monkeypatch.setattr(module, "NetworkCaptureSession", lambda *args: allocate("native"))
    monkeypatch.setattr(module, "SparsePortAggregator", lambda *args: allocate("sparse"))
    monkeypatch.setattr(module, "MacAggregator", lambda *args, **kwargs: allocate("mac"))
    monkeypatch.setattr(module, "ProtoAggregator", lambda *args, **kwargs: allocate("proto"))

    def writer(config, *args):
        name = config.measurement_name
        if fault["stage"] == "writer_" + name:
            raise fault["error"]
        client = SimpleNamespace(close=Mock(), write=forbidden, query=forbidden, flush=forbidden)
        if fault["close_failure"] == name:
            client.close.side_effect = OwnerAbort("synthetic release failure")
        clients.append(client)
        return SimpleNamespace(client=client, close=forbidden, flush=forbidden)

    monkeypatch.setattr(module, "InfluxDBWriter", writer)
    try:
        yield SimpleNamespace(refs=refs, clients=clients, allocated=allocated, fault=fault, forbidden=forbidden)
    finally:
        # Doubles own no external handles; also clear any failed owner's retained tracebacks.
        fault["error"].__traceback__ = None
        for client in clients:
            client.close.side_effect = None
        fault.clear()
        clients.clear()


def assert_detached(owner, allocations):
    assert all(getattr(owner, name, None) is None for name in ("native", "sparse", "mac", "proto"))
    assert getattr(owner, "writers", {}) == {}
    gc.collect()
    assert all(ref() is None for ref in allocations.refs.values())


@pytest.mark.parametrize("stage", ["native", "sparse", "mac", "proto", "writer_network", "writer_mac", "writer_proto"])
@pytest.mark.parametrize("error_type", [RuntimeError, OwnerAbort])
def test_partial_allocation_releases_returned_resources(monkeypatch, allocations, stage, error_type):
    error = error_type("construction aborted")
    allocations.fault.update(stage=stage, error=error)
    ledger = Mock()
    ledger.load_checkpoint.return_value = None
    owner = module.ContinuousPipeline.__new__(module.ContinuousPipeline)
    try:
        with pytest.raises(error_type) as caught:
            owner.__init__(settings(), ledger)
        assert caught.value is error
        traceback.clear_frames(caught.tb)
        error.__traceback__ = None
        assert_detached(owner, allocations)
        for client in allocations.clients:
            client.close.assert_called_once_with()
        owner.close()
        for client in allocations.clients:
            client.close.assert_called_once_with()
        assert ledger.mock_calls == [(("load_checkpoint"), (), {})]
        allocations.forbidden.assert_not_called()
    finally:
        error.__traceback__ = None


@pytest.mark.parametrize("missing,expected_clients", [("mac_influx", 1), ("proto_influx", 2)])
def test_missing_enabled_configuration_releases_earlier_clients(allocations, missing, expected_clients):
    config = settings().model_copy(update={missing: None})
    owner = module.ContinuousPipeline.__new__(module.ContinuousPipeline)
    ledger = Mock()
    ledger.load_checkpoint.return_value = None
    try:
        with pytest.raises(ValueError, match="enabled measurement configuration missing") as caught:
            owner.__init__(config, ledger)
        traceback.clear_frames(caught.tb)
        caught.value.__traceback__ = None
        assert len(allocations.clients) == expected_clients
        assert_detached(owner, allocations)
        for client in allocations.clients:
            client.close.assert_called_once_with()
        allocations.forbidden.assert_not_called()
    finally:
        allocations.fault["error"].__traceback__ = None


@pytest.mark.parametrize(
    "stage",
    [
        "decode_native",
        "restore_native",
        "decode_sparse",
        "decode_mac",
        "decode_proto",
        "restore_sparse",
        "restore_mac",
        "restore_proto",
    ],
)
@pytest.mark.parametrize("close_failure", [None, "network"])
def test_restore_failure_releases_all_writers_and_preserves_primary(monkeypatch, allocations, stage, close_failure):
    allocations.fault["close_failure"] = close_failure
    config = settings()
    state = {
        "version": 2,
        "timestamp_contract": "native-window-start-ms-v1",
        "config": hashlib.sha256(config.model_dump_json().encode()).hexdigest(),
        "native": "native",
        "sparse": "sparse",
        "mac": "mac",
        "proto": "proto",
        "latest_record_ms": 4123,
    }
    ledger = Mock()
    ledger.load_checkpoint.return_value = state
    before = deepcopy(state)
    owner = module.ContinuousPipeline.__new__(module.ContinuousPipeline)
    error = allocations.fault["error"]

    def decode(value):
        if stage == "decode_" + value:
            raise error
        if stage.startswith("restore_"):
            allocations.fault["stage"] = stage
        return {}

    monkeypatch.setattr(module, "decode", decode)
    try:
        with pytest.raises(OwnerAbort) as caught:
            owner.__init__(config, ledger)
        assert caught.value is error
        # pytest retains fault frames (including restore's self), independently of the owner slots.
        traceback.clear_frames(caught.tb)
        error.__traceback__ = None
        assert_detached(owner, allocations)
        assert len(allocations.clients) == 3
        for client in allocations.clients:
            client.close.assert_called_once_with()
        assert state == before
        assert owner.release_failures == (() if close_failure is None else ("network.client",))
        if close_failure:
            with pytest.raises(ClientReleaseError):
                owner.close()
        else:
            owner.close()
        for client in allocations.clients:
            client.close.assert_called_once_with()
        assert ledger.mock_calls == [(("load_checkpoint"), (), {})]
        allocations.forbidden.assert_not_called()
    finally:
        error.__traceback__ = None


def test_close_failure_does_not_skip_later_clients_or_repeat(allocations):
    ledger = Mock()
    ledger.load_checkpoint.return_value = None
    owner = module.ContinuousPipeline(settings(), ledger)
    allocations.clients[0].close.side_effect = OwnerAbort("synthetic release failure")
    try:
        with pytest.raises(ClientReleaseError) as caught:
            owner.close()
        assert str(caught.value) == "InfluxDB client release failed."
        assert caught.value.__cause__ is None
        assert_detached(owner, allocations)
        for client in allocations.clients:
            client.close.assert_called_once_with()
        assert owner.release_failures == ("network.client",)
        with pytest.raises(ClientReleaseError):
            owner.close()
        for client in allocations.clients:
            client.close.assert_called_once_with()
        allocations.forbidden.assert_not_called()
    finally:
        allocations.clients[0].close.side_effect = None


@pytest.mark.parametrize("attach_client", [False, True])
def test_normalization_close_drops_native_without_network_allocation(monkeypatch, allocations, attach_client):
    monkeypatch.setattr(module, "InfluxDBWriter", InfluxDBWriter)
    ledger = Mock()
    ledger.load_checkpoint.return_value = None
    owner = module.ContinuousPipeline(settings(), ledger, write_enabled=False)
    writers = list(owner.writers.values())
    clients = []
    try:
        assert not allocations.clients
        assert all(not hasattr(writer, "client") for writer in writers)
        if attach_client:
            for writer in writers:
                client = Mock()
                writer.client = client
                clients.append(client)
        owner.close()
        owner.close()
        assert_detached(owner, allocations)
        for client in clients:
            assert client.mock_calls == [(("close"), (), {})]
        assert ledger.mock_calls == [(("load_checkpoint"), (), {})]
        allocations.forbidden.assert_not_called()
    finally:
        clients.clear()


@pytest.mark.parametrize("constructor_fault", [False, True])
def test_cleanup_keeps_actual_custody_checkpoint_outbox_and_rows(tmp_path, monkeypatch, allocations, constructor_fault):
    ledger = Ledger(tmp_path)
    owner = None
    error = allocations.fault["error"]
    try:
        ledger.register_run("owner", None)
        packet = b"\x00" * 60
        data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
        data += struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet
        first = ledger.receive("owner", 0, data)["id"]
        ledger.receive("owner", 1, data)
        ledger.close_run("owner", 1)
        ledger.observe({"interface": "synthetic", "recording": False})
        config = settings()
        state = {
            "version": 2,
            "timestamp_contract": "native-window-start-ms-v1",
            "config": hashlib.sha256(config.model_dump_json().encode()).hexdigest(),
            **{name: module.encode({}) for name in ("native", "sparse", "mac", "proto")},
            "latest_record_ms": 4123,
        }
        ledger.prepare(
            first,
            state,
            [
                {
                    "database": "owner_test",
                    "measurement": "network",
                    "tag_keys": [],
                    "records": [{"time": "1970-01-01T00:00:04.123000+00:00", "packet_count": 1}],
                }
            ],
        )

        def snapshot():
            return (
                list(ledger.db.iterdump()),
                {path.name: path.read_bytes() for path in ledger.raw.iterdir()},
                ledger.load_checkpoint(),
                ledger.pending_batches(),
                ledger.receipt("owner", 0),
                ledger.receipt("owner", 1),
            )

        before = snapshot()
        if constructor_fault:
            allocations.fault["stage"] = "restore_native"
        owner = module.ContinuousPipeline.__new__(module.ContinuousPipeline)
        if constructor_fault:
            with pytest.raises(OwnerAbort) as caught:
                owner.__init__(config, ledger)
            assert caught.value is error
            traceback.clear_frames(caught.tb)
            error.__traceback__ = None
        else:
            owner.__init__(config, ledger)
        for name in ("process_one", "publish_pending", "points", "checkpoint"):
            monkeypatch.setattr(owner, name, allocations.forbidden)
        owner.close()
        owner.close()
        assert snapshot() == before
        assert_detached(owner, allocations)
        allocations.forbidden.assert_not_called()
        for client in allocations.clients:
            client.close.assert_called_once_with()
    finally:
        error.__traceback__ = None
        if owner is not None:
            try:
                owner.close()
            except BaseException:
                pass
        ledger.close()
