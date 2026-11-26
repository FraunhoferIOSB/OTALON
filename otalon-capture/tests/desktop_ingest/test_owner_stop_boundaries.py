"""STOP observes real phase boundaries without finalizing synthetic custody."""

import asyncio
import hashlib
import struct
import threading
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from desktop_ingest import pipeline as module
from desktop_ingest.ledger import Ledger
from desktop_ingest.processor_lifecycle import ProcessorOwner
from desktop_ingest.settings import ReliablePipelineSettings


def settings():
    return ReliablePipelineSettings.model_validate(
        dict(
            interval_ms=375,
            influx=dict(
                host="http://owner.invalid",
                token="synthetic-only",
                database="owner_test",
                measurement_name="network",
                tags=[],
                fields={"packet_count": "packet_count"},
            ),
            write_options=dict(batch_size=10, flush_interval=1000, jitter_interval=0, precision="ms"),
        )
    )


def payload():
    return [
        dict(
            database="owner_test",
            measurement="network",
            writer="network",
            tag_keys=[],
            lines=["network packet_count=1i 4123"],
            records=[dict(time="1970-01-01T00:00:04.123000+00:00", packet_count=1)],
        )
    ]


def custody(root, prepared=False, empty=False):
    ledger = Ledger(root)
    ledger.register_run("owner", None)
    frame = b"\x00" * 60
    data = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    data += (struct.pack("<IIII", 1, 0, len(frame), len(frame)) + frame) * 2
    first = ledger.receive("owner", 0, data)["id"]
    ledger.receive("owner", 1, data)
    ledger.close_run("owner", 1)
    ledger.observe(dict(interface="synthetic", recording=False))
    config = settings()
    state = dict(
        version=2,
        timestamp_contract="native-window-start-ms-v1",
        config=hashlib.sha256(config.model_dump_json().encode()).hexdigest(),
        **{name: module.encode({}) for name in ("native", "sparse", "mac", "proto")},
        latest_record_ms=4123,
    )
    if prepared:
        ledger.prepare(first, state, [] if empty else payload())
    return ledger, state


def snapshot(ledger):
    return (
        list(ledger.db.iterdump()),
        {path.name: path.read_bytes() for path in ledger.raw.iterdir()},
        ledger.load_checkpoint(),
        ledger.pending_batches(),
        ledger.receipt("owner", 0),
        ledger.receipt("owner", 1),
    )


def allocate(monkeypatch, ledger, stop=None):
    native = SimpleNamespace(
        push_packet=Mock(return_value=None), export_state=Mock(return_value={}), restore_state=Mock()
    )
    monkeypatch.setattr(module, "NetworkCaptureSession", lambda *args: native)
    client = SimpleNamespace(write=Mock(), query=Mock(return_value=payload()[0]["records"]), close=Mock())

    def writer(config, *args):
        return SimpleNamespace(config=config, client=client, write_precision="ms")

    monkeypatch.setattr(module, "InfluxDBWriter", writer)
    owner = module.ContinuousPipeline(settings(), ledger)
    if stop is not None:
        owner.bind_stop(stop.is_set)
    return owner, native, client


@pytest.mark.parametrize("phase", ["entry", "chunk", "read", "packet", "points", "checkpoint", "prepare"])
def test_stop_blocks_next_processing_phase(tmp_path, monkeypatch, phase):
    ledger, state = custody(tmp_path)
    stop = threading.Event()
    owner, native, client = allocate(monkeypatch, ledger, stop)
    before = snapshot(ledger)
    calls = []

    def returned(name, result):
        def work(*args, **kwargs):
            calls.append(name)
            if phase == name:
                stop.set()
            return result

        return work

    next_chunk = ledger.next_chunk

    def chunk():
        result = next_chunk()
        calls.append("chunk")
        if phase == "chunk":
            stop.set()
        return result

    monkeypatch.setattr(ledger, "next_chunk", chunk)
    original_read = module.Path.read_bytes

    def read(path):
        result = original_read(path)
        calls.append("read")
        if phase == "read":
            stop.set()
        return result

    monkeypatch.setattr(module.Path, "read_bytes", read)
    native.push_packet = returned("packet", {"metrics": [], "record_start_ms": 1000})
    monkeypatch.setattr(owner, "points", returned("points", []))
    monkeypatch.setattr(owner, "checkpoint", returned("checkpoint", state))
    original_prepare = ledger.prepare

    def prepare(*args):
        calls.append("prepare")
        original_prepare(*args)
        if phase == "prepare":
            stop.set()

    monkeypatch.setattr(ledger, "prepare", prepare)
    if phase == "entry":
        stop.set()
    try:
        assert owner.process_one() is False
        assert calls == [] if phase == "entry" else calls[-1] == phase
        if phase != "prepare":
            assert snapshot(ledger) == before
        else:
            # The already-started atomic prepare is retained, not rolled back.
            assert ledger.load_checkpoint() == state
            assert len(ledger.pending_batches()) == 1
            assert ledger.receipt("owner", 0)["processing"] == "prepared"
        client.write.assert_not_called()
        client.query.assert_not_called()
    finally:
        owner.close()
        owner.close()
        client.close.assert_called_once()
        ledger.close()


@pytest.mark.parametrize("phase", ["entry", "batches", "write", "query", "verification", "empty"])
def test_stop_blocks_publication_visibility_and_empty_commit(tmp_path, monkeypatch, phase):
    ledger, _ = custody(tmp_path, prepared=True, empty=phase == "empty")
    stop = threading.Event()
    owner, native, client = allocate(monkeypatch, ledger, stop)
    before = snapshot(ledger)
    original_batches = ledger.pending_batches

    def batches():
        result = original_batches()
        if phase in {"batches", "empty"}:
            stop.set()
        return result

    monkeypatch.setattr(ledger, "pending_batches", batches)
    if phase == "write":
        client.write.side_effect = lambda **kwargs: stop.set()
    elif phase == "query":

        def query(**kwargs):
            stop.set()
            return []  # A stopped result must not be interpreted as visibility failure.

        client.query.side_effect = query
    elif phase == "verification":
        monkeypatch.setattr(owner, "verify_visible", lambda part: stop.set())
    elif phase == "entry":
        stop.set()
    try:
        owner.publish_pending()
        assert snapshot(ledger) == before
        assert client.write.call_count == (1 if phase in {"write", "query", "verification"} else 0)
        assert client.query.call_count == (1 if phase == "query" else 0)
        native.push_packet.assert_not_called()
    finally:
        owner.close()
        ledger.close()


def test_stop_between_split_requests_and_visibility_rows(tmp_path, monkeypatch):
    ledger, state = custody(tmp_path)
    part = payload()[0]
    part["lines"] = ["a" * 4_000_000] * 3
    part["records"] *= 2
    ledger.prepare(ledger.next_chunk()["id"], state, [part])
    stop = threading.Event()
    owner, _, client = allocate(monkeypatch, ledger, stop)
    before = snapshot(ledger)
    try:
        client.write.side_effect = lambda **kwargs: stop.set()
        owner.publish_pending()
        assert client.write.call_count == 1
        client.query.assert_not_called()
        assert snapshot(ledger) == before
        stop.clear()
        client.write.side_effect = None

        def query(**kwargs):
            stop.set()
            return part["records"][:1]

        client.query.side_effect = query
        owner.publish_pending()
        assert client.query.call_count == 1
        assert snapshot(ledger) == before
    finally:
        owner.close()
        ledger.close()


@pytest.mark.asyncio
@pytest.mark.parametrize("phase", ["constructor", "process", "close"])
async def test_settled_owner_never_becomes_usable_after_stop(tmp_path, monkeypatch, phase):
    ledger, _ = custody(tmp_path)
    before = snapshot(ledger)
    entered, release = threading.Event(), threading.Event()
    calls = []
    active = 0

    def work(name):
        nonlocal active
        active += 1
        assert active == 1
        calls.append(name)
        if name == phase:
            entered.set()
            assert release.wait(1)
        active -= 1

    class Pipeline:
        def process_one(self):
            work("process")
            owner.stop_event.set()
            return True

        def close(self):
            work("close")

    def factory(*args):
        work("constructor")
        return Pipeline()

    monkeypatch.setattr(module, "ContinuousPipeline", factory)
    owner = ProcessorOwner(None, ledger, lambda: None)
    task = asyncio.create_task(owner.run())
    try:
        assert await asyncio.to_thread(entered.wait, 1)
        owner.stop_event.set()
        await asyncio.sleep(0)
        assert not task.done()
    finally:
        release.set()
        await task
    assert not owner.usable and not owner.ever_usable
    assert owner.processor_state != "usable"
    assert owner._work_task is None and active == 0
    assert calls == (["constructor", "close"] if phase == "constructor" else ["constructor", "process", "close"])
    assert snapshot(ledger) == before
    ledger.close()


@pytest.mark.asyncio
async def test_actual_owner_binds_stop_before_processing(tmp_path, monkeypatch):
    ledger, _ = custody(tmp_path)
    owner, native, client = allocate(monkeypatch, ledger)
    processor = ProcessorOwner(settings(), ledger, lambda: None)
    monkeypatch.setattr(module, "ContinuousPipeline", lambda *args: owner)
    before = snapshot(ledger)

    def packet(*args):
        processor.stop_event.set()
        return None

    native.push_packet.side_effect = packet
    await processor.run()
    assert native.push_packet.call_count == 1
    assert snapshot(ledger) == before
    assert not processor.ever_usable
    client.write.assert_not_called()
    client.query.assert_not_called()
    ledger.close()


def held_child(root, phase):
    """Executed in a real module child; no live service or operator inputs."""
    import ctypes
    import os
    import signal
    from pathlib import Path

    from pytest import MonkeyPatch

    root = Path(root)
    ledger = Ledger(root / "custody")
    patch = MonkeyPatch()

    def hold(*args, **kwargs):
        (root / "held").write_text(str(os.getpid()))
        if phase == "gil":
            read_fd, write_fd = os.pipe()
            buffer = ctypes.create_string_buffer(1)
            ctypes.PyDLL(None).read(read_fd, buffer, 1)
            os.close(write_fd)
        else:
            threading.Event().wait()
        (root / "late-success").write_text("forbidden")

    async def run():
        processor = ProcessorOwner(settings(), ledger, lambda: None)

        def stopping(signum, frame):
            with (root / "terms").open("a") as output:
                output.write("TERM\n")
            processor.stop_event.set()

        signal.signal(signal.SIGTERM, signal.SIG_IGN if phase == "gil" else stopping)
        if phase in {"constructor", "gil"}:
            patch.setattr(module, "NetworkCaptureSession", hold)
            patch.setattr(module, "InfluxDBWriter", Mock(side_effect=AssertionError("late allocation")))
        else:
            pipeline, native, client = allocate(patch, ledger)
            patch.setattr(module, "ContinuousPipeline", lambda *args: pipeline)
            if phase == "process":
                native.push_packet.side_effect = hold
            elif phase == "publish":
                client.write.side_effect = hold
            elif phase == "query":
                client.query.side_effect = hold
            elif phase == "close":
                client.close.side_effect = hold
                processor.stop_event.set()
                processor.pipeline = pipeline
        await processor.run()
        (root / "late-success").write_text("forbidden")

    asyncio.run(run())
