"""Durable continuous ingress contract, isolated files and actual native binding."""

import importlib
import struct

import pytest


def module():
    spec = importlib.util.find_spec("desktop_ingest.ledger") if importlib.util.find_spec("desktop_ingest") else None
    assert spec is not None, "continuous durable receiver is missing"
    return importlib.import_module("desktop_ingest.ledger")


def pcap(times):
    frame = bytes.fromhex("0200000000020200000000010806") + bytes(46)
    out = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ms in times:
        out += struct.pack("<IIII", ms // 1000, ms % 1000 * 1000, len(frame), len(frame)) + frame
    return out


def test_custody_retries_are_idempotent_conflicts_and_holes_fail(tmp_path):
    cls = module().Ledger
    ledger = cls(tmp_path, max_bytes=1000000)
    ledger.register_run("r1", None)
    receipt = ledger.receive("r1", 0, pcap([1000]))
    assert ledger.receive("r1", 0, pcap([1000])) == receipt
    with pytest.raises(ValueError):
        ledger.receive("r1", 0, pcap([2000]))
    ledger.receive("r1", 2, pcap([3000]))
    assert ledger.next_chunk()["ordinal"] == 0
    ledger.mark_consumed(receipt["id"])
    assert ledger.next_chunk() is None
    ledger.close()
    restored = cls(tmp_path, max_bytes=1000000)
    assert restored.next_chunk() is None
    restored.receive("r1", 1, pcap([2000]))
    assert restored.next_chunk()["ordinal"] == 1


def test_invalid_pcap_does_not_receive_and_limits_are_enforced(tmp_path):
    ledger = module().Ledger(tmp_path, max_bytes=100)
    ledger.register_run("r1", None)
    with pytest.raises(ValueError):
        ledger.receive("r1", 0, pcap([1000])[:-1])
    assert ledger.next_chunk() is None
    with pytest.raises(ValueError):
        ledger.receive("r1", 0, pcap([1000, 2000]))


def test_prepared_payload_and_checkpoint_survive_write_failure(tmp_path):
    ledger = module().Ledger(tmp_path, max_bytes=1000000)
    ledger.register_run("r1", None)
    receipt = ledger.receive("r1", 0, pcap([1000]))
    ledger.prepare(
        receipt["id"],
        {"version": 1, "marker": "carry"},
        [
            {
                "database": "netcap",
                "measurement": "network_metrics",
                "writer": "network",
                "tag_keys": [],
                "lines": ["x n=1i 1"],
                "records": [{"time": 0}],
            }
        ],
    )
    ledger.close()
    restored = module().Ledger(tmp_path, max_bytes=1000000)
    assert restored.load_checkpoint() == {"version": 1, "marker": "carry"}
    assert restored.pending_batches()[0]["payload"][0]["lines"] == ["x n=1i 1"]
    restored.commit_batch(restored.pending_batches()[0]["id"])
    assert restored.pending_batches() == []
    assert len(restored.committed_batches(0)) == 1
