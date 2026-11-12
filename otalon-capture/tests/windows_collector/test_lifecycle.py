"""Collector framing, closure order and durable retry use actual production code."""

import struct

import pytest
from windows_collector.collector import Spool, Transport


def data():
    frame = bytes.fromhex("0200000000020200000000010806") + bytes(46)
    return struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1) + struct.pack("<IIII", 1, 0, 60, 60) + frame


def test_malformed_closed_file_keeps_evidence_and_is_not_queued(tmp_path):
    spool = Spool(tmp_path)
    run = spool.begin_run()
    path = tmp_path / (run + "_00001_20261112120000.pcap")
    path.write_bytes(data()[:-1])
    with pytest.raises(ValueError):
        spool.closed_file(run, path)
    assert not spool.pending() and path.exists()


def test_notification_order_is_numeric_immutable_and_missing_file_is_not_renumbered(tmp_path):
    spool = Spool(tmp_path)
    run = spool.begin_run()
    path = tmp_path / (run + "_00003_20261112120000.pcap")
    path.write_bytes(data())
    spool.closed_file(run, path)
    assert spool.pending()[0]["ordinal"] == 2


def test_real_transport_sends_source_digest_and_versioned_run(tmp_path):
    spool = Spool(tmp_path)
    run = spool.begin_run()
    path = tmp_path / (run + "_00001_20261112120000.pcap")
    path.write_bytes(data())
    spool.closed_file(run, path)
    requests = []
    transport = Transport.__new__(Transport)
    transport.interface = "physical-fixture"
    transport.fingerprint = "a" * 64

    def request(url, body=None, method="POST", raw=False):
        requests.append((url, method, body))
        if raw:
            import hashlib

            return {"accepted": True, "hash": hashlib.sha256(body).hexdigest()}
        if method == "GET":
            row = spool.pending()[0]
            return {"custody": "accepted", "hash": row["hash"], "size_bytes": row["size"]}
        return {"registered": True}

    transport.request = request
    transport.flush(spool)
    assert requests[0][1] == "PUT" and requests[0][2]["version"] == 1
    assert requests[1][1] == "PUT" and requests[1][0].endswith("/chunks/0")
    assert not spool.pending()
