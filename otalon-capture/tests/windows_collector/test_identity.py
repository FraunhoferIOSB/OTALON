"""Notifications may be relative; confirm the persisted receipt before deletion."""

import pytest
from test_lifecycle import data
from windows_collector.collector import Spool, Transport


def test_relative_notification_resolves_only_inside_owned_spool(tmp_path):
    spool = Spool(tmp_path)
    run = spool.begin_run()
    name = run + "_00001_20261112120000.pcap"
    (tmp_path / name).write_bytes(data())
    spool.closed_file(run, name)
    assert len(spool.pending()) == 1


def test_put_success_without_matching_readback_never_deletes(tmp_path):
    spool = Spool(tmp_path)
    run = spool.begin_run()
    path = tmp_path / (run + "_00001_20261112120000.pcap")
    path.write_bytes(data())
    spool.closed_file(run, path)
    transport = Transport.__new__(Transport)
    transport.interface = "fixture"
    transport.fingerprint = "a" * 64

    def request(url, body=None, method="POST", raw=False):
        if raw:
            return {"accepted": True, "hash": spool.pending()[0]["hash"]}
        if method == "GET":
            return {"custody": "accepted", "hash": "0" * 64, "size_bytes": len(data())}
        return {"registered": True}

    transport.request = request
    with pytest.raises(ValueError, match="receipt"):
        transport.flush(spool)
    assert path.exists() and spool.pending()
