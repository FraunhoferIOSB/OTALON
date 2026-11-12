"""A write ACK is not visibility; conflicting same-point payloads fault."""

import pytest
from desktop_ingest.ledger import Ledger
from test_ledger import pcap


def test_same_key_changed_fields_cannot_silently_complete(tmp_path):
    ledger = Ledger(tmp_path)
    ledger.register_run("r", None)
    ids = [ledger.receive("r", i, pcap([1000 + i]))["id"] for i in range(2)]

    def part(value):
        return [
            {
                "database": "netcap",
                "measurement": "network_metrics",
                "writer": "network",
                "lines": ["fixture"],
                "tag_keys": ["uci"],
                "records": [{"time": "2020-01-01T00:00:00+00:00", "uci": "series", "packet_count": value}],
            }
        ]

    ledger.prepare(ids[0], {}, part(1))
    ledger.commit_batch(1)
    with pytest.raises(ValueError, match="point identity conflict"):
        ledger.prepare(ids[1], {}, part(2))
    assert not ledger.db.execute("SELECT consumed FROM chunks WHERE id=?", (ids[1],)).fetchone()[0]


def test_visibility_checks_exact_tags_time_and_fields():
    from desktop_ingest.pipeline import ContinuousPipeline

    pipe = ContinuousPipeline.__new__(ContinuousPipeline)
    assert hasattr(pipe, "verify_visible"), "exact query visibility missing"

    class Client:
        def query(self, query, mode):
            assert "network_metrics" in query and "2020-01-01" in query
            return [{"time": "2020-01-01T00:00:00Z", "uci": "s", "packet_count": 2}]

    from types import SimpleNamespace

    pipe.writers = {"network": SimpleNamespace(client=Client())}
    part = {
        "writer": "network",
        "measurement": "network_metrics",
        "tag_keys": ["uci"],
        "records": [{"time": "2020-01-01T00:00:00+00:00", "uci": "s", "packet_count": 1}],
    }
    with pytest.raises(ValueError, match="visible fields differ"):
        pipe.verify_visible(part)
    part["records"][0]["packet_count"] = 2
    pipe.verify_visible(part)
