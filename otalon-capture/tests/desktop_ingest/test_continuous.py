"""Continuous producer preserves native/Python state and exact retry payloads."""

import importlib.util
import json
from pathlib import Path

import pytest
from test_ledger import pcap


@pytest.mark.parametrize("sparse", [True, False])
@pytest.mark.parametrize("interval_ms", [1000, 375])
def test_every_file_split_and_restart_matches_uninterrupted(tmp_path, sparse, interval_ms):
    assert importlib.util.find_spec("desktop_ingest.pipeline"), "continuous pipeline missing"
    from desktop_ingest.ledger import Ledger
    from desktop_ingest.pipeline import ContinuousPipeline
    from otalon_capture.settings import Settings

    config = json.loads((Path(__file__).parents[2] / "config/config.json").read_text())
    config["capture"]["source"] = "offline-test"
    config["capture"]["type"] = "PCAP"
    config["capture"]["interval"] = interval_ms
    config["preprocess"]["aggregate_sparse_ports"] = sparse
    for k in ["influx", "mac_influx", "proto_influx"]:
        if k in config:
            config[k]["host"] = "http://127.0.0.1:1"
            config[k]["token"] = "test-only"
    settings = Settings.model_validate(config)
    packets = [1000200, 1000900, 1001300, 1001600, 1002400, 1003500]
    results = []
    for split in [len(packets), 1, 2, 3, 4]:
        root = tmp_path / str(split)
        ledger = Ledger(root, max_bytes=1000000)
        ledger.register_run("r1", None)
        pipeline = ContinuousPipeline(settings, ledger, write_enabled=False)
        ledger.receive("r1", 0, pcap(packets[:split]))
        pipeline.process_one()
        checkpoint = ledger.load_checkpoint()
        pipeline.close()
        assert ledger.load_checkpoint() == checkpoint
        pipeline = ContinuousPipeline(settings, ledger, write_enabled=False)
        if split < len(packets):
            ledger.receive("r1", 1, pcap(packets[split:]))
            pipeline.process_one()
        payload = [x for b in ledger.pending_batches() for x in b["payload"]]
        records = {k: [] for k in ["network_metrics", "mac_traffic", "proto_traffic"]}
        for part in payload:
            records[part["measurement"]] += part["lines"]
        results.append(records)
    assert all(r == results[0] for r in results)
    assert all(results[0][k] for k in results[0])


def _settings(sparse=True, precision="ms"):
    from desktop_ingest.settings import ReliablePipelineSettings

    def measurement(name, tag, field):
        return dict(
            host="http://localhost",
            token="synthetic-only",
            database="test",
            measurement_name=name,
            tags=[tag],
            fields={field: field},
        )

    return ReliablePipelineSettings.model_validate(
        dict(
            interval_ms=375,
            influx=measurement("network_metrics", "uci", "packet_count"),
            mac_influx=measurement("mac_traffic", "mac_address", "out_total_packets"),
            proto_influx=measurement("proto_traffic", "protocol", "proto_total_packets"),
            write_options=dict(batch_size=10, flush_interval=1000, jitter_interval=0, precision=precision),
            preprocess=dict(aggregate_sparse_ports=sparse),
            mac_aggregation=dict(enabled=True),
            proto_aggregation=dict(enabled=True),
        )
    )


@pytest.mark.parametrize("precision,multiplier", [("ms", 1), ("us", 1000), ("ns", 1_000_000)])
def test_fractional_cutoff_and_visibility_records_agree_after_restart(precision, multiplier):
    from desktop_ingest.pipeline import ContinuousPipeline

    class CheckpointLedger:
        state = None

        def load_checkpoint(self):
            return self.state

    ledger = CheckpointLedger()
    pipeline = ContinuousPipeline(_settings(precision=precision), ledger, write_enabled=False)

    def window(start):
        return {
            "record_start_ms": start,
            "metrics": [{"time": start, "uci": "src/dst/0/6/192.0.2.1/192.0.2.2/32001/80/TCP", "packet_count": 3}],
        }

    assert pipeline.points(window(4_123)) == []
    ledger.state = pipeline.checkpoint()
    pipeline.close()
    pipeline = ContinuousPipeline(_settings(precision=precision), ledger, write_enabled=False)
    payload = pipeline.points(window(4_498))
    assert {p["writer"] for p in payload} == {"network", "mac", "proto"}
    for part in payload:
        for line, row in zip(part["lines"], part["records"], strict=True):
            assert int(line.rsplit(" ", 1)[1]) == 4_123 * multiplier
            assert row["time"] == "1970-01-01T00:00:04.123000+00:00"
        from unittest.mock import Mock

        writer = pipeline.writers[part["writer"]]
        writer.client = Mock()
        for row in part["records"]:
            writer.client.query.return_value = [row]
            pipeline.verify_visible(dict(part, records=[row]))
            assert row["time"] in writer.client.query.call_args.kwargs["query"]
            writer.client.query.return_value = [dict(row, time="1970-01-01T00:00:04+00:00")]
            with pytest.raises(ValueError, match="visible timestamp differs"):
                pipeline.verify_visible(dict(part, records=[row]))
    assert set(pipeline.sparse.buckets) == {4_498}


@pytest.mark.parametrize("version,contract", [(1, None), (2, None), (2, "unknown")])
def test_old_carry_fails_closed_before_restore_or_publication(monkeypatch, version, contract):
    from desktop_ingest.pipeline import ContinuousPipeline

    class EmptyLedger:
        def load_checkpoint(self):
            return None

    state = ContinuousPipeline(_settings(), EmptyLedger(), write_enabled=False).checkpoint()
    state["version"] = version
    state["timestamp_contract"] = contract

    class OldLedger:
        def load_checkpoint(self):
            return state

    def forbidden(*args, **kwargs):
        pytest.fail("legacy carry must fail before native restore or writer creation")

    monkeypatch.setattr("desktop_ingest.pipeline.NetworkCaptureSession", forbidden)
    monkeypatch.setattr("desktop_ingest.pipeline.InfluxDBWriter", forbidden)
    with pytest.raises(ValueError, match="timestamp contract"):
        ContinuousPipeline(_settings(), OldLedger())


def test_coarse_precision_rejected_even_without_publication():
    from desktop_ingest.pipeline import ContinuousPipeline

    class EmptyLedger:
        def load_checkpoint(self):
            return None

    with pytest.raises(ValueError, match="millisecond"):
        ContinuousPipeline(_settings(precision="s"), EmptyLedger(), write_enabled=False)
