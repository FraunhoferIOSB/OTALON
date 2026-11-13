"""A write ACK is not visibility; conflicting same-point payloads fault."""

from copy import deepcopy
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
from desktop_ingest.ledger import Ledger
from pydantic import SecretStr
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


@pytest.fixture
def pending_pipeline(tmp_path):
    from desktop_ingest.pipeline import ContinuousPipeline

    pipe = ContinuousPipeline.__new__(ContinuousPipeline)
    pipe.write_enabled = True
    pipe.ledger = Ledger(tmp_path)
    pipe.ledger.register_run("r", None)
    pipe.writers = {
        name: SimpleNamespace(
            config=SimpleNamespace(host="http://influx.test:8181", database="netcap", token=SecretStr("unit-only")),
            write_precision="ms",
            client=Mock(),
        )
        for name in ("network", "mac", "proto")
    }
    payload = []
    for second in range(2):
        for name in pipe.writers:
            rows = [
                {"time": f"2020-01-01T00:00:0{second}+00:00", "series": f"s{i}", "packet_count": i + 1}
                for i in range(2)
            ]
            payload.append(
                {
                    "writer": name,
                    "database": "netcap",
                    "measurement": name + "_metrics",
                    "tag_keys": ["series"],
                    "lines": [
                        f"{name}_metrics,series=s{i} packet_count={i + 1}i {1577836800000 + second * 1000}"
                        for i in range(2)
                    ],
                    "records": rows,
                }
            )
    for name, writer in pipe.writers.items():
        writer.client.query.side_effect = [
            [row] for part in payload if part["writer"] == name for row in part["records"]
        ]
    ident = pipe.ledger.receive("r", 0, pcap([1000]))["id"]
    pipe.ledger.prepare(ident, {"fixture": "unchanged"}, payload)
    yield pipe, payload
    pipe.ledger.close()


def test_publish_groups_common_destination_and_verifies_every_original_point(pending_pipeline):
    pipe, payload = pending_pipeline
    batch_before = deepcopy(pipe.ledger.pending_batches()[0])
    checkpoint_before = pipe.ledger.load_checkpoint()
    events = []
    for name, writer in pipe.writers.items():
        writer.client.write.side_effect = lambda **kwargs: events.append("write")
        rows = iter([row] for part in payload if part["writer"] == name for row in part["records"])

        def query(*, query, mode, rows=rows):
            events.append("query")
            return next(rows)

        writer.client.query.side_effect = query
    commit = pipe.ledger.commit_batch
    pipe.ledger.commit_batch = Mock(side_effect=lambda ident: (events.append("commit"), commit(ident)))

    pipe.publish_pending()

    pipe.writers["network"].client.write.assert_called_once_with(
        record=[line for part in payload for line in part["lines"]], write_precision="ms"
    )
    for name in ("mac", "proto"):
        pipe.writers[name].client.write.assert_not_called()
    assert events == ["write"] + ["query"] * 12 + ["commit"]
    for name, writer in pipe.writers.items():
        calls = writer.client.query.call_args_list
        expected = [part for part in payload if part["writer"] == name for _ in part["records"]]
        assert len(calls) == len(expected) == 4
        for call, part in zip(calls, expected):
            assert 'SELECT * FROM "' + part["measurement"] + '" WHERE time=' in call.kwargs["query"]
            assert '"series"=' in call.kwargs["query"] and call.kwargs["query"].endswith(" LIMIT 2")
            assert call.kwargs["mode"] == "pandas"
    assert not pipe.ledger.pending_batches()
    committed = pipe.ledger.committed_batches(0)[0]
    assert committed == dict(batch_before, committed=1)
    assert pipe.ledger.load_checkpoint() == checkpoint_before


@pytest.mark.parametrize("difference", ["host", "database", "token", "precision"])
def test_publish_keeps_distinct_destinations_separate(pending_pipeline, difference):
    pipe, payload = pending_pipeline
    mac = pipe.writers["mac"]
    if difference == "precision":
        mac.write_precision = "ns"
    else:
        setattr(
            mac.config, difference, SecretStr("other-unit-only") if difference == "token" else "other-" + difference
        )

    pipe.publish_pending()

    for name, included in (("network", {"network", "proto"}), ("mac", {"mac"})):
        writer = pipe.writers[name]
        writer.client.write.assert_called_once_with(
            record=[line for part in payload if part["writer"] in included for line in part["lines"]],
            write_precision=writer.write_precision,
        )
    pipe.writers["proto"].client.write.assert_not_called()
    assert len(pipe.ledger.committed_batches(0)) == 1


@pytest.mark.parametrize(
    "stage", ["first_write", "later_write", "query", "missing", "duplicate", "time", "tag", "field"]
)
def test_publish_fault_never_commits_or_changes_durable_batch(pending_pipeline, stage):
    pipe, payload = pending_pipeline
    batch_before = deepcopy(pipe.ledger.pending_batches()[0])
    checkpoint_before = pipe.ledger.load_checkpoint()
    if stage in {"first_write", "later_write"}:
        name = "network" if stage == "first_write" else "mac"
        if stage == "later_write":
            pipe.writers[name].config.database = "other-database"
        pipe.writers[name].client.write.side_effect = OSError("write failed")
    else:
        query = pipe.writers["proto"].client.query
        actual = dict(payload[2]["records"][0])
        if stage == "query":
            query.side_effect = OSError("query failed")
        else:
            if stage == "time":
                actual["time"] = "2020-01-01T00:00:09+00:00"
            if stage == "tag":
                actual["series"] = "wrong-series"
            if stage == "field":
                actual["packet_count"] += 1
            query.side_effect = None
            query.return_value = [] if stage == "missing" else [actual, actual] if stage == "duplicate" else [actual]

    with pytest.raises((OSError, ValueError)):
        pipe.publish_pending()

    assert pipe.ledger.pending_batches() == [batch_before]
    assert not pipe.ledger.committed_batches(0)
    assert pipe.ledger.load_checkpoint() == checkpoint_before
    if stage in {"first_write", "later_write"}:
        for writer in pipe.writers.values():
            writer.client.query.assert_not_called()


def test_publish_keeps_immutable_batches_separate(pending_pipeline):
    pipe, payload = pending_pipeline
    ident = pipe.ledger.receive("r", 1, pcap([1001]))["id"]
    pipe.ledger.prepare(ident, {"fixture": "next"}, payload)
    pipe.verify_visible = Mock()

    pipe.publish_pending()

    calls = pipe.writers["network"].client.write.call_args_list
    assert len(calls) == 2
    assert all(call.kwargs["record"] == [line for part in payload for line in part["lines"]] for call in calls)
    assert pipe.verify_visible.call_count == len(payload) * 2
    assert len(pipe.ledger.committed_batches(0)) == 2


def test_publish_disabled_keeps_pending_batch(pending_pipeline):
    pipe, _ = pending_pipeline
    before = pipe.ledger.pending_batches()
    pipe.write_enabled = False

    pipe.publish_pending()

    assert pipe.ledger.pending_batches() == before
    for writer in pipe.writers.values():
        writer.client.write.assert_not_called()
        writer.client.query.assert_not_called()


def test_publish_empty_carry_commits_without_network_calls():
    from desktop_ingest.pipeline import ContinuousPipeline

    pipe = ContinuousPipeline.__new__(ContinuousPipeline)
    pipe.write_enabled = True
    pipe.ledger = Mock()
    pipe.ledger.pending_batches.return_value = [{"id": 1, "payload": []}]
    pipe.writers = {}
    pipe.verify_visible = Mock()

    pipe.publish_pending()

    pipe.verify_visible.assert_not_called()
    pipe.ledger.commit_batch.assert_called_once_with(1)


@pytest.mark.parametrize("extra_bytes,fail_later", [(0, False), (1, False), (1, True)])
def test_publish_bounds_utf8_and_newline_bytes_before_verification(pending_pipeline, extra_bytes, fail_later):
    pipe, payload = pending_pipeline
    limit = 8_000_000
    payload = deepcopy(payload[:2])
    for index, part in enumerate(payload):
        prefix = part["measurement"] + ",series=s0,padding="
        suffix = " packet_count=1i 1577836800000"
        padding = "\u00e9" if index == 0 else ""
        size = limit // 2 if index == 0 else limit // 2 - 1 + extra_bytes
        padding += "x" * (size - len((prefix + padding + suffix).encode("utf-8")))
        part["lines"] = [prefix + padding + suffix]
        part["tag_keys"].append("padding")
        part["records"] = [dict(part["records"][0], padding=padding)]
    expected_lines = [part["lines"][0] for part in payload]
    assert all(len(line.encode("utf-8")) < limit for line in expected_lines)
    assert len("\n".join(expected_lines).encode("utf-8")) == limit + extra_bytes
    pipe.ledger.commit_batch(1)
    ident = pipe.ledger.receive("r", 1, pcap([1001]))["id"]
    pipe.ledger.prepare(ident, {"fixture": "bounded"}, payload)
    batch_before = pipe.ledger.pending_batches()[0]
    checkpoint_before = pipe.ledger.load_checkpoint()
    events = []
    client = pipe.writers["network"].client

    def write(**kwargs):
        events.append("write")
        if fail_later and len(events) == 2:
            raise OSError("later subrequest failed")

    client.write.side_effect = write
    for part in payload:
        def query(*, query, mode, part=part):
            events.append("query")
            return part["records"]

        pipe.writers[part["writer"]].client.query.side_effect = query
    if fail_later:
        with pytest.raises(OSError, match="later subrequest failed"):
            pipe.publish_pending()
        assert pipe.ledger.pending_batches() == [batch_before]
        assert len(pipe.ledger.committed_batches(0)) == 1
        assert events == ["write", "write"]
    else:
        pipe.publish_pending()
        assert not pipe.ledger.pending_batches()
        assert pipe.ledger.committed_batches(1)[0] == dict(batch_before, committed=1)
        assert events == ["write"] * (1 + bool(extra_bytes)) + ["query", "query"]
    calls = client.write.call_args_list
    assert [call.kwargs["record"] for call in calls] == (
        [[line] for line in expected_lines] if extra_bytes else [expected_lines]
    )
    assert all(len("\n".join(call.kwargs["record"]).encode("utf-8")) <= limit for call in calls)
    assert all(call.kwargs["write_precision"] == "ms" for call in calls)
    assert pipe.ledger.load_checkpoint() == checkpoint_before
    pipe.writers["mac"].client.write.assert_not_called()
    pipe.writers["proto"].client.write.assert_not_called()


@pytest.mark.parametrize("separate_destination", [False, True])
@pytest.mark.parametrize("extra_bytes", [0, 1])
def test_publish_single_line_byte_limit(pending_pipeline, separate_destination, extra_bytes):
    pipe, payload = pending_pipeline
    payload = deepcopy(payload[:2])
    part = payload[1]
    prefix = part["measurement"] + ",series=s0,padding="
    suffix = " packet_count=1i 1577836800000"
    padding = "x" * (8_000_000 + extra_bytes - len(prefix + suffix))
    part["lines"] = [prefix + padding + suffix]
    part["tag_keys"].append("padding")
    part["records"] = [dict(part["records"][0], padding=padding)]
    if separate_destination:
        pipe.writers["mac"].config.database = "other-database"
    pipe.ledger.commit_batch(1)
    ident = pipe.ledger.receive("r", 1, pcap([1001]))["id"]
    pipe.ledger.prepare(ident, {"fixture": "oversized"}, payload)
    batch_before = pipe.ledger.pending_batches()[0]
    checkpoint_before = pipe.ledger.load_checkpoint()

    if extra_bytes:
        with pytest.raises(ValueError, match="Influx line exceeds publication request byte limit"):
            pipe.publish_pending()
        assert pipe.ledger.pending_batches() == [batch_before]
        assert len(pipe.ledger.committed_batches(0)) == 1
        for writer in pipe.writers.values():
            writer.client.write.assert_not_called()
            writer.client.query.assert_not_called()
    else:
        pipe.writers["mac"].client.query.side_effect = [part["records"]]
        pipe.publish_pending()
        assert not pipe.ledger.pending_batches()
        assert pipe.ledger.committed_batches(1)[0] == dict(batch_before, committed=1)
        calls = [call for writer in pipe.writers.values() for call in writer.client.write.call_args_list]
        assert len(calls) == 2
        sizes = [len("\n".join(call.kwargs["record"]).encode("utf-8")) for call in calls]
        assert max(sizes) == 8_000_000
        assert min(sizes) < 8_000_000
    assert pipe.ledger.load_checkpoint() == checkpoint_before
