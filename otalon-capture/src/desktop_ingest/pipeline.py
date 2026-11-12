"""Single-owner native stream/carry and durable exact Influx outbox."""

from __future__ import annotations

import hashlib
from datetime import datetime, timezone
from pathlib import Path

from network_capture import NetworkCaptureSession
from otalon_capture.aggregation import SparsePortAggregator
from otalon_capture.influxdb_writer import InfluxDBWriter
from otalon_capture.mac_aggregation import MacAggregator
from otalon_capture.proto_aggregation import ProtoAggregator

from .codec import decode, encode
from .pcap import records


class ContinuousPipeline:
    def __init__(self, settings, ledger, write_enabled=True):
        from .settings import ReliablePipelineSettings

        if not isinstance(settings, ReliablePipelineSettings):
            data = settings.model_dump()
            data["interval_ms"] = data.pop("capture")["interval"]
            data.pop("log", None)
            settings = ReliablePipelineSettings.model_validate(data)
        self.settings = settings
        self.ledger = ledger
        self.write_enabled = write_enabled
        self.fingerprint = hashlib.sha256(settings.model_dump_json().encode()).hexdigest()
        self.native = NetworkCaptureSession(settings.interval_ms, 200000, 64_000_000)
        self.sparse = SparsePortAggregator(settings.preprocess.aggregate_sparse_ports, 2**60)
        # Continuous cutoff, not a wall-clock throttle, owns publication.
        self.sparse._flush_due = lambda: []
        self.mac = MacAggregator(settings.mac_aggregation.enabled, protocol_map=settings.protocol_map)
        self.proto = ProtoAggregator(settings.proto_aggregation.enabled, protocol_map=settings.protocol_map)
        self.writers = {}
        for k, config, enabled in [
            ("network", settings.influx, True),
            ("mac", settings.mac_influx, self.mac.enabled),
            ("proto", settings.proto_influx, self.proto.enabled),
        ]:
            if not enabled:
                continue
            if config is None:
                raise ValueError("enabled measurement configuration missing")
            if write_enabled:
                self.writers[k] = InfluxDBWriter(config, settings.write_options, settings.interval_ms)
            else:
                # Point normalization uses the existing production class without a network client.
                writer = InfluxDBWriter.__new__(InfluxDBWriter)
                writer.config = config
                writer.window_interval_ms = settings.interval_ms
                from otalon_capture.influxdb_writer import _map_precision

                writer.write_precision = _map_precision(settings.write_options.precision)
                writer.int_fields = {
                    "packet_count",
                    "total_volume",
                    "min_packet_size",
                    "max_packet_size",
                    "collapsed_port_count",
                }
                self.writers[k] = writer
        state = ledger.load_checkpoint()
        if state:
            if state["version"] != 1 or state["config"] != self.fingerprint:
                raise ValueError("checkpoint configuration mismatch")
            self.native.restore_state(decode(state["native"]))
            for k, agg in [("sparse", self.sparse), ("mac", self.mac), ("proto", self.proto)]:
                agg.buckets = decode(state[k])
            self.sparse._latest_record_ms = state["latest_record_ms"]

    def checkpoint(self):
        return {
            "version": 1,
            "config": self.fingerprint,
            "native": encode(self.native.export_state()),
            "sparse": encode(self.sparse.buckets),
            "mac": encode(self.mac.buckets),
            "proto": encode(self.proto.buckets),
            "latest_record_ms": self.sparse._latest_record_ms,
        }

    def points(self, window):
        values = {"network": [], "mac": [], "proto": []}
        for record in window["metrics"]:
            values["network"] += self.sparse.add(record)
            values["mac"] += self.mac.add(record)
            values["proto"] += self.proto.add(record)
        cutoff = window["record_start_ms"] // 1000 * 1000
        if self.sparse.enabled:
            values["network"] += self.sparse._flush_expired_buckets(cutoff)
        payload = []
        for k, writer in self.writers.items():
            lines = []
            raw = []
            for value in values[k]:
                timestamp = writer._extract_attribute(value, "get_time")
                if timestamp is None:
                    raise ValueError("missing original timestamp")
                if isinstance(value, dict):
                    aliases = {
                        "get_total_packet_count": "packet_count",
                        "get_total_volume": "total_volume",
                        "get_sd_packet_size": "std_packet_size",
                        "get_mean_packet_inter_arrival_time": "mean_interarrival_time",
                        "get_min_packet_inter_arrival_time": "min_interarrival_time",
                        "get_max_packet_inter_arrival_time": "max_interarrival_time",
                        "get_sd_packet_inter_arrival_time": "std_interarrival_time",
                    }
                    value = dict(
                        value, **{accessor: value[name] for accessor, name in aliases.items() if name in value}
                    )
                timestamp = int(timestamp)
                point = writer._build_point(value)
                line = point.to_line_protocol(precision=writer.write_precision)
                lines.append(line)
                row = {"time": writer._compute_point_timestamp(int(timestamp)).isoformat()}
                for tag in writer.config.tags:
                    row[tag] = str(writer._extract_attribute(value, tag))
                for field, attribute in writer.config.fields.items():
                    v = writer._normalize_field_value(field, writer._extract_attribute(value, attribute))
                    if v is not None:
                        row[field] = v
                raw.append(row)
            if lines:
                payload.append(
                    {
                        "measurement": writer.config.measurement_name,
                        "database": writer.config.database,
                        "lines": lines,
                        "records": raw,
                        "writer": k,
                        "tag_keys": list(writer.config.tags),
                    }
                )
        return payload

    def process_one(self):
        self.publish_pending()
        chunk = self.ledger.next_chunk()
        if not chunk:
            return False
        data = Path(chunk["path"]).read_bytes()
        if hashlib.sha256(data).hexdigest() != chunk["hash"]:
            raise ValueError("custody bytes changed")
        payload = []
        try:
            for frame, sec, ns in records(data):
                window = self.native.push_packet(frame, sec, ns)
                if window is not None:
                    payload += self.points(window)
            self.ledger.prepare(chunk["id"], self.checkpoint(), payload)
        except Exception:
            # Owner must reload last durable checkpoint before retry; no false completion.
            raise
        self.publish_pending()
        return True

    def publish_pending(self):
        if not self.write_enabled:
            return
        for batch in self.ledger.pending_batches():
            for part in batch["payload"]:
                writer = self.writers[part["writer"]]
                writer.client.write(record=part["lines"], write_precision=writer.write_precision)
            for part in batch["payload"]:
                self.verify_visible(part)
            self.ledger.commit_batch(batch["id"])

    def verify_visible(self, part):
        def quoted(value):
            return "'" + str(value).replace("'", "''") + "'"

        def identifier(value):
            return '"' + value.replace('"', '""') + '"'

        def timestamp(value):
            if hasattr(value, "to_pydatetime"):
                value = value.to_pydatetime()
            if isinstance(value, str):
                value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            if value.tzinfo is None:
                value = value.replace(tzinfo=timezone.utc)
            return value.astimezone(timezone.utc)

        for expected in part["records"]:
            predicates = ["time=" + quoted(expected["time"])] + [
                identifier(tag) + "=" + quoted(expected[tag]) for tag in part["tag_keys"]
            ]
            query = (
                "SELECT * FROM " + identifier(part["measurement"]) + " WHERE " + " AND ".join(predicates) + " LIMIT 2"
            )
            rows = self.writers[part["writer"]].client.query(query=query, mode="pandas")
            if hasattr(rows, "to_dict"):
                rows = rows.to_dict(orient="records")
            if len(rows) != 1:
                raise ValueError("exact point not yet visible")
            actual = rows[0]
            if timestamp(actual["time"]) != timestamp(expected["time"]):
                raise ValueError("visible timestamp differs")
            for key, value in expected.items():
                if key == "time":
                    continue
                if key not in actual or actual[key] != value:
                    raise ValueError("visible fields differ")

    def close(self):
        # A process stop is NOT clean stream end. Never flush pending packet buckets.
        for writer in self.writers.values():
            if hasattr(writer, "client"):
                writer.client.close()
