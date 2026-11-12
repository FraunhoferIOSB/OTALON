"""Bounded source-driven recovery using existing detector and post-processing code.

A historical monitor is never the live monitor. Missing context/artifacts remain
explicitly unevaluated in the durable outcome, rather than fabricated coverage.
"""

from __future__ import annotations

import hashlib
import threading
from copy import copy
from datetime import datetime

import polars as pl
from loguru import logger

from .context import isolated_frequency, isolated_preprocessor


class RecoveryWorker:
    def __init__(self, bundles, progress, repository, pipeline, runtime_config=None, persistence_policy=None):
        self.bundles = list(bundles)
        self._next_module = 0
        self.progress = progress
        self.repository = repository
        self.pipeline = pipeline
        self.runtime_config = runtime_config
        self.persistence_policy = persistence_policy
        self.stop_event = threading.Event()
        self.thread = None

    def process_one(self):
        from otalon_clas.detection.anomaly_persister import AnomalyPersister, _build_record, _filter_anomalous
        from otalon_clas.main import _detect, _resolve_live_detection_gates

        order = self.bundles[self._next_module :] + self.bundles[: self._next_module]
        for live in order:
            self._next_module = (self.bundles.index(live) + 1) % len(self.bundles)
            task = self.progress.next_work(live.config.name)
            if task is None:
                continue
            batch = task["batch"]
            module = live.config.name
            ident = hashlib.sha256(
                (self.repository.source_id + ":" + module + ":" + str(batch["id"]) + ":" + task["hash"]).encode()
            ).hexdigest()
            pending = next((o for o in self.progress.outcomes() if o["id"] == ident), None)
            if pending is not None:
                payload = pending["payload"]
            else:
                bundle = copy(live)
                bundle.freq_monitor = isolated_frequency(live.freq_monitor)
                # Separate mutable preprocessing maps/rolling state from the live reader.
                bundle.preprocessor = isolated_preprocessor(live.preprocessor)
                snapshot = live.model_snapshot()
                if snapshot and hasattr(bundle.preprocessor, "load_protocol_map"):
                    bundle.preprocessor.load_protocol_map(snapshot.protocol_map or {}, lock=True)
                raw_records = []
                for part in batch["payload"]:
                    if part["measurement"] == live.config.measurement:
                        raw_records.extend(part["records"])
                state = {"version": 1, "last_batch": batch["id"]}
                result = {
                    "bounds": "not_applicable",
                    "frequency": "not_applicable",
                    "classification": "not_applicable",
                    "historical_absence": "not_evaluated",
                    "context": "source-qualified",
                }
                records = []
                if raw_records:
                    current = (
                        pl.DataFrame(raw_records)
                        .with_columns(pl.col("time").str.to_datetime(time_zone="UTC"))
                        .sort("time")
                    )
                    window = getattr(bundle.preprocessor, "get_window_seconds", lambda: 0)()
                    from datetime import timedelta

                    context_start = (current["time"].min() - timedelta(seconds=max(window, 60))).isoformat()
                    previous = self.progress.previous_records(
                        module, live.config.measurement, batch["id"] - 1, start_time=context_start
                    )
                    if previous:
                        past = (
                            pl.DataFrame(previous)
                            .with_columns(pl.col("time").str.to_datetime(time_zone="UTC"))
                            .sort("time")
                        )
                        # Only historical rows can seed historical last_seen.
                        for series in past[live.config.tag_key].unique().to_list():
                            profile = bundle.freq_monitor._profiles.get(series)
                            if profile is not None:
                                profile.last_seen = past.filter(pl.col(live.config.tag_key) == series)["time"].max()
                        window = getattr(bundle.preprocessor, "get_window_seconds", lambda: 0)()
                        if window:
                            from datetime import timedelta

                            past = past.filter(pl.col("time") >= current["time"].min() - timedelta(seconds=window))
                            context = pl.concat([past, current], how="diagonal_relaxed")
                        else:
                            context = current
                    else:
                        context = current
                    processed = bundle.preprocessor.preprocess_for_prediction(context)
                    if not processed.is_empty():
                        processed = processed.filter(pl.col("time") >= current["time"].min())
                    if processed.is_empty():
                        raise ValueError("nonempty batch produced no detector rows")
                    now = current["time"].max().isoformat()
                    gates = (
                        _resolve_live_detection_gates(self.runtime_config, self.bundles)
                        if self.runtime_config
                        else None
                    )
                    frequency_context = pl.concat([past, current], how="diagonal_relaxed") if previous else current
                    outcome = _detect(bundle, processed, frequency_context, now, gates)
                    result.update(
                        bounds="evaluated",
                        frequency="evaluated" if bundle.freq_monitor._profiles else "context_missing",
                        classification="evaluated" if snapshot is not None else "artifact_missing",
                    )
                    if gates:
                        if not gates.bounds_enabled[module]:
                            result["bounds"] = "operator_disabled"
                        if not gates.frequency_enabled.get(module, True):
                            result["frequency"] = "operator_disabled"
                        if not gates.classification_enabled[module]:
                            result["classification"] = "operator_disabled"
                    post = self.pipeline.run(outcome.fused)
                    persister = self.persistence_policy or AnomalyPersister(None)
                    anomalies = persister._apply_suppression_and_lowsignal_gate(
                        _filter_anomalous(post), live.config.tag_key
                    )
                    if not anomalies.is_empty():
                        for interval in persister._split_into_intervals(anomalies, module, live.config.tag_key):
                            record = _build_record(interval)
                            records.append(
                                {
                                    column.name: (value.isoformat() if isinstance(value, datetime) else value)
                                    for column in record.__table__.columns
                                    if (value := getattr(record, column.name)) is not None
                                }
                            )
                payload = {
                    "id": ident,
                    "module": module,
                    "batch_id": batch["id"],
                    "batch_hash": task["hash"],
                    "checkpoint": state,
                    "result": result,
                    "records": records,
                }
                self.progress.put_outcome(ident, module, payload)
            links = self.repository.persist(payload)
            self.progress.complete(module, batch["id"], payload["checkpoint"], links, payload["result"])
            self.progress.ack_outcome(ident)
            return True
        return False

    def start(self):
        if self.thread is not None:
            raise ValueError("recovery worker already started")

        def loop():
            while not self.stop_event.is_set():
                worked = False
                try:
                    worked = self.process_one()
                except Exception as exc:
                    logger.error("Continuous recovery blocked: {}", type(exc).__name__)
                self.stop_event.wait(0.1 if worked else 1)

        self.thread = threading.Thread(target=loop, name="continuous-recovery", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=15)
