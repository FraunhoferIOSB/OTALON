"""Create-only CLAS-owned metadata and transactional historical outcome writes.

No scanner migration, telemetry schema change, or historical last_seen write.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone

from sqlalchemy import JSON, Column, DateTime, Integer, MetaData, String, Table, inspect, select, text
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import AnomalyRecord
from otalon_clas.detection.grouping import _create_alarm_from_anomaly

metadata = MetaData()
batches = Table(
    "continuous_capture_batches",
    metadata,
    Column("source_id", String, primary_key=True),
    Column("batch_id", Integer, primary_key=True),
    Column("schema_version", Integer, nullable=False),
    Column("payload_hash", String, nullable=False),
    Column("registered_at", DateTime(timezone=True), nullable=False),
)
work = Table(
    "continuous_capture_module_work",
    metadata,
    Column("work_id", String, primary_key=True),
    Column("source_id", String, nullable=False),
    Column("module", String, nullable=False),
    Column("batch_id", Integer, nullable=False),
    Column("schema_version", Integer, nullable=False),
    Column("payload_hash", String, nullable=False),
    Column("state", String, nullable=False),
    Column("checkpoint", JSON, nullable=False),
    Column("result", JSON, nullable=False),
    Column("anomaly_links", JSON, nullable=False),
    Column("completed_at", DateTime(timezone=True), nullable=False),
)


class RecoveryRepository:
    def __init__(self, engine, source_id="windows-local"):
        self.engine = engine
        self.source_id = source_id
        with engine.begin() as connection:
            if engine.dialect.name == "postgresql":
                connection.execute(text("SELECT pg_advisory_xact_lock(693069)"))
            metadata.create_all(connection)
            inspector = inspect(connection)
            for table in [batches, work]:
                actual = {c["name"] for c in inspector.get_columns(table.name)}
                if actual != {c.name for c in table.columns}:
                    raise ValueError("incompatible continuous progress schema")

    def completed(self, ident):
        with self.engine.connect() as connection:
            return connection.execute(select(work.c.state).where(work.c.work_id == ident)).scalar() == "persisted"

    def persist(self, payload):
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(encoded.encode()).hexdigest()
        with Session(self.engine) as session, session.begin():
            if self.engine.dialect.name == "postgresql":
                session.execute(text("SELECT pg_advisory_xact_lock(693070)"))
            old = session.execute(select(work).where(work.c.work_id == payload["id"])).mappings().first()
            if old:
                if old["payload_hash"] != digest:
                    raise ValueError("immutable recovery outcome conflict")
                return list(old["anomaly_links"])
            batch_hash = payload.get("batch_hash", hashlib.sha256(str(payload["batch_id"]).encode()).hexdigest())
            old_batch = (
                session.execute(
                    select(batches).where(
                        batches.c.source_id == self.source_id, batches.c.batch_id == payload["batch_id"]
                    )
                )
                .mappings()
                .first()
            )
            if old_batch and old_batch["payload_hash"] != batch_hash:
                raise ValueError("immutable batch conflict")
            if not old_batch:
                session.execute(
                    batches.insert().values(
                        source_id=self.source_id,
                        batch_id=payload["batch_id"],
                        schema_version=1,
                        payload_hash=batch_hash,
                        registered_at=datetime.now(timezone.utc),
                    )
                )
            links = []
            for values in payload["records"]:
                values = dict(values)
                for field in ["start_ts", "end_ts"]:
                    if isinstance(values.get(field), str):
                        values[field] = datetime.fromisoformat(values[field])
                original_id = values["id"]
                values["id"] = (
                    "ccr_"
                    + hashlib.sha256((self.source_id + ":" + payload["id"] + ":" + original_id).encode()).hexdigest()
                )
                values["confirmed"] = False
                values["alarm_id"] = None
                values["is_grouped"] = False
                record = AnomalyRecord(**values)
                old_record = session.get(AnomalyRecord, record.id)
                if old_record is not None:
                    record.confirmed = old_record.confirmed
                    record.alarm_id = old_record.alarm_id
                    record.is_grouped = old_record.is_grouped
                else:
                    alarm = _create_alarm_from_anomaly(record)
                    alarm.id = "cc_" + hashlib.sha256((self.source_id + ":" + str(record.id)).encode()).hexdigest()
                    alarm.enrichment = {
                        "continuous_recovery": {
                            "source": self.source_id,
                            "work": payload["id"],
                            "batch": payload["batch_id"],
                            "result": payload["result"],
                        }
                    }
                    session.add(alarm)
                    session.flush()
                    record.alarm_id = alarm.id
                    record.is_grouped = True
                session.merge(record)
                links.append(str(record.id))
            session.execute(
                work.insert().values(
                    work_id=payload["id"],
                    source_id=self.source_id,
                    module=payload["module"],
                    batch_id=payload["batch_id"],
                    schema_version=1,
                    payload_hash=digest,
                    state="persisted",
                    checkpoint=payload["checkpoint"],
                    result=payload["result"],
                    anomaly_links=links,
                    completed_at=datetime.now(timezone.utc),
                )
            )
            return links
