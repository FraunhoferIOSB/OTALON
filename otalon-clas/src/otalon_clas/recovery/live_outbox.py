"""Persist live interval payload before attempting PG; retry canonical live IDs."""

from __future__ import annotations

import hashlib
import json
from datetime import datetime

from loguru import logger

from otalon_clas.common.postgres_connector import AnomalyRecord
from otalon_clas.detection.anomaly_persister import AnomalyPersister, _build_record


class LiveOutboxPersister(AnomalyPersister):
    def __init__(self, connector, progress, **kwargs):
        super().__init__(connector, **kwargs)
        self.progress = progress

    def _upsert_intervals(self, intervals):
        if not intervals:
            return self.retry()
        records = []
        for interval in intervals:
            record = _build_record(interval)
            records.append(
                {
                    column.name: (value.isoformat() if isinstance(value, datetime) else value)
                    for column in record.__table__.columns
                    if (value := getattr(record, column.name)) is not None
                }
            )
        payload = {"records": records}
        ident = "live_" + hashlib.sha256(json.dumps(payload, sort_keys=True, allow_nan=False).encode()).hexdigest()
        self.progress.put_outcome(ident, "__live__", payload)
        return self.retry()

    def retry(self):
        count = 0
        for outcome in self.progress.outcomes(module="__live__"):
            try:
                with self._connector.session() as session:
                    for values in outcome["payload"]["records"]:
                        values = dict(values)
                        for key in ["start_ts", "end_ts"]:
                            values[key] = datetime.fromisoformat(values[key])
                        record = AnomalyRecord(**values)
                        existing = session.get(AnomalyRecord, record.id)
                        if existing is not None:
                            record.alarm_id = existing.alarm_id
                            record.is_grouped = existing.is_grouped
                            record.confirmed = existing.confirmed
                        session.merge(record)
                self.progress.ack_outcome(outcome["id"])
                count += len(outcome["payload"]["records"])
            except Exception as exc:
                logger.error("Live persistence backlog retained: {}", type(exc).__name__)
                break
        return count
