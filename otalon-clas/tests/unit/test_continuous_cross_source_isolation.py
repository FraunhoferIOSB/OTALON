"""Live cross-source enrichment cannot consume historical replay evidence."""

from datetime import datetime, timedelta, timezone

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord
from otalon_clas.detection.cross_source import _load_anomalies, _load_conn_involved_alarms


def test_live_cross_source_loaders_exclude_recovery_namespaces(tmp_path):
    engine = create_engine("sqlite:///" + str(tmp_path / "db"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    stamp = datetime.now(timezone.utc)
    with Session(engine) as session, session.begin():
        for ident in ["cc_owned", "live-owned"]:
            session.add(
                Alarm(
                    id=ident,
                    module="conn",
                    start_timestamp=stamp,
                    end_timestamp=stamp,
                    series_ids=["a/b///////Ethernet:ARP"],
                )
            )
        for ident in ["ccr_owned", "live-anomaly"]:
            session.add(
                AnomalyRecord(
                    id=ident,
                    module="mac_traffic",
                    series_id="a",
                    anomaly_type="bound",
                    start_ts=stamp,
                    end_ts=stamp,
                    violated_features=[],
                    is_anomaly=True,
                )
            )
    with Session(engine) as session:
        assert [r.alarm_id for r in _load_conn_involved_alarms(session, None, None)] == ["live-owned"]
        assert [
            r.anomaly_id
            for r in _load_anomalies(session, "mac_traffic", stamp - timedelta(seconds=1), stamp + timedelta(seconds=1))
        ] == ["live-anomaly"]
