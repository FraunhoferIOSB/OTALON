"""Retry-safe source-specific recovery outcomes, isolated SQL storage."""

import importlib.util

from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from otalon_clas.common.postgres_connector import Alarm, AnomalyRecord


def test_recovery_progress_and_alarm_write_are_one_transaction(tmp_path):
    assert importlib.util.find_spec("otalon_clas.recovery.repository"), "recovery transactional repository missing"
    from otalon_clas.recovery.repository import RecoveryRepository

    engine = create_engine("sqlite:///" + str(tmp_path / "database"))
    Alarm.__table__.create(engine)
    AnomalyRecord.__table__.create(engine)
    repo = RecoveryRepository(engine)
    payload = {
        "id": "work-1",
        "module": "conn",
        "batch_id": 1,
        "checkpoint": {},
        "result": {"bounds": "evaluated"},
        "records": [],
    }
    repo.persist(payload)
    repo.persist(payload)
    assert repo.completed("work-1")
    with Session(engine) as s:
        from sqlalchemy import text

        assert s.execute(text("SELECT count(*) FROM continuous_capture_module_work")).scalar() == 1
        assert s.execute(text("SELECT count(*) FROM continuous_capture_batches")).scalar() == 1
    bad = dict(payload, result={"bounds": "changed"})
    import pytest

    with pytest.raises(ValueError):
        repo.persist(bad)
