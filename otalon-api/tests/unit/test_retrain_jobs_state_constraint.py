"""Regression tests for the ``retrain_jobs.ck_retrain_job_state`` constraint.

API-025 added the additive ``rejected`` state so a cooldown refusal is no
longer recorded as a real ``failed`` run. The ``operations_jobs`` half of
that change shipped with an explicit ``DROP CONSTRAINT`` / ``ADD
CONSTRAINT`` migration, but ``retrain_jobs`` relied on ``CREATE TABLE IF
NOT EXISTS`` alone. On any deployment where otalon-clas had already
created the table with the previous five-state constraint, the create was
a no-op and every cooldown refusal died with::

    psycopg2.errors.CheckViolation: new row for relation "retrain_jobs"
    violates check constraint "ck_retrain_job_state"

Found by the detect-fix-0729 closing gate against the live stack. These
tests pin BOTH DDL definitions — the api-side bootstrap and the canonical
otalon-clas ORM — so the two cannot drift apart again.
"""

from __future__ import annotations

import re
from pathlib import Path

_ALL_STATES = ("queued", "running", "publishing", "succeeded", "failed", "rejected")

_API_REPO = Path(__file__).resolve().parents[2] / "src" / "otalon_api" / "repositories" / "runtime_retrain_repo.py"
_CLAS_ORM = (
    Path(__file__).resolve().parents[3] / "otalon-clas" / "src" / "otalon_clas" / "common" / "postgres_connector.py"
)


def _state_constraint_bodies(source: str) -> list[str]:
    """Return every ``CHECK (state IN (...))`` clause found in a DDL source file.

    Both spellings are covered: the raw-SQL ``CHECK (state IN (...))`` used by
    the api bootstrap and the SQLAlchemy ``CheckConstraint("state IN (...)")``
    used by the otalon-clas ORM. Only constraint definitions are relevant --
    a plain ``WHERE state IN (...)`` filter legitimately lists a subset of the
    states (for example the non-terminal ones used by the single-flight index),
    so matching those too would make the assertion fail on correct code.
    """
    return re.findall(r"""(?:CHECK \(|CheckConstraint\(\s*["'])state IN \(([^)]*)\)""", source)


def test_api_bootstrap_ddl_allows_rejected() -> None:
    """The api-side ``retrain_jobs`` DDL must accept the ``rejected`` state."""
    source = _API_REPO.read_text(encoding="utf-8")
    bodies = _state_constraint_bodies(source)
    assert bodies, "no state constraint found in runtime_retrain_repo.py"
    for body in bodies:
        for state in _ALL_STATES:
            assert f"'{state}'" in body, f"{state!r} missing from api DDL: {body!r}"


def test_api_bootstrap_rebuilds_the_constraint_explicitly() -> None:
    """``CREATE TABLE IF NOT EXISTS`` cannot widen a pre-existing constraint.

    An explicit drop/add is therefore required for already-deployed
    databases; without it the additive state only works on a fresh volume.
    """
    source = _API_REPO.read_text(encoding="utf-8")
    assert "DROP CONSTRAINT IF EXISTS ck_retrain_job_state" in source
    assert "ADD CONSTRAINT ck_retrain_job_state" in source


def test_cyberclas_orm_matches_the_api_state_set() -> None:
    """The canonical owner ORM must allow exactly the same states."""
    source = _CLAS_ORM.read_text(encoding="utf-8")
    bodies = [b for b in _state_constraint_bodies(source) if "queued" in b]
    assert bodies, "no retrain-job state constraint found in postgres_connector.py"
    for body in bodies:
        for state in _ALL_STATES:
            assert f"'{state}'" in body, f"{state!r} missing from otalon-clas ORM: {body!r}"
