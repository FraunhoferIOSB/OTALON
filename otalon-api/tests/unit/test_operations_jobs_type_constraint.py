"""Regression tests for the ``operations_jobs_type_check`` constraint.

UI-080 records a ``detection_gate_change`` job whenever an operator applies
the "Change detection modes" dialog. ``JobType`` already allowed the value,
but the ``operations_jobs`` DDL did not: the table was created with

    CHECK (type IN ('training','ingest','backup','service','maintenance'))

and ``CREATE TABLE IF NOT EXISTS`` cannot widen a constraint on an
already-deployed volume. Every Apply therefore died with::

    psycopg2.errors.CheckViolation: new row for relation "operations_jobs"
    violates check constraint "operations_jobs_type_check"

which FastAPI's generic handler surfaced as a bare HTTP 500 with no detail,
making the whole feature non-functional. Confirmed live on 2026-08-14.

These tests pin BOTH halves so they cannot drift apart again: the domain
``JobType`` literal and the two DDL definitions (the ``CREATE TABLE`` body
for fresh volumes and the explicit drop/add migration for existing ones).
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import get_args

from otalon_api.domain.operations.job import JobType
from otalon_api.repositories.operations_schema import (
    OPERATIONS_JOBS_TABLE_SQL,
    OPERATIONS_JOBS_TYPE_MIGRATION_SQL,
)

_ALL_TYPES = (
    "training",
    "ingest",
    "backup",
    "service",
    "maintenance",
    "detection_gate_change",
)


def _type_constraint_bodies(source: str) -> list[str]:
    """Return every ``CHECK (type IN (...))`` clause found in a DDL source."""
    return re.findall(r"""CHECK \(type IN \(([^)]*)\)""", source)


def test_job_type_literal_allows_detection_gate_change() -> None:
    """``detection_gate_change`` is the semantically correct job type."""
    assert set(get_args(JobType)) == set(_ALL_TYPES)


def test_create_table_ddl_allows_every_job_type() -> None:
    """A fresh volume must accept every type the domain model allows."""
    bodies = _type_constraint_bodies(OPERATIONS_JOBS_TABLE_SQL)
    assert bodies, "no type constraint found in OPERATIONS_JOBS_TABLE_SQL"
    for body in bodies:
        for job_type in _ALL_TYPES:
            assert f"'{job_type}'" in body, f"{job_type!r} missing from DDL: {body!r}"


def test_migration_rebuilds_the_type_constraint_explicitly() -> None:
    """``CREATE TABLE IF NOT EXISTS`` cannot widen a pre-existing constraint.

    An explicit drop/add is therefore required for already-deployed
    databases; without it the additive type only works on a fresh volume,
    which is exactly how the HTTP 500 reached production.
    """
    assert "DROP CONSTRAINT IF EXISTS operations_jobs_type_check" in OPERATIONS_JOBS_TYPE_MIGRATION_SQL
    assert "ADD CONSTRAINT operations_jobs_type_check" in OPERATIONS_JOBS_TYPE_MIGRATION_SQL
    bodies = _type_constraint_bodies(OPERATIONS_JOBS_TYPE_MIGRATION_SQL)
    assert bodies, "no type constraint found in OPERATIONS_JOBS_TYPE_MIGRATION_SQL"
    for body in bodies:
        for job_type in _ALL_TYPES:
            assert f"'{job_type}'" in body, f"{job_type!r} missing from migration: {body!r}"


def test_migration_runs_during_operations_schema_bootstrap() -> None:
    """The migration must be wired into the bootstrap, not merely defined."""
    schema_module = Path(__file__).resolve().parents[2] / "src" / "otalon_api" / "repositories" / "operations_schema.py"
    source = schema_module.read_text(encoding="utf-8")
    assert "cur.execute(OPERATIONS_JOBS_TYPE_MIGRATION_SQL)" in source


def _normalized_types(body: str) -> list[str]:
    """Return the sorted, whitespace-stripped literals of a CHECK body."""
    return sorted(part.strip() for part in body.split(","))


def test_create_table_and_migration_agree() -> None:
    """Both DDL paths must allow exactly the same set of job types."""
    create_body = _type_constraint_bodies(OPERATIONS_JOBS_TABLE_SQL)[0]
    migration_body = _type_constraint_bodies(OPERATIONS_JOBS_TYPE_MIGRATION_SQL)[0]
    assert _normalized_types(create_body) == _normalized_types(migration_body)
