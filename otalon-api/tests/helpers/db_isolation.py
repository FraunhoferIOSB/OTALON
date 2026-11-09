"""Fail-closed data-isolation contract for destructive integration cleanup.

The operations integration suites (jobs + SSE Wave B) truncate the shared
``operations_jobs`` / ``operations_audit`` tables around every test. Those
tables also hold *live* operator history on the production ``otalon-clas``
database. A previous unguarded autouse cleanup deleted that real history when
the full API suite ran with the ordinary environment (``POSTGRES_DATABASE``
defaulting to ``otalon-clas``).

This module is the single shared guard for every destructive operations
cleanup. Destructive DELETEs may run only when the target database is clearly
disposable:

* its name contains ``test`` (a throwaway test database), OR
* the operator explicitly opts in via ``OPERATIONS_TEST_DB_OK=1``.

The check derives the target database name from the repository's own DSN
rather than re-reading the environment, so it guards the database the cleanup
will actually hit even if the environment and the constructed repository ever
diverge. On a live database the cleanup fixture skips before issuing any DELETE.
"""

from __future__ import annotations

import os
from typing import Any, Protocol

_OPT_IN_ENV = "OPERATIONS_TEST_DB_OK"
_TEST_DB_TOKEN = "test"


class _DsnRepo(Protocol):
    """Minimal repository surface exposing its DSN and an update executor."""

    _dsn: dict[str, Any]

    def _execute_update(self, sql: str, params: dict[str, Any] | None = None) -> int: ...


def target_database_name(repo: _DsnRepo) -> str:
    """Return the database name the repository is wired to.

    Args:
        repo: A repository exposing a ``_dsn`` mapping with a ``dbname`` key.

    Returns:
        The lower-cased target database name, or an empty string when the
        DSN does not declare one.
    """
    dsn = getattr(repo, "_dsn", {}) or {}
    return str(dsn.get("dbname", "")).lower()


def is_disposable_test_db(repo: _DsnRepo) -> bool:
    """Return whether destructive cleanup is permitted for ``repo``'s database.

    Destructive cleanup is permitted only when the repository's target
    database is clearly disposable: an explicit opt-in via the
    ``OPERATIONS_TEST_DB_OK=1`` environment variable, or a database name that
    contains ``test``. Any other database (notably the live ``otalon-clas``)
    is refused so real operator history can never be deleted.

    Args:
        repo: The repository whose target database is being checked.

    Returns:
        ``True`` when destructive cleanup may proceed, ``False`` otherwise.
    """
    if os.environ.get(_OPT_IN_ENV) == "1":
        return True
    return _TEST_DB_TOKEN in target_database_name(repo)


def disposable_db_skip_reason(repo: _DsnRepo) -> str:
    """Return the skip message used when a live database refuses cleanup.

    Args:
        repo: The repository whose target database was refused.

    Returns:
        A human-readable explanation naming the refused database and the
        two ways to opt in.
    """
    name = target_database_name(repo) or "<unknown>"
    return (
        f"Refusing to DELETE operations_audit/operations_jobs on non-test "
        f"database {name!r}. Point POSTGRES_DATABASE at a *test* database "
        f"or set {_OPT_IN_ENV}=1 to opt in explicitly."
    )


def guarded_clean_operations_tables(repo: _DsnRepo) -> None:
    """Truncate the operations tables, but only on a disposable test database.

    This is the one destructive-cleanup implementation shared by the jobs and
    SSE Wave-B integration modules. It fails closed: if the repository's
    database is not clearly disposable it raises before issuing any DELETE, so
    the caller's fixture can convert that into a skip and no live row is ever
    removed.

    Args:
        repo: The repository whose ``operations_audit`` / ``operations_jobs``
            rows should be cleared.

    Raises:
        RuntimeError: If the target database is not a disposable test database.
    """
    if not is_disposable_test_db(repo):
        raise RuntimeError(disposable_db_skip_reason(repo))
    repo._execute_update("DELETE FROM operations_audit")
    repo._execute_update("DELETE FROM operations_jobs")
