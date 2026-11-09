"""Domain-scoped destructive reset executor behind fail-closed safety gates.

Each named domain scope maps to a *narrow* allowlisted PostgreSQL operation
(``delete_all_rows`` on a single allowlisted table). The executor never issues a
free-form ``DELETE``/``TRUNCATE``/``DROP`` and never touches a table outside the
existing ``postgres_repo.DB_TABLE_ALLOWLIST``. A ``factory`` reset additionally
requires a fresh, verified backup precondition.

Safety posture (WAVE F): destructive execution is only reached from a request
that supplies the exact typed confirmation phrase and (for factory) passes the
stale-backup gate, and ``dry_run`` defaults to ``True`` so the live unattended
run only ever exercises the precheck/rejection paths. Tests inject a fake
repository to prove that a correctly confirmed, non-dry-run request invokes ONLY
the mapped narrow table operation.
"""

from __future__ import annotations

from typing import Any, Protocol


class SupportsNarrowReset(Protocol):
    """Minimal repository surface the reset executor is allowed to call."""

    def delete_all_rows(self, table_name: str) -> int:
        """Delete all rows from a single allowlisted table and return the count."""
        ...

    def delete_all_rows_batch(self, table_names: tuple[str, ...]) -> dict[str, int]:
        """Delete allowlisted tables atomically and return row counts."""
        ...


# Domain scope → ordered tuple of narrow allowlisted tables. Every table here
# MUST be a member of ``postgres_repo.DB_TABLE_ALLOWLIST``; the repository
# re-checks membership and raises otherwise, so this mapping cannot widen the
# blast radius. ``factory`` is intentionally the union of the data scopes and is
# additionally guarded by the stale-backup precondition in the router.
#
# Scope names are operator-facing and MUST describe what is actually deleted.
# The ``detection-results`` scope clears the PostgreSQL ``anomalies`` table
# (detected-anomaly event records). It is deliberately NOT named ``timeseries``:
# the raw network time-series lives in InfluxDB (``network_metrics`` and
# siblings), which this PG-table-only reset surface never touches — an operator
# who wanted to purge captured time-series would otherwise be misled into wiping
# detection results instead (F-AUDIT-01).
_SCOPE_TABLES: dict[str, tuple[str, ...]] = {
    "anomaly-history": ("anomalies", "alarms"),
    "trained-bounds": ("bounds",),
    "detection-results": ("anomalies",),
    "factory": ("anomalies", "alarms", "bounds"),
}


class OperationsResetService:
    """Execute domain-scoped resets only through narrow allowlisted operations."""

    def __init__(self, repo: SupportsNarrowReset) -> None:
        """Initialize with a repository exposing only the narrow reset surface."""
        self._repo = repo

    @staticmethod
    def scopes() -> tuple[str, ...]:
        """Return the supported domain reset scopes."""
        return tuple(_SCOPE_TABLES)

    @staticmethod
    def required_phrase(scope: str) -> str:
        """Return the exact typed confirmation phrase for a scope."""
        return f"RESET {scope.upper()}"

    def tables_for(self, scope: str) -> tuple[str, ...]:
        """Return the narrow tables a scope maps to."""
        if scope not in _SCOPE_TABLES:
            raise ValueError(f"Unsupported reset scope: {scope}")
        return _SCOPE_TABLES[scope]

    def preview(self, scope: str, backup: dict[str, Any] | None = None) -> dict[str, Any]:
        """Describe PostgreSQL reset impact without opening a write path."""
        tables = self.tables_for(scope)
        backup_ok = bool(backup and backup.get("verified") and not backup.get("stale"))
        return {
            "target": "postgresql",
            "scope": scope,
            "tables": list(tables),
            "destructive": True,
            "execution_supported": True,
            "requires_fresh_full_backup": scope == "factory",
            "backup_compatible": backup_ok if scope == "factory" else None,
            "executed": False,
        }

    def execute(self, scope: str, confirmation: str, dry_run: bool = True) -> dict[str, Any]:
        """Run the mapped narrow reset behind the typed-confirmation gate.

        Args:
            scope: A supported domain reset scope.
            confirmation: The operator-supplied typed confirmation phrase.
            dry_run: When ``True`` (default) nothing is deleted; the plan is
                returned so the live unattended run stays non-destructive.

        Returns:
            A result dict describing the (planned or executed) narrow operations.

        Raises:
            ValueError: For an unknown scope or an incorrect confirmation phrase.
        """
        tables = self.tables_for(scope)
        phrase = self.required_phrase(scope)
        if confirmation != phrase:
            raise ValueError(f"Typed confirmation must be '{phrase}'")
        if dry_run:
            return {
                "executed": False,
                "scope": scope,
                "tables": list(tables),
                "deleted": {},
            }
        deleted = self._repo.delete_all_rows_batch(tables)
        return {
            "executed": True,
            "scope": scope,
            "tables": list(tables),
            "deleted": deleted,
        }
