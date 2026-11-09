"""Typed exceptions raised by :mod:`otalon_scan.repositories.postgres_repo`.

Introduced by F-03 (``refactor-otalon-scan-device-network-ownership-v1``)
to host repository-layer error types that need to be importable
independently of the (large) ``postgres_repo`` module. F-01's
:class:`~otalon_scan.repositories.postgres_repo.ParentRowMissingError` continues
to live in :mod:`postgres_repo` for backwards compatibility with existing
imports; new typed exceptions land here.
"""

from __future__ import annotations


class IdentityCollisionError(Exception):
    """Raised by :meth:`ScannerPostgresRepo.upsert_network_interface` when an
    identity column (``ipv4`` / ``ipv6``) in the call collides with a UNIQUE
    constraint on a *different* existing row than the one the helper chose
    as its ``ON CONFLICT`` target.

    The conflict target of ``INSERT … ON CONFLICT … DO UPDATE`` is a single
    UNIQUE index (the helper picks ``mac`` > ``ipv4`` > ``ipv6`` based on
    which identity column is non-NULL in the call). If the call's ``ipv4``
    or ``ipv6`` value already belongs to *another* row whose ``mac`` is
    different from the call's ``mac`` (so the chosen conflict target does
    not catch it), PostgreSQL raises a UNIQUE violation for one of the
    other constraints (``uq_iface_ipv4`` or ``uq_iface_ipv6``). The helper
    catches that ``IntegrityError`` and re-raises it as this typed
    exception so callers can react meaningfully instead of having to parse
    raw driver errors.

    Rare in practice — it only occurs when an IP address that used to be
    bound to one MAC has been re-observed on another physical interface
    (e.g. NAT swap, replaced hardware). Operator-resolved.

    Attributes:
        message: Human-readable message naming both rows and the
            conflicting identity column.
        conflict_column: Identity column that triggered the collision
            (``"ipv4"`` or ``"ipv6"``).
        conflict_value: The value the helper tried to write.
        existing_row_id: PK of the existing row that already holds
            ``conflict_value`` (when extractable).
    """

    def __init__(
        self,
        *,
        message: str,
        conflict_column: str | None = None,
        conflict_value: str | None = None,
        existing_row_id: int | None = None,
    ) -> None:
        """Initialise an identity-collision error.

        Args:
            message: Human-readable description identifying both rows
                and the conflicting identity column.
            conflict_column: ``"ipv4"`` / ``"ipv6"`` (when extractable
                from the original ``IntegrityError``); ``None`` otherwise.
            conflict_value: The value that triggered the collision.
            existing_row_id: PK of the offending existing row (when
                determinable); ``None`` if not resolvable from the error.
        """
        super().__init__(message)
        self.conflict_column = conflict_column
        self.conflict_value = conflict_value
        self.existing_row_id = existing_row_id
