"""Human product-user roles, separate from machine API-key roles."""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    """Authorization roles supported by product users."""

    ADMIN = "admin"
    OPERATOR = "operator"
    VIEWER = "viewer"
