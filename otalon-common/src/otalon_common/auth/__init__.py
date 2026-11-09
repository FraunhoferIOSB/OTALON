"""Shared API-key and product-identity authentication primitives."""

from otalon_common.auth.api_key import (
    KeyEntry,
    KeyRegistry,
    KeyRole,
    OnMissing,
    constant_time_equals,
    parse_allowed_keys,
)
from otalon_common.auth.password import (
    dummy_password_hash,
    hash_password,
    verify_password,
)
from otalon_common.auth.user_role import UserRole

__all__ = [
    "KeyEntry",
    "KeyRegistry",
    "KeyRole",
    "OnMissing",
    "UserRole",
    "constant_time_equals",
    "dummy_password_hash",
    "hash_password",
    "parse_allowed_keys",
    "verify_password",
]
