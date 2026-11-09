"""Tests for product-user roles and Argon2id password helpers."""

from __future__ import annotations

from otalon_common.auth import UserRole, hash_password, verify_password


def test_user_role_is_separate_product_role_enum() -> None:
    """Product roles include admin without changing machine-key roles."""
    assert [role.value for role in UserRole] == ["admin", "operator", "viewer"]


def test_argon2id_hash_verifies_and_rejects_wrong_password() -> None:
    """Argon2id accepts the source password and rejects a different one."""
    password_hash = hash_password("correct-password")
    assert password_hash.startswith("$argon2id$")
    assert verify_password("correct-password", password_hash)
    assert not verify_password("wrong-password", password_hash)
