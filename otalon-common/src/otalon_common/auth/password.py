"""Argon2id password hashing primitives for product identities."""

from __future__ import annotations

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

_PASSWORD_HASHER = PasswordHasher()
_DUMMY_PASSWORD_HASH = (
    "$argon2id$v=19$m=65536,t=3,p=4$"
    "3v/FWvSspCL8RAF0TuOg4A$"
    "m/CMaG7vcyTPFOrgQSxE7zmfqvx5iSlBl1exRgVcGKM"
)


def hash_password(password: str) -> str:
    """Return an Argon2id encoded hash for ``password``.

    Args:
        password: Plaintext password supplied by a product user.

    Returns:
        Argon2id encoded password hash.
    """
    return _PASSWORD_HASHER.hash(password)


def verify_password(password: str, password_hash: str) -> bool:
    """Verify ``password`` through Argon2's constant-time verifier.

    Args:
        password: Plaintext password supplied by a product user.
        password_hash: Argon2 encoded password hash.

    Returns:
        ``True`` when Argon2 accepts the password, otherwise ``False``.
    """
    try:
        return _PASSWORD_HASHER.verify(password_hash, password)
    except (InvalidHashError, VerificationError, VerifyMismatchError):
        return False


def dummy_password_hash() -> str:
    """Return a valid dummy hash for uniform unknown-user verification."""
    return _DUMMY_PASSWORD_HASH
