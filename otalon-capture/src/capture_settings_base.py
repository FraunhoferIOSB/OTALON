"""Shared settings base for the three otalon-capture packages.

``otalon_capture``, ``pcap_import`` and ``pcap_recorder`` ship from this one
subproject and configure themselves identically: ``config/*.json`` with
``$ENV_VAR`` placeholders, a missing variable being a hard error. Before
SUITE-038 each package carried its own byte-similar copy of the resolver.

This module pins that policy once so the three settings classes only declare
their fields and their ``extra`` mode. It also models the operator credential
shared by the two HTTP surfaces of this subproject (PCAP-007), which the
recorder and the import worker used to read — and parse — twice.
"""

from __future__ import annotations

import hmac
import os
from pathlib import Path
from typing import Self, Union

from otalon_common.config import BaseSettings, MissingEnvVarPolicy
from pydantic import ConfigDict, SecretStr

JsonPath = Union[str, Path]

ALLOWED_KEYS_ENV_VAR = "OTALON_API_ALLOWED_KEYS"
"""Suite-wide ``<name>:<role>:<key>`` credential list."""

ADMIN_API_KEY_ENV_VAR = "ADMIN_API_KEY"
"""Suite-wide administrator credential, accepted as an operator key."""

OPERATOR_ROLE = "operator"
"""The only role in :data:`ALLOWED_KEYS_ENV_VAR` this subproject authorizes."""


class CaptureBaseSettings(BaseSettings):
    """Base settings for otalon-capture packages.

    Pins the subproject-wide loader policy: a missing environment variable
    raises, JSON-looking values are parsed as JSON, and nested ``$``
    references inside a resolved value are expanded — all three matching the
    behaviour of the per-package resolvers this class replaces.
    """

    @classmethod
    def from_json(
        cls,
        path: JsonPath,
        env_policy: MissingEnvVarPolicy = MissingEnvVarPolicy.RAISE,
        default: str | None = None,
        json_arrays: bool = True,
        expand_nested: bool = True,
    ) -> Self:
        """Load configuration from ``path`` and resolve environment placeholders.

        Args:
            path: Path to the JSON configuration file.
            env_policy: Policy for missing variables; RAISE by default.
            default: Fallback value when env_policy is USE_DEFAULT.
            json_arrays: Parse JSON-looking values as JSON.
            expand_nested: Expand nested ``$`` references in resolved values.

        Returns:
            A validated settings instance.

        Raises:
            RuntimeError: If a referenced environment variable is not set.
        """
        return super().from_json(
            path,
            env_policy=env_policy,
            default=default,
            json_arrays=json_arrays,
            expand_nested=expand_nested,
        )


def encode_api_key(value: str) -> bytes:
    """Return ``value`` as bytes suitable for a constant-time comparison.

    ``hmac.compare_digest`` refuses ``str`` operands that hold a non-ASCII
    character (``TypeError: comparing strings with non-ASCII characters is
    not supported``). Starlette decodes request headers as latin-1, so any
    byte above 0x7F in ``X-API-Key`` produced such a string and crashed the
    dependency with a 500 instead of answering 401 (audit V4).

    Encoding both operands the same way keeps every input comparable
    without discarding information and without short-circuiting on length,
    so the comparison remains constant-time for equal-length candidates.

    Args:
        value: The supplied or configured key as decoded by Starlette.

    Returns:
        The UTF-8 encoding of ``value``; lone surrogates are preserved.
    """

    return value.encode("utf-8", "surrogateescape")


def _parse_allowed_keys(configured: str) -> list[str]:
    """Extract the operator keys from a ``<name>:<role>:<key>`` list.

    Args:
        configured: Raw comma-separated credential list.

    Returns:
        The keys of every entry carrying the operator role, empty values
        excluded so a truncated entry cannot authorize an empty header.
    """

    keys: list[str] = []
    for entry in configured.split(","):
        parts = entry.strip().split(":", 2)
        if len(parts) == 3 and parts[1] == OPERATOR_ROLE and parts[2]:
            keys.append(parts[2])
    return keys


class OperatorAuthSettings(CaptureBaseSettings):
    """Operator credentials accepted by this subproject's HTTP surfaces.

    Both ``pcap_recorder`` and ``pcap_import`` gate their mutating and
    status routes on the suite ``X-API-Key`` operator credential. Each used
    to read *and re-parse* ``OTALON_API_ALLOWED_KEYS`` plus ``ADMIN_API_KEY``
    inline, so the two copies were free to drift — and had (PCAP-007).

    Attributes:
        operator_keys: Every credential authorized as an operator. Empty
            means *no* credential is configured, which the callers must
            answer with ``503`` rather than by admitting the request.
    """

    # Declared explicitly: the shared base forbids extra keys, while the
    # otalon-capture policy row is ``extra="ignore"`` (SUITE-038).
    model_config = ConfigDict(extra="ignore")

    operator_keys: tuple[SecretStr, ...] = ()

    @classmethod
    def from_env(cls) -> Self:
        """Resolve the operator credentials from the process environment.

        Deliberately not sourced from ``config/*.json``: this subproject
        loads its config under ``MissingEnvVarPolicy.RAISE``, so a
        placeholder for an unset credential would turn today's fail-closed
        ``503`` into a boot crash, and a tracked config file is the wrong
        home for key material. This is the ONE raw read of the pair in the
        subproject; the parsing behind it is shared (PCAP-007).

        Returns:
            Settings carrying every configured operator credential.
        """

        keys: list[str] = []
        admin_key = os.environ.get(ADMIN_API_KEY_ENV_VAR)
        if admin_key:
            keys.append(admin_key)
        keys.extend(_parse_allowed_keys(os.environ.get(ALLOWED_KEYS_ENV_VAR, "")))
        deduplicated = list(dict.fromkeys(keys))
        return cls(operator_keys=tuple(SecretStr(key) for key in deduplicated))

    @property
    def is_configured(self) -> bool:
        """Whether any operator credential is available at all."""

        return bool(self.operator_keys)

    def matches(self, supplied: str) -> bool:
        """Check ``supplied`` against every configured credential.

        Args:
            supplied: The raw ``X-API-Key`` header value.

        Returns:
            ``True`` when the value equals one of the configured keys.
        """

        candidate = encode_api_key(supplied)
        # Compared as bytes, matching the recorder's pre-PCAP-007 behaviour:
        # ``hmac.compare_digest`` raises TypeError on str operands holding a
        # non-ASCII character and Starlette decodes headers as latin-1, so two
        # crafted bytes in the header turned a failed authentication into an
        # unhandled 500 (audit V4/QUA-C5). Each comparison stays constant-time.
        return any(hmac.compare_digest(candidate, encode_api_key(key.get_secret_value())) for key in self.operator_keys)
