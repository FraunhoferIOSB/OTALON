"""Environment variable resolution for JSON configuration structures."""

import json
import math
import os
import re
from enum import Enum
from typing import Any, Final

from loguru import logger


class MissingEnvVarPolicy(str, Enum):
    """Policy controlling behavior when an environment variable is not set.

    Attributes:
        RAISE: Abort loading with a ``RuntimeError`` naming the variable.
        WARN_AND_SKIP: Warn and keep the literal ``$VAR`` placeholder string.
        USE_DEFAULT: Substitute the caller-supplied default value.
        WARN_AND_DROP: Warn and remove the key from its containing mapping so
            the consuming model's field default applies.
        USE_NONE: Resolve to ``None`` without warning. An environment variable
            set to the empty string is treated as unset under this policy.
    """

    RAISE = "raise"
    WARN_AND_SKIP = "warn_and_skip"
    USE_DEFAULT = "use_default"
    WARN_AND_DROP = "warn_and_drop"
    USE_NONE = "use_none"


class _DropSentinel:
    """Marker returned for a key that must be removed from its parent mapping."""


_DROP: Final = _DropSentinel()
"""Signals ``WARN_AND_DROP``: the enclosing dict comprehension filters this out."""

_ESCAPE_PREFIX: Final = "$$"
"""A doubled dollar marks a literal value that must never be looked up."""

_INT_RE = re.compile(r"^[+-]?(0|[1-9][0-9]*)$")
"""Plain decimal integer: no underscores, no redundant leading zeros.

``int()`` accepts both, which silently changed meaning: a file mode
``"0755"`` became ``755`` and a human-grouped ``"1_000"`` became ``1000``.
Where the leading zero is significant the value must stay a string and be
coerced by the consuming model (audit QUA-C4).
"""

_FLOAT_RE = re.compile(
    r"^[+-]?(?:(?:0|[1-9][0-9]*)(?:\.[0-9]*)?|\.[0-9]+)(?:[eE][+-]?[0-9]+)?$"
)
"""Plain decimal float, deliberately excluding ``nan``/``inf``/underscores.

``float()`` accepts ``"nan"``, ``"infinity"`` and ``"-inf"``, so an
environment typo turned into a non-finite number that poisons every later
comparison instead of failing at load time.
"""


def coerce_env_value(
    value: str, json_arrays: bool = False
) -> bool | int | float | str | list[Any] | dict[str, Any]:
    """Convert a raw environment string to the appropriate Python type.

    Coercion order: JSON (opt-in) > bool > int > float > str (stripped). Only
    *plain* decimal numbers are converted; anything else is returned as a
    stripped string so the consuming Pydantic model can coerce (or reject) it
    with the field's real type in hand.

    Deliberately NOT coerced, because ``int()``/``float()`` accept them and
    silently change the value's meaning (audit QUA-C4):

    * leading zeros — ``"0755"`` (a file mode) became ``755``
    * underscores — ``"1_000"`` became ``1000``
    * non-finite floats — ``"nan"``, ``"infinity"``, ``"-inf"``

    Args:
        value: The raw string value to coerce.
        json_arrays: When True, parse values starting with ``[`` or ``{`` as
            JSON, falling back to the stripped string when parsing fails.
            Defaults to False so existing callers keep their behavior.

    Returns:
        The coerced Python value, or the stripped string when no safe
        interpretation exists.
    """
    stripped = value.strip()

    if json_arrays and stripped[:1] in ("[", "{"):
        try:
            parsed: Any = json.loads(stripped)
        except json.JSONDecodeError:
            return stripped
        if isinstance(parsed, (list, dict)):
            return parsed
        return stripped

    lowered = stripped.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False

    if _INT_RE.match(stripped):
        return int(stripped)

    if _FLOAT_RE.match(stripped):
        coerced = float(stripped)
        # Guarded by the regex, but asserted explicitly: a non-finite value
        # must never reach configuration.
        if math.isfinite(coerced):
            return coerced

    return stripped


def resolve_env_placeholders(
    data: Any,
    policy: MissingEnvVarPolicy = MissingEnvVarPolicy.RAISE,
    default: str | None = None,
    json_arrays: bool = False,
    expand_nested: bool = False,
) -> Any:
    """Recursively resolve environment variable placeholders in a data structure.

    Walks a JSON-parsed data structure (dicts, lists, strings) and resolves all
    string values starting with ``$`` via ``os.environ``. Resolved strings are
    coerced to Python types (bool, int, float, str, and optionally list/dict).

    A value starting with ``$$`` is a literal and is returned unchanged without
    an environment lookup.

    Args:
        data: The JSON-parsed structure to walk (dict, list, or scalar).
        policy: Behavior for unset variables (default: RAISE).
        default: Fallback value when policy is USE_DEFAULT and variable is unset.
        json_arrays: Parse resolved values that look like JSON as JSON.
        expand_nested: Apply ``os.path.expandvars`` to the resolved value before
            coercion, so a value may reference further variables.

    Returns:
        The resolved data structure with environment variables substituted.
        Keys whose value was dropped under WARN_AND_DROP are absent.

    Raises:
        RuntimeError: If policy is RAISE and a variable is not set.
    """
    if isinstance(data, dict):
        resolved_items = (
            (
                key,
                resolve_env_placeholders(
                    val, policy, default, json_arrays, expand_nested
                ),
            )
            for key, val in data.items()
        )
        return {
            key: val
            for key, val in resolved_items
            if not isinstance(val, _DropSentinel)
        }

    if isinstance(data, list):
        resolved_list = (
            resolve_env_placeholders(item, policy, default, json_arrays, expand_nested)
            for item in data
        )
        return [item for item in resolved_list if not isinstance(item, _DropSentinel)]

    if isinstance(data, str) and data.startswith("$"):
        if data.startswith(_ESCAPE_PREFIX):
            return data
        return _resolve_placeholder_string(
            data, policy, default, json_arrays, expand_nested
        )

    return data


def _resolve_placeholder_string(
    data: str,
    policy: MissingEnvVarPolicy,
    default: str | None,
    json_arrays: bool,
    expand_nested: bool,
) -> Any:
    """Resolve a single ``$VAR`` placeholder string.

    Args:
        data: The placeholder string, including the leading ``$``.
        policy: The configured missing-variable policy.
        default: Fallback value for USE_DEFAULT policy.
        json_arrays: Parse a resolved JSON-looking value as JSON.
        expand_nested: Expand further ``$`` references in the resolved value.

    Returns:
        The resolved value, or the sentinel/placeholder chosen by the policy.

    Raises:
        RuntimeError: If policy is RAISE and the variable is not set.
    """
    var_name = data[1:]
    env_value = os.environ.get(var_name)

    treat_empty_as_missing = policy == MissingEnvVarPolicy.USE_NONE
    if env_value is None or (treat_empty_as_missing and env_value == ""):
        return _handle_missing_var(data, var_name, policy, default, json_arrays)

    if expand_nested:
        env_value = os.path.expandvars(env_value)
    return coerce_env_value(env_value, json_arrays=json_arrays)


def _handle_missing_var(
    original: str,
    var_name: str,
    policy: MissingEnvVarPolicy,
    default: str | None,
    json_arrays: bool = False,
) -> Any:
    """Handle a missing environment variable according to the configured policy.

    Args:
        original: The original placeholder string (e.g., ``$MISSING_VAR``).
        var_name: The environment variable name.
        policy: The configured missing-variable policy.
        default: Fallback value for USE_DEFAULT policy.
        json_arrays: Parse a JSON-looking default as JSON.

    Returns:
        The resolved value (original placeholder, ``None``, a drop sentinel,
        or the coerced default).

    Raises:
        RuntimeError: If policy is RAISE.
    """
    if policy == MissingEnvVarPolicy.RAISE:
        raise RuntimeError(f"Environment variable '{var_name}' is not set")

    if policy == MissingEnvVarPolicy.WARN_AND_SKIP:
        logger.warning(
            "Environment variable '{}' is not set, keeping placeholder", var_name
        )
        return original

    if policy == MissingEnvVarPolicy.WARN_AND_DROP:
        logger.warning(
            "Environment variable '{}' is not set, using the field default", var_name
        )
        return _DROP

    if policy == MissingEnvVarPolicy.USE_NONE:
        return None

    if default is not None:
        return coerce_env_value(default, json_arrays=json_arrays)
    return original
