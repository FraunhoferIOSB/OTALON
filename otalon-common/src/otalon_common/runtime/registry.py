"""Dependency-free registry of hot-reconfigurable runtime-configuration keys.

The registry is the single source of truth for which ``(service, key)`` pairs
may be written to the shared ``runtime_config`` table, which value type each
pair carries, and which validator its value must satisfy. It holds validation
logic only: no database driver, ORM, or web framework is imported here, so
otalon-common keeps its documented "no DB/web deps" contract. Data access
against ``runtime_config`` stays the responsibility of each consuming service.

Error messages raised by the validators and by :func:`validate_write` are a
hard cross-subproject contract: the otalon-clas repository tests match on the
substrings ``secret-looking``, ``allow-list``, ``boolean literal``, ``float``,
and ``in (0, 0.5]``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Callable, Literal

RuntimeValueType = Literal["bool", "int", "float", "str", "list"]
"""Value types a runtime-configuration key may declare."""

Validator = Callable[[str], None]
"""Callable that raises :class:`ValueError` when a string value is invalid."""

_SECRET_PATTERNS: tuple[str, ...] = ("TOKEN", "PASSWORD", "_KEY", "_SECRET")


class ListEntryValidationError(ValueError):
    """A ``list``-typed runtime value with an invalid array entry.

    The message carries the 0-based entry index in the ``entry[N]: …``
    form. It is a distinct class (still a :class:`ValueError`, so every
    existing ``except ValueError`` path keeps working) so the API can
    map entry-level failures to HTTP 422 while structural failures stay
    on their existing 400 semantics (CLAS-071 design D10).
    """


_BOOL_TRUE: frozenset[str] = frozenset({"true", "1", "yes", "on"})
_BOOL_FALSE: frozenset[str] = frozenset({"false", "0", "no", "off"})
_BOOL_LITERALS: frozenset[str] = _BOOL_TRUE | _BOOL_FALSE


def _format_bound(value: float) -> str:
    """Render an interval bound without a redundant trailing ``.0``."""
    if float(value).is_integer():
        return str(int(value))
    return str(value)


@dataclass(frozen=True)
class BoolLiteralValidator:
    """Validator accepting the recognized boolean literals only."""

    def __call__(self, value: str) -> None:
        """Raise :class:`ValueError` when *value* is not a boolean literal."""
        if str(value).strip().lower() not in _BOOL_LITERALS:
            raise ValueError(f"expected a boolean literal, got {value!r}")


@dataclass(frozen=True)
class IntRangeValidator:
    """Validator accepting integers within an inclusive ``[lo, hi]`` range."""

    lo: int
    hi: int

    @property
    def domain(self) -> str:
        """Return the human-readable interval notation of this range."""
        return f"[{self.lo}, {self.hi}]"

    def __call__(self, value: str) -> None:
        """Raise :class:`ValueError` when *value* is not an integer in range."""
        try:
            parsed = int(str(value).strip())
        except (TypeError, ValueError) as exc:
            raise ValueError(f"expected an integer, got {value!r}") from exc
        if not self.lo <= parsed <= self.hi:
            raise ValueError(f"expected an integer in {self.domain}, got {parsed}")


@dataclass(frozen=True)
class FloatIntervalValidator:
    """Validator accepting floats in ``(lo, hi]`` or ``(lo, hi)``.

    The lower bound is always exclusive, matching the quantile semantics of
    the original otalon-clas ``_validate_quantile``.
    """

    lo: float
    hi: float
    inclusive_hi: bool = True

    @property
    def domain(self) -> str:
        """Return the human-readable interval notation of this interval."""
        closing = "]" if self.inclusive_hi else ")"
        return f"({_format_bound(self.lo)}, {_format_bound(self.hi)}{closing}"

    def __call__(self, value: str) -> None:
        """Raise :class:`ValueError` when *value* is not a float in interval."""
        try:
            parsed = float(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"expected a float, got {value!r}") from exc
        upper_ok = parsed <= self.hi if self.inclusive_hi else parsed < self.hi
        if not (parsed > self.lo and upper_ok):
            raise ValueError(f"expected a float in {self.domain}, got {parsed}")


def bool_literal() -> BoolLiteralValidator:
    """Return a validator accepting boolean literals such as ``true``/``0``."""
    return BoolLiteralValidator()


def int_range(lo: int, hi: int) -> IntRangeValidator:
    """Return a validator accepting integers in the inclusive range ``[lo, hi]``."""
    if lo > hi:
        raise ValueError(f"int_range requires lo <= hi, got lo={lo}, hi={hi}")
    return IntRangeValidator(lo=lo, hi=hi)


def float_interval(
    lo: float, hi: float, *, inclusive_hi: bool = True
) -> FloatIntervalValidator:
    """Return a validator accepting floats in ``(lo, hi]`` or ``(lo, hi)``."""
    if lo >= hi:
        raise ValueError(f"float_interval requires lo < hi, got lo={lo}, hi={hi}")
    return FloatIntervalValidator(lo=lo, hi=hi, inclusive_hi=inclusive_hi)


@dataclass(frozen=True)
class RuntimeKeyDeclaration:
    """Validator-free declarative view of a runtime-configuration key.

    This is the shape the static manifest publishes and the shape the
    manifest/registration drift tests compare, because a validator instance
    cannot be expressed as static data.
    """

    service: str
    key: str
    value_type: RuntimeValueType
    domain: str | None
    description: str


@dataclass(frozen=True)
class RuntimeKeySpec:
    """Specification of one hot-reconfigurable ``(service, key)`` pair."""

    service: str
    key: str
    value_type: RuntimeValueType
    validator: Validator
    domain: str | None
    description: str

    def validate(self, value: str) -> None:
        """Run this key's validator against *value*."""
        self.validator(value)

    def declaration(self) -> RuntimeKeyDeclaration:
        """Return the validator-free declarative view of this specification."""
        return RuntimeKeyDeclaration(
            service=self.service,
            key=self.key,
            value_type=self.value_type,
            domain=self.domain,
            description=self.description,
        )


_REGISTRY: dict[tuple[str, str], RuntimeKeySpec] = {}


def register(spec: RuntimeKeySpec) -> None:
    """Register *spec*, idempotently for an identical specification.

    Args:
        spec: Specification of the ``(service, key)`` pair to register.

    Raises:
        ValueError: When the same ``(service, key)`` is already registered
            with a conflicting specification.
    """
    identity = (spec.service, spec.key)
    existing = _REGISTRY.get(identity)
    if existing is None:
        _REGISTRY[identity] = spec
        return
    if existing != spec:
        raise ValueError(
            f"runtime_config key ({spec.service!r}, {spec.key!r}) is already "
            f"registered with a conflicting specification"
        )


def lookup(service: str, key: str) -> RuntimeKeySpec | None:
    """Return the specification for ``(service, key)`` or ``None``."""
    return _REGISTRY.get((service, key))


def all_specs() -> tuple[RuntimeKeySpec, ...]:
    """Return every registered specification ordered by service and key."""
    return tuple(sorted(_REGISTRY.values(), key=lambda spec: (spec.service, spec.key)))


def reset_registry() -> None:
    """Drop every registration.

    Provided for test isolation; production code registers once at startup.
    """
    _REGISTRY.clear()


def is_secret_key(key: str) -> bool:
    """Return ``True`` when *key* matches a secret-deny pattern.

    Callable independently of any registration so that every consumer can run
    the deny-check **before** consulting the registry, which prevents a secret
    key from becoming writable by being registered.
    """
    upper = key.upper()
    return any(pattern in upper for pattern in _SECRET_PATTERNS)


def validate_write(service: str, key: str, value: str) -> RuntimeKeySpec:
    """Validate a runtime-config write in the contractual order.

    The order is secret deny-list, then registry allow-list, then the key's
    domain validator. No caller-visible side effect happens before all three
    checks pass.

    Args:
        service: Owning service of the key.
        key: Runtime-configuration key name.
        value: Candidate value in its string representation.

    Returns:
        The registered specification of the validated key.

    Raises:
        ValueError: When *key* looks like a secret, is not registered, or
            *value* fails the key's domain validator.
    """
    if is_secret_key(key):
        raise ValueError(
            f"Refusing to persist secret-looking runtime_config key: {key!r}"
        )
    spec = lookup(service, key)
    if spec is None:
        raise ValueError(
            f"runtime_config key ({service!r}, {key!r}) is not in the v1 allow-list; arbitrary keys are rejected"
        )
    spec.validate(str(value))
    if spec.value_type == "list":
        _require_string_array(spec, value)
    return spec


def _require_string_array(spec: RuntimeKeySpec, value: str) -> None:
    """Raise :class:`ValueError` when a list value is not a JSON string array.

    The per-key validator already ran (it raises
    :class:`ListEntryValidationError` per invalid entry); this guard
    keeps :func:`validate_write` honest on the structural layer even if
    a future list key happens to be registered with a validator that
    trusts its input.
    """
    try:
        parsed = json.loads(value)
        if not isinstance(parsed, list):
            raise ValueError("not an array")
        if any(not isinstance(element, str) for element in parsed):
            raise ValueError("non-string element")
    except ValueError as exc:
        raise ValueError(
            f"value of list-typed runtime_config key {spec.key!r} must be a JSON array of strings"
        ) from exc


def normalize_value(service: str, key: str, value: str) -> str:
    """Validate and return the canonical persisted representation of a value."""
    spec = validate_write(service, key, value)
    normalized = str(value).strip().lower()
    if spec.value_type == "bool":
        return "true" if normalized in _BOOL_TRUE else "false"
    if spec.value_type == "list":
        return _canonicalize_list_value(value)
    return str(value)


def _canonicalize_list_value(value: str) -> str:
    """Return the canonical compact JSON text of a validated list value.

    A ``list`` key persists as the compact JSON serialization
    (``separators=(",", ":")``) of its stripped, lowercased string
    array, de-duplicated preserving first-occurrence order. Lowercasing
    is lossless here because every comparison in the otalon-clas
    blacklist matcher is case-insensitive (it normalizes tokens the
    same way), so whitespace and case variants of the same input
    converge to identical persisted text.
    """
    entries = [entry.strip().lower() for entry in json.loads(value)]
    seen: set[str] = set()
    unique = [entry for entry in entries if not (entry in seen or seen.add(entry))]
    return json.dumps(unique, separators=(",", ":"))
