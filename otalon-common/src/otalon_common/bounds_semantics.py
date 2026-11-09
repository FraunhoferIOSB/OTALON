"""Pure bounds correction semantics shared by API and MCP adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Mapping


class BoundsSemanticsError(ValueError):
    """Base error for invalid bounds correction requests."""


@dataclass(frozen=True)
class BoundsCorrection:
    """Validated result of a bounds correction calculation."""

    action: str
    prior_lower: dict[str, Any] | None
    prior_upper: dict[str, Any] | None
    lower: dict[str, Any]
    upper: dict[str, Any]


def calculate_bounds_correction(
    action: str,
    existing_lower: Mapping[str, Any] | None,
    existing_upper: Mapping[str, Any] | None,
    requested_lower: Mapping[str, Any],
    requested_upper: Mapping[str, Any],
    *,
    required_features: set[str] | None = None,
) -> BoundsCorrection:
    """Validate and calculate create, widen-only, or replace semantics.

    ``required_features`` is used by strict callers that require complete
    envelopes. MCP repository callers omit it and retain their established
    adapter-level feature policy.
    """
    if action not in {"expand", "replace", "create"}:
        raise BoundsSemanticsError(f"unsupported bounds action: {action}")
    prior_lower = dict(existing_lower) if existing_lower is not None else None
    prior_upper = dict(existing_upper) if existing_upper is not None else None
    if required_features is not None:
        supplied = set(requested_lower) & set(requested_upper)
        missing = sorted(required_features - supplied)
        if missing:
            raise BoundsSemanticsError(f"missing features: {', '.join(missing)}")
    if action == "create" and existing_lower is not None:
        raise BoundsSemanticsError("bounds already exist; use expand or replace")
    if action == "expand":
        if existing_lower is None or existing_upper is None:
            raise BoundsSemanticsError("no bounds row exists; use create")
        lower = dict(existing_lower)
        upper = dict(existing_upper)
        for feature, value in requested_lower.items():
            if value is not None:
                lower[feature] = min(lower.get(feature, value), value)
        for feature, value in requested_upper.items():
            if value is not None:
                upper[feature] = max(upper.get(feature, value), value)
        return BoundsCorrection(action, prior_lower, prior_upper, lower, upper)
    return BoundsCorrection(
        action,
        prior_lower,
        prior_upper,
        dict(requested_lower),
        dict(requested_upper),
    )
