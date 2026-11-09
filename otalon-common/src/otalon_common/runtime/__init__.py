"""Shared runtime-configuration contract: registry, validators, manifest.

This package is deliberately free of database and web dependencies. It carries
the validation logic every consumer of the ``runtime_config`` table shares,
while data access stays with each service and its own database stack.
"""

from otalon_common.runtime.manifest import (
    MANIFEST,
    OTALON_AI_SERVICE,
    OTALON_CLAS_SERVICE,
    OTALON_SCAN_SERVICE,
    manifest_entry,
    manifest_for_service,
)
from otalon_common.runtime.registry import (
    BoolLiteralValidator,
    FloatIntervalValidator,
    IntRangeValidator,
    ListEntryValidationError,
    RuntimeKeyDeclaration,
    RuntimeKeySpec,
    RuntimeValueType,
    Validator,
    all_specs,
    bool_literal,
    float_interval,
    int_range,
    is_secret_key,
    lookup,
    normalize_value,
    register,
    reset_registry,
    validate_write,
)
from otalon_common.runtime.series_blacklist import series_blacklist_syntax_validator

__all__ = [
    "BoolLiteralValidator",
    "OTALON_CLAS_SERVICE",
    "OTALON_AI_SERVICE",
    "OTALON_SCAN_SERVICE",
    "FloatIntervalValidator",
    "IntRangeValidator",
    "ListEntryValidationError",
    "MANIFEST",
    "RuntimeKeyDeclaration",
    "RuntimeKeySpec",
    "RuntimeValueType",
    "Validator",
    "all_specs",
    "bool_literal",
    "float_interval",
    "int_range",
    "is_secret_key",
    "lookup",
    "normalize_value",
    "manifest_entry",
    "manifest_for_service",
    "register",
    "reset_registry",
    "series_blacklist_syntax_validator",
    "validate_write",
]
