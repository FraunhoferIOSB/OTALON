"""Pydantic wire models for the module endpoints (SCAN-033 extraction).

Moved verbatim out of :mod:`otalon_scan.api.server`; shapes unchanged.
"""

from __future__ import annotations

from typing import List

from pydantic import BaseModel

__all__ = [
    "ModuleSchemaKeyItem",
    "ModuleSchemaResponse",
    "ModulesResponse",
]


class ModulesResponse(BaseModel):
    """Response with module names."""

    modules: List[str]


class ModuleSchemaKeyItem(BaseModel):
    """Single accepted-key descriptor for ``GET /scans/modules/{name}/schema``."""

    key: str
    type: str
    required: bool
    description: str


class ModuleSchemaResponse(BaseModel):
    """Envelope for ``GET /scans/modules/{name}/schema``."""

    module: str
    accepted_keys: List[ModuleSchemaKeyItem]
    requires_auth: bool
    extensible: bool = False
