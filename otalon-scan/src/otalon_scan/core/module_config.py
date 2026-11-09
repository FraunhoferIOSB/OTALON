"""Central registry mapping module slugs to their Pydantic config schemas.

Two registries are exposed:

- :data:`MODULE_SCHEMA_REGISTRY` — module-slug → ``*Overrides`` schema
  (legacy from ``harden-otalon-scan-security`` Phase 2). The API
  layer consults this registry to dispatch ``overrides`` validation in
  :class:`~otalon_scan.api.server.StartScanRequest`. The ``*Overrides`` schemas
  validate only the partial-override payload (``extra="forbid"``,
  everything optional).
- :data:`MODULE_CONFIG_REGISTRY` — module-slug → ``*Config`` full-config
  schema. Introduced by F-02 (capability
  ``scan--module-config-schemas``). The orchestrator validates each
  module's ``config.json`` defaults against this schema at lifespan
  startup (:func:`validate_module_default_configs`); the future MCP
  ``start_scan`` tool will use the same schemas as its parameter-
  validation surface (``scan--mcp-tools``).

Callers MAY pass ``module_name`` in the path-prefixed form
(``modules/arp_scan``) — :func:`resolve_module_slug` normalises both
shapes to the canonical leaf-slug before lookup.

Normative references:

- Phase 2 of ``harden-otalon-scan-security`` (``*Overrides`` registry).
- F-02 ``scan--module-config-schemas`` Requirement
  "Module Loads Its Own Config Schema" (``*Config`` registry).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Mapping

from pydantic import BaseModel, ValidationError

from otalon_scan.core.models import CveLookupConfig
from otalon_scan.modules.arp_scan.config import ArpScanConfig
from otalon_scan.modules.arp_scan.schema import ArpScanOverrides
from otalon_scan.modules.opcua_discover.config import OpcUaDiscoverConfig
from otalon_scan.modules.opcua_discover.schema import OpcuaDiscoverOverrides
from otalon_scan.modules.pn_discovery.config import PnDiscoveryConfig
from otalon_scan.modules.pn_discovery.schema import PnDiscoveryOverrides
from otalon_scan.modules.port_scan.config import PortScanConfig
from otalon_scan.modules.port_scan.schema import PortScanOverrides
from otalon_scan.modules.snmp_scan.config import SnmpScanConfig
from otalon_scan.modules.snmp_scan.schema import SnmpScanOverrides

__all__ = [
    "MODULE_CONFIG_REGISTRY",
    "MODULE_SCHEMA_REGISTRY",
    "config_schema_for_module",
    "resolve_module_slug",
    "schema_for_module",
    "validate_module_default_configs",
]


MODULE_SCHEMA_REGISTRY: Mapping[str, type[BaseModel]] = {
    "arp_scan": ArpScanOverrides,
    "port_scan": PortScanOverrides,
    "snmp_scan": SnmpScanOverrides,
    "opcua_discover": OpcuaDiscoverOverrides,
    "pn_discovery": PnDiscoveryOverrides,
}


# F-02 / scan--module-config-schemas Requirement "Module Loads Its Own Config Schema".
# Maps the canonical leaf-slug to the module's *Config full-schema. The
# orchestrator's lifespan startup calls :func:`validate_module_default_configs`
# with this registry to reject any drift between a module's on-disk
# ``config.json`` defaults and its declared schema (Requirement "Config
# Defaults Loaded From config.json").
#
# ``cve_lookup`` is a forward-compatible placeholder: the
# :class:`CveLookupConfig` model exists today (see ``otalon_scan.core.models``),
# but the actual scanner is implemented in the downstream
# ``scan--module-completion`` change. Listing it here lets the future
# MCP ``start_scan`` tool register its allow-list against a stable
# registry shape without a circular dependency.
MODULE_CONFIG_REGISTRY: Mapping[str, type[BaseModel]] = {
    "arp_scan": ArpScanConfig,
    "port_scan": PortScanConfig,
    "snmp_scan": SnmpScanConfig,
    "opcua_discover": OpcUaDiscoverConfig,
    "pn_discovery": PnDiscoveryConfig,
    "cve_lookup": CveLookupConfig,
}


def resolve_module_slug(module_name: str) -> str:
    """Return the canonical leaf slug for ``module_name``.

    Accepts both ``"arp_scan"`` and ``"modules/arp_scan"`` shapes, mirroring
    the normalisation that :class:`~otalon_scan.core.module_manager.ModuleManager`
    applies internally.

    :param module_name: Caller-supplied module identifier.
    :returns: The leaf slug (last path segment), stripped of surrounding
        whitespace. An empty input yields an empty string.
    """
    return (module_name or "").strip().split("/")[-1]


def schema_for_module(module_name: str) -> type[BaseModel] | None:
    """Return the ``*Overrides`` schema registered for ``module_name``, or ``None``.

    :param module_name: Caller-supplied module identifier (path-prefixed or
        leaf-only).
    :returns: The :class:`BaseModel` subclass registered for the resolved
        slug, or ``None`` if no schema is registered.
    """
    slug = resolve_module_slug(module_name)
    return MODULE_SCHEMA_REGISTRY.get(slug)


def config_schema_for_module(module_name: str) -> type[BaseModel] | None:
    """Return the ``*Config`` full-config schema for ``module_name``.

    Counterpart of :func:`schema_for_module` but pointing at the
    :data:`MODULE_CONFIG_REGISTRY` introduced by F-02.

    :param module_name: Caller-supplied module identifier (path-prefixed or
        leaf-only).
    :returns: The :class:`BaseModel` subclass registered for the resolved
        slug, or ``None`` if no full-config schema is registered (e.g. the
        slug points at a test/dummy module).
    """
    slug = resolve_module_slug(module_name)
    return MODULE_CONFIG_REGISTRY.get(slug)


def validate_module_default_configs(modules_root: Path) -> None:
    """Validate every module's ``config.json`` against its ``*Config`` schema.

    Walks the modules root, locates each ``<module>/config.json``, looks up
    the matching ``*Config`` schema in :data:`MODULE_CONFIG_REGISTRY`, and
    validates the JSON payload against it. Any validation failure raises
    :class:`pydantic.ValidationError` (caller is expected to log a
    CRITICAL line and refuse to start the service — see ``D2`` /
    ``scan--app-lifecycle``).

    Modules that have no registered ``*Config`` (e.g. test scaffolds) are
    skipped silently. ``cve_lookup`` is listed in the registry but has no
    on-disk module directory in this change; it is also skipped.

    :param modules_root: Filesystem path containing one folder per module.
    :raises pydantic.ValidationError: First per-module schema mismatch.
    :raises FileNotFoundError: ``modules_root`` does not exist.
    """
    if not modules_root.exists():
        raise FileNotFoundError(f"modules_root does not exist: {modules_root}")

    for module_dir in sorted(p for p in modules_root.iterdir() if p.is_dir()):
        slug = module_dir.name
        schema = MODULE_CONFIG_REGISTRY.get(slug)
        if schema is None:
            continue
        config_path = module_dir / "config.json"
        if not config_path.exists():
            continue
        with config_path.open("r", encoding="utf-8") as fh:
            payload = json.load(fh)
        try:
            schema.model_validate(payload)
        except ValidationError as exc:
            # Re-raise with the module slug in the error context so the
            # operator sees which config.json is at fault. Pydantic v2
            # does not let us mutate ``ValidationError`` in place; we
            # raise a fresh ``ValueError`` chained to the original.
            raise ValueError(
                f"module {slug!r} config.json failed schema validation " f"against {schema.__name__}: {exc}"
            ) from exc
