"""Pydantic v2 DTOs that flow between modules and the orchestrator.

These models define the data shapes used by the :class:`ScanModule`
Protocol (see :mod:`otalon_scan.core.protocols`):

- :class:`ScanConfig` — the validated input handed to ``module.scan()``
- :class:`ScanProgress` — intermediate event yielded by a module
- :class:`ScanResult` — terminal event yielded exactly once by a module
- :class:`DeviceFinding` — a single discovered device / interface,
  carried inside ``ScanResult.findings`` and in some ``ScanProgress``
  payloads

The DTOs are deliberately decoupled from the SQLAlchemy ORM in
:mod:`otalon_scan.repositories.models`; the orchestrator translates them into
persistent rows inside ``ModuleManager._persist_batch``.

F-02 additions (capability ``scan--module-config-schemas``):

- :class:`CveLookupConfig` — forward-compatible placeholder for the
  future ``cve_lookup`` module (wired by ``scan--module-completion``).
  The actual module implementation lives outside this change; the
  placeholder schema is the canonical starting point so MCP tool
  validation (``scan--mcp-tools``) and the orchestrator's startup
  validation hook can register it today.

F-02 additions (capability ``scan--scanresult-contract``):

- Per-module ``*Finding`` models with ``extra='forbid'`` typed fields
  (:class:`ArpFinding`, :class:`PortFinding`, :class:`PnFinding`,
  :class:`OpcUaFinding`, :class:`SnmpFinding`, :class:`CveFinding`).
- Per-module ``*ScanResult`` models with a ``module_type`` discriminator
  matching the module's directory name, and a typed ``findings`` list
  using the corresponding ``*Finding`` model.
- :data:`TypedScanResult` — the discriminated union over every concrete
  ``*ScanResult`` variant, exposed for ``TypeAdapter``-driven dispatch.

The legacy :class:`ScanResult` (without ``module_type``) remains
constructable so test/dummy modules and the orchestrator's synthetic
fallback path keep working. Production modules SHOULD yield a typed
concrete ``*ScanResult`` instance per the
``scan--module-contract`` Module Output Contract requirement.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Annotated, Any, Dict, List, Literal, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, TypeAdapter, field_serializer


class DeviceFinding(BaseModel):
    """A single discovered device or network interface.

    Fields are deliberately optional: different scan modules surface
    different subsets (an ARP scan discovers IP/MAC; PROFINET-DCP adds
    vendor/role/station-name; SNMP adds firmware/article number; OPC UA
    surfaces application metadata + endpoint port).
    """

    model_config = ConfigDict(extra="allow")

    ipv4: Optional[str] = None
    ipv6: Optional[str] = None
    mac: Optional[str] = None
    subnet: Optional[str] = None

    # P8 Welle A (F-04/F-10): the discovered network name (PROFINET
    # station-name, SNMP ``sysName``). Carried into the ``devices.hostname``
    # column. A hostname is NOT a device type — modules MUST set this rather
    # than ``device_type`` for discovered station/host names, leaving
    # ``device_type`` NULL unless a genuine type is known.
    hostname: Optional[str] = None
    vendor: Optional[str] = None
    device_family: Optional[str] = None
    device_type: Optional[str] = None
    description: Optional[str] = None
    article_number: Optional[str] = None
    device_role: Optional[str] = None
    firmware_version: Optional[str] = None

    # SCAN-018 SNMP asset-enrichment: additive device master-data fields
    # carried from the SNMP walker into the ``devices`` UPSERT. Other
    # modules leave them None (NULL-skipped on conflict).
    product_name: Optional[str] = None
    hw_version: Optional[str] = None
    sw_version: Optional[str] = None
    serial_number: Optional[str] = None

    open_ports_summary: Optional[Dict[str, Any]] = None
    notes: Optional[str] = None

    extra: Dict[str, Any] = Field(default_factory=dict)


class ScanConfig(BaseModel):
    """Validated configuration handed to ``module.scan()``.

    Modules MUST NOT re-parse or re-validate. The orchestrator builds
    this object by merging the module's ``config.json`` defaults with
    the runtime ``overrides`` from the start-scan request.

    The model is intentionally permissive (``extra="allow"``) so each
    module can surface its own scanner-specific fields without bloating
    the shared schema. Module-specific validation happens inside each
    module's ``scan()`` implementation by raising :class:`ScanModuleError`.
    """

    model_config = ConfigDict(extra="allow")

    module_name: str = Field(..., description="MITRE-prefixed module identifier, e.g. 'T0846/arp_scan'.")
    network_interface: Optional[str] = None

    target_ip: Optional[Any] = Field(
        default=None,
        description="Single IP, list of IPs, or CIDR/range string (module-specific).",
    )
    target_mac: Optional[Any] = Field(
        default=None,
        description="Single MAC, list of MACs, or None.",
    )
    target_subnet: Optional[str] = None
    target_port: Optional[int] = None

    parameters: Dict[str, Any] = Field(
        default_factory=dict,
        description="Free-form scanner-specific parameters (timing, retries, communities, ...).",
    )


class ScanProgress(BaseModel):
    """Intermediate event yielded by a module during a scan.

    The orchestrator forwards :class:`ScanProgress` events to the SSE
    channel (Mission Q9) and may also append them to the persistence
    buffer when they carry final per-host findings.
    """

    model_config = ConfigDict(extra="allow")

    module_name: str
    message: Optional[str] = None
    percent: Optional[float] = Field(default=None, ge=0.0, le=100.0)
    finding: Optional[DeviceFinding] = None
    timestamp: datetime = Field(default_factory=lambda: datetime.now(tz=timezone.utc))


class ScanResult(BaseModel):
    """Terminal event yielded exactly once by a module.

    The orchestrator treats receipt of a :class:`ScanResult` as the
    signal that the scan has completed successfully; it then performs a
    final flush of the persistence buffer.
    """

    model_config = ConfigDict(extra="allow")

    module_name: str
    protocol: Optional[str] = Field(
        default=None,
        description="Protocol tag for activity logging (e.g. 'arp', 'opcua', 'snmp').",
    )
    findings: List[DeviceFinding] = Field(default_factory=list)

    raw_results: Any = Field(
        default=None,
        description=(
            "Module-native results structure (DataFrame, list[dict], dict). "
            "Carried through for API serialization compatibility with the pre-refactor shape."
        ),
    )

    started_at: Optional[datetime] = None
    finished_at: Optional[datetime] = None

    source_ip: Optional[str] = None
    source_mac: Optional[str] = None
    abort_reason: Optional[str] = None

    @field_serializer("raw_results", when_used="json")
    def _serialize_raw_results(self, value: Any) -> Any:
        """Coerce non-JSON-native ``raw_results`` to a serialisable shape.

        ``raw_results`` is ``Any`` so it may carry a pandas DataFrame
        (the legacy shape from arp_scan / port_scan) which pydantic's
        JSON-mode serializer cannot handle natively. We duck-type the
        DataFrame surface and fall back through:

        1. pandas DataFrame  → ``to_dict(orient="records")``
        2. numpy-like array (``tolist``)  → ``tolist()``
        3. anything else  → returned verbatim (pydantic handles
           ``list`` / ``dict`` / scalar shapes itself)

        Without this serializer ``model_dump(mode="json")`` raises
        ``PydanticSerializationError: Unable to serialize unknown type:
        <class 'pandas.core.frame.DataFrame'>`` on every module run
        whose ``ScanResult`` carries a DataFrame — which produced the
        post-2026-05-19 noise in ModuleManager._finalize_run logs even
        though persistence succeeded.
        """
        if value is None:
            return None
        # Pandas DataFrame (duck-typing; avoid a hard pandas import here).
        to_dict = getattr(value, "to_dict", None)
        if callable(to_dict) and hasattr(value, "columns"):
            try:
                return to_dict(orient="records")
            except Exception:  # noqa: BLE001 -- duck-typing fallback; see docstring
                pass
        # numpy ndarray / pandas Series.
        tolist = getattr(value, "tolist", None)
        if callable(tolist) and not isinstance(value, (dict, str, bytes)):
            try:
                return tolist()
            except Exception:  # noqa: BLE001 -- duck-typing fallback; see docstring
                pass
        return value


# ---------------------------------------------------------------------------
# F-02 / scan--module-config-schemas: forward-compatible placeholder for
# ``cve_lookup``. The actual scanner is implemented by the downstream
# ``scan--module-completion`` change; this placeholder gives the MCP
# ``start_scan`` tool (``scan--mcp-tools``) and the orchestrator's
# startup-config validation hook a known shape to dispatch on today.
# Later changes MAY extend ``CveLookupConfig`` with additional fields
# (NVD endpoint, CPE filters, severity floor, etc.); the placeholder
# defined here is the authoritative starting point — extend rather
# than replace.
# ---------------------------------------------------------------------------


class CveLookupConfig(BaseModel):
    """Forward-compatible placeholder config for the future ``cve_lookup`` module."""

    model_config = ConfigDict(extra="forbid", strict=True)

    module_type: Literal["cve_lookup"] = "cve_lookup"

    target_cpe: Optional[str] = Field(
        default=None,
        description=(
            "Optional CPE 2.3 product URI to query (e.g. "
            "'cpe:2.3:o:siemens:simatic_s7-1500:*'). When omitted the "
            "module SHALL iterate over inventory devices."
        ),
    )
    nvd_api_base: str = Field(
        default="https://services.nvd.nist.gov/rest/json/cves/2.0",
        description="NVD REST API base URL.",
    )
    request_timeout_s: int = Field(default=30, ge=1, le=300)


# ---------------------------------------------------------------------------
# F-02 / scan--scanresult-contract: per-module finding + result models +
# discriminated union. The discriminator is ``module_type`` and SHALL
# exactly match the module's directory-name slug (Requirement
# "Discriminator Value Matches Module Identifier"). Each ``*Finding``
# model sets ``extra='forbid'`` to reject unknown fields (Requirement
# "Per-Module Finding Models").
#
# The legacy :class:`ScanResult` above remains constructable so test /
# dummy modules and the orchestrator's synthetic fallback path stay
# working; production modules SHOULD yield a typed concrete
# ``*ScanResult`` per the ``scan--module-contract`` Module Output
# Contract requirement.
# ---------------------------------------------------------------------------


class ArpFinding(BaseModel):
    """Per-host finding emitted by ``arp_scan``."""

    model_config = ConfigDict(extra="forbid")

    ip_address: str
    mac_address: Optional[str] = None
    subnet: Optional[str] = None


class PortFinding(BaseModel):
    """Per-port finding emitted by ``port_scan``."""

    model_config = ConfigDict(extra="forbid")

    ip_address: str
    port: int = Field(..., ge=1, le=65535)
    transport: Literal["tcp", "udp"] = "tcp"
    state: Optional[str] = None
    service: Optional[str] = None
    product: Optional[str] = None
    version: Optional[str] = None


class PnFinding(BaseModel):
    """Per-station finding emitted by ``pn_discovery``."""

    model_config = ConfigDict(extra="forbid")

    mac_address: str
    station_name: Optional[str] = None
    device_role: Optional[str] = None
    vendor: Optional[str] = None
    ip_address: Optional[str] = None


class OpcUaFinding(BaseModel):
    """Per-endpoint finding emitted by ``opcua_discover``."""

    model_config = ConfigDict(extra="forbid")

    endpoint_url: str
    application_uri: Optional[str] = None
    application_name: Optional[str] = None
    product_uri: Optional[str] = None
    transport_profile_uri: Optional[str] = None


class SnmpFinding(BaseModel):
    """Per-target finding emitted by ``snmp_scan``."""

    model_config = ConfigDict(extra="forbid")

    ip_address: str
    sys_descr: Optional[str] = None
    sys_object_id: Optional[str] = None
    sys_name: Optional[str] = None
    firmware_version: Optional[str] = None
    article_number: Optional[str] = None
    # SCAN-018: asset master-data the SNMP walker collects. ``device_family``
    # carries the SNMP ``product_family`` value (operator decision D2).
    device_family: Optional[str] = None
    product_name: Optional[str] = None
    hw_version: Optional[str] = None
    sw_version: Optional[str] = None
    serial_number: Optional[str] = None


class CveFinding(BaseModel):
    """Per-CVE finding emitted by ``cve_lookup`` (forward-compatible)."""

    model_config = ConfigDict(extra="forbid")

    cve_id: str
    severity: Optional[str] = None
    cvss_score: Optional[float] = Field(default=None, ge=0.0, le=10.0)
    summary: Optional[str] = None
    cpe: Optional[str] = None


# Per-module typed result models. Each carries the ``module_type``
# discriminator (Requirement "ScanResult Discriminated Union") plus the
# ``scan_id`` and typed ``findings`` list. They inherit from the legacy
# :class:`ScanResult` so existing fields (``module_name``, ``protocol``,
# ``raw_results``, ``started_at`` / ``finished_at``, ``source_ip`` /
# ``source_mac``, ``abort_reason``) remain available — the discriminated
# union is an addition, not a replacement.


# Note on findings shape: the per-module ``*Finding`` models above
# (:class:`ArpFinding`, :class:`PortFinding`, …) are the strict typed
# shapes for future MCP-tool consumers and for orchestrators that want
# to narrow on ``module_type``. The current orchestrator persist path
# still operates on :class:`DeviceFinding` instances; the per-module
# typed-result classes below therefore keep ``findings: List[DeviceFinding]``
# so the existing persistence wiring stays intact. A future migration
# (``scan--module-completion``) MAY tighten the result classes to use
# the typed ``*Finding`` lists; the orchestrator's persistence path
# will need to be updated in lock-step.


class ArpScanResult(ScanResult):
    """Terminal result for ``arp_scan``."""

    module_type: Literal["arp_scan"] = "arp_scan"
    scan_id: Optional[str] = None


class PortScanResult(ScanResult):
    """Terminal result for ``port_scan``."""

    module_type: Literal["port_scan"] = "port_scan"
    scan_id: Optional[str] = None


class PnDiscoveryResult(ScanResult):
    """Terminal result for ``pn_discovery``."""

    module_type: Literal["pn_discovery"] = "pn_discovery"
    scan_id: Optional[str] = None


class OpcUaDiscoverResult(ScanResult):
    """Terminal result for ``opcua_discover``."""

    module_type: Literal["opcua_discover"] = "opcua_discover"
    scan_id: Optional[str] = None


class SnmpScanResult(ScanResult):
    """Terminal result for ``snmp_scan``."""

    module_type: Literal["snmp_scan"] = "snmp_scan"
    scan_id: Optional[str] = None


class CveLookupResult(ScanResult):
    """Terminal result for ``cve_lookup`` (forward-compatible)."""

    module_type: Literal["cve_lookup"] = "cve_lookup"
    scan_id: Optional[str] = None


# Discriminated union over every concrete typed result. The
# ``TypeAdapter(TypedScanResult).validate_python(...)`` dispatch is O(1)
# on ``module_type`` and the natural mypy-friendly way to narrow when
# the orchestrator receives a serialised result from a child process.
#
# Spec name (``scan--scanresult-contract``) calls this ``ScanResult``,
# but reusing that name here would shadow the existing class that
# remains in use for test/dummy callers. We expose the union under a
# distinct alias so both contracts coexist; the future migration to
# fully retire the legacy class will rename in one step.
TypedScanResult = Annotated[
    Union[
        ArpScanResult,
        PortScanResult,
        PnDiscoveryResult,
        OpcUaDiscoverResult,
        SnmpScanResult,
        CveLookupResult,
    ],
    Field(discriminator="module_type"),
]


# Convenience adapter for callers that want
# ``typed_scan_result_adapter.validate_python(payload)`` without
# importing ``TypeAdapter`` themselves.
typed_scan_result_adapter: TypeAdapter[TypedScanResult] = TypeAdapter(TypedScanResult)


# Module slug → concrete result class map. Used by callers that need to
# build a typed result instance from a known slug (the orchestrator's
# synthetic fallback path, tests). Keeps the slug→type contract in one
# place for symmetry with :data:`MODULE_CONFIG_REGISTRY` in
# :mod:`otalon_scan.core.module_config`.
MODULE_RESULT_REGISTRY: Dict[str, type[ScanResult]] = {
    "arp_scan": ArpScanResult,
    "port_scan": PortScanResult,
    "pn_discovery": PnDiscoveryResult,
    "opcua_discover": OpcUaDiscoverResult,
    "snmp_scan": SnmpScanResult,
    "cve_lookup": CveLookupResult,
}
