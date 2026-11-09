"""Pydantic request/response models for the otalon-scan HTTP surface.

One module per resource, mirroring :mod:`otalon_scan.api.routers`. Re-exports
only — no side effects at import time.
"""

from .devices import (
    BulkDeleteDevicesRequest,
    BulkDeleteDevicesResponse,
    DeviceIdentityPatchRequest,
    DeviceItem,
    DeviceObservationsResponse,
    DeviceScansResponse,
    ServiceObservationItem,
)
from .interfaces import InterfaceItem, InterfacesResponse
from .modules import ModuleSchemaKeyItem, ModuleSchemaResponse, ModulesResponse
from .scans import (
    BulkDeleteScansRequest,
    BulkDeleteScansResponse,
    FinishedScansResponse,
    RunningScansResponse,
    ScanItem,
    ScansListResponse,
    StartScanRequest,
    StartScanResponse,
    StopScanResponse,
)
from .vulnerabilities import (
    CveLookupItem,
    CveLookupsListResponse,
    StopLookupResponse,
    VulnerabilityItem,
    VulnerabilityLookupRequest,
    VulnerabilityLookupResponse,
    VulnerabilityPatchRequest,
)

__all__ = [
    "BulkDeleteDevicesRequest",
    "BulkDeleteDevicesResponse",
    "BulkDeleteScansRequest",
    "BulkDeleteScansResponse",
    "CveLookupItem",
    "CveLookupsListResponse",
    "DeviceIdentityPatchRequest",
    "DeviceItem",
    "DeviceObservationsResponse",
    "DeviceScansResponse",
    "FinishedScansResponse",
    "InterfaceItem",
    "InterfacesResponse",
    "ModuleSchemaKeyItem",
    "ModuleSchemaResponse",
    "ModulesResponse",
    "RunningScansResponse",
    "ScanItem",
    "ScansListResponse",
    "ServiceObservationItem",
    "StartScanRequest",
    "StartScanResponse",
    "StopLookupResponse",
    "StopScanResponse",
    "VulnerabilityItem",
    "VulnerabilityLookupRequest",
    "VulnerabilityLookupResponse",
    "VulnerabilityPatchRequest",
]
