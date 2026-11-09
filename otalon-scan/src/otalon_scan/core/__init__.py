"""CyberScan-ICS core package.

Exports:

- :class:`~otalon_scan.core.protocols.ScanModule`: Protocol every scan module
  MUST implement (capability ``scan--module-contract``).
- :class:`~otalon_scan.core.protocols.ScanModuleError`: Exception raised by
  modules on internal failure.
- :class:`~otalon_scan.core.models.ScanConfig` / :class:`ScanProgress` /
  :class:`ScanResult` / :class:`DeviceFinding`: data flow between
  modules and the orchestrator.
- :class:`~otalon_scan.core.module_manager.ModuleManager`: orchestrator that
  owns persistence (capability ``scan--persistence-ownership``).
- :func:`~otalon_scan.core.log_config.setup_logging`: loguru initializer.
- :func:`~otalon_scan.core.config_utils.merge_configurations`: JSON config helper.

Note:
- The legacy ``BaseModule`` abstract base class has been removed as
  part of the HC6 / Phase 2 refactor. Modules now conform to the
  :class:`ScanModule` Protocol instead of subclassing
  ``BaseModule``.
"""

from __future__ import annotations

from .config_utils import merge_configurations
from .log_config import setup_logging
from .models import DeviceFinding, ScanConfig, ScanProgress, ScanResult
from .module_manager import ModuleManager
from .protocols import ScanModule, ScanModuleError

__all__ = [
    "DeviceFinding",
    "ModuleManager",
    "ScanConfig",
    "ScanModule",
    "ScanModuleError",
    "ScanProgress",
    "ScanResult",
    "merge_configurations",
    "setup_logging",
]
