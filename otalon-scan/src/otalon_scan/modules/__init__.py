"""CyberScan-ICS scanner modules package.

Each subpackage under :mod:`otalon_scan.modules` provides a single scanner module
(``arp_scan``, ``port_scan``, ``pn_discovery``, ``snmp_scan``,
``opcua_discover``). Modules are discovered and dispatched by
:class:`otalon_scan.core.module_manager.ModuleManager`.
"""

from __future__ import annotations
