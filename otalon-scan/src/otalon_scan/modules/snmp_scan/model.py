from __future__ import annotations

from typing import Any, Dict, List, Optional


class _AssetFields:
    """Mixin holding the device/neighbor master-data fields and setters.

    Both the scanned SNMP target (:class:`Device`) and a correlated LLDP
    neighbor (:class:`Neighbor`) carry the same identity attributes, so the
    setter API and ``parse_sysDescr`` enrichment are shared. Setters skip
    falsy values so a sparse walk leaves fields ``None`` and the persistence
    layer's NULL-skipping merge applies.
    """

    mac_addr: Optional[str] = None
    ip_addr: Optional[str] = None
    if_vendor: Optional[str] = None
    is_firmware: bool = False
    vendor: Optional[str] = None
    contact: Optional[str] = None
    location: Optional[str] = None
    sys_name: Optional[str] = None
    device_role: Optional[str] = None
    product_type: Optional[str] = None
    product_name: Optional[str] = None
    order_number: Optional[str] = None
    hw_version: Optional[str] = None
    software_name: Optional[str] = None
    sw_version: Optional[str] = None
    serial_number: Optional[str] = None
    sys_descr: Optional[str] = None

    def set_mac_addr(self, x: Optional[str]) -> None:
        self.mac_addr = x

    def set_if_vendor(self, x: Optional[str]) -> None:
        self.if_vendor = x

    def set_is_firmware(self) -> None:
        self.is_firmware = True

    def set_device_role(self, x: Optional[str]) -> None:
        self.device_role = x

    def set_vendor(self, x: Optional[str]) -> None:
        if x:
            self.vendor = x

    def set_contact(self, x: Optional[str]) -> None:
        if x:
            self.contact = x

    def set_location(self, x: Optional[str]) -> None:
        if x:
            self.location = x

    def set_sys_name(self, x: Optional[str]) -> None:
        if x:
            self.sys_name = x

    def set_product_type(self, x: Optional[str]) -> None:
        if x:
            self.product_type = x

    def set_product_name(self, x: Optional[str]) -> None:
        if x:
            self.product_name = x

    def set_order_number(self, x: Optional[str]) -> None:
        if x:
            self.order_number = x

    def set_hw_version(self, x: Optional[str]) -> None:
        if x:
            self.hw_version = x

    def set_software_name(self, x: Optional[str]) -> None:
        if x:
            self.software_name = x

    def set_sw_version(self, x: Optional[str]) -> None:
        if x:
            self.sw_version = x

    def set_serial_number(self, x: Optional[str]) -> None:
        if x:
            self.serial_number = x

    def _export_finding(self) -> Dict[str, Any]:
        """Render the shared asset fields into a single finding ``dict``."""

        def make_param(key: str, val: Any) -> None:
            if val:
                a_finding[key] = str(val)

        a_finding: Dict[str, Any] = {}
        make_param("article_number", self.order_number)
        make_param("confidence", "1.000")
        make_param("description", self.product_type)
        make_param("device_name", self.sys_name)
        make_param("device_role", self.device_role)
        make_param("device_type", self.product_name)
        make_param("hw_version", self.hw_version)
        make_param("ip_address", self.ip_addr)
        make_param("is_firmware", self.is_firmware)
        make_param("location", self.location)
        make_param("mac_address", self.mac_addr)
        make_param("oui", self.if_vendor)
        make_param("manufacturer", self.vendor)
        make_param("product_name", self.product_name)
        make_param("serial_number", self.serial_number)
        make_param("source", "SNMPSubmanager")
        make_param("software_name", self.software_name)
        make_param("sw_version", self.sw_version)
        return a_finding


class Neighbor(_AssetFields):
    """An LLDP neighbor of the scanned switch, correlated with a real MAC.

    Built by the walker from the join
    ``lldpRemTable[localPort] ⋈ BridgePort↔ifIndex ⋈ dot1dTpFdbTable[port]``.
    Carries the neighbor's MAC (from the bridge forwarding DB), management
    IPv4 (from ``lldpRemManAddrTable``), SysName / PortId / SysDesc, plus any
    vendor/product/HW/SW/article fields parsed from the SysDesc string.
    """

    def __init__(self, local_port: int) -> None:
        self.local_port = local_port
        self.port_id: Optional[str] = None
        self.port_desc: Optional[str] = None

    def export_yourself(self) -> Dict[str, Any]:
        """Render this neighbor as a single finding ``dict``."""
        return self._export_finding()


class Device(_AssetFields):
    """The scanned SNMP target plus its correlated LLDP neighbors."""

    def __init__(self, ipaddr: str) -> None:
        self.ip_addr = ipaddr
        self.neighbors: List[Neighbor] = []

    def add_neighbor(self, neighbor: Neighbor) -> None:
        self.neighbors.append(neighbor)

    def export_yourself(self) -> List[Dict[str, Any]]:
        """Return the switch finding PLUS one record per correlated neighbor."""
        findings: List[Dict[str, Any]] = [self._export_finding()]
        for neighbor in self.neighbors:
            findings.append(neighbor.export_yourself())
        return findings
