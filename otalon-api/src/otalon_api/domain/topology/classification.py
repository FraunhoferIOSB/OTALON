"""Topology node classification logic.

Contains logic for classifying network nodes by MITRE ATT&CK for ICS asset
type based on device-type name strings from scan results.

Ported from the retired Panel-based UI's
``topology_service::_classify_device_type``.
"""

from __future__ import annotations

DEVICE_TYPE_APPLICATION_SERVER = "Application Server"
DEVICE_TYPE_CONTROL_SERVER = "Control Server"
DEVICE_TYPE_DATA_GATEWAY = "Data Gateway"
DEVICE_TYPE_DATA_HISTORIAN = "Data Historian"
DEVICE_TYPE_DCS_CONTROLLER = "DCS Controller"
DEVICE_TYPE_FIELD_IO = "Field I/O"
DEVICE_TYPE_FIREWALL = "Firewall"
DEVICE_TYPE_HMI = "HMI"
DEVICE_TYPE_IED = "IED"
DEVICE_TYPE_JUMP_HOST = "Jump Host"
DEVICE_TYPE_PAC = "PAC"
DEVICE_TYPE_PLC = "PLC"
DEVICE_TYPE_RTU = "RTU"
DEVICE_TYPE_ROUTERS = "Routers"
DEVICE_TYPE_SAFETY_CONTROLLER = "Safety Controller"
DEVICE_TYPE_SWITCH = "Switch"
DEVICE_TYPE_VPN_SERVER = "VPN Server"
DEVICE_TYPE_WORKSTATION = "Workstation"
DEVICE_TYPE_OTHER = "Other"

VALID_DEVICE_TYPES = frozenset(
    {
        DEVICE_TYPE_PLC,
        DEVICE_TYPE_APPLICATION_SERVER,
        DEVICE_TYPE_CONTROL_SERVER,
        DEVICE_TYPE_DATA_GATEWAY,
        DEVICE_TYPE_DATA_HISTORIAN,
        DEVICE_TYPE_DCS_CONTROLLER,
        DEVICE_TYPE_FIELD_IO,
        DEVICE_TYPE_FIREWALL,
        DEVICE_TYPE_HMI,
        DEVICE_TYPE_IED,
        DEVICE_TYPE_JUMP_HOST,
        DEVICE_TYPE_PAC,
        DEVICE_TYPE_RTU,
        DEVICE_TYPE_ROUTERS,
        DEVICE_TYPE_SAFETY_CONTROLLER,
        DEVICE_TYPE_SWITCH,
        DEVICE_TYPE_VPN_SERVER,
        DEVICE_TYPE_WORKSTATION,
        DEVICE_TYPE_OTHER,
    }
)


def classify_device_type(type_name: str | None) -> str:
    """Classify a device-type string into a known ICS device category.

    The classification uses keyword matching on the lowercased input.
    More specific server and controller types are checked before broad
    workstation and PLC keywords.

    Args:
        type_name: Raw device-type string (e.g. from ``devices.device_type``
                   or ``devices.device_role``). Unmatched values map to
                   ``"Other"``.

    Returns:
        One of the ``DEVICE_TYPE_*`` constants.
    """
    s = str(type_name or "").lower()
    if "vpn" in s and "server" in s:
        return DEVICE_TYPE_VPN_SERVER
    if "jump host" in s or "jump-host" in s:
        return DEVICE_TYPE_JUMP_HOST
    if "data historian" in s or "historian" in s:
        return DEVICE_TYPE_DATA_HISTORIAN
    if "data gateway" in s or "gateway" in s:
        return DEVICE_TYPE_DATA_GATEWAY
    if "control server" in s or "scada server" in s:
        return DEVICE_TYPE_CONTROL_SERVER
    if "application server" in s or "app server" in s:
        return DEVICE_TYPE_APPLICATION_SERVER
    if "firewall" in s:
        return DEVICE_TYPE_FIREWALL
    if "router" in s:
        return DEVICE_TYPE_ROUTERS
    if "switch" in s or "scalanc" in s:
        return DEVICE_TYPE_SWITCH
    if "safety controller" in s or "safety plc" in s:
        return DEVICE_TYPE_SAFETY_CONTROLLER
    if "dcs" in s:
        return DEVICE_TYPE_DCS_CONTROLLER
    if "ied" in s:
        return DEVICE_TYPE_IED
    if "pac" in s:
        return DEVICE_TYPE_PAC
    if "rtu" in s:
        return DEVICE_TYPE_RTU
    if "hmi" in s or "panel" in s or "display" in s:
        return DEVICE_TYPE_HMI
    if "field i/o" in s or "field io" in s or "i/o" in s or "io module" in s:
        return DEVICE_TYPE_FIELD_IO
    if "plc" in s or "s7" in s:
        return DEVICE_TYPE_PLC
    if "controller" in s:
        return DEVICE_TYPE_PLC
    if "workstation" in s or "industrial pc" in s or "ipc" in s or " pc" in f" {s}":
        return DEVICE_TYPE_WORKSTATION
    if "server" in s or " pc" in s:
        return DEVICE_TYPE_APPLICATION_SERVER
    return DEVICE_TYPE_OTHER
