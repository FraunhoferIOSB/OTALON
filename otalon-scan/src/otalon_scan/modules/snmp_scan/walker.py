import os
import re
from typing import Dict, List, Optional, Tuple

from loguru import logger
from pysnmp.hlapi.v3arch.asyncio import *
from pysnmp.smi import builder, compiler, view

from .model import Device, Neighbor, _AssetFields

VERBOSE = False

# Resolve MIB directories: support both legacy "MIBs" (kept) and new "mibs" (provided PN/IEC MIBs)
current_dir = os.path.dirname(os.path.abspath(__file__))
legacy_mib_dir = os.path.join(current_dir, "MIBs")
pno_mib_dir = os.path.join(current_dir, "mibs")

# Also consider common system MIB paths (to emulate snmpwalk behavior when snmp-mibs-downloader is installed)
system_mib_dirs: List[str] = [
    "/usr/share/snmp/mibs",
    "/usr/share/snmp/mibs/iana",
    "/usr/share/snmp/mibs/ietf",
]

# Read MIBDIRS from environment like net-snmp tools, allow colon-separated paths
env_mibdirs = os.environ.get("MIBDIRS", "")
if env_mibdirs:
    for part in env_mibdirs.split(":"):
        part = part.strip()
        if part:
            system_mib_dirs.append(part)

# De-duplicate while preserving order
seen = set()


def _unique_paths(paths: List[str]) -> List[str]:
    out: List[str] = []
    for p in paths:
        if p not in seen:
            out.append(p)
            seen.add(p)
    return out


all_mib_dirs = _unique_paths([legacy_mib_dir, pno_mib_dir] + system_mib_dirs)

mibBuilder = builder.MibBuilder()

# Configure pysmi compiler to read ASN.1 sources (local/system first)
asn1_sources: List[str] = []
for d in all_mib_dirs:
    if os.path.isdir(d):
        asn1_sources.append(f"file://{d}")

# Optional remote sources for dependencies (LLDP-MIB, IANA, etc.), can be disabled via CS_SNMP_OFFLINE=1
if os.environ.get("CS_SNMP_OFFLINE", "0") != "1":
    asn1_sources.extend(
        [
            "https://mibs.pysnmp.com/asn1/@mib@",
            "http://mibs.snmplabs.com/asn1/@mib@",
        ]
    )

# Attach compiler with sources
compiler.add_mib_compiler(mibBuilder, sources=asn1_sources)

# Also allow loading of already-compiled MIBs if present in these folders
for d in all_mib_dirs:
    try:
        if os.path.isdir(d):
            mibBuilder.add_mib_sources(builder.DirMibSource(d))
    except Exception:
        pass

logger.debug("SNMP MIB ASN.1 sources: {asn1_sources}", asn1_sources=asn1_sources)
logger.debug("SNMP MIB directories: {all_mib_dirs}", all_mib_dirs=all_mib_dirs)

mibView = view.MibViewController(mibBuilder)


def _resolve_oid(module: str, symbol: str) -> ObjectIdentity:
    """
    Build an ObjectIdentity and attach ASN.1 sources so that pysmi can compile MIBs on demand.
    """
    ident = ObjectIdentity(module, symbol)
    for src in asn1_sources:
        try:
            ident.addAsn1Source(src)
        except Exception:
            pass
    return ident.resolveWithMib(mibView)


def parse_sysDescr(val_pretty: str, a_device: _AssetFields) -> None:
    """Parse a SysDescr/SysDesc string and enrich ``a_device`` in place.

    Works for both the scanned :class:`Device` and a correlated
    :class:`Neighbor` since both share the asset-field setters. Recognises
    the richer Siemens SIMATIC form (product + article + HW/FW), the legacy
    short Siemens form, Phoenix Contact AXC, Beckhoff BKxxxx, Hirschmann and
    generic OS strings.
    """
    a_device.sys_descr = val_pretty

    m = re.search(
        r"Siemens,\s*[^,]+,\s*([^,]+),\s*([0-9][^,]*),\s*HW: ([^,]+), FW: ([^,]+)",
        val_pretty,
    )
    if m:
        a_device.set_vendor("Siemens")
        a_device.set_product_name(m.group(1).strip())
        a_device.set_order_number(m.group(2).strip())
        a_device.set_hw_version(m.group(3).strip())
        a_device.set_sw_version(m.group(4).strip())
        return

    m = re.search(r"Siemens,.*HW: ([^,]+), FW: ([^,]+)", val_pretty)
    if m:
        a_device.set_vendor("Siemens")
        a_device.set_hw_version(m.group(1))
        a_device.set_sw_version(m.group(2))
        return

    m = re.search(r"Beckhoff\s+(\S+).*HW: ([^,]+),\s*SW: ([^,]+)", val_pretty)
    if m:
        a_device.set_vendor("Beckhoff")
        a_device.set_product_name(m.group(1).strip())
        a_device.set_hw_version(m.group(2).strip())
        a_device.set_sw_version(m.group(3).strip())
        return

    m = re.match(r"([A-Z]+\sF\s\d+)\s+(\d+)\s+(\d+)", val_pretty)
    if m:
        a_device.set_product_name(m.group(1))
        a_device.set_order_number(m.group(2))
        a_device.set_serial_number(m.group(3))
        a_device.set_vendor("PHOENIX CONTACT Electronics GmbH")
        return

    m = re.match(r"(Hirschmann.*)", val_pretty)
    if m:
        a_device.set_vendor("Hirschmann")
        a_device.set_product_name(m.group(1))
        return

    m = re.search(r"Windows|Linux|Ubuntu|Microsoft", val_pretty)
    if m:
        a_device.set_vendor("Microsoft Corporation" if "Windows" in val_pretty else "Linux")
        a_device.set_product_name(val_pretty)
        return


async def _walk_oid(
    a_device: Device,
    community: str,
    mpmodel: int,
    ident: ObjectIdentity,
    timeout: float = 1.0,
    retries: int = 5,
) -> None:
    """
    Walk a single base OID subtree and parse results into a_device.

    ``timeout`` (seconds) and ``retries`` are forwarded verbatim to the
    pysnmp ``UdpTransportTarget`` so a caller-controlled override can tune
    the per-operation UDP timeout and retry count. Both values are already
    bounds-validated at the API boundary by ``SnmpScanOverrides``; the
    defaults reproduce pysnmp's historic behaviour for the CLI path.
    """
    objects = walk_cmd(
        SnmpEngine(),
        CommunityData(community, mpModel=mpmodel),
        await UdpTransportTarget.create((a_device.ip_addr, 161), timeout=timeout, retries=retries),
        ContextData(),
        ObjectType(ident),
        lexicographicMode=False,
    )
    async for errorIndication, errorStatus, errorIndex, varBinds in objects:
        if errorIndication or errorStatus:
            if errorIndication:
                logger.error("SNMP Walk error: {errorIndication}", errorIndication=errorIndication)
            else:
                logger.error(
                    "SNMP Walk error: {errorStatus_prettyPrint}", errorStatus_prettyPrint=errorStatus.prettyPrint()
                )
            break
        for oid, val in varBinds:
            id_str = oid.prettyPrint()
            val_str = val.prettyPrint()

            # Deep logging (success lines)
            if VERBOSE:
                logger.success("SNMP Walk: {id_str} = {val_str}", id_str=id_str, val_str=val_str)

            # SNMPv2 system group (identity, description) with both labeled and numeric fallback
            if id_str == "SNMPv2-MIB::sysDescr.0" or id_str.endswith("mib-2.1.1.0"):
                parse_sysDescr(val_str, a_device)
            elif id_str == "SNMPv2-MIB::sysContact.0" or id_str.endswith("mib-2.1.4.0"):
                a_device.set_contact(val_str)
            elif id_str == "SNMPv2-MIB::sysName.0" or id_str.endswith("mib-2.1.5.0"):
                a_device.set_sys_name(val_str)
            elif id_str == "SNMPv2-MIB::sysLocation.0" or id_str.endswith("mib-2.1.6.0"):
                a_device.set_location(val_str)

            # PROFINET LLDP extension: device NameOfStation (fallback by numeric OID if labels unresolved)
            # LLDP org-defined base: 1.0.8802.1.1.2.1.5.<org>. For PI (Profinet), org=3791.
            # Observed in logs: ...1.2.1.1.6.x carries NameOfStation string.
            if (
                id_str.startswith("LLDP-EXT-PNO-MIB::lldpXPnoLocPortNoS")
                or id_str.endswith(".1.1.6.1")
                or id_str.endswith(".1.1.6.2")
            ):
                a_device.set_sys_name(val_str)


# ---------------------------------------------------------------------------
# LLDP neighbor correlation (SCAN-022)
# ---------------------------------------------------------------------------
#
# The scanned switch lists its LLDP neighbors in ``lldpRemTable`` with
# SysName / PortId / SysDesc and a management IP in ``lldpRemManAddrTable``,
# but (on the SCALANCE XC208G, ``lldpRemChassisIdSubtype`` = 7 = local) NO
# neighbor MAC. The real MACs live in the bridge forwarding DB. The proven
# correlation path is:
#
#   lldpRemTable[localPort] -> {SysName, mgmtIP, SysDesc, PortId}
#     JOIN via BridgePort<->ifIndex with
#   dot1dTpFdbTable[bridgePort] -> MAC
#
# All four tables are walked with the numeric-OID-fallback pattern; a switch
# that does not expose one of them is tolerated (the table simply yields no
# rows and the join degrades gracefully).

# Numeric base OIDs (verified responsive on the real switch with -v2c).
_OID_LLDP_REM_TABLE = "1.0.8802.1.1.2.1.4.1.1"
_OID_LLDP_REM_MAN_ADDR = "1.0.8802.1.1.2.1.4.2.1"
_OID_FDB_PORT = "1.3.6.1.2.1.17.4.3.1.2"
_OID_BASE_PORT_IFINDEX = "1.3.6.1.2.1.17.1.4.1.2"


async def _collect_walk(
    target_ip: Optional[str],
    community: str,
    mpmodel: int,
    base_oid: str,
    timeout: float,
    retries: int,
) -> Dict[str, str]:
    """Walk a numeric base OID subtree and return ``{oid_str: val_str}``.

    Unlike :func:`_walk_oid` this collects raw OID/value pairs for offline
    correlation instead of parsing them into a device. A failed walk returns
    an empty mapping so a missing table never aborts the wider scan.
    """
    result: Dict[str, str] = {}
    try:
        objects = walk_cmd(
            SnmpEngine(),
            CommunityData(community, mpModel=mpmodel),
            await UdpTransportTarget.create((target_ip, 161), timeout=timeout, retries=retries),
            ContextData(),
            ObjectType(ObjectIdentity(base_oid)),
            lexicographicMode=False,
        )
        async for errorIndication, errorStatus, _errorIndex, varBinds in objects:
            if errorIndication or errorStatus:
                logger.warning(
                    "SNMP collect walk error on {base_oid}: {err}",
                    base_oid=base_oid,
                    err=errorIndication or errorStatus.prettyPrint(),
                )
                break
            for oid, val in varBinds:
                result[oid.prettyPrint()] = val.prettyPrint()
    except Exception as exc:
        logger.warning(
            "SNMP collect walk failed on {base_oid}: {exc}",
            base_oid=base_oid,
            exc=exc,
        )
    return result


# pysnmp ``prettyPrint`` resolves leading sub-identifiers to MIB names
# (e.g. ``SNMPv2-SMI::iso.0.8802...`` or ``SNMPv2-SMI::mib-2.17.4.3...``).
# To compare against the numeric base OIDs we substitute the known textual
# prefixes back to their numeric dotted form. ``snmpwalk -On`` output (used
# in the unit fixtures) is already numeric and passes through unchanged.
_OID_TEXT_PREFIXES = {
    "SNMPv2-SMI::iso.": "1.",
    "SNMPv2-SMI::mib-2.": "1.3.6.1.2.1.",
    "SNMPv2-SMI::internet.": "1.3.6.1.",
    "SNMPv2-SMI::private.": "1.3.6.1.4.",
    "SNMPv2-SMI::enterprises.": "1.3.6.1.4.1.",
    "iso.": "1.",
}


def _numeric_oid(oid_str: str) -> str:
    """Normalize a pysnmp ``prettyPrint`` OID string to numeric dotted form."""
    normalized = oid_str[1:] if oid_str.startswith(".") else oid_str
    for prefix, numeric in _OID_TEXT_PREFIXES.items():
        if normalized.startswith(prefix):
            return numeric + normalized[len(prefix) :]
    return normalized


def _strip_base(oid_str: str, base: str) -> Optional[str]:
    """Return the index suffix of ``oid_str`` relative to numeric ``base``."""
    normalized = _numeric_oid(oid_str)
    prefix = base + "."
    if normalized.startswith(prefix):
        return normalized[len(prefix) :]
    return None


def _hexstring_to_mac(val_str: str) -> Optional[str]:
    """Convert a pysnmp Hex-STRING (``00 01 05 2B AE A2``) to ``aa:bb:..``."""
    octets = [tok for tok in val_str.strip().split() if tok]
    if len(octets) != 6:
        return None
    try:
        return ":".join(f"{int(tok, 16):02x}" for tok in octets)
    except ValueError:
        return None


def _bridgeport_index_to_mac(suffix: str) -> Optional[str]:
    """Convert a dotted decimal FDB index (``48.184.81.49.6.132``) to a MAC."""
    parts = suffix.split(".")
    if len(parts) != 6:
        return None
    try:
        return ":".join(f"{int(p):02x}" for p in parts)
    except ValueError:
        return None


def _parse_lldp_rem(rem: Dict[str, str]) -> Dict[Tuple[str, ...], Dict[str, str]]:
    """Group ``lldpRemTable`` rows by their ``(timeMark, localPort, remIndex)``.

    Column semantics (verified on the SCALANCE): col 5 = SysName,
    7 = PortId, 8 = PortDesc, 9 = SysName(dup), 10 = SysDesc. The index shape
    is ``<col>.<timeMark>.<localPortNum>.<remIndex>`` where the 2nd component
    is the local port number (= ifIndex on this switch).
    """
    by_key: Dict[Tuple[str, ...], Dict[str, str]] = {}
    col_field = {"5": "sys_name", "7": "port_id", "8": "port_desc", "9": "sys_name", "10": "sys_desc"}
    for oid_str, val_str in rem.items():
        suffix = _strip_base(oid_str, _OID_LLDP_REM_TABLE)
        if suffix is None:
            continue
        parts = suffix.split(".")
        if len(parts) != 4:
            continue
        col, key = parts[0], tuple(parts[1:])
        field = col_field.get(col)
        if field is None:
            continue
        row = by_key.setdefault(key, {})
        if val_str and (field not in row or field == "sys_desc"):
            row[field] = val_str
    return by_key


def _parse_lldp_man_addr(man: Dict[str, str]) -> Dict[Tuple[str, ...], str]:
    """Map ``lldpRemManAddrTable`` rows to ``{(timeMark, localPort, remIndex): ipv4}``.

    The trailing ``.1.4.<a.b.c.d>`` of the OID encodes the neighbor IPv4
    (subtype 1 = IPv4, length 4). The leading three components match the
    ``lldpRemTable`` index key.
    """
    by_key: Dict[Tuple[str, ...], str] = {}
    for oid_str in man:
        suffix = _strip_base(oid_str, _OID_LLDP_REM_MAN_ADDR)
        if suffix is None:
            continue
        parts = suffix.split(".")
        # <col>.<timeMark>.<localPort>.<remIndex>.<addrSubtype>.<addrLen>.<a.b.c.d>
        if len(parts) < 8:
            continue
        key = tuple(parts[1:4])
        ipv4 = ".".join(parts[-4:])
        by_key.setdefault(key, ipv4)
    return by_key


def _parse_fdb(fdb: Dict[str, str]) -> Dict[int, List[str]]:
    """Map ``dot1dTpFdbTable`` (col .2) to ``{bridgePort: [mac, ...]}``."""
    by_port: Dict[int, List[str]] = {}
    for oid_str, val_str in fdb.items():
        suffix = _strip_base(oid_str, _OID_FDB_PORT)
        if suffix is None:
            continue
        mac = _bridgeport_index_to_mac(suffix)
        if mac is None:
            continue
        try:
            port = int(val_str)
        except ValueError:
            continue
        by_port.setdefault(port, []).append(mac)
    return by_port


def _parse_base_port_ifindex(base: Dict[str, str]) -> Dict[int, int]:
    """Map ``dot1dBasePortIfIndex`` to ``{bridgePort: ifIndex}``."""
    by_port: Dict[int, int] = {}
    for oid_str, val_str in base.items():
        suffix = _strip_base(oid_str, _OID_BASE_PORT_IFINDEX)
        if suffix is None:
            continue
        try:
            by_port[int(suffix)] = int(val_str)
        except ValueError:
            continue
    return by_port


def correlate_neighbors(
    rem: Dict[str, str],
    man: Dict[str, str],
    fdb: Dict[str, str],
    base_port: Dict[str, str],
) -> List[Neighbor]:
    """Join the four SNMP tables into a list of correlated :class:`Neighbor`.

    For each ``lldpRemTable`` row we know the local port (= ifIndex). We map
    ifIndex back to the bridge port(s) via ``dot1dBasePortIfIndex`` and pull
    the learned MAC(s) for that bridge port from ``dot1dTpFdbTable``. A
    neighbor is emitted only when at least a MAC or an IPv4 is known.
    """
    rem_rows = _parse_lldp_rem(rem)
    man_addr = _parse_lldp_man_addr(man)
    fdb_by_port = _parse_fdb(fdb)
    ifindex_by_bridgeport = _parse_base_port_ifindex(base_port)

    macs_by_ifindex: Dict[int, List[str]] = {}
    for bridge_port, macs in fdb_by_port.items():
        ifindex = ifindex_by_bridgeport.get(bridge_port, bridge_port)
        macs_by_ifindex.setdefault(ifindex, []).extend(macs)

    neighbors: List[Neighbor] = []
    for key, row in rem_rows.items():
        try:
            local_port = int(key[1])
        except (IndexError, ValueError):
            continue
        ipv4 = man_addr.get(key)
        port_macs = macs_by_ifindex.get(local_port, [])
        mac = port_macs[0] if len(port_macs) == 1 else (port_macs[0] if port_macs else None)
        if mac is None and ipv4 is None:
            continue
        neighbor = Neighbor(local_port)
        neighbor.set_mac_addr(mac)
        if ipv4:
            neighbor.ip_addr = ipv4
        neighbor.set_sys_name(row.get("sys_name"))
        neighbor.port_id = row.get("port_id")
        neighbor.port_desc = row.get("port_desc")
        sys_desc = row.get("sys_desc")
        if sys_desc:
            parse_sysDescr(sys_desc, neighbor)
        neighbors.append(neighbor)
    return neighbors


async def _walk_neighbors(
    a_device: Device,
    community: str,
    mpmodel: int,
    timeout: float,
    retries: int,
) -> None:
    """Walk the four neighbor tables and attach correlated neighbors."""
    rem = await _collect_walk(a_device.ip_addr, community, mpmodel, _OID_LLDP_REM_TABLE, timeout, retries)
    man = await _collect_walk(a_device.ip_addr, community, mpmodel, _OID_LLDP_REM_MAN_ADDR, timeout, retries)
    fdb = await _collect_walk(a_device.ip_addr, community, mpmodel, _OID_FDB_PORT, timeout, retries)
    base_port = await _collect_walk(a_device.ip_addr, community, mpmodel, _OID_BASE_PORT_IFINDEX, timeout, retries)
    if not rem:
        logger.warning("snmp_scan: lldpRemTable empty for {ip}; no neighbors discovered", ip=a_device.ip_addr)
        return
    for neighbor in correlate_neighbors(rem, man, fdb, base_port):
        a_device.add_neighbor(neighbor)
    logger.info(
        "snmp_scan: correlated {n} LLDP neighbor(s) for {ip}",
        n=len(a_device.neighbors),
        ip=a_device.ip_addr,
    )


async def main(a_device: Device, community: str, mpmodel: int, timeout: float = 1.0, retries: int = 5) -> None:
    """
    Walk relevant OIDs with robust MIB resolution:
    - SNMPv2-MIB::system
    - LLDP-EXT-PNO-MIB::lldpXPnoLocTable (for NameOfStation and PNIO discovery data)
    Fallback: numeric OIDs for LLDP org extension if MIB label resolution fails.

    ``timeout`` (seconds) and ``retries`` are forwarded to every per-OID
    walk so a caller-controlled override propagates to the pysnmp UDP
    transport.
    """
    # 1) SNMPv2 system
    try:
        sys_ident = _resolve_oid("SNMPv2-MIB", "system")
        await _walk_oid(a_device, community, mpmodel, sys_ident, timeout=timeout, retries=retries)
    except Exception as exc:
        logger.warning("SNMPv2-MIB system walk failed or MIB unresolved: {exc}", exc=exc)

    # 2) PROFINET LLDP extension (uses provided MIBs under ./mibs)
    pn_walked = False
    try:
        pno_ident = _resolve_oid("LLDP-EXT-PNO-MIB", "lldpXPnoLocTable")
        await _walk_oid(a_device, community, mpmodel, pno_ident, timeout=timeout, retries=retries)
        pn_walked = True
    except Exception as exc:
        logger.warning("LLDP-EXT-PNO-MIB walk failed or MIB unresolved: {exc}", exc=exc)

    # 2b) Fallback: numeric OID for LLDP org-defined data (PI OUI=3791)
    # Base: 1.0.8802.1.1.2.1.5.3791 (organizational MIBs), observed table paths in logs under .1.2 and .1.3
    if not pn_walked:
        try:
            # Attempt both likely subtrees seen in logs
            for suffix in (".1.2", ".1.3"):
                numeric_pno_base = ObjectIdentity(f"1.0.8802.1.1.2.1.5.3791{suffix}")
                await _walk_oid(a_device, community, mpmodel, numeric_pno_base, timeout=timeout, retries=retries)
        except Exception as exc:
            logger.warning("Numeric LLDP PNO walk failed: {exc}", exc=exc)

    # 3) LLDP neighbor correlation (SCAN-022): walk lldpRemTable +
    # lldpRemManAddrTable + dot1dTpFdbTable + dot1dBasePortIfIndex and join
    # them into neighbor records with real MACs. Tolerant of missing tables.
    try:
        await _walk_neighbors(a_device, community, mpmodel, timeout, retries)
    except Exception as exc:
        logger.warning("snmp_scan: LLDP neighbor correlation failed: {exc}", exc=exc)


async def walker(a_device: Device, community: str, mpmodel: int, timeout: float = 1.0, retries: int = 5) -> None:
    """
    Entry point used by the SNMP module: perform async walks for relevant OIDs.

    Native ``async def`` per HC8 — callers must ``await`` this directly from
    a running event loop. The legacy ``asyncio.run(...)`` wrapper was removed
    so the function composes cleanly with the orchestrator-managed loop.

    ``timeout`` (seconds) and ``retries`` are forwarded to the pysnmp UDP
    transport; both are bounds-validated upstream by ``SnmpScanOverrides``.
    """
    await main(a_device, community, mpmodel, timeout=timeout, retries=retries)
