"""PROFINET DCP wire codec — pure, dependency-free frame build/parse.

SCAN-029 replaced the previous ``scapy`` / ``scapy.contrib.pnio_dcp``
dependency with this in-house codec. The module is deliberately
**I/O-free**: it only turns Python values into bytes and bytes back into
Python values, which makes the whole protocol surface unit-testable
without ``NET_RAW`` privileges, without a live PROFINET segment, and
without any third-party packet library.

Protocol summary (IEC 61158-6-10 / IEC 61784-2, DCP part)::

    Ethernet II header      dst(6) src(6) ethertype(2) = 0x8892
    PROFINET IO header      FrameID(2)
                              0xFEFE — DCP Identify request  (multicast)
                              0xFEFF — DCP Identify response (unicast)
    DCP PDU header          ServiceID(1) ServiceType(1) Xid(4)
                            ResponseDelay/Reserved(2) DCPDataLength(2)
    DCP blocks              [ Option(1) SubOption(1) BlockLength(2)
                              BlockPayload(BlockLength) Pad(BlockLength % 2) ]*

``BlockLength`` counts the bytes that follow the length field itself and
therefore *includes* the two-byte ``BlockInfo`` that leads the payload of
every response block. Blocks are padded to an even byte count.

There is NO IP layer anywhere in DCP — it is a pure Layer-2 broadcast
protocol, which is exactly why an IP-oriented tool (nmap and friends)
cannot stand in for it and a raw ``AF_PACKET`` socket is used instead
(see :mod:`otalon_scan.modules.pn_discovery.raw_socket`).
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from otalon_scan.utils.mac import InvalidMacError, canonicalise

__all__ = [
    "DCP_DEVICE_ROLES",
    "DCP_IDENTIFY_MULTICAST_MAC",
    "ETHERTYPE_PROFINET",
    "FRAME_ID_IDENTIFY_REQUEST",
    "FRAME_ID_IDENTIFY_RESPONSE",
    "DcpBlock",
    "DcpPdu",
    "DcpStation",
    "EthernetFrame",
    "build_identify_request",
    "decode_station",
    "format_ipv4",
    "format_mac",
    "encode_mac",
    "parse_blocks",
    "parse_dcp_pdu",
    "parse_ethernet_frame",
]

# ---------------------------------------------------------------------------
# Wire constants
# ---------------------------------------------------------------------------

ETHERTYPE_PROFINET: int = 0x8892

FRAME_ID_IDENTIFY_REQUEST: int = 0xFEFE
FRAME_ID_IDENTIFY_RESPONSE: int = 0xFEFF

SERVICE_ID_IDENTIFY: int = 0x05
SERVICE_TYPE_REQUEST: int = 0x00
SERVICE_TYPE_RESPONSE_SUCCESS: int = 0x01

#: Standard PROFINET DCP Identify-All multicast destination.
DCP_IDENTIFY_MULTICAST_MAC: str = "01:0e:cf:00:00:00"

OPTION_IP: int = 0x01
SUBOPTION_IP_MAC_ADDRESS: int = 0x01
SUBOPTION_IP_PARAMETER: int = 0x02
SUBOPTION_IP_FULL_SUITE: int = 0x03

OPTION_DEVICE_PROPERTIES: int = 0x02
SUBOPTION_DEVICE_VENDOR: int = 0x01
SUBOPTION_NAME_OF_STATION: int = 0x02
SUBOPTION_DEVICE_ROLE: int = 0x04

OPTION_ALL_SELECTOR: int = 0xFF
SUBOPTION_ALL_SELECTOR: int = 0xFF

ETHERNET_HEADER_LENGTH: int = 14
DCP_PDU_HEADER_LENGTH: int = 10
BLOCK_HEADER_LENGTH: int = 4
BLOCK_INFO_LENGTH: int = 2

#: Minimum Ethernet payload; short frames are zero-padded before transmit.
MIN_ETHERNET_FRAME_LENGTH: int = 60

#: Device-role labels, indexed by the ``DeviceRoleDetails`` byte.
#:
#: This table is carried over VERBATIM from the previous scapy-based
#: implementation so operator-facing output does not silently change with
#: SCAN-029. Note that IEC 61158 specifies ``DeviceRoleDetails`` as a bit
#: field (bit0 IO-Device, bit1 IO-Controller, bit2 IO-Multidevice,
#: bit3 IO-Supervisor); re-interpreting it is a behaviour change and
#: therefore explicitly out of scope here.
DCP_DEVICE_ROLES: List[str] = [
    "No Role",
    "Supervisor",
    "Primary",
    "Primary Supervisor",
    "Secondary",
    "Secondary Supervisor",
    "Primary/Secondary",
    "Primary/Secondary Supervisor",
]


class DcpParseError(ValueError):
    """Raised when a byte string cannot be decoded as the expected DCP unit.

    Callers that sniff a live segment SHOULD catch this and drop the frame:
    a multicast capture legitimately surfaces truncated or unrelated
    PROFINET traffic and a single bad frame must not abort a scan.
    """


# ---------------------------------------------------------------------------
# Primitive codecs
# ---------------------------------------------------------------------------


def format_mac(raw: bytes) -> str:
    """Return the canonical ``aa:bb:cc:dd:ee:ff`` form of six MAC bytes.

    Args:
        raw: Exactly six bytes of a MAC address in wire order.

    Returns:
        The canonical lowercase colon-separated MAC string.

    Raises:
        DcpParseError: If ``raw`` is not exactly six bytes long.
    """
    if len(raw) != 6:
        raise DcpParseError(f"MAC address must be 6 bytes, got {len(raw)}")
    return ":".join(f"{octet:02x}" for octet in raw)


def encode_mac(mac: str) -> bytes:
    """Return the six wire bytes of a MAC address given in any common form.

    Args:
        mac: MAC address in any form accepted by
            :func:`otalon_scan.utils.mac.canonicalise`.

    Returns:
        The six-byte wire representation.

    Raises:
        DcpParseError: If ``mac`` does not parse as a MAC address.
    """
    try:
        canonical = canonicalise(mac)
    except InvalidMacError as exc:
        raise DcpParseError(f"cannot encode {mac!r} as a MAC address") from exc
    return bytes(int(octet, 16) for octet in canonical.split(":"))


def format_ipv4(raw: bytes) -> str:
    """Return the dotted-quad form of four IPv4 bytes.

    Args:
        raw: Exactly four bytes of an IPv4 address in network order.

    Returns:
        The dotted-quad string, e.g. ``"192.168.0.10"``.

    Raises:
        DcpParseError: If ``raw`` is not exactly four bytes long.
    """
    if len(raw) != 4:
        raise DcpParseError(f"IPv4 address must be 4 bytes, got {len(raw)}")
    return ".".join(str(octet) for octet in raw)


# ---------------------------------------------------------------------------
# Structures
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class EthernetFrame:
    """A decoded Ethernet II header plus its undecoded payload."""

    destination: str
    source: str
    ethertype: int
    payload: bytes


@dataclass(frozen=True)
class DcpBlock:
    """One DCP block: its ``(option, suboption)`` key and raw payload.

    Attributes:
        option: The DCP option byte.
        suboption: The DCP suboption byte.
        payload: ``BlockLength`` bytes of block payload, ``BlockInfo``
            included and padding excluded.
    """

    option: int
    suboption: int
    payload: bytes

    @property
    def data(self) -> bytes:
        """Return the payload with the leading two ``BlockInfo`` bytes removed."""
        return self.payload[BLOCK_INFO_LENGTH:]


@dataclass(frozen=True)
class DcpPdu:
    """A decoded PROFINET DCP protocol data unit."""

    frame_id: int
    service_id: int
    service_type: int
    xid: int
    blocks: List[DcpBlock] = field(default_factory=list)

    @property
    def is_identify_response(self) -> bool:
        """Return ``True`` for a successful DCP Identify response PDU."""
        return self.frame_id == FRAME_ID_IDENTIFY_RESPONSE and self.service_id == SERVICE_ID_IDENTIFY


@dataclass(frozen=True)
class DcpStation:
    """The subset of DCP Identify data this scanner surfaces per station.

    Field names and their empty-string default mirror the dict shape the
    previous scapy-based implementation produced, so the API serializer,
    the ``raw_results`` DataFrame and the vendor mapping stay unchanged.
    """

    mac_address: str
    device_vendor_value: str = ""
    name_of_station: str = ""
    device_role_details: str = ""
    ip_address: str = ""
    subnet_mask: str = ""
    standard_gateway: str = ""

    def as_dict(self) -> Dict[str, str]:
        """Return the legacy flat dict consumed downstream by ``start.py``."""
        return {
            "mac_address": self.mac_address,
            "device_vendor_value": self.device_vendor_value,
            "name_of_station": self.name_of_station,
            "device_role_details": self.device_role_details,
            "ip_address": self.ip_address,
            "subnet_mask": self.subnet_mask,
            "standard_gateway": self.standard_gateway,
        }


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def build_identify_request(
    source_mac: str,
    destination_mac: str = DCP_IDENTIFY_MULTICAST_MAC,
    xid: int = 0x00000001,
) -> bytes:
    """Build a complete ``DCP Identify All`` request frame.

    The request carries a single ``All Selector`` block
    (option ``0xFF`` / suboption ``0xFF``, zero block length), which asks
    every station in the broadcast domain to answer with its full property
    set. The frame is zero-padded to the 60-byte Ethernet minimum so it can
    be handed to a raw socket unchanged.

    Args:
        source_mac: The sending interface's MAC address.
        destination_mac: L2 destination; defaults to the PROFINET DCP
            Identify multicast group.
        xid: Transaction identifier echoed by responding stations.

    Returns:
        The ready-to-transmit Ethernet frame.

    Raises:
        DcpParseError: If either MAC address fails to parse.
    """
    ethernet_header = encode_mac(destination_mac) + encode_mac(source_mac) + struct.pack("!H", ETHERTYPE_PROFINET)
    all_selector_block = struct.pack("!BBH", OPTION_ALL_SELECTOR, SUBOPTION_ALL_SELECTOR, 0)
    dcp_pdu = (
        struct.pack("!H", FRAME_ID_IDENTIFY_REQUEST)
        + struct.pack("!BB", SERVICE_ID_IDENTIFY, SERVICE_TYPE_REQUEST)
        + struct.pack("!I", xid & 0xFFFFFFFF)
        + struct.pack("!H", 1)
        + struct.pack("!H", len(all_selector_block))
        + all_selector_block
    )
    frame = ethernet_header + dcp_pdu
    if len(frame) < MIN_ETHERNET_FRAME_LENGTH:
        frame += b"\x00" * (MIN_ETHERNET_FRAME_LENGTH - len(frame))
    return frame


# ---------------------------------------------------------------------------
# Response parsing
# ---------------------------------------------------------------------------


def parse_ethernet_frame(frame: bytes) -> EthernetFrame:
    """Split an Ethernet II frame into its header fields and payload.

    Args:
        frame: The raw frame as read from the wire (no FCS expected).

    Returns:
        The decoded :class:`EthernetFrame`.

    Raises:
        DcpParseError: If ``frame`` is shorter than an Ethernet II header.
    """
    if len(frame) < ETHERNET_HEADER_LENGTH:
        raise DcpParseError(f"frame too short for an Ethernet header: {len(frame)} bytes")
    (ethertype,) = struct.unpack("!H", frame[12:ETHERNET_HEADER_LENGTH])
    return EthernetFrame(
        destination=format_mac(frame[0:6]),
        source=format_mac(frame[6:12]),
        ethertype=ethertype,
        payload=frame[ETHERNET_HEADER_LENGTH:],
    )


def parse_blocks(data: bytes) -> List[DcpBlock]:
    """Decode the concatenated DCP blocks of a response PDU.

    Parsing is tolerant: a trailing run of bytes too short to hold another
    block header, or a block whose declared length overruns the buffer,
    terminates the scan of ``data`` instead of raising. Live captures
    routinely contain Ethernet padding after the last block.

    Args:
        data: ``DCPDataLength`` bytes of block area.

    Returns:
        Every fully-contained block, in wire order.
    """
    blocks: List[DcpBlock] = []
    offset = 0
    while offset + BLOCK_HEADER_LENGTH <= len(data):
        option, suboption, block_length = struct.unpack("!BBH", data[offset : offset + BLOCK_HEADER_LENGTH])
        payload_start = offset + BLOCK_HEADER_LENGTH
        payload_end = payload_start + block_length
        if payload_end > len(data):
            break
        if option == 0 and suboption == 0 and block_length == 0:
            break
        blocks.append(DcpBlock(option=option, suboption=suboption, payload=data[payload_start:payload_end]))
        offset = payload_end + (block_length % 2)
    return blocks


def parse_dcp_pdu(payload: bytes) -> DcpPdu:
    """Decode a PROFINET IO/DCP PDU (everything after the Ethernet header).

    Args:
        payload: FrameID followed by the DCP PDU header and block area.

    Returns:
        The decoded :class:`DcpPdu`.

    Raises:
        DcpParseError: If ``payload`` is too short to hold the FrameID plus
            the fixed DCP PDU header.
    """
    minimum = 2 + DCP_PDU_HEADER_LENGTH
    if len(payload) < minimum:
        raise DcpParseError(f"payload too short for a DCP PDU: {len(payload)} bytes")
    (frame_id,) = struct.unpack("!H", payload[0:2])
    service_id, service_type = struct.unpack("!BB", payload[2:4])
    (xid,) = struct.unpack("!I", payload[4:8])
    (data_length,) = struct.unpack("!H", payload[10:minimum])
    block_area = payload[minimum : minimum + data_length]
    return DcpPdu(
        frame_id=frame_id,
        service_id=service_id,
        service_type=service_type,
        xid=xid,
        blocks=parse_blocks(block_area),
    )


def _decode_text(raw: bytes) -> str:
    """Return ``raw`` as text, dropping trailing NULs and undecodable bytes."""
    return raw.rstrip(b"\x00").decode("utf-8", errors="ignore")


def _decode_device_role(raw: bytes) -> str:
    """Map a ``DeviceRoleDetails`` payload to its label, clamping out-of-range values."""
    if not raw:
        return ""
    index = raw[0]
    if index >= len(DCP_DEVICE_ROLES):
        index = len(DCP_DEVICE_ROLES) - 1
    return DCP_DEVICE_ROLES[index]


def _decode_ip_parameters(raw: bytes) -> Optional[Dict[str, str]]:
    """Return address/mask/gateway from an IP-parameter block payload, if complete."""
    if len(raw) < 12:
        return None
    return {
        "ip_address": format_ipv4(raw[0:4]),
        "subnet_mask": format_ipv4(raw[4:8]),
        "standard_gateway": format_ipv4(raw[8:12]),
    }


def _station_fields_from_blocks(blocks: List[DcpBlock]) -> Dict[str, str]:
    """Fold the interesting DCP blocks into the flat station field mapping.

    Later blocks of the same ``(option, suboption)`` win, matching the
    previous implementation's last-block-wins behaviour.
    """
    fields: Dict[str, str] = {}
    for block in blocks:
        key = (block.option, block.suboption)
        if key == (OPTION_DEVICE_PROPERTIES, SUBOPTION_DEVICE_VENDOR):
            fields["device_vendor_value"] = _decode_text(block.data)
        elif key == (OPTION_DEVICE_PROPERTIES, SUBOPTION_NAME_OF_STATION):
            fields["name_of_station"] = _decode_text(block.data)
        elif key == (OPTION_DEVICE_PROPERTIES, SUBOPTION_DEVICE_ROLE):
            fields["device_role_details"] = _decode_device_role(block.data)
        elif key in (
            (OPTION_IP, SUBOPTION_IP_PARAMETER),
            (OPTION_IP, SUBOPTION_IP_FULL_SUITE),
        ):
            parameters = _decode_ip_parameters(block.data)
            if parameters is not None:
                fields.update(parameters)
    return fields


def decode_station(frame: bytes) -> Optional[DcpStation]:
    """Decode one sniffed Ethernet frame into a :class:`DcpStation`.

    Args:
        frame: A raw frame captured on the scan interface.

    Returns:
        The station description, or ``None`` if the frame is not a
        PROFINET DCP Identify response (wrong EtherType, wrong FrameID,
        or too short/malformed to decode).
    """
    try:
        ethernet = parse_ethernet_frame(frame)
        if ethernet.ethertype != ETHERTYPE_PROFINET:
            return None
        pdu = parse_dcp_pdu(ethernet.payload)
    except DcpParseError:
        return None
    if not pdu.is_identify_response:
        return None
    return DcpStation(mac_address=ethernet.source, **_station_fields_from_blocks(pdu.blocks))
