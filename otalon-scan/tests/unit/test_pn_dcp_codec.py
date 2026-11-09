"""SCAN-029 — regression tests for the in-house PROFINET DCP codec.

These tests replace the coverage the previous implementation got for
free from ``scapy.contrib.pnio_dcp``. They exercise both directions of
the wire format without any privileged I/O:

- **Request construction** — EtherType, FrameID, service bytes, the
  ``All Selector`` block, and the 60-byte Ethernet minimum.
- **Block parsing** — TLV walk including odd-length padding, truncated
  trailing bytes, and declared lengths that overrun the buffer.
- **Station decoding** — Vendor / Station name / Role / IP / Subnet mask
  / Gateway extraction from a synthesised Identify response, plus
  rejection of frames that are not DCP Identify responses.

The synthetic response frames below are assembled from the field layout
documented in :mod:`otalon_scan.modules.pn_discovery.dcp`; they are NOT captured
traffic and contain no third-party code.
"""

from __future__ import annotations

import struct
from typing import List, Tuple

import pytest

from otalon_scan.modules.pn_discovery.dcp import (
    DCP_DEVICE_ROLES,
    DCP_IDENTIFY_MULTICAST_MAC,
    ETHERTYPE_PROFINET,
    FRAME_ID_IDENTIFY_REQUEST,
    FRAME_ID_IDENTIFY_RESPONSE,
    DcpParseError,
    build_identify_request,
    decode_station,
    encode_mac,
    format_ipv4,
    format_mac,
    parse_blocks,
    parse_dcp_pdu,
    parse_ethernet_frame,
)

LOCAL_MAC = "00:11:22:33:44:55"
STATION_MAC = "aa:bb:cc:dd:ee:01"


# ---------------------------------------------------------------------------
# Frame builders (test fixtures, not production code)
# ---------------------------------------------------------------------------


def _block(option: int, suboption: int, payload: bytes) -> bytes:
    """Assemble one DCP block with its length header and even-byte padding."""
    body = struct.pack("!BBH", option, suboption, len(payload)) + payload
    return body + (b"\x00" if len(payload) % 2 else b"")


def _identify_response(source_mac: str, blocks: bytes, frame_id: int = FRAME_ID_IDENTIFY_RESPONSE) -> bytes:
    """Assemble a complete Ethernet + DCP Identify response frame."""
    ethernet = encode_mac(LOCAL_MAC) + encode_mac(source_mac) + struct.pack("!H", ETHERTYPE_PROFINET)
    pdu = (
        struct.pack("!H", frame_id)
        + struct.pack("!BB", 0x05, 0x01)
        + struct.pack("!I", 0x00000001)
        + struct.pack("!H", 0)
        + struct.pack("!H", len(blocks))
        + blocks
    )
    frame = ethernet + pdu
    return frame + b"\x00" * max(0, 60 - len(frame))


def _full_station_blocks() -> bytes:
    """Return the block area of a station reporting every field this scanner reads."""
    return b"".join(
        [
            # IP option / IP-Parameter suboption: BlockInfo + ip + mask + gw
            _block(0x01, 0x02, struct.pack("!H", 1) + bytes([192, 168, 0, 10, 255, 255, 255, 0, 192, 168, 0, 1])),
            # Device properties / manufacturer-specific (odd payload → padded)
            _block(0x02, 0x01, struct.pack("!H", 0) + b"S7-1500"),
            # Device properties / name of station
            _block(0x02, 0x02, struct.pack("!H", 0) + b"plc-01"),
            # Device properties / device role: index 2 → "Primary"
            _block(0x02, 0x04, struct.pack("!H", 0) + bytes([0x02, 0x00])),
        ]
    )


# ---------------------------------------------------------------------------
# Primitive codecs
# ---------------------------------------------------------------------------


def test_format_mac_returns_canonical_lowercase() -> None:
    """Six wire bytes SHALL render as a canonical colon-separated MAC."""
    assert format_mac(bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01])) == STATION_MAC


@pytest.mark.parametrize("raw", [b"", b"\x00" * 5, b"\x00" * 7])
def test_format_mac_rejects_wrong_length(raw: bytes) -> None:
    """Anything other than exactly six bytes SHALL raise."""
    with pytest.raises(DcpParseError):
        format_mac(raw)


@pytest.mark.parametrize(
    "given",
    ["AA:BB:CC:DD:EE:01", "aa-bb-cc-dd-ee-01", "aabb.ccdd.ee01", "aabbccddee01"],
)
def test_encode_mac_accepts_every_canonicalisable_form(given: str) -> None:
    """All input forms accepted by ``canonicalise`` SHALL encode identically."""
    assert encode_mac(given) == bytes([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0x01])


def test_encode_mac_rejects_garbage() -> None:
    """A non-MAC string SHALL raise rather than produce silent zero bytes."""
    with pytest.raises(DcpParseError):
        encode_mac("not-a-mac")


def test_format_ipv4_roundtrip_and_length_guard() -> None:
    """Four bytes SHALL render dotted-quad; other lengths SHALL raise."""
    assert format_ipv4(bytes([192, 168, 0, 10])) == "192.168.0.10"
    with pytest.raises(DcpParseError):
        format_ipv4(bytes([192, 168, 0]))


# ---------------------------------------------------------------------------
# Request construction
# ---------------------------------------------------------------------------


def test_identify_request_has_correct_ethernet_header() -> None:
    """The request SHALL target the DCP multicast group with EtherType 0x8892."""
    frame = build_identify_request(source_mac=LOCAL_MAC)
    ethernet = parse_ethernet_frame(frame)

    assert ethernet.destination == DCP_IDENTIFY_MULTICAST_MAC
    assert ethernet.source == LOCAL_MAC
    assert ethernet.ethertype == ETHERTYPE_PROFINET


def test_identify_request_carries_identify_service_and_all_selector() -> None:
    """The request SHALL be a DCP Identify with a single All-Selector block."""
    frame = build_identify_request(source_mac=LOCAL_MAC, xid=0x0A0B0C0D)
    payload = parse_ethernet_frame(frame).payload

    assert struct.unpack("!H", payload[0:2])[0] == FRAME_ID_IDENTIFY_REQUEST
    assert payload[2] == 0x05
    assert payload[3] == 0x00
    assert struct.unpack("!I", payload[4:8])[0] == 0x0A0B0C0D
    assert struct.unpack("!H", payload[10:12])[0] == 4
    assert payload[12:16] == bytes([0xFF, 0xFF, 0x00, 0x00])


def test_identify_request_is_padded_to_minimum_ethernet_length() -> None:
    """The frame SHALL be zero-padded to the 60-byte Ethernet minimum.

    Content ends after the Ethernet header (14) + FrameID (2) + DCP PDU
    header (10) + the All-Selector block (4) = 30 bytes; everything after
    that is pure padding.
    """
    frame = build_identify_request(source_mac=LOCAL_MAC)
    content_length = 14 + 2 + 10 + 4

    assert len(frame) == 60
    assert frame[content_length:] == b"\x00" * (60 - content_length)


def test_identify_request_honours_custom_destination() -> None:
    """An operator-configured destination MAC SHALL be used verbatim."""
    frame = build_identify_request(source_mac=LOCAL_MAC, destination_mac="01:0E:CF:00:00:01")
    assert parse_ethernet_frame(frame).destination == "01:0e:cf:00:00:01"


def test_identify_request_rejects_unusable_source_mac() -> None:
    """A malformed source MAC SHALL raise instead of emitting a broken frame."""
    with pytest.raises(DcpParseError):
        build_identify_request(source_mac="zz:zz:zz:zz:zz:zz")


# ---------------------------------------------------------------------------
# Ethernet / PDU parsing
# ---------------------------------------------------------------------------


def test_parse_ethernet_frame_rejects_runt() -> None:
    """A frame shorter than the 14-byte Ethernet header SHALL raise."""
    with pytest.raises(DcpParseError):
        parse_ethernet_frame(b"\x00" * 13)


def test_parse_dcp_pdu_rejects_truncated_header() -> None:
    """A PDU shorter than FrameID + fixed header SHALL raise."""
    with pytest.raises(DcpParseError):
        parse_dcp_pdu(b"\xfe\xff\x05\x01")


def test_parse_dcp_pdu_reports_identify_response() -> None:
    """A well-formed response PDU SHALL be flagged as an Identify response."""
    frame = _identify_response(STATION_MAC, _full_station_blocks())
    pdu = parse_dcp_pdu(parse_ethernet_frame(frame).payload)

    assert pdu.is_identify_response
    assert pdu.frame_id == FRAME_ID_IDENTIFY_RESPONSE
    assert len(pdu.blocks) == 4


# ---------------------------------------------------------------------------
# TLV block parsing
# ---------------------------------------------------------------------------


def test_parse_blocks_walks_padding_correctly() -> None:
    """An odd-length block SHALL be followed by exactly one pad byte."""
    data = _block(0x02, 0x02, b"\x00\x00abc") + _block(0x02, 0x04, b"\x00\x00\x02\x00")
    blocks = parse_blocks(data)

    assert [(b.option, b.suboption) for b in blocks] == [(0x02, 0x02), (0x02, 0x04)]
    assert blocks[0].data == b"abc"
    assert blocks[1].data == b"\x02\x00"


def test_parse_blocks_stops_on_declared_length_overrun() -> None:
    """A block claiming more bytes than remain SHALL be dropped, not raise."""
    good = _block(0x02, 0x02, b"\x00\x00ok")
    truncated = struct.pack("!BBH", 0x02, 0x01, 40) + b"\x00\x00short"
    blocks = parse_blocks(good + truncated)

    assert len(blocks) == 1
    assert blocks[0].data == b"ok"


def test_parse_blocks_ignores_trailing_ethernet_padding() -> None:
    """Trailing zero padding after the last block SHALL terminate the walk."""
    blocks = parse_blocks(_block(0x02, 0x02, b"\x00\x00name") + b"\x00" * 10)

    assert len(blocks) == 1
    assert blocks[0].data == b"name"


def test_parse_blocks_on_empty_input_returns_empty_list() -> None:
    """An empty block area SHALL yield no blocks."""
    assert parse_blocks(b"") == []


def test_block_data_strips_block_info() -> None:
    """``DcpBlock.data`` SHALL exclude the two leading BlockInfo bytes."""
    (block,) = parse_blocks(_block(0x02, 0x02, struct.pack("!H", 0x1234) + b"payload"))
    assert block.payload[:2] == b"\x12\x34"
    assert block.data == b"payload"


# ---------------------------------------------------------------------------
# Station decoding — the operator-visible acceptance surface
# ---------------------------------------------------------------------------


def test_decode_station_extracts_every_reported_field() -> None:
    """Vendor / Station / Role / IP / Mask / Gateway SHALL all be recovered."""
    station = decode_station(_identify_response(STATION_MAC, _full_station_blocks()))

    assert station is not None
    assert station.as_dict() == {
        "mac_address": STATION_MAC,
        "device_vendor_value": "S7-1500",
        "name_of_station": "plc-01",
        "device_role_details": "Primary",
        "ip_address": "192.168.0.10",
        "subnet_mask": "255.255.255.0",
        "standard_gateway": "192.168.0.1",
    }


def test_decode_station_defaults_missing_fields_to_empty_string() -> None:
    """A station reporting only its name SHALL leave the rest empty, not None."""
    station = decode_station(_identify_response(STATION_MAC, _block(0x02, 0x02, b"\x00\x00io-2")))

    assert station is not None
    assert station.name_of_station == "io-2"
    assert station.ip_address == ""
    assert station.device_vendor_value == ""
    assert station.device_role_details == ""


def test_decode_station_accepts_full_ip_suite_block() -> None:
    """The Full-IP-Suite suboption SHALL populate the same IP fields."""
    payload = struct.pack("!H", 1) + bytes([10, 0, 0, 5, 255, 255, 0, 0, 10, 0, 0, 1]) + bytes(16)
    station = decode_station(_identify_response(STATION_MAC, _block(0x01, 0x03, payload)))

    assert station is not None
    assert station.ip_address == "10.0.0.5"
    assert station.subnet_mask == "255.255.0.0"
    assert station.standard_gateway == "10.0.0.1"


def test_decode_station_ignores_incomplete_ip_block() -> None:
    """A short IP block SHALL be skipped rather than yielding a partial address."""
    station = decode_station(_identify_response(STATION_MAC, _block(0x01, 0x02, struct.pack("!H", 1) + b"\x0a\x00")))

    assert station is not None
    assert station.ip_address == ""


@pytest.mark.parametrize("index,expected", list(enumerate(DCP_DEVICE_ROLES)))
def test_decode_station_maps_every_device_role(index: int, expected: str) -> None:
    """Each in-range DeviceRoleDetails value SHALL map to its documented label."""
    blocks = _block(0x02, 0x04, struct.pack("!H", 0) + bytes([index, 0x00]))
    station = decode_station(_identify_response(STATION_MAC, blocks))

    assert station is not None
    assert station.device_role_details == expected


def test_decode_station_clamps_out_of_range_device_role() -> None:
    """An out-of-range role byte SHALL clamp to the last label (legacy behaviour)."""
    blocks = _block(0x02, 0x04, struct.pack("!H", 0) + bytes([0xFE, 0x00]))
    station = decode_station(_identify_response(STATION_MAC, blocks))

    assert station is not None
    assert station.device_role_details == DCP_DEVICE_ROLES[-1]


def test_decode_station_strips_trailing_nul_from_text_fields() -> None:
    """NUL-padded station names SHALL be surfaced without the padding."""
    station = decode_station(_identify_response(STATION_MAC, _block(0x02, 0x02, b"\x00\x00io-2\x00\x00")))

    assert station is not None
    assert station.name_of_station == "io-2"


def test_decode_station_last_block_wins_for_duplicate_suboptions() -> None:
    """Duplicate blocks SHALL resolve last-wins, matching the previous behaviour."""
    blocks = _block(0x02, 0x02, b"\x00\x00first") + _block(0x02, 0x02, b"\x00\x00second")
    station = decode_station(_identify_response(STATION_MAC, blocks))

    assert station is not None
    assert station.name_of_station == "second"


@pytest.mark.parametrize(
    "frame,reason",
    [
        (b"\x00" * 13, "runt frame"),
        (encode_mac(LOCAL_MAC) + encode_mac(STATION_MAC) + struct.pack("!H", 0x0800) + b"\x00" * 40, "wrong ethertype"),
    ],
)
def test_decode_station_returns_none_for_non_dcp_frames(frame: bytes, reason: str) -> None:
    """Non-DCP traffic on the socket SHALL be dropped silently."""
    assert decode_station(frame) is None, reason


def test_decode_station_rejects_identify_request_frames() -> None:
    """The scanner's own request (FrameID 0xFEFE) SHALL NOT decode as a station."""
    frame = _identify_response(STATION_MAC, _full_station_blocks(), frame_id=FRAME_ID_IDENTIFY_REQUEST)
    assert decode_station(frame) is None


def test_decode_station_survives_block_area_garbage() -> None:
    """Garbage in the block area SHALL still yield a MAC-only station, not an error."""
    station = decode_station(_identify_response(STATION_MAC, b"\xff\xfe\xff\xfe\xff"))

    assert station is not None
    assert station.mac_address == STATION_MAC


# ---------------------------------------------------------------------------
# Round-trip: what the scanner sends is what the codec would refuse to decode
# ---------------------------------------------------------------------------


def test_request_and_response_frame_ids_are_distinct() -> None:
    """Request and response FrameIDs SHALL differ so loopback is separable."""
    assert FRAME_ID_IDENTIFY_REQUEST != FRAME_ID_IDENTIFY_RESPONSE


def test_multiple_stations_decode_independently() -> None:
    """Each captured frame SHALL decode into its own station record."""
    responders: List[Tuple[str, str]] = [("aa:bb:cc:dd:ee:01", "plc-01"), ("aa:bb:cc:dd:ee:02", "io-2")]
    decoded = [
        decode_station(_identify_response(mac, _block(0x02, 0x02, b"\x00\x00" + name.encode())))
        for mac, name in responders
    ]

    assert [s.mac_address for s in decoded if s] == [mac for mac, _ in responders]
    assert [s.name_of_station for s in decoded if s] == [name for _, name in responders]
