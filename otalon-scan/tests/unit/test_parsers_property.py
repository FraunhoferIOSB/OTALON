"""D-T1 — Hypothesis property-based tests for the input validators.

Covers ``.dev/TODO_otalon-scan.md`` D-T1 acceptance criteria for the
parsers/validators in ``src/otalon_scan/core/validators.py``:

- ``validate_target_ip`` — IPv4 + IPv6 round-trip + malformed rejection.
- ``validate_target_subnet`` — CIDR round-trip + malformed rejection.
- ``validate_port_range`` — nmap-style range expressions round-trip +
  malformed rejection.
- ``validate_timing_template`` — ``-T0`` .. ``-T5`` round-trip +
  malformed rejection.

The original D-T1 spec also called out MAC and SNMP-OID parsers, but
those don't have dedicated validator entry points in the current
codebase (MACs are canonicalised by ``otalon_scan.utils.mac.canonicalise`` and
flow into the DCP codec / pysnmp downstream; OIDs are hardcoded
module/symbol pairs in ``snmp_scan/walker.py``). When a dedicated parser
lands for either, add a corresponding strategy here.

SCAN-029 note: the MAC path no longer passes through scapy at all — the
PROFINET DCP wire codec (``otalon_scan.modules.pn_discovery.dcp``) encodes and
decodes MAC addresses itself and is property-tested in
``tests/unit/test_pn_dcp_codec.py``.
"""

from __future__ import annotations

import ipaddress

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from otalon_scan.core.validators import (
    validate_port_range,
    validate_target_ip,
    validate_target_subnet,
    validate_timing_template,
)

# ---- target_ip ----


@given(st.ip_addresses(v=4))
def test_validate_target_ip_v4_well_formed_roundtrip(addr: ipaddress.IPv4Address) -> None:
    """Any well-formed IPv4 SHALL round-trip through ``validate_target_ip``."""
    result = validate_target_ip(str(addr))
    assert ipaddress.ip_address(result) == addr


@given(st.ip_addresses(v=6))
def test_validate_target_ip_v6_well_formed_roundtrip(addr: ipaddress.IPv6Address) -> None:
    """Any well-formed IPv6 SHALL round-trip through ``validate_target_ip``."""
    result = validate_target_ip(str(addr))
    assert ipaddress.ip_address(result) == addr


@given(
    st.text(min_size=1, max_size=80).filter(
        lambda s: not _is_valid_ip(s),
    )
)
def test_validate_target_ip_rejects_malformed(s: str) -> None:
    """Malformed input SHALL raise ``ValueError``."""
    with pytest.raises(ValueError):
        validate_target_ip(s)


# ---- target_subnet (CIDR) ----


def _cidr_strategy() -> st.SearchStrategy[str]:
    """Generate ``<ipv4>/<mask>`` strings with masks in [0, 32]."""
    return st.builds(
        lambda a, m: f"{a}/{m}",
        st.ip_addresses(v=4).map(str),
        st.integers(min_value=0, max_value=32),
    )


@given(_cidr_strategy())
@settings(max_examples=200)
def test_validate_target_subnet_well_formed_roundtrip(cidr: str) -> None:
    """Any well-formed IPv4 CIDR SHALL parse and return the canonical form."""
    result = validate_target_subnet(cidr)
    # The canonical form differs from input when host bits were set;
    # both sides must agree under ip_network re-parsing.
    canonical = ipaddress.ip_network(cidr, strict=False)
    assert ipaddress.ip_network(result, strict=False) == canonical


@given(
    st.builds(
        lambda a, m: f"{a}/{m}",
        st.ip_addresses(v=4).map(str),
        st.integers(min_value=33, max_value=200),  # illegal IPv4 mask
    )
)
def test_validate_target_subnet_rejects_illegal_mask(cidr: str) -> None:
    """An IPv4 CIDR with mask > 32 SHALL raise ``ValueError``."""
    with pytest.raises(ValueError):
        validate_target_subnet(cidr)


# ---- port_range ----


def _port_range_strategy() -> st.SearchStrategy[str]:
    """Generate nmap-style port-range expressions in the accepted grammar.

    Mix single ports, ascending ranges, comma-separated lists.
    """
    single = st.integers(min_value=1, max_value=65535).map(str)
    range_ = st.tuples(
        st.integers(min_value=1, max_value=65534),
        st.integers(min_value=2, max_value=65535),
    ).map(lambda t: f"{min(t)}-{max(t)}")
    token = st.one_of(single, range_)
    return st.lists(token, min_size=1, max_size=8).map(",".join)


@given(_port_range_strategy())
def test_validate_port_range_well_formed_roundtrip(expr: str) -> None:
    """Well-formed port-range expressions SHALL round-trip unchanged."""
    result = validate_port_range(expr)
    assert result == expr


@given(
    # Descending ranges: low > high
    st.tuples(
        st.integers(min_value=100, max_value=65535),
        st.integers(min_value=1, max_value=99),
    ).map(lambda t: f"{t[0]}-{t[1]}")
)
def test_validate_port_range_rejects_descending(expr: str) -> None:
    """A descending range SHALL raise ``ValueError``."""
    with pytest.raises(ValueError):
        validate_port_range(expr)


@given(
    # Out-of-range ports (>65535)
    st.integers(min_value=65536, max_value=99_999).map(str)
)
def test_validate_port_range_rejects_oob(expr: str) -> None:
    """A numeric port outside [1, 65535] SHALL raise ``ValueError``."""
    with pytest.raises(ValueError):
        validate_port_range(expr)


# ---- timing_template ----


@given(st.integers(min_value=0, max_value=5).map(str))
def test_validate_timing_template_accepts_0_through_5(s: str) -> None:
    """Single digits 0..5 SHALL pass."""
    assert validate_timing_template(s) == s


@given(
    st.one_of(
        st.integers(min_value=6, max_value=99).map(str),  # too high
        st.integers(min_value=-99, max_value=-1).map(str),  # negative
        st.text(min_size=2, max_size=4).filter(lambda s: not s.isdigit()),  # non-digits
    )
)
def test_validate_timing_template_rejects_invalid(s: str) -> None:
    """Anything outside the ``[0-5]`` regex SHALL raise ``ValueError``."""
    with pytest.raises(ValueError):
        validate_timing_template(s)


# ---- helpers ----


def _is_valid_ip(s: str) -> bool:
    """Best-effort check used to filter Hypothesis's text strategy below."""
    try:
        ipaddress.ip_address(s.strip())
        return True
    except (ValueError, TypeError):
        return False
