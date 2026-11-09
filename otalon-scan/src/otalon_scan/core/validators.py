"""Security input validators for caller-controlled scan parameters.

These pure functions validate every value that flows into a scan module via
``StartScanRequest.overrides``. They run at the API boundary, before any
module-level code or subprocess is invoked, and reject invalid input by
raising :class:`ValueError`. On success each validator returns the
canonical normalized form of the value.

The validators MUST NOT call any subprocess and MUST be safe to invoke at
request-handling time without further sandboxing.

Normative reference: ``scan--input-validation`` spec.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any, List

import psutil
from loguru import logger
from pydantic import ValidationInfo

from otalon_scan.core.interface_roles import classify_interface_role
from otalon_scan.utils.mac import InvalidMacError, canonicalise

__all__ = [
    "MIRROR_OVERRIDE_CONTEXT_KEY",
    "mirror_override_allowed",
    "validate_network_interface",
    "validate_target_subnet",
    "validate_target_ip",
    "validate_target_mac",
    "validate_port_range",
    "validate_timing_template",
    "validate_host_timeout_ms",
    "validate_hard_timeout_s",
    "validate_snmp_communities",
    "validate_operation_timeout",
    "validate_retry_attempts",
]


_PORT_RANGE_RE: re.Pattern[str] = re.compile(r"^\d+(-\d+)?(,\d+(-\d+)?)*$")
_TIMING_TEMPLATE_RE: re.Pattern[str] = re.compile(r"^[0-5]$")

# Bounds for the nmap per-host timeout (milliseconds). Lower bound keeps a
# scan meaningful; the 3 600 000 ms (1 h) upper bound caps how long a single
# caller-controlled host probe may block the NET_RAW/NET_ADMIN process.
_HOST_TIMEOUT_MS_MIN: int = 100
_HOST_TIMEOUT_MS_MAX: int = 3_600_000

# Bounds for the hard subprocess timeout (seconds) wrapping the whole nmap
# invocation. Upper bound (1 h) is a denial-of-service guard: a caller may
# not pin the scanner subprocess open indefinitely.
_HARD_TIMEOUT_S_MIN: int = 1
_HARD_TIMEOUT_S_MAX: int = 3_600

# Bounds for the per-request SNMP operation timeout (seconds). They mirror
# the full-config ``SnmpScanConfig.operation_timeout`` field so an API
# override cannot exceed what the trusted config.json contract already
# permits; the value becomes the ``timeout=`` argument of the pysnmp UDP
# transport and never reaches a shell.
_SNMP_OPERATION_TIMEOUT_S_MIN: int = 1
_SNMP_OPERATION_TIMEOUT_S_MAX: int = 600

# Bounds for the per-request SNMP retry count. They mirror the full-config
# ``SnmpScanConfig.retry_attempts`` field. Zero retries is valid (single
# attempt); the upper bound caps how much UDP traffic a single caller-
# controlled walk may amplify against a target on the privileged process.
_SNMP_RETRY_ATTEMPTS_MIN: int = 0
_SNMP_RETRY_ATTEMPTS_MAX: int = 10

# SCAN-037: key under which the deliberate operator opt-in to bind an
# active scan to a mirror/SPAN port travels through Pydantic's validation
# context into the per-module override schemas. The flag originates from
# the explicit top-level ``StartScanRequest.allow_mirror_interface`` field;
# it is deliberately NOT a per-module override key so it can never be
# smuggled in through a module ``overrides`` payload.
MIRROR_OVERRIDE_CONTEXT_KEY: str = "allow_mirror_interface"


def mirror_override_allowed(info: ValidationInfo) -> bool:
    """Return whether the caller explicitly opted in to a mirror/SPAN bind.

    Reads :data:`MIRROR_OVERRIDE_CONTEXT_KEY` from the Pydantic validation
    context supplied by :class:`~otalon_scan.api.schemas.scans.StartScanRequest`.
    Any absent, non-dict, or non-``True`` context yields ``False`` — the
    safe default is always "reject".

    :param info: The :class:`pydantic.ValidationInfo` handed to a
        ``field_validator``.
    :returns: ``True`` only when the context carries the flag as literal
        boolean ``True``.
    """
    context = getattr(info, "context", None)
    if not isinstance(context, dict):
        return False
    return context.get(MIRROR_OVERRIDE_CONTEXT_KEY) is True


def validate_network_interface(value: str, allow_mirror: bool = False) -> str:
    """Validate a network interface name against the host's live interfaces.

    Accepts a string that matches (case-sensitive) one of the keys returned
    by ``psutil.net_if_addrs()`` on the host running this service.

    SCAN-037 (ICS/OT safety): an interface classified as ``mirror`` by
    :func:`otalon_scan.core.interface_roles.classify_interface_role` (declared
    via ``CAPTURE_SOURCE`` / ``OTALON_SCAN_MIRROR_INTERFACES``) is a passive
    SPAN/TAP port. Actively transmitting on it — ARP sweeps, nmap probes,
    PROFINET DCP, SNMP walks — is an operational fault on an OT network, so
    the trigger path rejects it by default. ``allow_mirror=True`` is the
    deliberate operator opt-in; the bypass is logged at WARNING with the
    interface name so the decision is auditable.

    :param value: The interface name to validate (e.g. ``"eth0"``).
    :param allow_mirror: When ``True``, a mirror/SPAN interface is accepted
        instead of rejected. Defaults to ``False``.
    :returns: The interface name unchanged on success.
    :raises ValueError: If ``value`` is not a string, is not present in
        ``psutil.net_if_addrs()``, or is classified as a mirror/SPAN port
        while ``allow_mirror`` is ``False``.
    """
    if not isinstance(value, str):
        raise ValueError(f"network_interface must be a string, got {type(value).__name__}")
    interfaces = psutil.net_if_addrs()
    if value not in interfaces:
        raise ValueError(f"network_interface {value!r} not present on host")
    if _is_mirror_interface(value, interfaces[value]):
        if not allow_mirror:
            raise ValueError(
                f"network_interface {value!r} is a mirror/SPAN port and MUST NOT be used "
                f"for an active scan; pass allow_mirror_interface=true to override deliberately"
            )
        logger.bind(network_interface=value, event="mirror_interface_override").warning(
            "active scan bound to mirror/SPAN interface {iface} via explicit operator override",
            iface=value,
        )
    return value


def _is_mirror_interface(name: str, addrs: List[Any]) -> bool:
    """Return whether ``name`` classifies as a mirror/SPAN port.

    Link state is irrelevant for the mirror verdict —
    :func:`~otalon_scan.core.interface_roles.classify_interface_role` decides
    ``mirror`` purely from the declared mirror-name set, so a fixed
    ``is_up=True`` is passed rather than a second :mod:`psutil` syscall.

    :param name: Interface name.
    :param addrs: The ``psutil.net_if_addrs()`` entry for ``name``.
    :returns: ``True`` when the interface role is ``"mirror"``.
    """
    return classify_interface_role(name, addrs, True) == "mirror"


def validate_target_subnet(value: str) -> str:
    """Validate an IPv4 or IPv6 subnet in CIDR notation.

    Accepts any string that parses via ``ipaddress.ip_network(value, strict=False)``.
    Both IPv4 and IPv6 networks are accepted. Host bits are tolerated
    (``strict=False``); the canonical network form is returned.

    :param value: The subnet in CIDR form (e.g. ``"10.0.0.0/24"``).
    :returns: The canonical string form of the network as produced by
        :class:`ipaddress.ip_network`.
    :raises ValueError: If ``value`` is not a string or does not parse as a
        valid IP network.
    """
    if not isinstance(value, str):
        raise ValueError(f"target_subnet must be a string, got {type(value).__name__}")
    try:
        network = ipaddress.ip_network(value, strict=False)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"target_subnet {value!r} is not a valid IP network: {exc}") from exc
    return str(network)


def validate_target_ip(value: str) -> str:
    """Validate a single IPv4 or IPv6 address.

    Accepts any string that parses via ``ipaddress.ip_address(value)``. Both
    IPv4 and IPv6 addresses are accepted; the canonical string form is
    returned.

    :param value: The IP address (e.g. ``"192.168.1.10"`` or ``"::1"``).
    :returns: The canonical string form of the address as produced by
        :class:`ipaddress.ip_address`.
    :raises ValueError: If ``value`` is not a string or does not parse as a
        valid IP address.
    """
    if not isinstance(value, str):
        raise ValueError(f"target_ip must be a string, got {type(value).__name__}")
    try:
        address = ipaddress.ip_address(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"target_ip {value!r} is not a valid IP address: {exc}") from exc
    return str(address)


def validate_target_mac(value: str) -> str:
    """Validate a single MAC address and return its canonical form.

    Accepts any of the input forms understood by
    :func:`otalon_scan.utils.mac.canonicalise` (colon / dash / dot separated, bare
    hex, mixed case) and returns the canonical lowercase colon-separated
    form (e.g. ``"aa:bb:cc:dd:ee:ff"``).

    Used by the ``pn_discovery`` single-target override: PROFINET DCP
    Identify is an inherently multicast L2 discovery, so this value is not
    a unicast destination — it is the station MAC the module filters the
    DCP responses down to (see ``pn_discovery/start.py``). The value never
    reaches a shell; this validator solely rejects malformed input at the
    API boundary.

    :param value: The MAC address in any accepted form.
    :returns: The canonical lowercase colon-separated MAC string.
    :raises ValueError: If ``value`` is not a string or does not parse as a
        valid MAC address. :class:`~otalon_scan.utils.mac.InvalidMacError` is a
        :class:`ValueError` subclass, so callers catching ``ValueError``
        (the per-module schema validators) handle it uniformly.
    """
    if not isinstance(value, str):
        raise ValueError(f"target_mac must be a string, got {type(value).__name__}")
    try:
        return canonicalise(value)
    except InvalidMacError as exc:
        raise ValueError(f"target_mac {value!r} is not a valid MAC address: {exc}") from exc


def validate_port_range(value: str) -> str:
    """Validate an nmap-style port range expression.

    The accepted grammar is ``^\\d+(-\\d+)?(,\\d+(-\\d+)?)*$`` (single ports
    or ascending ranges, comma-separated). Each numeric token MUST be in
    ``[1, 65535]``; ranges MUST satisfy ``low <= high``.

    Examples of accepted input: ``"22"``, ``"22,80,443"``, ``"1-1024"``,
    ``"22,80,1000-2000"``.

    :param value: The port-range expression.
    :returns: The input value unchanged on success.
    :raises ValueError: If ``value`` is not a string, fails the regex, has
        a numeric token outside ``[1, 65535]``, or contains a descending
        range.
    """
    if not isinstance(value, str):
        raise ValueError(f"port_range must be a string, got {type(value).__name__}")
    if not _PORT_RANGE_RE.match(value):
        raise ValueError(f"port_range {value!r} does not match accepted grammar")
    for token in value.split(","):
        if "-" in token:
            low_str, high_str = token.split("-", 1)
            low = int(low_str)
            high = int(high_str)
            if not (1 <= low <= 65535) or not (1 <= high <= 65535):
                raise ValueError(f"port_range {value!r}: port out of range [1, 65535]")
            if low > high:
                raise ValueError(f"port_range {value!r}: descending range {low}-{high}")
        else:
            port = int(token)
            if not (1 <= port <= 65535):
                raise ValueError(f"port_range {value!r}: port {port} out of range [1, 65535]")
    return value


def validate_timing_template(value: str) -> str:
    """Validate an nmap timing-template selector.

    Accepts a single decimal digit ``0``-``5`` (regex ``^[0-5]$``),
    corresponding to nmap's ``-T0`` through ``-T5`` flags.

    :param value: The timing-template selector.
    :returns: The input value unchanged on success.
    :raises ValueError: If ``value`` is not a string or does not match the
        accepted regex.
    """
    if not isinstance(value, str):
        raise ValueError(f"timing_template must be a string, got {type(value).__name__}")
    if not _TIMING_TEMPLATE_RE.match(value):
        raise ValueError(f"timing_template {value!r} must be one of '0'..'5'")
    return value


def validate_host_timeout_ms(value: int) -> int:
    """Validate the nmap per-host timeout in milliseconds.

    The value is bounded to ``[100, 3_600_000]`` ms. The integer is passed
    to nmap as the numeric portion of ``--host-timeout <n>ms`` and never
    reaches a shell; the bounds prevent a caller from either degenerating
    the scan (sub-100 ms) or blocking the privileged process for longer
    than one hour per host.

    :param value: The per-host timeout in milliseconds.
    :returns: The value unchanged on success.
    :raises ValueError: If ``value`` is not an ``int`` (``bool`` rejected)
        or falls outside the accepted bounds.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"host_timeout_ms must be an int, got {type(value).__name__}")
    if not (_HOST_TIMEOUT_MS_MIN <= value <= _HOST_TIMEOUT_MS_MAX):
        raise ValueError(f"host_timeout_ms {value} out of range [{_HOST_TIMEOUT_MS_MIN}, {_HOST_TIMEOUT_MS_MAX}]")
    return value


def validate_hard_timeout_s(value: int) -> int:
    """Validate the hard subprocess timeout in seconds.

    The value is bounded to ``[1, 3_600]`` s. It becomes the ``timeout=``
    keyword of :func:`subprocess.run` wrapping the nmap invocation; the
    upper bound is a denial-of-service guard so a caller cannot pin the
    privileged scanner subprocess open indefinitely.

    :param value: The hard subprocess timeout in seconds.
    :returns: The value unchanged on success.
    :raises ValueError: If ``value`` is not an ``int`` (``bool`` rejected)
        or falls outside the accepted bounds.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"hard_timeout_s must be an int, got {type(value).__name__}")
    if not (_HARD_TIMEOUT_S_MIN <= value <= _HARD_TIMEOUT_S_MAX):
        raise ValueError(f"hard_timeout_s {value} out of range [{_HARD_TIMEOUT_S_MIN}, {_HARD_TIMEOUT_S_MAX}]")
    return value


def validate_snmp_communities(value: object) -> object:
    """Validate the SNMP ``communities`` override structure.

    The expected shape mirrors the legacy ``config.json``: a list of
    ``[cidr, community_string, snmp_version]`` triples. Each entry is
    structurally checked — the CIDR MUST parse via
    :func:`ipaddress.ip_network` (so a caller cannot smuggle an arbitrary
    string into the community-matching logic), the community string MUST be
    a non-empty ``str`` (bounded to 128 chars), and the SNMP version MUST be
    an ``int`` in ``{0, 1}`` (SNMP v1 / v2c mpModel). No value is ever
    interpolated into a shell; this validator solely rejects malformed or
    abusive structures at the API boundary.

    :param value: The raw ``communities`` payload.
    :returns: The value unchanged on success (the runtime re-parses it).
    :raises ValueError: On any structural or bounds violation.
    """
    if not isinstance(value, list):
        raise ValueError(f"communities must be a list, got {type(value).__name__}")
    for index, entry in enumerate(value):
        if not isinstance(entry, (list, tuple)) or len(entry) != 3:
            raise ValueError(f"communities[{index}] must be a [cidr, community, version] triple")
        cidr, community, version = entry
        if not isinstance(cidr, str):
            raise ValueError(f"communities[{index}] cidr must be a string")
        try:
            ipaddress.ip_network(cidr, strict=False)
        except (ValueError, TypeError) as exc:
            raise ValueError(f"communities[{index}] cidr {cidr!r} is not a valid network: {exc}") from exc
        if not isinstance(community, str) or not community or len(community) > 128:
            raise ValueError(f"communities[{index}] community must be a non-empty string <=128 chars")
        if isinstance(version, bool) or not isinstance(version, int) or version not in (0, 1):
            raise ValueError(f"communities[{index}] version must be 0 or 1")
    return value


def validate_operation_timeout(value: int) -> int:
    """Validate the per-request SNMP operation timeout in seconds.

    The value is bounded to ``[1, 600]`` s, mirroring the trusted
    ``SnmpScanConfig.operation_timeout`` contract. It is forwarded as the
    ``timeout=`` keyword of the pysnmp ``UdpTransportTarget`` and never
    reaches a shell; the bounds prevent both a degenerate sub-second walk
    and a caller pinning the privileged SNMP socket open for longer than
    ten minutes per operation.

    :param value: The SNMP operation timeout in seconds.
    :returns: The value unchanged on success.
    :raises ValueError: If ``value`` is not an ``int`` (``bool`` rejected)
        or falls outside the accepted bounds.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"operation_timeout must be an int, got {type(value).__name__}")
    if not (_SNMP_OPERATION_TIMEOUT_S_MIN <= value <= _SNMP_OPERATION_TIMEOUT_S_MAX):
        raise ValueError(
            f"operation_timeout {value} out of range "
            f"[{_SNMP_OPERATION_TIMEOUT_S_MIN}, {_SNMP_OPERATION_TIMEOUT_S_MAX}]"
        )
    return value


def validate_retry_attempts(value: int) -> int:
    """Validate the per-request SNMP retry count.

    The value is bounded to ``[0, 10]``, mirroring the trusted
    ``SnmpScanConfig.retry_attempts`` contract. It is forwarded as the
    ``retries=`` keyword of the pysnmp ``UdpTransportTarget`` and never
    reaches a shell; the upper bound caps how much UDP traffic a single
    caller-controlled walk may amplify against a target.

    :param value: The SNMP retry count (``0`` means a single attempt).
    :returns: The value unchanged on success.
    :raises ValueError: If ``value`` is not an ``int`` (``bool`` rejected)
        or falls outside the accepted bounds.
    """
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"retry_attempts must be an int, got {type(value).__name__}")
    if not (_SNMP_RETRY_ATTEMPTS_MIN <= value <= _SNMP_RETRY_ATTEMPTS_MAX):
        raise ValueError(
            f"retry_attempts {value} out of range [{_SNMP_RETRY_ATTEMPTS_MIN}, {_SNMP_RETRY_ATTEMPTS_MAX}]"
        )
    return value
