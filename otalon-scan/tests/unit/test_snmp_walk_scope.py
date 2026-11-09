"""Unit tests for SNMP walk scope (SCAN-017).

Ensures that ``walk_cmd`` is invoked with ``lexicographicMode=False`` so
that ``_walk_oid`` stays inside the requested subtree instead of walking
the agent's entire MIB (which caused ~100 s scans on SCALANCE devices).
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from pysnmp.hlapi.v3arch.asyncio import ObjectIdentity

from otalon_scan.modules.snmp_scan.model import Device
from otalon_scan.modules.snmp_scan.walker import _walk_oid


def _fake_walk_cmd(*args: object, **kwargs: object) -> Any:
    """Return an async generator that yields one error-free empty response."""

    async def _gen() -> Any:
        yield (None, None, 0, [])

    return _gen()


@pytest.mark.asyncio
async def test_walk_oid_uses_lexicographic_mode_false() -> None:
    """``_walk_oid`` must pass ``lexicographicMode=False`` to ``walk_cmd``.

    Without this flag pysnmp 7.x treats the walk as an unconstrained
    lexicographic traversal and iterates the *entire* agent MIB. A
    SCALANCE switch exposes ~10 000+ OIDs, turning a 1--2 s subtree
    walk into a ~100 s full walk.
    """
    a_device = Device("192.168.0.233")
    ident = ObjectIdentity("1.3.6.1.2.1.1")

    with patch("otalon_scan.modules.snmp_scan.walker.walk_cmd", side_effect=_fake_walk_cmd) as mock_walk:
        await _walk_oid(a_device, "public", 0, ident, timeout=1.0, retries=0)

    assert mock_walk.called
    _call_kwargs = mock_walk.call_args.kwargs
    assert _call_kwargs.get("lexicographicMode") is False
