"""Tests for helper utilities."""

from __future__ import annotations

from typing import Dict

import pytest

from otalon_capture.helper import _build_auth_header


@pytest.mark.parametrize(
    ("token", "expected"),
    [("", {}), ("  ", {}), ("abc", {"Authorization": "Bearer abc"})],
)
def test_build_auth_header(token: str, expected: Dict[str, str]) -> None:
    assert _build_auth_header(token) == expected
