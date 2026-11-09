"""F-03 tests for :func:`otalon_scan.utils.mac.canonicalise`.

Pure-function tests — no DB, no I/O. Exercises every supported input
form documented in the docstring plus the failure modes (empty,
non-hex, wrong length).

Test boundaries chosen so the coverage report shows every branch of
:func:`canonicalise` exercised at least once (task 5.6 of
``refactor-otalon-scan-device-network-ownership-v1``).
"""

from __future__ import annotations

import pytest

from otalon_scan.utils.mac import InvalidMacError, canonicalise

# ---- Happy paths --------------------------------------------------------------


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("aa:bb:cc:dd:ee:ff", "aa:bb:cc:dd:ee:ff"),
        ("AA:BB:CC:DD:EE:FF", "aa:bb:cc:dd:ee:ff"),
        ("Aa:Bb:Cc:Dd:Ee:Ff", "aa:bb:cc:dd:ee:ff"),
        ("aa-bb-cc-dd-ee-ff", "aa:bb:cc:dd:ee:ff"),
        ("AA-BB-CC-DD-EE-FF", "aa:bb:cc:dd:ee:ff"),
        ("aabb.ccdd.eeff", "aa:bb:cc:dd:ee:ff"),
        ("AABB.CCDD.EEFF", "aa:bb:cc:dd:ee:ff"),
        ("aabbccddeeff", "aa:bb:cc:dd:ee:ff"),
        ("AABBCCDDEEFF", "aa:bb:cc:dd:ee:ff"),
        ("02:00:00:00:00:01", "02:00:00:00:00:01"),
    ],
)
def test_canonicalise_accepts_supported_forms(raw: str, expected: str) -> None:
    """Every documented input form SHALL round-trip to the canonical form."""
    assert canonicalise(raw) == expected


def test_canonicalise_result_matches_db_check_regex() -> None:
    """The canonical output SHALL match the ``ck_devices_primary_mac_format`` regex."""
    import re

    db_regex = re.compile(r"^[0-9a-f]{2}(:[0-9a-f]{2}){5}$")
    for raw in (
        "AA:BB:CC:DD:EE:FF",
        "aabbccddeeff",
        "aa-bb-cc-dd-ee-ff",
        "aabb.ccdd.eeff",
    ):
        assert db_regex.match(canonicalise(raw))


# ---- Failure modes -------------------------------------------------------------


@pytest.mark.parametrize(
    "bad",
    [
        "",
        "aa:bb:cc:dd:ee",  # too short
        "aa:bb:cc:dd:ee:ff:00",  # too long
        "gg:bb:cc:dd:ee:ff",  # non-hex
        "aabbccddee",  # 10 hex chars
        "aabbccddeeff00",  # 14 hex chars
        "::::",
        "not-a-mac",
    ],
)
def test_canonicalise_rejects_malformed(bad: str) -> None:
    """Malformed input SHALL raise :class:`InvalidMacError` (a :class:`ValueError`)."""
    with pytest.raises(InvalidMacError) as excinfo:
        canonicalise(bad)
    # Subclass relationship — catch-as-ValueError works for backwards compat.
    assert isinstance(excinfo.value, ValueError)
    # The raw input is preserved on the exception.
    assert excinfo.value.raw == bad


def test_canonicalise_rejects_non_string_input() -> None:
    """Non-string input SHALL raise :class:`InvalidMacError`."""
    for bad in (None, 12345, b"aabbccddeeff", ["aa", "bb"]):
        with pytest.raises(InvalidMacError):
            canonicalise(bad)  # type: ignore[arg-type]


def test_invalid_mac_error_message_includes_raw() -> None:
    """The exception message SHALL include the raw input for operator debugging."""
    with pytest.raises(InvalidMacError) as excinfo:
        canonicalise("HELLO")
    assert "HELLO" in str(excinfo.value)
