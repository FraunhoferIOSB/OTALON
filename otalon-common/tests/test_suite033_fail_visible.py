"""Regression tests for the SUITE-033 otalon-common fixes.

* QUA-C7 — ``create_influx_client`` accepted a scheme-less URL such as
  ``"influxdb:8181"``, which ``urlparse`` reports as
  ``scheme='influxdb', hostname=None``. The client was then built with the
  nonsense host ``"influxdb://None"`` and failed much later as an opaque
  connection error.
* QUA-C4 — ``coerce_env_value`` used bare ``int()``/``float()``, which accept
  forms whose meaning silently changes: ``"0755"`` (a file mode) became
  ``755``, ``"1_000"`` became ``1000``, and ``"nan"``/``"infinity"`` became
  non-finite floats that poison every later comparison.
"""

from __future__ import annotations

import math

import pytest

from otalon_common.config.env_resolver import coerce_env_value
from otalon_common.influx.connection import create_influx_client


class TestInfluxUrlValidation:
    """QUA-C7 — reject unusable URLs at the call, not deep inside the client."""

    @pytest.mark.parametrize(
        "url",
        [
            "influxdb:8181",
            "localhost:8181",
            "influxdb3:8181",
            "",
            "   ",
            "not a url",
            "//influxdb:8181",
        ],
    )
    def test_scheme_less_urls_are_rejected(self, url: str) -> None:
        with pytest.raises(ValueError, match="invalid InfluxDB URL"):
            create_influx_client(url=url, token="t", database="netcap")

    def test_the_error_names_the_offending_url(self) -> None:
        with pytest.raises(ValueError) as exc:
            create_influx_client(url="influxdb:8181", token="t", database="netcap")

        message = str(exc.value)
        assert "influxdb:8181" in message
        assert "http://influxdb3:8181" in message, "error should show the expected shape"

    @pytest.mark.parametrize("url", ["ftp://influxdb:8181", "file:///tmp/x"])
    def test_non_http_schemes_are_rejected(self, url: str) -> None:
        with pytest.raises(ValueError, match="invalid InfluxDB URL"):
            create_influx_client(url=url, token="t", database="netcap")

    @pytest.mark.parametrize(
        "url",
        ["http://influxdb3:8181", "https://influx.example.com", "http://127.0.0.1:8181"],
    )
    def test_valid_urls_are_accepted(self, url: str) -> None:
        client = create_influx_client(url=url, token="t", database="netcap")

        assert client is not None


class TestEnvValueCoercion:
    """QUA-C4 — never let coercion change what a value means."""

    @pytest.mark.parametrize("value", ["0755", "007", "0600", "01"])
    def test_leading_zeros_stay_strings(self, value: str) -> None:
        """A file mode must not become a different decimal number."""
        assert coerce_env_value(value) == value

    @pytest.mark.parametrize("value", ["1_000", "1_000_000", "1_0.5"])
    def test_underscored_numbers_stay_strings(self, value: str) -> None:
        assert coerce_env_value(value) == value

    @pytest.mark.parametrize(
        "value", ["nan", "NaN", "inf", "-inf", "infinity", "Infinity", "-Infinity"]
    )
    def test_non_finite_floats_stay_strings(self, value: str) -> None:
        result = coerce_env_value(value)

        assert isinstance(result, str)
        assert not isinstance(result, float)

    def test_no_coercion_can_produce_a_non_finite_float(self) -> None:
        for value in ["nan", "inf", "-inf", "infinity", "1e400"]:
            result = coerce_env_value(value)
            if isinstance(result, float):
                assert math.isfinite(result), f"{value!r} produced {result!r}"

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("12", 12), ("-3", -3), ("0", 0), ("8181", 8181), ("+5", 5)],
    )
    def test_plain_integers_still_coerce(self, value: str, expected: int) -> None:
        result = coerce_env_value(value)

        assert result == expected
        assert isinstance(result, int)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("1.5", 1.5), ("-2.5", -2.5), ("0.5", 0.5), (".5", 0.5), ("1e3", 1000.0)],
    )
    def test_plain_floats_still_coerce(self, value: str, expected: float) -> None:
        result = coerce_env_value(value)

        assert result == expected
        assert isinstance(result, float)

    @pytest.mark.parametrize(
        ("value", "expected"),
        [("true", True), ("TRUE", True), ("false", False), ("False", False)],
    )
    def test_booleans_still_coerce(self, value: str, expected: bool) -> None:
        assert coerce_env_value(value) is expected

    def test_plain_strings_are_stripped(self) -> None:
        assert coerce_env_value("  spaced  ") == "spaced"

    def test_empty_string_stays_empty(self) -> None:
        assert coerce_env_value("") == ""

    def test_a_rejected_number_is_still_usable_by_pydantic(self) -> None:
        """The value survives as a string so the model can coerce it."""
        from pydantic import BaseModel

        class _Model(BaseModel):
            mode: int

        raw = coerce_env_value("0755")

        assert raw == "0755"
        assert _Model(mode=raw).mode == 755
