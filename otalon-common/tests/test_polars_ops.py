"""Tests for Polars UCI expand/collapse operations."""

import polars as pl
from otalon_common.uci.constants import UCI_FIELDS
from otalon_common.uci.polars_ops import collapse_uci, expand_uci

SAMPLE_UCI = "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"


class TestExpandUci:
    """Tests for expand_uci()."""

    def test_dataframe_expands_to_9_columns(self) -> None:
        df = pl.DataFrame({"uci": [SAMPLE_UCI]})
        result = expand_uci(df)
        for field in UCI_FIELDS:
            assert field in result.columns

    def test_field_values_correct(self) -> None:
        df = pl.DataFrame({"uci": [SAMPLE_UCI]})
        result = expand_uci(df)
        row = result.row(0, named=True)
        assert row["src_mac"] == "aa:bb"
        assert row["dst_mac"] == "cc:dd"
        assert row["vlan"] == "100"
        assert row["ip_proto"] == "6"
        assert row["src_ip"] == "1.1.1.1"
        assert row["dst_ip"] == "2.2.2.2"
        assert row["src_port"] == "443"
        assert row["dst_port"] == "50000"
        assert row["protocols"] == "TCP"

    def test_preserves_original_uci_column(self) -> None:
        df = pl.DataFrame({"uci": [SAMPLE_UCI]})
        result = expand_uci(df)
        assert "uci" in result.columns

    def test_lazyframe_support(self) -> None:
        lf = pl.LazyFrame({"uci": [SAMPLE_UCI]})
        result = expand_uci(lf)
        assert isinstance(result, pl.LazyFrame)
        collected = result.collect()
        for field in UCI_FIELDS:
            assert field in collected.columns


class TestCollapseUci:
    """Tests for collapse_uci()."""

    def test_roundtrip(self) -> None:
        df = pl.DataFrame({"uci": [SAMPLE_UCI]})
        expanded = expand_uci(df)
        expanded_no_uci = expanded.drop("uci")
        collapsed = collapse_uci(expanded_no_uci)
        assert collapsed["uci"][0] == SAMPLE_UCI

    def test_drop_uci_fields(self) -> None:
        df = pl.DataFrame({"uci": [SAMPLE_UCI]})
        expanded = expand_uci(df)
        collapsed = collapse_uci(expanded, drop_uci_fields=True)
        for field in UCI_FIELDS:
            assert field not in collapsed.columns
        assert "uci" in collapsed.columns

    def test_lazyframe_roundtrip(self) -> None:
        lf = pl.LazyFrame({"uci": [SAMPLE_UCI]})
        expanded = expand_uci(lf)
        expanded_no_uci = expanded.drop("uci")
        collapsed = collapse_uci(expanded_no_uci)
        assert isinstance(collapsed, pl.LazyFrame)
        result = collapsed.collect()
        assert result["uci"][0] == SAMPLE_UCI

    def test_multiple_rows(self) -> None:
        uci2 = "xx:yy/zz:ww/200/17/10.0.0.1/10.0.0.2/8080/9090/UDP"
        df = pl.DataFrame({"uci": [SAMPLE_UCI, uci2]})
        expanded = expand_uci(df)
        expanded_no_uci = expanded.drop("uci")
        collapsed = collapse_uci(expanded_no_uci)
        assert collapsed["uci"][0] == SAMPLE_UCI
        assert collapsed["uci"][1] == uci2
