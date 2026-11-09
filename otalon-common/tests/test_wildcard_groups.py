"""Tests for wildcard group building."""

from otalon_common.connection.wildcard_groups import build_wildcard_groups


class TestBuildWildcardGroups:
    """Tests for build_wildcard_groups()."""

    def test_single_member_retains_concrete_key(self) -> None:
        ucis = ["aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP"]
        result = build_wildcard_groups(ucis)
        assert ucis[0] in result
        assert result[ucis[0]] == ucis

    def test_multiple_ports_create_wildcard(self) -> None:
        ucis = [
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP",
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50001/TCP",
        ]
        result = build_wildcard_groups(ucis)
        assert len(result) == 1
        key = list(result.keys())[0]
        assert "*/TCP" in key or key.count("*") >= 1
        assert len(result[key]) == 2

    def test_different_base_keys_separate_groups(self) -> None:
        ucis = [
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP",
            "xx:yy/zz:ww/200/17/10.0.0.1/10.0.0.2/8080/9090/UDP",
        ]
        result = build_wildcard_groups(ucis)
        assert len(result) == 2

    def test_same_ports_no_wildcard(self) -> None:
        ucis = [
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP",
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP",
        ]
        result = build_wildcard_groups(ucis)
        key = list(result.keys())[0]
        assert "*" not in key

    def test_result_values_sorted(self) -> None:
        ucis = [
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50001/TCP",
            "aa:bb/cc:dd/100/6/1.1.1.1/2.2.2.2/443/50000/TCP",
        ]
        result = build_wildcard_groups(ucis)
        key = list(result.keys())[0]
        assert result[key] == sorted(ucis)

    def test_empty_input(self) -> None:
        assert build_wildcard_groups([]) == {}
