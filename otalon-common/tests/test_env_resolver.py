"""Tests for environment variable resolution."""

import os

import pytest

from otalon_common.config.env_resolver import (
    MissingEnvVarPolicy,
    coerce_env_value,
    resolve_env_placeholders,
)


class TestCoerceEnvValue:
    """Tests for coerce_env_value()."""

    def test_bool_true(self) -> None:
        assert coerce_env_value("true") is True

    def test_bool_true_uppercase(self) -> None:
        assert coerce_env_value("TRUE") is True

    def test_bool_false(self) -> None:
        assert coerce_env_value("false") is False

    def test_bool_false_mixed_case(self) -> None:
        assert coerce_env_value("False") is False

    def test_integer(self) -> None:
        assert coerce_env_value("8080") == 8080
        assert isinstance(coerce_env_value("8080"), int)

    def test_negative_integer(self) -> None:
        assert coerce_env_value("-1") == -1
        assert isinstance(coerce_env_value("-1"), int)

    def test_float(self) -> None:
        assert coerce_env_value("3.14") == 3.14
        assert isinstance(coerce_env_value("3.14"), float)

    def test_string(self) -> None:
        assert coerce_env_value("hello") == "hello"

    def test_string_stripped(self) -> None:
        assert coerce_env_value("  hello  ") == "hello"

    def test_zero_is_int(self) -> None:
        assert coerce_env_value("0") == 0
        assert isinstance(coerce_env_value("0"), int)


class TestResolveEnvPlaceholders:
    """Tests for resolve_env_placeholders()."""

    def test_resolve_nested_dict(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DB_HOST", "localhost")
        monkeypatch.setenv("DB_PORT", "5432")
        data = {"db": {"host": "$DB_HOST", "port": "$DB_PORT"}}
        result = resolve_env_placeholders(data)
        assert result == {"db": {"host": "localhost", "port": 5432}}

    def test_resolve_list(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("VAL_A", "10")
        monkeypatch.setenv("VAL_B", "hello")
        data = ["$VAL_A", "$VAL_B"]
        result = resolve_env_placeholders(data)
        assert result == [10, "hello"]

    def test_resolve_boolean(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DEBUG_MODE", "true")
        result = resolve_env_placeholders("$DEBUG_MODE")
        assert result is True

    def test_non_placeholder_unchanged(self) -> None:
        data = {"key": "plain_value", "num": 42}
        result = resolve_env_placeholders(data)
        assert result == {"key": "plain_value", "num": 42}

    def test_raise_policy_missing_var(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        with pytest.raises(RuntimeError, match="MISSING_VAR"):
            resolve_env_placeholders(
                {"key": "$MISSING_VAR"}, policy=MissingEnvVarPolicy.RAISE
            )

    def test_warn_and_skip_policy(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"key": "$MISSING_VAR"},
            policy=MissingEnvVarPolicy.WARN_AND_SKIP,
        )
        assert result == {"key": "$MISSING_VAR"}

    def test_use_default_policy(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"key": "$MISSING_VAR"},
            policy=MissingEnvVarPolicy.USE_DEFAULT,
            default="fallback",
        )
        assert result == {"key": "fallback"}

    def test_use_default_policy_coerces(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"key": "$MISSING_VAR"},
            policy=MissingEnvVarPolicy.USE_DEFAULT,
            default="42",
        )
        assert result == {"key": 42}

    def test_deeply_nested(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("DEEP_VAL", "found")
        data = {"a": {"b": {"c": [{"d": "$DEEP_VAL"}]}}}
        result = resolve_env_placeholders(data)
        assert result == {"a": {"b": {"c": [{"d": "found"}]}}}


class TestJsonArrayCoercion:
    """SUITE-038: opt-in JSON coercion, off by default."""

    def test_array_is_a_string_by_default(self) -> None:
        assert coerce_env_value('["a","b"]') == '["a","b"]'

    def test_object_is_a_string_by_default(self) -> None:
        assert coerce_env_value('{"k": 1}') == '{"k": 1}'

    def test_array_is_parsed_when_enabled(self) -> None:
        assert coerce_env_value('["a","b"]', json_arrays=True) == ["a", "b"]

    def test_object_is_parsed_when_enabled(self) -> None:
        assert coerce_env_value('{"k": 1}', json_arrays=True) == {"k": 1}

    def test_empty_array_is_parsed_when_enabled(self) -> None:
        assert coerce_env_value("[]", json_arrays=True) == []

    def test_malformed_json_falls_back_to_string(self) -> None:
        assert coerce_env_value("[not json", json_arrays=True) == "[not json"

    def test_json_scalar_is_not_unwrapped(self) -> None:
        assert coerce_env_value("[1", json_arrays=True) == "[1"

    def test_surrounding_whitespace_is_stripped_before_parsing(self) -> None:
        assert coerce_env_value('  ["a"]  ', json_arrays=True) == ["a"]

    def test_non_json_values_are_unaffected_by_the_flag(self) -> None:
        assert coerce_env_value("8080", json_arrays=True) == 8080
        assert coerce_env_value("true", json_arrays=True) is True
        assert coerce_env_value("plain", json_arrays=True) == "plain"

    def test_flag_reaches_nested_structures(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JSON_LIST_VAR", '["x","y"]')
        result = resolve_env_placeholders(
            {"a": {"b": "$JSON_LIST_VAR"}}, json_arrays=True
        )
        assert result == {"a": {"b": ["x", "y"]}}

    def test_resolver_keeps_string_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("JSON_LIST_VAR", '["x","y"]')
        result = resolve_env_placeholders({"a": "$JSON_LIST_VAR"})
        assert result == {"a": '["x","y"]'}


class TestExpandNested:
    """SUITE-038: opt-in nested variable expansion, off by default."""

    def test_nested_reference_is_literal_by_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OUTER_VAR", "pre-$INNER_VAR-post")
        monkeypatch.setenv("INNER_VAR", "x")
        result = resolve_env_placeholders({"v": "$OUTER_VAR"})
        assert result == {"v": "pre-$INNER_VAR-post"}

    def test_nested_reference_is_expanded_when_enabled(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OUTER_VAR", "pre-$INNER_VAR-post")
        monkeypatch.setenv("INNER_VAR", "x")
        result = resolve_env_placeholders({"v": "$OUTER_VAR"}, expand_nested=True)
        assert result == {"v": "pre-x-post"}

    def test_braced_nested_reference_is_expanded(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OUTER_VAR", "a${INNER_VAR}b")
        monkeypatch.setenv("INNER_VAR", "-")
        result = resolve_env_placeholders({"v": "$OUTER_VAR"}, expand_nested=True)
        assert result == {"v": "a-b"}

    def test_expansion_happens_before_coercion(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("OUTER_VAR", "$INNER_VAR")
        monkeypatch.setenv("INNER_VAR", "42")
        result = resolve_env_placeholders({"v": "$OUTER_VAR"}, expand_nested=True)
        assert result == {"v": 42}

    def test_value_without_nesting_is_unaffected(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("FLAT_VAR", "plain-value")
        assert resolve_env_placeholders({"v": "$FLAT_VAR"}, expand_nested=True) == {
            "v": "plain-value"
        }


class TestWarnAndDropPolicy:
    """SUITE-038: WARN_AND_DROP removes the key so the model default applies."""

    def test_missing_key_is_removed(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"a": "$MISSING_VAR", "b": 1},
            policy=MissingEnvVarPolicy.WARN_AND_DROP,
        )
        assert result == {"b": 1}

    def test_siblings_in_a_nested_mapping_survive(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"outer": {"a": "$MISSING_VAR", "b": 2}},
            policy=MissingEnvVarPolicy.WARN_AND_DROP,
        )
        assert result == {"outer": {"b": 2}}

    def test_a_present_variable_is_still_resolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRESENT_VAR", "8080")
        result = resolve_env_placeholders(
            {"a": "$PRESENT_VAR"}, policy=MissingEnvVarPolicy.WARN_AND_DROP
        )
        assert result == {"a": 8080}

    def test_dropped_entries_do_not_leak_into_lists(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"a": ["$MISSING_VAR", "keep"]},
            policy=MissingEnvVarPolicy.WARN_AND_DROP,
        )
        assert result == {"a": ["keep"]}

    def test_warn_and_skip_still_keeps_the_placeholder(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"a": "$MISSING_VAR"}, policy=MissingEnvVarPolicy.WARN_AND_SKIP
        )
        assert result == {"a": "$MISSING_VAR"}


class TestUseNonePolicy:
    """SUITE-038: USE_NONE resolves missing or empty variables to None."""

    def test_missing_variable_becomes_none(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"a": "$MISSING_VAR"}, policy=MissingEnvVarPolicy.USE_NONE
        )
        assert result == {"a": None}

    def test_empty_variable_becomes_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("EMPTY_VAR", "")
        result = resolve_env_placeholders(
            {"a": "$EMPTY_VAR"}, policy=MissingEnvVarPolicy.USE_NONE
        )
        assert result == {"a": None}

    def test_empty_variable_is_not_missing_under_other_policies(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("EMPTY_VAR", "")
        result = resolve_env_placeholders(
            {"a": "$EMPTY_VAR"}, policy=MissingEnvVarPolicy.RAISE
        )
        assert result == {"a": ""}

    def test_present_variable_is_resolved(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("PRESENT_VAR", "value")
        result = resolve_env_placeholders(
            {"a": "$PRESENT_VAR"}, policy=MissingEnvVarPolicy.USE_NONE
        )
        assert result == {"a": "value"}

    def test_key_is_kept_rather_than_dropped(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        result = resolve_env_placeholders(
            {"a": "$MISSING_VAR"}, policy=MissingEnvVarPolicy.USE_NONE
        )
        assert "a" in result


class TestDollarEscape:
    """SUITE-038: a doubled dollar is a literal, never a lookup."""

    def test_double_dollar_is_passed_through_under_raise(self) -> None:
        result = resolve_env_placeholders(
            {"a": "$$LITERAL"}, policy=MissingEnvVarPolicy.RAISE
        )
        assert result == {"a": "$$LITERAL"}

    def test_double_dollar_is_passed_through_under_use_none(self) -> None:
        result = resolve_env_placeholders(
            {"a": "$$LITERAL"}, policy=MissingEnvVarPolicy.USE_NONE
        )
        assert result == {"a": "$$LITERAL"}

    def test_double_dollar_is_not_looked_up_even_when_set(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("$LITERAL", "should-not-be-used")
        result = resolve_env_placeholders({"a": "$$LITERAL"})
        assert result == {"a": "$$LITERAL"}


class TestExistingBehaviourUnchanged:
    """SUITE-038: the defaults must stay bit-identical for otalon-clas."""

    def test_numeric_hardening_still_in_force(self) -> None:
        assert coerce_env_value("0755") == "0755"
        assert coerce_env_value("1_000") == "1_000"
        assert coerce_env_value("nan") == "nan"
        assert coerce_env_value("infinity") == "infinity"

    def test_numeric_hardening_holds_with_json_arrays_enabled(self) -> None:
        assert coerce_env_value("0755", json_arrays=True) == "0755"
        assert coerce_env_value("nan", json_arrays=True) == "nan"

    def test_raise_is_still_the_default_policy(self) -> None:
        os.environ.pop("MISSING_VAR", None)
        with pytest.raises(RuntimeError, match="MISSING_VAR"):
            resolve_env_placeholders({"a": "$MISSING_VAR"})
