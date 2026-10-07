"""Tests for the rule condition matcher."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from threatcode.engine.rules.loader import Rule
from threatcode.engine.rules.matcher import (
    MAX_CONDITION_DEPTH,
    VALID_OPERATORS,
    PathError,
    PathKind,
    Tri,
    evaluate_condition,
    evaluate_condition_tri,
    evaluate_rule,
    match_state,
    matches_rule,
    parse_path,
    parse_port_ranges,
    ports_overlap,
    resolve_path,
    tri_and,
    tri_not,
    tri_or,
)
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.values import UNKNOWN, Unknown

T, F, U = Tri.TRUE, Tri.FALSE, Tri.UNKNOWN


def _make_node(
    resource_type: str = "aws_s3_bucket", evidence: str = "config", **props: object
) -> InfraNode:
    return InfraNode(
        id=f"{resource_type}.test",
        resource_type=resource_type,
        name="test",
        category=NodeCategory.STORAGE,
        trust_zone=TrustZone.DATA,
        properties=dict(props),
        evidence=evidence,  # type: ignore[arg-type]
    )


def _make_rule(resource_types: tuple[str, ...] | str, condition: dict[str, Any]) -> Rule:
    return Rule(
        id="TEST_RULE",
        title="Test Rule",
        description="Test",
        stride_category="tampering",
        severity="medium",
        resource_types=(resource_types,) if isinstance(resource_types, str) else resource_types,
        condition=condition,
    )


def _tri(condition: dict[str, Any], props: dict[str, Any], evidence: str = "config") -> Tri:
    node = _make_node(evidence=evidence)
    node.properties.update(props)
    return evaluate_condition_tri(condition, node)


def _op(op: str, argument: Any, value: Any) -> Tri:
    """Evaluate one operator against one property value."""
    return _tri({"p": {op: argument}}, {"p": value})


class TestEvaluateCondition:
    def test_not_exists_true(self) -> None:
        node = _make_node()
        assert evaluate_condition({"encryption": {"not_exists": True}}, node) is True

    def test_not_exists_false(self) -> None:
        node = _make_node(encryption="AES256")
        assert evaluate_condition({"encryption": {"not_exists": True}}, node) is False

    def test_exists_true(self) -> None:
        node = _make_node(encryption="AES256")
        assert evaluate_condition({"encryption": {"exists": True}}, node) is True

    def test_equals(self) -> None:
        node = _make_node(acl="public-read")
        assert evaluate_condition({"acl": {"equals": "public-read"}}, node) is True
        assert evaluate_condition({"acl": {"equals": "private"}}, node) is False

    def test_not_equals(self) -> None:
        node = _make_node(acl="private")
        assert evaluate_condition({"acl": {"not_equals": "public-read"}}, node) is True

    def test_contains_string(self) -> None:
        node = _make_node(policy='{"Action":"*"}')
        assert evaluate_condition({"policy": {"contains": '"Action":"*"'}}, node) is True

    def test_matches_any(self) -> None:
        node = _make_node(acl="public-read")
        condition = {"acl": {"matches_any": ["public-read", "public-read-write"]}}
        assert evaluate_condition(condition, node) is True

        node2 = _make_node(acl="private")
        assert evaluate_condition(condition, node2) is False

    def test_is_empty_true(self) -> None:
        node = _make_node(tags={})
        assert evaluate_condition({"tags": {"is_empty": True}}, node) is True

    def test_is_empty_false(self) -> None:
        node = _make_node(tags={"env": "prod"})
        assert evaluate_condition({"tags": {"is_empty": True}}, node) is False

    def test_greater_than(self) -> None:
        node = _make_node(retention=30)
        assert evaluate_condition({"retention": {"greater_than": 7}}, node) is True
        assert evaluate_condition({"retention": {"greater_than": 30}}, node) is False

    def test_less_than(self) -> None:
        node = _make_node(retention=3)
        assert evaluate_condition({"retention": {"less_than": 7}}, node) is True

    def test_all_of(self) -> None:
        node = _make_node(acl="private", encryption="AES256")
        condition = {
            "all_of": [
                {"acl": {"equals": "private"}},
                {"encryption": {"equals": "AES256"}},
            ]
        }
        assert evaluate_condition(condition, node) is True

    def test_any_of(self) -> None:
        node = _make_node(acl="public-read")
        condition = {
            "any_of": [
                {"acl": {"equals": "public-read"}},
                {"acl": {"equals": "public-read-write"}},
            ]
        }
        assert evaluate_condition(condition, node) is True

    def test_none_of(self) -> None:
        node = _make_node(acl="private")
        condition = {
            "none_of": [
                {"acl": {"equals": "public-read"}},
                {"acl": {"equals": "public-read-write"}},
            ]
        }
        assert evaluate_condition(condition, node) is True

    def test_not_operator(self) -> None:
        node = _make_node(acl="private")
        condition = {"not": {"acl": {"equals": "public-read"}}}
        assert evaluate_condition(condition, node) is True

    def test_nested_path(self) -> None:
        node = _make_node()
        node.properties["server_side_encryption_configuration"] = {
            "rule": {"sse_algorithm": "aws:kms"}
        }
        condition = {
            "server_side_encryption_configuration.rule.sse_algorithm": {"equals": "aws:kms"}
        }
        assert evaluate_condition(condition, node) is True

    def test_direct_equality(self) -> None:
        node = _make_node(acl="private")
        assert evaluate_condition({"acl": "private"}, node) is True
        assert evaluate_condition({"acl": "public"}, node) is False

    def test_evaluate_condition_returns_a_real_bool(self) -> None:
        node = _make_node(acl="private")
        assert evaluate_condition({"acl": "private"}, node) is True
        assert evaluate_condition({"acl": "other"}, node) is False

    def test_several_properties_are_anded(self) -> None:
        node = _make_node(a=1, b=2)
        assert evaluate_condition({"a": 1, "b": 2}, node) is True
        assert evaluate_condition({"a": 1, "b": 3}, node) is False

    def test_evaluate_rule_wraps_a_properties_dict(self) -> None:
        assert evaluate_rule({"acl": {"equals": "private"}}, {"acl": "private"}) is True
        assert evaluate_rule({"acl": {"equals": "private"}}, {}) is False


class TestPathParsing:
    def test_dotted_segments(self) -> None:
        assert [a.text for a in parse_path("a.b.c")] == ["a", "b", "c"]

    def test_bracket_quoted_key_keeps_its_dots(self) -> None:
        atoms = parse_path("labels['a.b']")
        assert [(a.text, a.exact) for a in atoms] == [("labels", False), ("a.b", True)]

    def test_double_quoted_bracket(self) -> None:
        assert [a.text for a in parse_path('labels["x.y/z"].w')] == ["labels", "x.y/z", "w"]

    def test_escaped_dot(self) -> None:
        atoms = parse_path(r"labels.pod-security\.kubernetes\.io/enforce")
        assert [a.text for a in atoms] == ["labels", "pod-security.kubernetes.io/enforce"]
        assert atoms[1].exact

    def test_index_and_wildcard_brackets(self) -> None:
        atoms = parse_path("a[0].b[*].c")
        assert [a.text for a in atoms] == ["a", "0", "b", "*", "c"]
        assert atoms[1].index == 0
        assert atoms[3].wildcard

    def test_a_quoted_star_is_a_literal_key_not_a_wildcard(self) -> None:
        atom = parse_path("a['*']")[1]
        assert not atom.wildcard
        assert atom.text == "*"

    @pytest.mark.parametrize(
        "path",
        ["", ".a", "a.", "a..b", "a[", "a[x]", "a['x]", "a['']", "a[0]b", "a\\", "a\\x", "a[]"],
    )
    def test_malformed_paths_are_rejected(self, path: str) -> None:
        with pytest.raises(PathError):
            parse_path(path)

    def test_too_many_segments_are_rejected(self) -> None:
        with pytest.raises(PathError, match="segments"):
            parse_path(".".join("abcdefghijklmnopq"))

    def test_a_malformed_path_resolves_to_nothing(self) -> None:
        assert resolve_path({"a": 1}, "a..b").kind is PathKind.MISSING
        assert resolve_path({"a": 1}, 5).kind is PathKind.MISSING  # type: ignore[arg-type]


class TestPathResolution:
    def test_plain_nested_value(self) -> None:
        resolved = resolve_path({"a": {"b": {"c": 1}}}, "a.b.c")
        assert (resolved.kind, resolved.value) == (PathKind.VALUE, 1)

    def test_missing_key(self) -> None:
        assert resolve_path({"a": {}}, "a.b").kind is PathKind.MISSING

    def test_none_counts_as_missing(self) -> None:
        assert resolve_path({"a": None}, "a").kind is PathKind.MISSING

    def test_dotted_label_key_resolves(self) -> None:
        props = {"labels": {"pod-security.kubernetes.io/enforce": "restricted"}}
        resolved = resolve_path(props, "labels.pod-security.kubernetes.io/enforce")
        assert resolved.value == "restricted"

    def test_longest_literal_key_wins_over_nesting(self) -> None:
        props = {"a.b": 1, "a": {"b": 2}}
        assert resolve_path(props, "a.b").value == 1

    def test_falls_back_to_a_shorter_key_when_the_longer_one_leads_nowhere(self) -> None:
        props = {"a.b": {"c": 1}, "a": {"b": {"d": 2}}}
        assert resolve_path(props, "a.b.d").value == 2

    def test_annotation_with_dots_and_slashes_resolves(self) -> None:
        props = {"template": [{"metadata": [{"annotations": {"run.googleapis.com/x": "v"}}]}]}
        assert (
            resolve_path(props, "template.metadata.annotations.run.googleapis.com/x").value == "v"
        )

    def test_bracket_form_resolves(self) -> None:
        props = {"labels": {"a.b": "x"}}
        assert resolve_path(props, "labels['a.b']").value == "x"

    def test_escaped_form_resolves(self) -> None:
        props = {"labels": {"a.b": "x"}}
        assert resolve_path(props, r"labels.a\.b").value == "x"

    def test_bracket_key_does_not_split_into_nested_lookup(self) -> None:
        props = {"labels": {"a": {"b": "nested"}}}
        assert resolve_path(props, "labels['a.b']").kind is PathKind.MISSING

    def test_integer_segment_indexes_a_list(self) -> None:
        props = {"versioning": [{"enabled": False}, {"enabled": True}]}
        assert resolve_path(props, "versioning.0.enabled").value is False
        assert resolve_path(props, "versioning.1.enabled").value is True
        assert resolve_path(props, "versioning[1].enabled").value is True

    def test_integer_segment_out_of_range_is_missing(self) -> None:
        assert resolve_path({"a": [1]}, "a.3").kind is PathKind.MISSING

    def test_single_block_list_is_descended_into(self) -> None:
        props = {"settings": [{"ip_configuration": [{"ipv4_enabled": True}]}]}
        assert resolve_path(props, "settings.ip_configuration.ipv4_enabled").value is True

    def test_multi_element_list_fans_out(self) -> None:
        props = {"ingress": [{"from_port": 22}, {"from_port": 443}, {"to_port": 1}]}
        resolved = resolve_path(props, "ingress.from_port")
        assert resolved.kind is PathKind.MANY
        assert resolved.value == [22, 443]

    def test_wildcard_over_a_list(self) -> None:
        props = {"ingress": [{"cidr_blocks": ["a"]}, {"cidr_blocks": ["b", "c"]}]}
        resolved = resolve_path(props, "ingress.*.cidr_blocks")
        assert resolved.kind is PathKind.MANY
        assert resolved.value == [["a"], ["b", "c"]]

    def test_wildcard_as_last_step_yields_the_elements(self) -> None:
        resolved = resolve_path({"a": [1, 2, 3]}, "a.*")
        assert resolved.value == [1, 2, 3]

    def test_wildcard_over_mapping_values(self) -> None:
        props = {"rules": {"x": {"port": 1}, "y": {"port": 2}}}
        assert resolve_path(props, "rules.*.port").value == [1, 2]

    def test_nested_fan_outs_are_flattened(self) -> None:
        props = {"a": [{"b": [{"c": 1}, {"c": 2}]}, {"b": [{"c": 3}]}]}
        assert resolve_path(props, "a.*.b.*.c").value == [1, 2, 3]

    def test_empty_list_is_missing(self) -> None:
        assert resolve_path({"a": []}, "a.b").kind is PathKind.MISSING
        assert resolve_path({"a": []}, "a.*").kind is PathKind.MISSING

    def test_fan_out_with_no_hits_is_missing(self) -> None:
        assert resolve_path({"a": [{"x": 1}, {"x": 2}]}, "a.y").kind is PathKind.MISSING

    def test_one_element_list_of_scalars_has_no_children(self) -> None:
        assert resolve_path({"a": ["x"]}, "a.b").kind is PathKind.MISSING

    def test_unknown_at_the_path_is_unknown(self) -> None:
        resolved = resolve_path({"a": Unknown("var.x")}, "a")
        assert resolved.kind is PathKind.UNKNOWN
        assert resolved.value.reference == "var.x"

    def test_unknown_above_the_path_is_unknown(self) -> None:
        assert resolve_path({"a": UNKNOWN}, "a.b.c").kind is PathKind.UNKNOWN
        assert resolve_path({"a": [UNKNOWN]}, "a.b").kind is PathKind.UNKNOWN

    def test_unknown_elements_survive_a_fan_out(self) -> None:
        props = {"a": [{"b": 1}, {"b": UNKNOWN}]}
        resolved = resolve_path(props, "a.b")
        assert resolved.kind is PathKind.MANY
        assert resolved.value[0] == 1
        assert isinstance(resolved.value[1], Unknown)

    def test_scalar_with_remaining_path_is_missing(self) -> None:
        assert resolve_path({"a": "text"}, "a.b").kind is PathKind.MISSING


class TestAbsence:
    @pytest.mark.parametrize("value", [None, "", [], {}])
    def test_empty_values_are_absent(self, value: Any) -> None:
        assert _op("exists", True, value) is F
        assert _op("not_exists", True, value) is T
        assert _op("is_empty", True, value) is T

    @pytest.mark.parametrize("value", [False, 0, "false", "0", [0], {"a": None}, 0.0])
    def test_false_and_zero_are_present(self, value: Any) -> None:
        assert _op("exists", True, value) is T
        assert _op("not_exists", True, value) is F
        assert _op("is_empty", True, value) is F

    def test_a_missing_key_is_absent(self) -> None:
        assert _tri({"p": {"not_exists": True}}, {}) is T
        assert _tri({"p": {"exists": True}}, {}) is F

    def test_exists_false_is_not_exists(self) -> None:
        assert _op("exists", False, []) is T
        assert _op("exists", False, "x") is F
        assert _op("not_exists", False, "x") is T
        assert _op("is_empty", False, "x") is T

    def test_plan_json_empty_block_list_agrees_with_hcl_missing_key(self) -> None:
        for condition in (
            {"logging": {"not_exists": True}},
            {"any_of": [{"versioning": {"not_exists": True}}, {"versioning.0.enabled": False}]},
        ):
            assert _tri(condition, {"logging": [], "versioning": []}) is T
            assert _tri(condition, {}) is T

    def test_non_boolean_flag_argument_is_unknown(self) -> None:
        assert _op("exists", "yes", "x") is U
        assert _op("is_true", 1, "x") is U


class TestEquality:
    def test_true_is_not_one(self) -> None:
        assert _op("equals", True, 1) is F
        assert _op("equals", 1, True) is F
        assert _op("equals", False, 0) is F
        assert _op("equals", True, True) is T

    def test_not_equals_is_bool_strict_too(self) -> None:
        assert _op("not_equals", True, 1) is T
        assert _op("not_equals", 0, False) is T
        assert _op("not_equals", False, False) is F

    def test_numbers_and_strings_do_not_cross(self) -> None:
        assert _op("equals", 3, "3") is F
        assert _op("equals", 3, 3.0) is T

    def test_lists_and_mappings_compare_structurally(self) -> None:
        assert _op("equals", [1, 2], [1, 2]) is T
        assert _op("equals", [True], [1]) is F
        assert _op("equals", {"a": 1}, {"a": 1}) is T
        assert _op("equals", {"a": 1}, {"a": 2}) is F

    def test_missing_value_does_not_equal_anything(self) -> None:
        assert _tri({"p": {"equals": False}}, {}) is F
        assert _tri({"p": {"not_equals": False}}, {}) is T

    def test_equals_ci(self) -> None:
        assert _op("equals_ci", "true", "TRUE") is T
        assert _op("equals_ci", "Allow", "allow") is T
        assert _op("equals_ci", "true", "false") is F
        assert _op("equals_ci", "true", 1) is F

    def test_equals_ci_accepts_a_boolean_value(self) -> None:
        assert _op("equals_ci", "true", True) is T
        assert _op("equals_ci", "true", False) is F

    def test_equals_ci_with_a_non_string_argument_is_false(self) -> None:
        assert _op("equals_ci", 1, "1") is F


class TestIsTrue:
    @pytest.mark.parametrize("value", [True, "true", "TRUE", "True", "1", "yes", "YES", " true "])
    def test_truthy_values(self, value: Any) -> None:
        assert _op("is_true", True, value) is T
        assert _op("is_true", False, value) is F

    @pytest.mark.parametrize("value", [False, "false", "False", "0", "no", "", 0, 2, None, []])
    def test_falsy_values(self, value: Any) -> None:
        assert _op("is_true", True, value) is F
        assert _op("is_true", False, value) is T

    def test_the_string_false_is_not_truthy(self) -> None:
        # bool("false") is True; the matcher must not use it
        assert _op("is_true", False, "false") is T


class TestComparisons:
    def test_numeric_strings_are_coerced(self) -> None:
        assert _op("greater_than", 90, "120") is T
        assert _op("less_than", 90, "30") is T
        assert _op("greater_than", 1.1, "1.2") is T
        assert _op("greater_than", 90, " 120 ") is T

    def test_booleans_are_rejected(self) -> None:
        assert _op("greater_than", 0, True) is F
        assert _op("less_than", 5, True) is F
        assert _op("less_than", 5, False) is F

    def test_non_numeric_values_never_compare(self) -> None:
        assert _op("greater_than", 1, "abc") is F
        assert _op("less_than", 100, "1_000") is F
        assert _op("greater_than", 1, [5]) is F
        assert _op("less_than", 1, None) is F

    def test_missing_value_never_compares(self) -> None:
        assert _tri({"p": {"less_than": 90}}, {}) is F

    def test_boundaries_are_exclusive(self) -> None:
        assert _op("greater_than", 7, 7) is F
        assert _op("less_than", 7, 7) is F
        assert _op("greater_than", 7, 8) is T

    def test_negative_and_decimal_strings(self) -> None:
        assert _op("less_than", 0, "-1") is T
        assert _op("greater_than", 0.5, ".75") is T


class TestContains:
    def test_substring_of_a_string(self) -> None:
        assert _op("contains", "ab", "xaby") is T
        assert _op("contains", "q", "xaby") is F

    def test_string_with_a_non_string_argument_is_false_not_an_error(self) -> None:
        assert _op("contains", 1, "abc") is F
        assert _op("contains", True, "abc") is F
        assert _op("not_contains", 1, "abc") is T

    def test_element_of_a_list_by_equality(self) -> None:
        assert _op("contains", "0.0.0.0/0", ["10.0.0.0/8", "0.0.0.0/0"]) is T
        assert _op("contains", "0.0.0", ["0.0.0.0/0"]) is F

    def test_list_of_numbers(self) -> None:
        assert _op("contains", 22, [22, 80]) is T
        assert _op("contains", True, [1]) is F

    def test_key_of_a_mapping(self) -> None:
        assert _op("contains", "env", {"env": "prod"}) is T
        assert _op("contains", "prod", {"env": "prod"}) is F

    def test_list_of_mappings_is_not_searched(self) -> None:
        # Use any_item to query a list of objects
        assert _op("contains", "0.0.0.0/0", [{"cidr_blocks": ["0.0.0.0/0"]}]) is F

    def test_other_value_types_do_not_contain(self) -> None:
        assert _op("contains", "a", 5) is F
        assert _op("contains", "a", None) is F
        assert _tri({"p": {"contains": "a"}}, {}) is F

    def test_not_contains_is_the_negation(self) -> None:
        assert _op("not_contains", "private", "public-read") is T
        assert _op("not_contains", "public", "public-read") is F
        assert _tri({"p": {"not_contains": "a"}}, {}) is T
        assert _op("not_contains", "a", ["a"]) is F

    def test_matches_any_is_value_in_list(self) -> None:
        assert _op("matches_any", ["a", "b"], "b") is T
        assert _op("matches_any", ["a", "b"], "c") is F
        assert _op("matches_any", [1, 2], True) is F
        assert _op("matches_any", [True], True) is T
        assert _tri({"p": {"matches_any": ["a"]}}, {}) is F

    def test_matches_any_with_a_non_list_argument_is_unknown(self) -> None:
        assert _op("matches_any", "a", "a") is U


class TestFanOutOperators:
    PROPS = {
        "ingress": [
            {"cidr_blocks": ["10.0.0.0/8"], "from_port": 443},
            {"cidr_blocks": ["0.0.0.0/0"], "from_port": 22},
        ]
    }

    def test_equals_is_true_when_any_element_matches(self) -> None:
        assert _tri({"ingress.from_port": {"equals": 22}}, self.PROPS) is T
        assert _tri({"ingress.from_port": {"equals": 80}}, self.PROPS) is F

    def test_not_equals_is_true_only_when_none_matches(self) -> None:
        assert _tri({"ingress.from_port": {"not_equals": 22}}, self.PROPS) is F
        assert _tri({"ingress.from_port": {"not_equals": 80}}, self.PROPS) is T

    def test_contains_searches_every_element(self) -> None:
        assert _tri({"ingress.cidr_blocks": {"contains": "0.0.0.0/0"}}, self.PROPS) is T
        assert _tri({"ingress.cidr_blocks": {"contains": "::/0"}}, self.PROPS) is F
        assert _tri({"ingress.cidr_blocks": {"not_contains": "0.0.0.0/0"}}, self.PROPS) is F

    def test_matches_any_over_elements(self) -> None:
        assert _tri({"ingress.from_port": {"matches_any": [22, 3389]}}, self.PROPS) is T

    def test_exists_and_not_exists_over_elements(self) -> None:
        assert _tri({"ingress.cidr_blocks": {"exists": True}}, self.PROPS) is T
        assert _tri({"ingress.missing": {"not_exists": True}}, self.PROPS) is T

    def test_greater_than_over_elements(self) -> None:
        assert _tri({"ingress.from_port": {"greater_than": 400}}, self.PROPS) is T
        assert _tri({"ingress.from_port": {"greater_than": 500}}, self.PROPS) is F

    def test_wildcard_path_into_nested_lists(self) -> None:
        assert _tri({"ingress.*.cidr_blocks": {"contains": "0.0.0.0/0"}}, self.PROPS) is T


class TestQuantifiers:
    INGRESS = [
        {"cidr_blocks": ["10.0.0.0/8"], "from_port": 443, "to_port": 443, "protocol": "tcp"},
        {"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"},
    ]

    def test_any_item(self) -> None:
        cond = {"ingress": {"any_item": {"from_port": 22}}}
        assert _tri(cond, {"ingress": self.INGRESS}) is T
        assert _tri({"ingress": {"any_item": {"from_port": 80}}}, {"ingress": self.INGRESS}) is F

    def test_all_items(self) -> None:
        props = {"ingress": self.INGRESS}
        assert _tri({"ingress": {"all_items": {"protocol": "tcp"}}}, props) is T
        assert _tri({"ingress": {"all_items": {"from_port": 22}}}, props) is F

    def test_none_items(self) -> None:
        props = {"ingress": self.INGRESS}
        assert _tri({"ingress": {"none_items": {"from_port": 80}}}, props) is T
        assert _tri({"ingress": {"none_items": {"from_port": 22}}}, props) is F

    def test_an_element_is_judged_as_a_whole(self) -> None:
        cond = {
            "ingress": {
                "any_item": {
                    "all_of": [
                        {"cidr_blocks": {"contains": "0.0.0.0/0"}},
                        {"from_port": {"equals": 443}},
                    ]
                }
            }
        }
        assert _tri(cond, {"ingress": self.INGRESS}) is F

    def test_logical_keys_work_inside_a_quantifier(self) -> None:
        cond = {
            "ingress": {
                "any_item": {
                    "any_of": [{"from_port": 80}, {"cidr_blocks": {"is_world_cidr": True}}]
                }
            }
        }
        assert _tri(cond, {"ingress": self.INGRESS}) is T

    def test_empty_list_any_is_false_all_is_true(self) -> None:
        assert _tri({"p": {"any_item": {"x": 1}}}, {"p": []}) is F
        assert _tri({"p": {"all_items": {"x": 1}}}, {"p": []}) is T
        assert _tri({"p": {"none_items": {"x": 1}}}, {"p": []}) is T

    def test_absent_list_any_is_false_all_is_true(self) -> None:
        assert _tri({"p": {"any_item": {"x": 1}}}, {}) is F
        assert _tri({"p": {"all_items": {"x": 1}}}, {}) is T
        assert _tri({"p": {"none_items": {"x": 1}}}, {}) is T

    def test_scalar_elements_are_bound_to_value(self) -> None:
        cond = {"p": {"any_item": {"_value": {"equals": "b"}}}}
        assert _tri(cond, {"p": ["a", "b"]}) is T
        assert _tri(cond, {"p": ["a", "c"]}) is F

    def test_a_single_mapping_is_a_one_element_list(self) -> None:
        assert _tri({"p": {"any_item": {"x": 1}}}, {"p": {"x": 1}}) is T

    def test_a_lone_scalar_is_a_one_element_list(self) -> None:
        assert _tri({"p": {"any_item": {"_value": "a"}}}, {"p": "a"}) is T

    def test_quantifiers_nest(self) -> None:
        cond = {"a": {"any_item": {"b": {"any_item": {"c": 1}}}}}
        assert _tri(cond, {"a": [{"b": [{"c": 0}]}, {"b": [{"c": 1}]}]}) is T
        assert _tri(cond, {"a": [{"b": [{"c": 0}]}, {"b": []}]}) is F

    def test_a_quantifier_over_a_fan_out_sees_every_element(self) -> None:
        props = {"rules": [{"ports": [1, 2]}, {"ports": [3]}]}
        cond = {"rules.ports": {"any_item": {"_value": {"equals": 3}}}}
        assert _tri(cond, props) is T

    def test_a_non_condition_argument_is_unknown(self) -> None:
        assert _tri({"p": {"any_item": "x"}}, {"p": [1]}) is U

    def test_unknown_element_is_unknown_unless_another_element_matches(self) -> None:
        cond = {"p": {"any_item": {"x": 1}}}
        assert _tri(cond, {"p": [{"x": 0}, UNKNOWN]}) is U
        assert _tri(cond, {"p": [{"x": 1}, UNKNOWN]}) is T
        assert _tri({"p": {"all_items": {"x": 1}}}, {"p": [{"x": 1}, UNKNOWN]}) is U
        assert _tri({"p": {"all_items": {"x": 1}}}, {"p": [{"x": 0}, UNKNOWN]}) is F


class TestWorldCidr:
    @pytest.mark.parametrize(
        "value",
        ["0.0.0.0/0", "::/0", "*", "Internet", "ANY", "any", "10.0.0.0/0", " 0.0.0.0/0 "],
    )
    def test_world_values(self, value: str) -> None:
        assert _op("is_world_cidr", True, value) is T
        assert _op("is_world_cidr", False, value) is F

    @pytest.mark.parametrize(
        "value", ["10.0.0.0/8", "0.0.0.0/1", "192.168.1.1", "VirtualNetwork", "", "not a cidr", 0]
    )
    def test_non_world_values(self, value: Any) -> None:
        assert _op("is_world_cidr", True, value) is F

    def test_any_element_of_a_list(self) -> None:
        assert _op("is_world_cidr", True, ["10.0.0.0/8", "0.0.0.0/0"]) is T
        assert _op("is_world_cidr", True, ["10.0.0.0/8", "172.16.0.0/12"]) is F
        assert _op("is_world_cidr", True, []) is F

    def test_fan_out_over_elements(self) -> None:
        props = {"ingress": [{"cidr_blocks": ["10.0.0.0/8"]}, {"cidr_blocks": ["0.0.0.0/0"]}]}
        assert _tri({"ingress.cidr_blocks": {"is_world_cidr": True}}, props) is T

    def test_non_string_list_members_are_ignored(self) -> None:
        assert _op("is_world_cidr", True, [1, None, "0.0.0.0/0"]) is T
        assert _op("is_world_cidr", True, [1, None]) is F

    def test_mapping_value_is_not_a_cidr(self) -> None:
        assert _op("is_world_cidr", True, {"cidr": "0.0.0.0/0"}) is F


class TestPortOverlaps:
    @staticmethod
    def _ports(wanted: list[Any], element: dict[str, Any], evidence: str = "config") -> Tri:
        return _tri({"port_overlaps": wanted}, element, evidence)

    def test_single_port(self) -> None:
        element = {"from_port": 22, "to_port": 22, "protocol": "tcp"}
        assert self._ports([22], element) is T
        assert self._ports([3389], element) is F

    def test_range_contains_the_wanted_port(self) -> None:
        element = {"from_port": 0, "to_port": 1024, "protocol": "tcp"}
        assert self._ports([22], element) is T
        assert self._ports([8080], element) is F

    def test_wanted_ranges_as_strings(self) -> None:
        element = {"from_port": 1050, "to_port": 1050, "protocol": "tcp"}
        assert self._ports(["1024-1100"], element) is T
        assert self._ports([22, "2000-3000"], element) is F

    def test_partial_overlap_counts(self) -> None:
        element = {"from_port": 20, "to_port": 25, "protocol": "tcp"}
        assert self._ports([25, 26], element) is T
        assert self._ports([26], element) is F

    def test_protocol_minus_one_means_every_port(self) -> None:
        assert self._ports([22], {"from_port": 0, "to_port": 0, "protocol": "-1"}) is T
        assert self._ports([22], {"protocol": -1}) is T
        assert self._ports([22], {"ip_protocol": "-1"}) is T
        assert self._ports([22], {"protocol": "all"}) is T

    def test_icmp_has_no_ports(self) -> None:
        assert self._ports([22], {"from_port": -1, "to_port": -1, "protocol": "icmp"}) is F
        assert self._ports([22], {"from_port": 0, "to_port": 65535, "protocol": "icmp"}) is F

    def test_numeric_strings_in_from_and_to(self) -> None:
        assert self._ports([22], {"from_port": "22", "to_port": "22", "protocol": "tcp"}) is T

    def test_only_from_port_is_a_single_port(self) -> None:
        assert self._ports([22], {"from_port": 22, "protocol": "tcp"}) is T

    def test_azure_single_port_string(self) -> None:
        assert self._ports([22], {"destination_port_range": "22", "protocol": "Tcp"}) is T
        assert self._ports([22], {"destination_port_range": "443", "protocol": "Tcp"}) is F

    def test_azure_range_and_star(self) -> None:
        assert self._ports([22], {"destination_port_range": "20-25"}) is T
        assert self._ports([22], {"destination_port_range": "*"}) is T
        assert self._ports([22], {"destination_port_range": "1024-65535"}) is F

    def test_azure_list_of_ranges(self) -> None:
        element = {"destination_port_ranges": ["3389", "22"]}
        assert self._ports([22], element) is T
        assert self._ports([3389], element) is T
        assert self._ports([80], element) is F

    def test_azure_protocol_star_does_not_open_every_port(self) -> None:
        # In Azure the protocol "*" means any protocol, and the ports are named separately
        element = {"protocol": "*", "destination_port_range": "443"}
        assert self._ports([22], element) is F

    def test_generic_port_keys(self) -> None:
        assert self._ports([22], {"port": 22}) is T
        assert self._ports([22], {"port_range": "22"}) is T
        assert self._ports([22], {"port": 80}) is F

    def test_element_without_ports_is_false_on_config_and_unknown_on_design(self) -> None:
        assert self._ports([22], {"protocol": "tcp"}) is F
        assert self._ports([22], {"protocol": "tcp"}, evidence="design") is U

    def test_unknown_ports_are_unknown(self) -> None:
        assert self._ports([22], {"from_port": UNKNOWN, "to_port": 22, "protocol": "tcp"}) is U
        assert self._ports([22], {"destination_port_range": UNKNOWN}) is U
        assert self._ports([22], {"protocol": UNKNOWN, "from_port": 1, "to_port": 2}) is U

    def test_invalid_wanted_list_is_unknown(self) -> None:
        assert self._ports(["abc"], {"from_port": 22, "to_port": 22}) is U
        assert self._ports([], {"from_port": 22, "to_port": 22}) is U
        assert self._ports([70000], {"from_port": 22, "to_port": 22}) is U

    def test_inside_any_item_with_a_world_cidr(self) -> None:
        cond = {
            "ingress": {
                "any_item": {
                    "cidr_blocks": {"is_world_cidr": True},
                    "port_overlaps": [22, 3389],
                }
            }
        }
        bad = [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 22, "to_port": 22, "protocol": "tcp"}]
        web = [{"cidr_blocks": ["0.0.0.0/0"], "from_port": 443, "to_port": 443, "protocol": "tcp"}]
        private = [
            {"cidr_blocks": ["10.0.0.0/8"], "from_port": 22, "to_port": 22, "protocol": "tcp"}
        ]
        assert _tri(cond, {"ingress": bad}) is T
        assert _tri(cond, {"ingress": web}) is F
        assert _tri(cond, {"ingress": private}) is F
        assert _tri(cond, {"ingress": []}) is F

    def test_ports_overlap_helper(self) -> None:
        assert ports_overlap(22, 22, "tcp", [22]) is True
        assert ports_overlap(0, 0, "-1", [22]) is True
        assert ports_overlap(0, 0, "tcp", [22]) is False
        assert ports_overlap(-1, -1, "icmp", [22]) is False
        assert ports_overlap("20-25", None, None, [22]) is True
        assert ports_overlap(["3389", "22"], None, None, [22]) is True
        assert ports_overlap("*", None, None, [22]) is True
        assert ports_overlap("abc", None, None, [22]) is False
        assert ports_overlap(None, None, "tcp", [22]) is False

    def test_parse_port_ranges(self) -> None:
        assert parse_port_ranges([22, "1024-1100", "*"]) == ((22, 22), (1024, 1100), (0, 65535))
        assert parse_port_ranges("22") == ((22, 22),)
        assert parse_port_ranges(["100-50"]) == ((50, 100),)

    @pytest.mark.parametrize("bad", [[True], ["a-b"], [-1], [65536], ["1-"], [None], [1.5]])
    def test_parse_port_ranges_rejects(self, bad: list[Any]) -> None:
        with pytest.raises(ValueError):
            parse_port_ranges(bad)


class TestUnknownValues:
    OPERATORS: list[tuple[str, Any]] = [
        ("exists", True),
        ("exists", False),
        ("not_exists", True),
        ("equals", "x"),
        ("not_equals", "x"),
        ("equals_ci", "x"),
        ("contains", "x"),
        ("not_contains", "x"),
        ("matches_any", ["x"]),
        ("greater_than", 1),
        ("less_than", 1),
        ("is_true", True),
        ("is_true", False),
        ("is_empty", True),
        ("is_world_cidr", True),
        ("any_item", {"x": 1}),
        ("all_items", {"x": 1}),
        ("none_items", {"x": 1}),
    ]

    @pytest.mark.parametrize(("op", "argument"), OPERATORS)
    def test_an_unknown_value_makes_every_operator_unknown(self, op: str, argument: Any) -> None:
        assert _op(op, argument, Unknown("aws_kms_key.k.arn")) is U

    @pytest.mark.parametrize(("op", "argument"), OPERATORS)
    def test_an_unknown_ancestor_makes_every_operator_unknown(self, op: str, argument: Any) -> None:
        assert _tri({"a.b": {op: argument}}, {"a": UNKNOWN}) is U

    def test_unknown_never_fires_a_rule_even_under_negation(self) -> None:
        props = {"kms_key_id": Unknown("aws_kms_key.k.arn")}
        assert evaluate_rule({"kms_key_id": {"not_exists": True}}, props) is False
        assert evaluate_rule({"kms_key_id": {"exists": True}}, props) is False
        assert evaluate_rule({"not": {"kms_key_id": {"exists": True}}}, props) is False
        assert evaluate_rule({"none_of": [{"kms_key_id": {"exists": True}}]}, props) is False

    def test_a_trail_without_the_key_still_fires_the_absence_rule(self) -> None:
        assert evaluate_rule({"kms_key_id": {"not_exists": True}}, {"name": "t"}) is True

    def test_list_with_an_unknown_element_is_unknown_when_nothing_matches(self) -> None:
        assert _op("contains", "0.0.0.0/0", ["10.0.0.0/8", UNKNOWN]) is U
        assert _op("contains", "10.0.0.0/8", ["10.0.0.0/8", UNKNOWN]) is T
        assert _op("equals", ["a"], ["a", UNKNOWN]) is U
        assert _op("is_world_cidr", True, ["10.0.0.0/8", UNKNOWN]) is U
        assert _op("is_world_cidr", True, ["0.0.0.0/0", UNKNOWN]) is T

    def test_mapping_with_an_unknown_value_is_unknown_when_nothing_matches(self) -> None:
        assert _op("equals", {"a": 1}, {"a": UNKNOWN}) is U

    def test_fan_out_with_an_unknown_leaf(self) -> None:
        props = {"a": [{"b": 1}, {"b": UNKNOWN}]}
        assert _tri({"a.b": {"equals": 1}}, props) is T
        assert _tri({"a.b": {"equals": 2}}, props) is U
        assert _tri({"a.b": {"not_equals": 2}}, props) is U
        assert _tri({"a.b": {"not_equals": 1}}, props) is F

    def test_unknown_text_is_not_equal_to_a_plain_string_with_the_same_text(self) -> None:
        assert _op("equals", "(known after apply)", UNKNOWN) is U

    def test_known_values_next_to_unknown_ones_are_unaffected(self) -> None:
        props = {"a": UNKNOWN, "b": "x"}
        assert _tri({"b": "x"}, props) is T
        assert _tri({"all_of": [{"b": "x"}, {"a": "y"}]}, props) is U
        assert _tri({"all_of": [{"b": "z"}, {"a": "y"}]}, props) is F


class TestDesignEvidence:
    OPERATORS = TestUnknownValues.OPERATORS

    @pytest.mark.parametrize(("op", "argument"), OPERATORS)
    def test_a_missing_property_is_unknown_for_every_operator(self, op: str, argument: Any) -> None:
        assert _tri({"p": {op: argument}}, {}, evidence="design") is U

    @pytest.mark.parametrize(("op", "argument"), OPERATORS)
    def test_a_missing_property_keeps_definite_semantics_on_config(
        self, op: str, argument: Any
    ) -> None:
        assert _tri({"p": {op: argument}}, {}, evidence="config") is not U

    def test_a_present_property_is_judged_normally_on_a_design_node(self) -> None:
        assert _tri({"p": {"equals": "x"}}, {"p": "x"}, evidence="design") is T
        assert _tri({"p": {"equals": "x"}}, {"p": "y"}, evidence="design") is F

    def test_absence_rule_does_not_fire_on_a_design_node_with_only_other_properties(self) -> None:
        cond = {"server_side_encryption_configuration": {"not_exists": True}}
        node = _make_node(evidence="design", instance_type="t3.micro")
        assert evaluate_condition_tri(cond, node) is U
        assert evaluate_condition(cond, node) is False
        assert evaluate_condition(cond, _make_node(evidence="config", other=1)) is True

    def test_a_positive_rule_still_fires_on_a_design_node(self) -> None:
        node = _make_node(evidence="design", publicly_accessible=True)
        assert evaluate_condition({"publicly_accessible": {"equals": True}}, node) is True

    def test_design_unknown_is_kept_through_negation(self) -> None:
        node = _make_node(evidence="design")
        assert evaluate_condition_tri({"not": {"p": {"exists": True}}}, node) is U
        assert evaluate_condition_tri({"none_of": [{"p": {"exists": True}}]}, node) is U

    def test_a_false_conjunct_still_decides_an_all_of_on_a_design_node(self) -> None:
        node = _make_node(evidence="design", a="x")
        cond = {"all_of": [{"a": "y"}, {"missing": {"not_exists": True}}]}
        assert evaluate_condition_tri(cond, node) is F

    def test_quantifier_elements_inherit_design_evidence(self) -> None:
        cond = {"ingress": {"any_item": {"port": {"exists": True}}}}
        node = _make_node(evidence="design", ingress=[{"cidr": "0.0.0.0/0"}])
        assert evaluate_condition_tri(cond, node) is U
        config = _make_node(evidence="config", ingress=[{"cidr": "0.0.0.0/0"}])
        assert evaluate_condition_tri(cond, config) is F

    def test_a_design_node_without_the_list_is_unknown_for_quantifiers(self) -> None:
        node = _make_node(evidence="design")
        assert evaluate_condition_tri({"p": {"any_item": {"x": 1}}}, node) is U
        assert evaluate_condition_tri({"p": {"all_items": {"x": 1}}}, node) is U

    def test_a_node_without_an_evidence_attribute_is_config(self) -> None:
        class Bare:
            properties: dict[str, Any] = {}

        assert evaluate_condition_tri({"p": {"not_exists": True}}, Bare()) is T  # type: ignore[arg-type]


LEAF_VALUES: dict[str, Any] = {"T": 1, "F": 2, "U": UNKNOWN}


def _combine(op: str, names: str) -> Tri:
    """Evaluate op over leaves that are TRUE ("T"), FALSE ("F") or UNKNOWN ("U")."""
    conditions = [{f"k{i}": {"equals": 1}} for i in range(len(names))]
    props = {f"k{i}": LEAF_VALUES[name] for i, name in enumerate(names)}
    return _tri({op: conditions}, props)


class TestKleeneLogic:
    @pytest.mark.parametrize(
        ("names", "expected"),
        [
            ("TT", T), ("TF", F), ("TU", U), ("FT", F), ("FF", F), ("FU", F),
            ("UT", U), ("UF", F), ("UU", U), ("T", T), ("F", F), ("U", U),
            ("TTT", T), ("TTU", U), ("TUF", F),
        ],
    )  # fmt: skip
    def test_all_of(self, names: str, expected: Tri) -> None:
        assert _combine("all_of", names) is expected

    @pytest.mark.parametrize(
        ("names", "expected"),
        [
            ("TT", T), ("TF", T), ("TU", T), ("FT", T), ("FF", F), ("FU", U),
            ("UT", T), ("UF", U), ("UU", U), ("T", T), ("F", F), ("U", U),
            ("FFF", F), ("FFU", U), ("UFT", T),
        ],
    )  # fmt: skip
    def test_any_of(self, names: str, expected: Tri) -> None:
        assert _combine("any_of", names) is expected

    @pytest.mark.parametrize(
        ("names", "expected"),
        [
            ("T", F), ("F", T), ("U", U), ("TT", F), ("TF", F), ("TU", F),
            ("FF", T), ("FU", U), ("UU", U),
        ],
    )  # fmt: skip
    def test_none_of(self, names: str, expected: Tri) -> None:
        assert _combine("none_of", names) is expected

    @pytest.mark.parametrize(("name", "expected"), [("T", F), ("F", T), ("U", U)])
    def test_not_keeps_unknown(self, name: str, expected: Tri) -> None:
        assert _tri({"not": {"k": {"equals": 1}}}, {"k": LEAF_VALUES[name]}) is expected

    def test_implicit_and_of_property_keys_is_kleene_too(self) -> None:
        assert _tri({"a": 1, "b": 1}, {"a": 1, "b": UNKNOWN}) is U
        assert _tri({"a": 1, "b": 1}, {"a": 2, "b": UNKNOWN}) is F
        assert _tri({"a": 1, "b": 1}, {"a": 1, "b": 1}) is T

    def test_helper_functions_agree_with_the_tables(self) -> None:
        assert tri_and([T, U, T]) is U
        assert tri_and([]) is T
        assert tri_or([F, U]) is U
        assert tri_or([]) is F
        assert tri_not(U) is U

    def test_a_tri_has_no_truth_value(self) -> None:
        with pytest.raises(TypeError):
            bool(U)
        with pytest.raises(TypeError):
            if T:
                pass

    def test_tri_of(self) -> None:
        assert Tri.of(True) is T
        assert Tri.of(False) is F


class TestConditionDepth:
    @staticmethod
    def _nested(levels: int, leaf: dict[str, Any]) -> dict[str, Any]:
        cond = leaf
        for _ in range(levels):
            cond = {"not": cond}
        return cond

    def test_the_limit_is_ten_levels(self) -> None:
        assert MAX_CONDITION_DEPTH == 10

    def test_ten_nested_nots_evaluate(self) -> None:
        assert _tri(self._nested(10, {"a": 1}), {"a": 1}) is T  # even count keeps TRUE
        assert _tri(self._nested(9, {"a": 1}), {"a": 1}) is F

    def test_eleven_nested_nots_are_unknown_not_a_match(self) -> None:
        # With a fail-closed False at the leaf an odd number of nots would turn it into TRUE
        assert _tri(self._nested(11, {"a": 1}), {"a": 1}) is U
        assert _tri(self._nested(11, {"a": 2}), {"a": 1}) is U
        assert evaluate_rule(self._nested(11, {"a": 1}), {"a": 1}) is False
        assert evaluate_rule(self._nested(11, {"a": 2}), {"a": 1}) is False

    def test_deep_none_of_chain_does_not_match(self) -> None:
        cond: dict[str, Any] = {"a": 1}
        for _ in range(15):
            cond = {"none_of": [cond]}
        assert evaluate_rule(cond, {"a": 2}) is False

    def test_quantifiers_count_towards_the_limit(self) -> None:
        def nest(levels: int) -> tuple[dict[str, Any], dict[str, Any]]:
            cond: dict[str, Any] = {"x": 1}
            props: dict[str, Any] = {"x": 1}
            for _ in range(levels):
                cond = {"p": {"any_item": cond}}
                props = {"p": [props]}
            return cond, props

        within = nest(MAX_CONDITION_DEPTH)
        beyond = nest(MAX_CONDITION_DEPTH + 2)
        assert _tri(within[0], within[1]) is T
        assert _tri(beyond[0], beyond[1]) is U


class TestMalformedConditionsAtRuntime:
    def test_unknown_operator_is_unknown_not_false(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            assert _op("equal", "x", "x") is U
            assert evaluate_rule({"not": {"p": {"equal": "x"}}}, {"p": "x"}) is False
        assert any("equal" in r.message for r in caplog.records)

    def test_unknown_operator_warns_once(self, caplog: pytest.LogCaptureFixture) -> None:
        with caplog.at_level(logging.WARNING):
            for _ in range(3):
                _op("eqauls_once_only", "x", "x")
        assert len([r for r in caplog.records if "eqauls_once_only" in r.message]) == 1

    def test_mixed_logical_and_property_keys_are_unknown(self) -> None:
        cond = {"all_of": [{"a": 1}], "b": {"equals": 99}}
        assert _tri(cond, {"a": 1, "b": 99}) is U
        assert evaluate_rule(cond, {"a": 1, "b": 99}) is False

    def test_two_logical_keys_are_unknown(self) -> None:
        cond = {"all_of": [{"a": 1}], "any_of": [{"a": 1}]}
        assert _tri(cond, {"a": 1}) is U

    def test_empty_operator_mapping_is_unknown_not_true(self) -> None:
        assert _tri({"a": {}}, {"a": 1}) is U

    def test_empty_and_non_mapping_conditions_are_unknown(self) -> None:
        assert _tri({}, {"a": 1}) is U
        assert _tri({"all_of": []}, {"a": 1}) is U
        assert _tri({"all_of": "x"}, {"a": 1}) is U
        assert _tri({"not": []}, {"a": 1}) is U
        assert _tri({"any_of": ["x"]}, {"a": 1}) is U

    def test_non_string_key_is_unknown(self) -> None:
        assert _tri({5: {"equals": 1}}, {"a": 1}) is U

    def test_operator_name_that_is_not_a_string_is_unknown(self) -> None:
        assert _tri({"a": {5: 1}}, {"a": 1}) is U

    def test_contains_with_a_numeric_argument_does_not_raise(self) -> None:
        assert evaluate_rule({"a": {"contains": 1}}, {"a": "abc"}) is False

    def test_valid_operators_cover_every_handler(self) -> None:
        assert {"all_of", "any_of", "none_of", "not", "port_overlaps"} <= VALID_OPERATORS
        assert {"any_item", "all_items", "none_items", "equals_ci", "is_world_cidr"} <= (
            VALID_OPERATORS
        )
        assert "property_path" not in VALID_OPERATORS


class TestMatchesRule:
    def test_matching_rule(self) -> None:
        node = _make_node(acl="public-read")
        rule = _make_rule("aws_s3_bucket", {"acl": {"equals": "public-read"}})
        assert matches_rule(rule, node) is True

    def test_non_matching_type(self) -> None:
        node = _make_node(resource_type="aws_instance", acl="public-read")
        rule = _make_rule("aws_s3_bucket", {"acl": {"equals": "public-read"}})
        assert matches_rule(rule, node) is False

    def test_a_sibling_type_with_the_same_prefix_does_not_match(self) -> None:
        rule = _make_rule("aws_s3_bucket", {"some_prop": {"not_exists": True}})
        for sibling in (
            "aws_s3_bucket_versioning",
            "aws_s3_bucket_policy",
            "aws_s3_bucket_public_access_block",
        ):
            assert matches_rule(rule, _make_node(resource_type=sibling)) is False
        assert matches_rule(rule, _make_node(resource_type="aws_s3_bucket")) is True

    def test_key_vault_and_aks_siblings_do_not_match(self) -> None:
        for parent, sibling in (
            ("azurerm_key_vault", "azurerm_key_vault_access_policy"),
            ("azurerm_kubernetes_cluster", "azurerm_kubernetes_cluster_node_pool"),
            ("aws_cloudtrail", "aws_cloudtrail_trail"),
        ):
            rule = _make_rule(parent, {"x": {"not_exists": True}})
            assert matches_rule(rule, _make_node(resource_type=parent)) is True
            assert matches_rule(rule, _make_node(resource_type=sibling)) is False

    def test_a_shorter_type_is_not_a_prefix_match(self) -> None:
        rule = _make_rule("aws_s3_bucket_acl", {"x": {"not_exists": True}})
        assert matches_rule(rule, _make_node(resource_type="aws_s3_bucket")) is False

    def test_resource_types_list_matches_any_member(self) -> None:
        rule = _make_rule(("aws_s3_bucket", "aws_s3_bucket_acl"), {"acl": "public-read"})
        assert matches_rule(rule, _make_node("aws_s3_bucket", acl="public-read")) is True
        assert matches_rule(rule, _make_node("aws_s3_bucket_acl", acl="public-read")) is True
        assert matches_rule(rule, _make_node("aws_s3_bucket_policy", acl="public-read")) is False

    def test_trailing_glob_matches_a_family(self) -> None:
        rule = _make_rule("aws_s3_bucket*", {"x": {"not_exists": True}})
        assert matches_rule(rule, _make_node("aws_s3_bucket")) is True
        assert matches_rule(rule, _make_node("aws_s3_bucket_versioning")) is True
        assert matches_rule(rule, _make_node("aws_s3_buckets")) is True
        assert matches_rule(rule, _make_node("aws_s3")) is False
        assert matches_rule(rule, _make_node("aws_instance")) is False

    def test_a_glob_next_to_exact_entries(self) -> None:
        rule = _make_rule(("aws_lb", "aws_alb*"), {"x": {"not_exists": True}})
        assert matches_rule(rule, _make_node("aws_lb")) is True
        assert matches_rule(rule, _make_node("aws_alb_listener")) is True
        assert matches_rule(rule, _make_node("aws_lb_listener")) is False

    def test_kubernetes_pod_does_not_match_a_pod_disruption_budget(self) -> None:
        rule = _make_rule("kubernetes_pod", {"x": {"not_exists": True}})
        assert matches_rule(rule, _make_node("kubernetes_pod_disruption_budget")) is False

    def test_data_mode_nodes_never_match(self) -> None:
        node = _make_node(acl="public-read")
        node.mode = "data"  # type: ignore[attr-defined]
        rule = _make_rule("aws_s3_bucket", {"acl": {"equals": "public-read"}})
        assert matches_rule(rule, node) is False
        assert match_state(rule, node) is F
        node.mode = "managed"  # type: ignore[attr-defined]
        assert matches_rule(rule, node) is True

    def test_match_state_distinguishes_unknown_from_no(self) -> None:
        rule = _make_rule("aws_cloudtrail", {"kms_key_id": {"not_exists": True}})
        unresolved = _make_node("aws_cloudtrail", kms_key_id=Unknown("aws_kms_key.k.arn"))
        assert match_state(rule, unresolved) is U
        assert matches_rule(rule, unresolved) is False
        assert match_state(rule, _make_node("aws_cloudtrail")) is T
        assert match_state(rule, _make_node("aws_cloudtrail", kms_key_id="k")) is F
        assert match_state(rule, _make_node("aws_instance")) is F

    def test_design_node_with_a_missing_property_is_unknown(self) -> None:
        rule = _make_rule("aws_s3_bucket", {"logging": {"not_exists": True}})
        assert match_state(rule, _make_node(evidence="design")) is U
        assert match_state(rule, _make_node(evidence="config")) is T

    def test_the_type_check_runs_before_the_condition(self) -> None:
        rule = _make_rule("aws_s3_bucket", {"a": {"equals": 1}})
        assert match_state(rule, _make_node("aws_instance", a=UNKNOWN)) is F
