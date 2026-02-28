"""Tests for the rule condition matcher."""

from __future__ import annotations

from threatcode.engine.rules.loader import Rule
from threatcode.engine.rules.matcher import evaluate_condition, matches_rule
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone


def _make_node(resource_type: str = "aws_s3_bucket", **props: object) -> InfraNode:
    return InfraNode(
        id=f"{resource_type}.test",
        resource_type=resource_type,
        name="test",
        category=NodeCategory.STORAGE,
        trust_zone=TrustZone.DATA,
        properties=dict(props),
    )


def _make_rule(resource_type: str, condition: dict) -> Rule:
    return Rule(
        id="TEST_RULE",
        title="Test Rule",
        description="Test",
        stride_category="tampering",
        severity="medium",
        resource_type=resource_type,
        condition=condition,
    )


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


class TestMatchesRule:
    def test_matching_rule(self) -> None:
        node = _make_node(acl="public-read")
        rule = _make_rule("aws_s3_bucket", {"acl": {"equals": "public-read"}})
        assert matches_rule(rule, node) is True

    def test_non_matching_type(self) -> None:
        node = _make_node(resource_type="aws_instance", acl="public-read")
        rule = _make_rule("aws_s3_bucket", {"acl": {"equals": "public-read"}})
        assert matches_rule(rule, node) is False

    def test_prefix_matching(self) -> None:
        node = _make_node(resource_type="aws_s3_bucket_versioning")
        rule = _make_rule("aws_s3_bucket", {"some_prop": {"not_exists": True}})
        assert matches_rule(rule, node) is True
