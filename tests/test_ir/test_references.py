"""Tests for threatcode.ir.references."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.ir.nodes import InfraNode, categorize_resource, infer_trust_zone
from threatcode.ir.references import (
    UNRESOLVABLE_ROOTS,
    ArnParts,
    ReferenceIndex,
    parse_arn,
    type_contains,
    type_endswith,
    type_is,
)
from threatcode.values import Unknown


def _node(address: str, name: str = "", module: str = "", node_id: str = "") -> InfraNode:
    """A node for `address`; the type is the component before the name."""
    parts = address.replace("data.", "", 1).split(".")
    rtype = parts[-2] if len(parts) >= 2 else "cfn_resource"
    rtype = rtype.split("[")[0]
    return InfraNode(
        id=node_id or address,
        resource_type=rtype,
        name=name or parts[-1].split("[")[0],
        category=categorize_resource(rtype),
        trust_zone=infer_trust_zone(rtype, {}),
        module=module,
    )


def _index(*addresses: str, **named: Any) -> ReferenceIndex:
    nodes = {a: _node(a) for a in addresses}
    nodes.update(named)
    return ReferenceIndex(nodes)


class TestExactAndAttributeShapes:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("aws_vpc.main", ["aws_vpc.main"]),
            ("aws_vpc.main.id", ["aws_vpc.main"]),
            ("aws_vpc.main.arn", ["aws_vpc.main"]),
            ("aws_vpc.main.tags.Name", ["aws_vpc.main"]),
            ("  aws_vpc.main.id  ", ["aws_vpc.main"]),
            ("module.net.aws_vpc.inner.id", ["module.net.aws_vpc.inner"]),
            ("module.a.module.b.aws_vpc.deep", ["module.a.module.b.aws_vpc.deep"]),
            ("data.aws_vpc.lookup.id", ["data.aws_vpc.lookup"]),
            ("aws_subnet.a-b.id", ["aws_subnet.a-b"]),
        ],
    )
    def test_accepted_shapes(self, raw: str, expected: list[str]) -> None:
        index = _index(
            "aws_vpc.main",
            "module.net.aws_vpc.inner",
            "module.a.module.b.aws_vpc.deep",
            "data.aws_vpc.lookup",
            "aws_subnet.a-b",
        )
        assert index.resolve(raw) == expected

    def test_longest_prefix_wins_over_a_shorter_known_id(self) -> None:
        # Both ids are known; the attribute is whatever is left after the longest match
        index = _index("aws_vpc.main", "aws_vpc.main.id")
        assert index.resolve("aws_vpc.main.id") == ["aws_vpc.main.id"]
        assert index.resolve("aws_vpc.main.arn") == ["aws_vpc.main"]

    @pytest.mark.parametrize(
        "raw",
        ["aws_vpc.other", "aws_vpc.other.id", "aws_subnet.main", "vpc-0abc123", "example.com", ""],
    )
    def test_anything_that_matches_no_node_resolves_to_nothing(self, raw: str) -> None:
        assert _index("aws_vpc.main").resolve(raw) == []

    def test_module_output_reference_resolves_to_nothing(self) -> None:
        assert _index("module.net.aws_vpc.main").resolve("module.net.vpc_id") == []

    def test_cloudformation_logical_ids(self) -> None:
        index = _index("MyBucket", "MyVpc")
        assert index.resolve("MyBucket") == ["MyBucket"]
        assert index.resolve("MyBucket.Arn") == ["MyBucket"]
        assert index.resolve("Missing") == []


class TestRejectedRoots:
    @pytest.mark.parametrize(
        "raw",
        [
            "var.vpc_id",
            "local.vpc",
            "each.key",
            "each.value.id",
            "count.index",
            "self.id",
            "path.module",
            "terraform.workspace",
            "${var.vpc_id}",
            "${local.vpc}",
            "${each.value}",
        ],
    )
    def test_root_that_names_no_resource(self, raw: str) -> None:
        # Even when a node's id would match the rest of the expression
        index = _index("aws_vpc.main", "var.vpc_id", "local.vpc", "each.key", "self.id")
        assert index.resolve(raw) == []

    def test_every_root_in_the_table_is_rejected(self) -> None:
        assert UNRESOLVABLE_ROOTS == {"var", "local", "each", "count", "self", "path", "terraform"}


class TestIndexes:
    def _counted(self) -> ReferenceIndex:
        return _index("aws_instance.app[0]", "aws_instance.app[1]", "aws_instance.app[2]")

    def test_reference_without_an_index_resolves_to_every_instance(self) -> None:
        index = self._counted()
        expected = ["aws_instance.app[0]", "aws_instance.app[1]", "aws_instance.app[2]"]
        assert index.resolve("aws_instance.app") == expected
        assert index.resolve("aws_instance.app.id") == expected
        assert index.resolve("aws_instance.app.*.id") == expected
        assert index.resolve("aws_instance.app[*].id") == expected

    def test_reference_with_an_index_resolves_to_that_instance(self) -> None:
        index = self._counted()
        assert index.resolve("aws_instance.app[1]") == ["aws_instance.app[1]"]
        assert index.resolve("aws_instance.app[1].id") == ["aws_instance.app[1]"]

    def test_index_that_does_not_exist_falls_back_to_every_instance(self) -> None:
        expected = ["aws_instance.app[0]", "aws_instance.app[1]", "aws_instance.app[2]"]
        assert self._counted().resolve("aws_instance.app[9].id") == expected

    def test_indexed_reference_resolves_to_an_unindexed_node(self) -> None:
        # A parser that models a counted resource as one node
        assert _index("aws_instance.app").resolve("aws_instance.app[0].id") == ["aws_instance.app"]

    def test_for_each_keys_resolve_to_their_instance_or_all(self) -> None:
        index = _index('aws_s3_bucket.b["east"]', 'aws_s3_bucket.b["west.1"]')
        assert index.resolve('aws_s3_bucket.b["west.1"].arn') == ['aws_s3_bucket.b["west.1"]']
        assert index.resolve("aws_s3_bucket.b") == [
            'aws_s3_bucket.b["east"]',
            'aws_s3_bucket.b["west.1"]',
        ]

    def test_module_instances_resolve_by_base_address(self) -> None:
        index = _index("module.net[0].aws_vpc.main", "module.net[1].aws_vpc.main")
        assert index.resolve("module.net.aws_vpc.main.id") == [
            "module.net[0].aws_vpc.main",
            "module.net[1].aws_vpc.main",
        ]

    def test_fan_out_order_is_sorted_and_stable(self) -> None:
        shuffled = _index("aws_instance.app[2]", "aws_instance.app[0]", "aws_instance.app[1]")
        assert shuffled.resolve("aws_instance.app") == [
            "aws_instance.app[0]",
            "aws_instance.app[1]",
            "aws_instance.app[2]",
        ]


class TestInterpolation:
    def _index(self) -> ReferenceIndex:
        return _index("aws_subnet.a", "aws_subnet.b", "aws_vpc.main", "aws_instance.app[0]")

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("${aws_subnet.a.id}", ["aws_subnet.a"]),
            ("${aws_subnet.a.id}-${aws_vpc.main.id}", ["aws_subnet.a", "aws_vpc.main"]),
            ("${aws_vpc.main.id}-${aws_subnet.a.id}", ["aws_vpc.main", "aws_subnet.a"]),
            ("net-${aws_subnet.a.id}-suffix", ["aws_subnet.a"]),
            ("${aws_subnet.a.id}${aws_subnet.a.arn}", ["aws_subnet.a"]),
            ("${aws_instance.app[0].id}", ["aws_instance.app[0]"]),
            ("${element(aws_subnet.a.*.id, 0)}", ["aws_subnet.a"]),
            ('${join(",", [aws_subnet.a.id, aws_subnet.b.id])}', ["aws_subnet.a", "aws_subnet.b"]),
            ("${var.name}-${aws_vpc.main.id}", ["aws_vpc.main"]),
            ("${var.name}", []),
            ("${upper(var.name)}", []),
            ("plain ${} text", []),
        ],
    )
    def test_extracts_every_reference_in_the_string(self, raw: str, expected: list[str]) -> None:
        assert self._index().resolve(raw) == expected

    def test_lone_identifier_inside_an_interpolation_is_not_a_node(self) -> None:
        # In ${...} a bare word is a function or local name, even if a node has that id
        index = _index("MyBucket")
        assert index.resolve("${MyBucket}") == []
        assert index.resolve("MyBucket") == ["MyBucket"]

    def test_bare_expression_with_several_references(self) -> None:
        index = self._index()
        assert index.resolve("[aws_subnet.a.id, aws_subnet.b.id]") == [
            "aws_subnet.a",
            "aws_subnet.b",
        ]

    def test_list_of_references_keeps_first_seen_order_and_dedupes(self) -> None:
        index = self._index()
        raw = ["aws_subnet.b.id", "${aws_subnet.a.id}", "aws_subnet.b.arn"]
        assert index.resolve(raw) == ["aws_subnet.b", "aws_subnet.a"]


class TestModuleScoping:
    def _index(self) -> ReferenceIndex:
        return _index(
            "aws_vpc.main",
            "module.net.aws_vpc.main",
            "module.net.aws_subnet.a",
            "module.other.aws_vpc.main",
            "module.a.module.b.aws_vpc.deep",
        )

    def test_unqualified_reference_resolves_inside_the_referring_module_first(self) -> None:
        assert self._index().resolve("aws_vpc.main.id", "module.net") == ["module.net.aws_vpc.main"]

    def test_unqualified_reference_at_the_root_stays_at_the_root(self) -> None:
        assert self._index().resolve("aws_vpc.main.id") == ["aws_vpc.main"]

    def test_unqualified_reference_never_crosses_into_another_module(self) -> None:
        index = _index("module.net.aws_subnet.a", "module.other.aws_subnet.a")
        assert index.resolve("aws_subnet.a", "") == []
        assert index.resolve("aws_subnet.a", "module.net") == ["module.net.aws_subnet.a"]
        assert index.resolve("aws_subnet.a", "module.third") == []

    def test_reference_falls_back_to_the_address_as_written(self) -> None:
        # Nothing module-local, but the root has it: the plain address still resolves
        assert self._index().resolve("aws_vpc.main", "module.third") == ["aws_vpc.main"]

    def test_qualified_reference_ignores_the_referring_module(self) -> None:
        index = self._index()
        assert index.resolve("module.other.aws_vpc.main.id", "module.net") == [
            "module.other.aws_vpc.main"
        ]

    def test_nested_module_scope(self) -> None:
        index = self._index()
        assert index.resolve("aws_vpc.deep", "module.a.module.b") == [
            "module.a.module.b.aws_vpc.deep"
        ]

    def test_module_scope_ignores_the_instance_index(self) -> None:
        assert self._index().resolve("aws_vpc.main", "module.net[0]") == ["module.net.aws_vpc.main"]


class TestNodeKeysAndIds:
    def test_resolution_returns_node_ids_not_lookup_keys(self) -> None:
        # The graph qualifies colliding ids but references are written unqualified
        node = _node("aws_vpc.main", node_id="unit_a/main.tf::aws_vpc.main")
        index = ReferenceIndex({"aws_vpc.main": node})
        assert index.resolve("aws_vpc.main.id") == ["unit_a/main.tf::aws_vpc.main"]

    def test_empty_index_resolves_nothing(self) -> None:
        assert ReferenceIndex({}).resolve("aws_vpc.main") == []


class TestNameMatching:
    def _index(self) -> ReferenceIndex:
        return ReferenceIndex(
            {
                "aws_vpc.main": _node("aws_vpc.main", name="prod"),
                "aws_subnet.a": _node("aws_subnet.a", name="shared"),
                "aws_security_group.s": _node("aws_security_group.s", name="shared"),
                "aws_iam_role.r": _node("aws_iam_role.r", name="web-role"),
            }
        )

    def test_bare_name_never_matches_without_a_required_type(self) -> None:
        assert self._index().resolve("prod") == []

    def test_bare_name_matches_when_exactly_one_node_of_the_type_has_it(self) -> None:
        assert self._index().resolve("prod", required_type=type_is("aws_vpc")) == ["aws_vpc.main"]

    def test_the_name_must_belong_to_a_node_of_the_required_type(self) -> None:
        assert self._index().resolve("prod", required_type=type_is("aws_subnet")) == []

    def test_a_name_shared_by_two_types_matches_only_the_required_one(self) -> None:
        index = self._index()
        assert index.resolve("shared", required_type=type_endswith("subnet")) == ["aws_subnet.a"]
        assert index.resolve("shared", required_type=type_contains("security_group")) == [
            "aws_security_group.s"
        ]

    def test_two_nodes_of_the_type_with_one_name_are_ambiguous_and_match_nothing(self) -> None:
        index = ReferenceIndex(
            {
                "aws_subnet.a": _node("aws_subnet.a", name="dup"),
                "aws_subnet.b": _node("aws_subnet.b", name="dup"),
            }
        )
        result = index.resolve_detailed("dup", required_type=type_endswith("subnet"))
        assert result.ids == ()
        assert result.ambiguous == ("aws_subnet.a", "aws_subnet.b")
        assert index.resolve("dup", required_type=type_endswith("subnet")) == []

    def test_ambiguity_is_settled_by_the_referring_module(self) -> None:
        index = ReferenceIndex(
            {
                "module.x.aws_subnet.a": _node("module.x.aws_subnet.a", "dup", "module.x"),
                "module.y.aws_subnet.a": _node("module.y.aws_subnet.a", "dup", "module.y"),
            }
        )
        required = type_endswith("subnet")
        assert index.resolve("dup", "module.x", required_type=required) == ["module.x.aws_subnet.a"]
        assert index.resolve("dup", "", required_type=required) == []

    def test_dotted_references_never_match_by_name(self) -> None:
        index = self._index()
        assert index.resolve("something.prod", required_type=type_is("aws_vpc")) == []

    def test_an_exact_address_beats_name_matching(self) -> None:
        index = ReferenceIndex(
            {
                "MyVpc": _node("MyVpc", name="other"),
                "Other": _node("Other", name="MyVpc"),
            }
        )
        assert index.resolve("MyVpc", required_type=lambda t: True) == ["MyVpc"]


class TestRequiredTypeFilter:
    def test_nodes_of_another_type_are_rejected_not_returned(self) -> None:
        index = _index("aws_vpc.main", "aws_subnet.a")
        result = index.resolve_detailed("aws_subnet.a.id", required_type=type_is("aws_vpc"))
        assert result.ids == ()
        assert result.rejected == ("aws_subnet.a",)

    def test_a_vpc_reference_never_returns_a_non_vpc_node(self) -> None:
        index = _index("aws_vpc.main", "aws_subnet.a")
        mixed = ["aws_subnet.a.id", "aws_vpc.main.id"]
        assert index.resolve(mixed, required_type=type_is("aws_vpc")) == ["aws_vpc.main"]

    def test_type_helpers(self) -> None:
        assert type_is("aws_vpc")("aws_vpc") and not type_is("aws_vpc")("aws_vpc_endpoint")
        assert type_endswith("subnet")("aws_subnet") and type_endswith("subnet")("google_subnet")
        assert not type_endswith("subnet")("aws_subnet_group")
        assert type_contains("security_group")("aws_security_group_rule")
        assert not type_contains("security_group")("aws_vpc")


class TestCloudFormationIntrinsics:
    def _index(self) -> ReferenceIndex:
        return _index("MyBucket", "MyVpc", "MyRole")

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ({"Ref": "MyVpc"}, ["MyVpc"]),
            ({"Ref": "Missing"}, []),
            ({"Ref": "AWS::Region"}, []),
            ({"Ref": 5}, []),
            ({"Fn::GetAtt": ["MyBucket", "Arn"]}, ["MyBucket"]),
            ({"Fn::GetAtt": "MyBucket.Arn"}, ["MyBucket"]),
            ({"Fn::GetAtt": []}, []),
            ({"Fn::Sub": "arn:aws:s3:::${MyBucket}/*"}, ["MyBucket"]),
            ({"Fn::Sub": "${MyBucket.Arn}/${MyVpc}"}, ["MyBucket", "MyVpc"]),
            ({"Fn::Sub": "${AWS::Region}-${MyVpc}"}, ["MyVpc"]),
            ({"Fn::Sub": ["${Name}-${MyVpc}", {"Name": "x"}]}, ["MyVpc"]),
            ({"Fn::Sub": "no placeholders"}, []),
            ({"Fn::Sub": 3}, []),
            (
                {
                    "Fn::Join": [
                        "",
                        ["arn:", {"Ref": "MyBucket"}, {"Fn::GetAtt": ["MyRole", "Arn"]}],
                    ]
                },
                ["MyBucket", "MyRole"],
            ),
            ({"Fn::If": ["Cond", {"Ref": "MyBucket"}, {"Ref": "MyVpc"}]}, ["MyBucket", "MyVpc"]),
            ([{"Ref": "MyVpc"}, {"Ref": "MyBucket"}], ["MyVpc", "MyBucket"]),
        ],
    )
    def test_intrinsic_forms(self, raw: Any, expected: list[str]) -> None:
        assert self._index().resolve(raw) == expected

    def test_deeply_nested_structures_do_not_recurse_without_bound(self) -> None:
        raw: Any = {"Ref": "MyVpc"}
        for _ in range(100):
            raw = {"Fn::Join": ["", [raw]]}
        assert self._index().resolve(raw) == []


class TestUnsupportedInput:
    @pytest.mark.parametrize("raw", [None, 5, 3.5, True, object(), {}, [], ()])
    def test_non_reference_values_resolve_to_nothing(self, raw: Any) -> None:
        assert _index("aws_vpc.main").resolve(raw) == []


ROLE_TYPE = type_is("aws_iam_role")


def _role(label: str, name: str = "", arn: str = "", node_id: str = "") -> InfraNode:
    properties: dict[str, Any] = {}
    if name:
        properties["name"] = name
    if arn:
        properties["arn"] = arn
    node = _node(node_id or f"aws_iam_role.{label}")
    node.properties.update(properties)
    return node


def _roles_index(*roles: InfraNode) -> ReferenceIndex:
    return ReferenceIndex({r.id: r for r in roles})


class TestResolveLiteral:
    def test_the_name_attribute_wins_over_the_label(self) -> None:
        by_label = _role("deploy", name="other")
        by_name = _role("ops", name="deploy")
        index = _roles_index(by_label, by_name)
        found = index.resolve_literal("deploy", required_type=ROLE_TYPE)
        assert found.ids == (by_name.id,)

    def test_the_label_is_the_last_resort(self) -> None:
        index = _roles_index(_role("deploy", name="x"), _role("ops"))
        assert index.resolve_literal("ops", required_type=ROLE_TYPE).ids == ("aws_iam_role.ops",)

    @pytest.mark.parametrize(
        "value",
        [
            "arn:aws:iam::123456789012:role/deploy",
            "arn:aws:iam::123456789012:role/service-role/deploy",
            "arn:aws:iam::123456789012:role/a/b/c/deploy",
        ],
    )
    def test_an_arn_resolves_through_its_last_component_and_the_name_attribute(
        self, value: str
    ) -> None:
        index = _roles_index(_role("ops", name="deploy"), _role("other", name="elsewhere"))
        assert index.resolve_literal(value, required_type=ROLE_TYPE).ids == ("aws_iam_role.ops",)

    def test_the_arn_attribute_matches_exactly(self) -> None:
        arn = "arn:aws:iam::123456789012:role/deploy"
        index = _roles_index(_role("ops", arn=arn), _role("deploy", name="deploy"))
        assert index.resolve_literal(arn, required_type=ROLE_TYPE).ids == ("aws_iam_role.ops",)

    def test_the_id_attribute_matches(self) -> None:
        vpc = _node("aws_vpc.main")
        vpc.properties["id"] = "vpc-0abc"
        index = ReferenceIndex({vpc.id: vpc})
        assert index.resolve_literal("vpc-0abc", required_type=type_is("aws_vpc")).ids == (
            "aws_vpc.main",
        )

    def test_a_name_two_nodes_share_is_ambiguous_and_binds_neither(self) -> None:
        index = _roles_index(_role("a", name="shared"), _role("b", name="shared"))
        found = index.resolve_literal("shared", required_type=ROLE_TYPE)
        assert found.ids == ()
        assert found.ambiguous == ("aws_iam_role.a", "aws_iam_role.b")

    def test_the_required_type_filters_the_match(self) -> None:
        role = _role("deploy", name="deploy")
        policy = _node("aws_iam_policy.deploy")
        policy.properties["name"] = "deploy"
        index = ReferenceIndex({role.id: role, policy.id: policy})
        assert index.resolve_literal("deploy", required_type=ROLE_TYPE).ids == (role.id,)
        assert index.resolve_literal("deploy", required_type=type_is("aws_iam_policy")).ids == (
            policy.id,
        )

    @pytest.mark.parametrize("value", ["nobody", "arn:aws:iam::1:role/nobody", "", "  "])
    def test_a_value_that_names_nothing_resolves_to_nothing(self, value: str) -> None:
        found = _roles_index(_role("deploy", name="deploy")).resolve_literal(
            value, required_type=ROLE_TYPE
        )
        assert found.ids == () and found.ambiguous == ()

    @pytest.mark.parametrize("value", [None, 5, Unknown("aws_iam_role.deploy"), ["deploy"]])
    def test_a_value_that_is_not_a_plain_string_resolves_to_nothing(self, value: Any) -> None:
        index = _roles_index(_role("deploy", name="deploy"))
        assert index.resolve_literal(value, required_type=ROLE_TYPE).ids == ()

    def test_an_interpolation_is_not_a_literal(self) -> None:
        index = _roles_index(_role("deploy", name="deploy"))
        assert (
            index.resolve_literal("${aws_iam_role.deploy.name}", required_type=ROLE_TYPE).ids == ()
        )

    def test_an_address_still_resolves_after_the_attribute_steps(self) -> None:
        index = _roles_index(_role("deploy", name="unrelated"))
        found = index.resolve_literal("aws_iam_role.deploy", required_type=ROLE_TYPE)
        assert found.ids == ("aws_iam_role.deploy",)


class TestResolveValue:
    def _index(self) -> ReferenceIndex:
        return _roles_index(_role("deploy", name="deploy-name"), _role("ops", name="ops-name"))

    def test_an_unknown_resolves_through_the_reference_it_carries(self) -> None:
        found = self._index().resolve_value(
            Unknown("aws_iam_role.ops.arn"), required_type=ROLE_TYPE
        )
        assert found.ids == ("aws_iam_role.ops",)

    def test_an_unknown_with_no_reference_resolves_to_nothing(self) -> None:
        assert self._index().resolve_value(Unknown(), required_type=ROLE_TYPE).ids == ()

    def test_an_interpolation_resolves_as_a_reference(self) -> None:
        found = self._index().resolve_value("${aws_iam_role.deploy.arn}", required_type=ROLE_TYPE)
        assert found.ids == ("aws_iam_role.deploy",)

    def test_a_plain_string_resolves_as_a_literal(self) -> None:
        assert self._index().resolve_value("ops-name", required_type=ROLE_TYPE).ids == (
            "aws_iam_role.ops",
        )

    def test_a_cloudformation_intrinsic_resolves(self) -> None:
        role = _role("DeployRole", node_id="DeployRole")
        role.resource_type = "aws_iam_role"
        found = ReferenceIndex({role.id: role}).resolve_value(
            {"Fn::GetAtt": ["DeployRole", "Arn"]}, required_type=ROLE_TYPE
        )
        assert found.ids == ("DeployRole",)

    def test_a_list_merges_its_items_in_order_without_repeats(self) -> None:
        found = self._index().resolve_value(
            ["ops-name", Unknown("aws_iam_role.deploy.arn"), "ops-name"], required_type=ROLE_TYPE
        )
        assert found.ids == ("aws_iam_role.ops", "aws_iam_role.deploy")

    @pytest.mark.parametrize("value", [None, 3, True, {}, []])
    def test_anything_else_resolves_to_nothing(self, value: Any) -> None:
        assert self._index().resolve_value(value, required_type=ROLE_TYPE).ids == ()


class TestParseArn:
    def test_the_fields(self) -> None:
        arn = parse_arn("arn:aws:iam::123456789012:role/service-role/deploy")
        assert arn == ArnParts("aws", "iam", "", "123456789012", "role/service-role/deploy")
        assert arn is not None
        assert (arn.name, arn.kind) == ("deploy", "role")

    def test_a_resource_with_colons(self) -> None:
        arn = parse_arn("arn:aws:lambda:us-east-1:123456789012:function:orders")
        assert arn is not None
        assert (arn.service, arn.region, arn.name, arn.kind) == (
            "lambda",
            "us-east-1",
            "orders",
            "function",
        )

    def test_an_s3_arn_has_no_kind(self) -> None:
        arn = parse_arn("arn:aws:s3:::my-bucket/key")
        assert arn is not None
        assert (arn.service, arn.resource, arn.name, arn.kind) == (
            "s3",
            "my-bucket/key",
            "key",
            "my-bucket",
        )

    @pytest.mark.parametrize(
        "value",
        ["", "role/deploy", "arn:aws", "arn:aws:iam", "arn:aws::::x", None, 4, Unknown("a.b")],
    )
    def test_anything_else_is_not_an_arn(self, value: Any) -> None:
        assert parse_arn(value) is None
