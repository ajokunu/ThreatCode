"""Tests for threatcode.parsers._cfn_refs: the resources a property tree refers to."""

from __future__ import annotations

import time
from typing import Any

import pytest

from threatcode.exceptions import ParseError
from threatcode.parsers._cfn_refs import (
    MAX_DEPTH,
    RefHit,
    WorkBudget,
    extract_refs,
    getatt_target,
    intrinsic_of,
    scan_refs,
    sub_names,
    sub_template,
)

IDS = {"Vpc", "Subnet", "Bucket", "Role", "Queue", "Table"}


def hits(value: Any, ids: set[str] | None = None) -> list[tuple[str, str, str]]:
    return [(h.path, h.logical_id, h.via) for h in scan_refs(value, ids or IDS).hits]


class TestRefAndGetAtt:
    def test_ref_to_a_resource(self) -> None:
        assert extract_refs({"VpcId": {"Ref": "Vpc"}}, IDS) == ["Vpc"]

    def test_getatt_in_list_form(self) -> None:
        assert extract_refs({"Role": {"Fn::GetAtt": ["Role", "Arn"]}}, IDS) == ["Role"]

    def test_getatt_in_dotted_form(self) -> None:
        assert extract_refs({"Role": {"Fn::GetAtt": "Role.Arn"}}, IDS) == ["Role"]

    def test_getatt_of_a_nested_attribute_names_the_first_segment(self) -> None:
        # Outputs of a nested stack are read as Stack.Outputs.Name
        assert extract_refs({"Fn::GetAtt": "Bucket.Outputs.Name"}, IDS) == ["Bucket"]
        assert extract_refs({"Fn::GetAtt": ["Bucket", "Outputs.Name"]}, IDS) == ["Bucket"]

    def test_the_via_says_how_it_was_found(self) -> None:
        tree = {
            "A": {"Ref": "Vpc"},
            "B": {"Fn::GetAtt": ["Role", "Arn"]},
            "C": {"Fn::Sub": "${Bucket}"},
        }
        assert [(h[1], h[2]) for h in hits(tree)] == [
            ("Vpc", "Ref"),
            ("Role", "GetAtt"),
            ("Bucket", "Sub"),
        ]

    def test_an_id_that_is_not_a_resource_is_ignored(self) -> None:
        # a parameter, a pseudo parameter and a typo all name nothing in Resources
        tree = [{"Ref": "Environment"}, {"Ref": "AWS::Region"}, {"Ref": "Bukcet"}]
        assert extract_refs(tree, IDS) == []

    def test_getatt_to_an_unknown_id_is_ignored(self) -> None:
        assert extract_refs({"Fn::GetAtt": ["Missing", "Arn"]}, IDS) == []

    @pytest.mark.parametrize("bad", [None, 7, [], {"Ref": 3}, {"Ref": ["Vpc"]}, {"Fn::GetAtt": 4}])
    def test_malformed_intrinsics_are_ignored(self, bad: Any) -> None:
        assert extract_refs({"X": bad}, IDS) == []

    def test_a_dynamic_attribute_name_is_still_scanned(self) -> None:
        tree = {"Fn::GetAtt": ["Role", {"Ref": "Bucket"}]}
        assert extract_refs(tree, IDS) == ["Role", "Bucket"]


class TestSub:
    def test_string_form(self) -> None:
        assert extract_refs({"Fn::Sub": "arn:aws:s3:::${Bucket}/*"}, IDS) == ["Bucket"]

    def test_attribute_placeholder_names_the_resource(self) -> None:
        assert extract_refs({"Fn::Sub": "${Bucket.Arn}/*"}, IDS) == ["Bucket"]

    def test_pseudo_parameters_are_ignored(self) -> None:
        text = "arn:${AWS::Partition}:s3:::${AWS::Region}-${AWS::AccountId}"
        assert extract_refs({"Fn::Sub": text}, IDS) == []

    def test_a_literal_escape_is_not_a_reference(self) -> None:
        assert extract_refs({"Fn::Sub": "${!Bucket} and ${Vpc}"}, IDS) == ["Vpc"]

    def test_list_form_reads_the_template_and_ignores_variable_names(self) -> None:
        tree = {"Fn::Sub": ["${Bucket}-${Table}", {"Table": "plain-text"}]}
        assert extract_refs(tree, IDS) == ["Bucket"]

    def test_list_form_scans_the_variable_values(self) -> None:
        tree = {"Fn::Sub": ["${Mine}", {"Mine": {"Fn::GetAtt": ["Queue", "Arn"]}}]}
        assert extract_refs(tree, IDS) == ["Queue"]

    def test_variable_name_with_an_attribute_is_still_the_variable(self) -> None:
        tree = {"Fn::Sub": ["${Table.Name}", {"Table.Name": "x"}]}
        assert extract_refs(tree, IDS) == ["Table"]  # the map names "Table.Name", not "Table"

    def test_placeholder_text_is_stripped(self) -> None:
        assert extract_refs({"Fn::Sub": "${ Bucket }"}, IDS) == ["Bucket"]

    def test_a_template_with_no_placeholder_is_empty(self) -> None:
        assert extract_refs({"Fn::Sub": "no placeholders"}, IDS) == []

    def test_a_non_string_template_is_ignored(self) -> None:
        assert extract_refs({"Fn::Sub": 5}, IDS) == []

    def test_sub_names_helper(self) -> None:
        assert sub_names("${A.b} ${!Lit} ${AWS::Region} ${} plain") == ["A", "AWS::Region"]

    def test_sub_template_helper(self) -> None:
        assert sub_template("x") == ("x", {})
        assert sub_template(["x", {"v": 1}]) == ("x", {"v": 1})
        assert sub_template(["x"]) == ("x", {})
        assert sub_template(3) is None


class TestNesting:
    def test_join_if_select_and_split_are_walked(self) -> None:
        tree = {
            "Fn::Join": [
                "-",
                [
                    {"Ref": "Vpc"},
                    {"Fn::If": ["UseTable", {"Ref": "Table"}, {"Ref": "AWS::NoValue"}]},
                    {"Fn::Select": [0, {"Fn::Split": [",", {"Fn::GetAtt": ["Queue", "Arn"]}]}]},
                ],
            ]
        }
        assert extract_refs(tree, IDS) == ["Vpc", "Table", "Queue"]

    def test_both_branches_of_an_if_are_collected(self) -> None:
        tree = {"Fn::If": ["C", {"Ref": "Vpc"}, {"Ref": "Subnet"}]}
        assert extract_refs(tree, IDS) == ["Vpc", "Subnet"]

    def test_the_condition_name_of_an_if_is_not_a_reference(self) -> None:
        # a condition may share its name with a resource
        tree = {"Fn::If": ["Bucket", "yes", "no"]}
        assert extract_refs(tree, IDS) == []

    def test_the_mapping_name_of_findinmap_is_not_a_reference(self) -> None:
        tree = {"Fn::FindInMap": ["Vpc", {"Ref": "Subnet"}, "Key"]}
        assert extract_refs(tree, IDS) == ["Subnet"]

    def test_references_inside_lists_and_mappings(self) -> None:
        tree = {"A": [{"B": [{"Ref": "Vpc"}]}, [{"Ref": "Table"}]]}
        assert extract_refs(tree, IDS) == ["Vpc", "Table"]

    def test_order_is_first_use_and_without_repeats(self) -> None:
        tree = [{"Ref": "Table"}, {"Ref": "Vpc"}, {"Ref": "Table"}, {"Ref": "Vpc"}]
        assert extract_refs(tree, IDS) == ["Table", "Vpc"]

    def test_a_multi_key_mapping_with_ref_is_a_plain_mapping(self) -> None:
        assert extract_refs({"Ref": "Vpc", "Other": 1}, IDS) == []

    def test_an_empty_tree_has_no_references(self) -> None:
        assert extract_refs({}, IDS) == []
        assert extract_refs(None, IDS) == []


class TestPaths:
    def test_a_scalar_attribute(self) -> None:
        assert hits({"VpcId": {"Ref": "Vpc"}}) == [("VpcId", "Vpc", "Ref")]

    def test_nested_keys_join_with_dots(self) -> None:
        tree = {"VpcConfig": {"SubnetIds": [{"Ref": "Subnet"}]}}
        assert hits(tree) == [("VpcConfig.SubnetIds", "Subnet", "Ref")]

    def test_a_list_of_references_is_one_attribute(self) -> None:
        tree = {"SubnetIds": [{"Ref": "Subnet"}, {"Fn::GetAtt": ["Vpc", "Id"]}]}
        assert hits(tree) == [("SubnetIds", "Subnet", "Ref"), ("SubnetIds", "Vpc", "GetAtt")]

    def test_a_list_of_blocks_adds_a_list_marker(self) -> None:
        tree = {"SecurityGroupIngress": [{"SourceSecurityGroupId": {"Ref": "Table"}}]}
        assert hits(tree) == [("SecurityGroupIngress[].SourceSecurityGroupId", "Table", "Ref")]

    def test_every_list_level_that_holds_a_list_or_block_adds_a_marker(self) -> None:
        tree = {"A": [[{"Ref": "Vpc"}], [{"B": {"Ref": "Table"}}]]}
        assert hits(tree) == [("A[]", "Vpc", "Ref"), ("A[][].B", "Table", "Ref")]

    def test_the_same_reference_at_two_paths_is_two_hits(self) -> None:
        tree = {"A": {"Ref": "Vpc"}, "B": {"Ref": "Vpc"}, "C": [{"Ref": "Vpc"}, {"Ref": "Vpc"}]}
        assert [h[0] for h in hits(tree)] == ["A", "B", "C"]

    def test_base_path_prefixes_every_hit(self) -> None:
        scan = scan_refs({"A": {"Ref": "Vpc"}}, IDS, base_path="Properties")
        assert scan.hits == [RefHit("Properties.A", "Vpc", "Ref")]


class TestImportValue:
    def test_a_literal_export_is_recorded_and_makes_no_reference(self) -> None:
        scan = scan_refs({"VpcId": {"Fn::ImportValue": "network-VpcId"}}, IDS)
        assert scan.hits == []
        assert scan.imports == ["network-VpcId"]

    def test_a_sub_export_name_is_recorded_as_its_template(self) -> None:
        tree = {"Fn::ImportValue": {"Fn::Sub": "${AWS::StackName}-VpcId"}}
        assert scan_refs(tree, IDS).imports == ["${AWS::StackName}-VpcId"]

    def test_a_computed_export_name_is_recorded_as_such(self) -> None:
        tree = {"Fn::ImportValue": {"Fn::Join": ["-", ["a", "b"]]}}
        assert scan_refs(tree, IDS).imports == ["(computed export name)"]

    def test_a_resource_inside_the_export_name_is_still_a_reference(self) -> None:
        tree = {"Fn::ImportValue": {"Fn::Sub": "${Vpc}-id"}}
        assert extract_refs(tree, IDS) == ["Vpc"]

    def test_imports_are_listed_once_in_first_seen_order(self) -> None:
        tree = [{"Fn::ImportValue": "b"}, {"Fn::ImportValue": "a"}, {"Fn::ImportValue": "b"}]
        assert scan_refs(tree, IDS).imports == ["b", "a"]


class TestBounds:
    def test_a_structure_that_contains_itself_terminates(self) -> None:
        loop: dict[str, Any] = {"Ref": "Vpc"}
        node: dict[str, Any] = {"Items": [loop]}
        node["Items"].append(node)
        node["Self"] = node
        assert extract_refs(node, IDS) == ["Vpc"]

    def test_a_list_that_contains_itself_terminates(self) -> None:
        items: list[Any] = [{"Ref": "Table"}]
        items.append(items)
        assert extract_refs({"X": items}, IDS) == ["Table"]

    def test_references_below_the_depth_cap_are_not_read(self) -> None:
        deep: Any = {"Ref": "Vpc"}
        for _ in range(MAX_DEPTH + 5):
            deep = {"Level": deep}
        assert extract_refs(deep, IDS) == []

    def test_references_at_a_sane_depth_are_read(self) -> None:
        deep: Any = {"Ref": "Vpc"}
        for _ in range(20):
            deep = {"Level": deep}
        assert extract_refs(deep, IDS) == ["Vpc"]

    def test_an_alias_bomb_is_refused_quickly(self) -> None:
        # nine levels of nine aliases is 387 million values if anything walks them all
        level: Any = ["lol"] * 9
        for _ in range(9):
            level = [level] * 9
        started = time.monotonic()
        with pytest.raises(ParseError, match="aliases are expanded"):
            scan_refs({"Data": level}, IDS, budget=WorkBudget(200_000))
        assert time.monotonic() - started < 5

    def test_the_budget_is_shared_across_calls(self) -> None:
        budget = WorkBudget(50)
        tree = {"A": [1] * 30}
        scan_refs(tree, IDS, budget=budget)
        with pytest.raises(ParseError):
            scan_refs(tree, IDS, budget=budget)

    def test_a_resource_of_normal_size_fits_the_default_budget(self) -> None:
        tree = {"Items": [{"Name": str(i), "Ref": {"Ref": "Vpc"}} for i in range(5_000)]}
        assert extract_refs(tree, IDS) == ["Vpc"]


class TestHelpers:
    def test_intrinsic_of(self) -> None:
        assert intrinsic_of({"Ref": "X"}) == ("Ref", "X")
        assert intrinsic_of({"Fn::Join": ["", []]}) == ("Fn::Join", ["", []])
        assert intrinsic_of({"Condition": "C"}) is None
        assert intrinsic_of({"Ref": "X", "Other": 1}) is None
        assert intrinsic_of("Ref") is None
        assert intrinsic_of({1: 2}) is None

    def test_getatt_target(self) -> None:
        assert getatt_target("A.b.c") == "A"
        assert getatt_target(["A", "b"]) == "A"
        assert getatt_target([]) is None
        assert getatt_target("") is None
        assert getatt_target(5) is None
