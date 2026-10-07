"""Self-tests for the example loaders and matchers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.examples import (
    EXAMPLES,
    ExampleError,
    expected_for,
    finding_present,
    is_subsequence,
    path_node_ids,
    resolve_address,
    scan_example,
    validate_expected,
)
from tests.helpers.scan import scan_text


class TestValidateExpected:
    GOOD: dict[str, Any] = {
        "example": "x",
        "inputs": ["a"],
        "attack_paths": [{"id": "p", "entry": "internet", "target": "t", "via": ["v"], "why": "w"}],
        "key_findings": [{"resource": "r", "rule_ids": ["R"], "why": "w"}],
    }

    def test_a_good_file_is_returned_unchanged(self) -> None:
        assert validate_expected(self.GOOD, "x.yml") == self.GOOD

    @pytest.mark.parametrize(
        ("mutate", "message"),
        [
            (lambda d: d.pop("inputs"), "missing 'inputs'"),
            (lambda d: d.update(extra=1), "unknown keys"),
            (lambda d: d["attack_paths"][0].pop("target"), "needs a non-empty 'target'"),
            (lambda d: d["attack_paths"].append(dict(d["attack_paths"][0])), "duplicate path id"),
            (lambda d: d["attack_paths"][0].update(via="v"), "'via' must be a list"),
            (lambda d: d["key_findings"][0].pop("rule_ids"), "needs rule_ids or a known kind"),
            (
                lambda d: d["key_findings"][0].update(pending={"package": "WP-9-9", "reason": "r"}),
                "invalid pending",
            ),
        ],
    )
    def test_a_malformed_file_is_rejected_with_its_location(
        self, mutate: Any, message: str
    ) -> None:
        doc = json.loads(json.dumps(self.GOOD))
        mutate(doc)
        with pytest.raises(ExampleError, match=message):
            validate_expected(doc, "x.yml")

    def test_not_a_mapping_is_rejected(self) -> None:
        with pytest.raises(ExampleError, match="must be a mapping"):
            validate_expected(["a"], "x.yml")


class TestPathReading:
    def test_a_nodes_list_is_read_as_given(self) -> None:
        assert path_node_ids({"nodes": ["internet", "a", "b"]}) == ["internet", "a", "b"]
        assert path_node_ids({"nodes": [{"id": "x"}, {"address": "y"}]}) == ["x", "y"]

    def test_hops_are_read_with_the_near_end_of_the_first_hop(self) -> None:
        path = {"hops": [{"from": "internet", "to": "lb"}, {"to": "db"}]}
        assert path_node_ids(path) == ["internet", "lb", "db"]

    def test_an_unreadable_shape_names_the_keys_it_saw(self) -> None:
        with pytest.raises(AssertionError, match=r"keys \['rationale'\]"):
            path_node_ids({"rationale": "text"})

    def test_subsequence_respects_order_and_allows_gaps(self) -> None:
        nodes = ["internet", "lb", "sg", "app", "role", "bucket"]
        assert is_subsequence(["lb", "app"], nodes)
        assert is_subsequence([], nodes)
        assert not is_subsequence(["app", "lb"], nodes)
        assert not is_subsequence(["lb", "lb"], nodes)
        assert not is_subsequence(["db"], nodes)


class TestFindingMatching:
    TF = (
        'resource "aws_instance" "app" {\n'
        '  ami = "ami-1"\n'
        "  associate_public_ip_address = true\n"
        "}\n"
    )

    def test_a_rule_id_or_a_kind_on_the_named_resource_counts(self) -> None:
        result = scan_text(self.TF, "main.tf")
        assert finding_present(
            result, {"resource": "aws_instance.app", "rule_ids": ["EC2_PUBLIC_IP"]}
        )
        assert finding_present(result, {"resource": "aws_instance.app", "kind": "public_ip"})
        assert not finding_present(result, {"resource": "aws_instance.app", "kind": "imdsv1"})
        assert not finding_present(
            result, {"resource": "aws_instance.other", "rule_ids": ["EC2_PUBLIC_IP"]}
        )

    def test_a_type_dot_name_resource_resolves_to_the_unique_node_of_that_name(self) -> None:
        result = scan_text(self.TF, "main.tf")
        assert resolve_address(result, "aws_instance.app") == "aws_instance.app"
        assert resolve_address(result, "aws_instance.missing") == "aws_instance.missing"


class TestTheShippedExamples:
    def test_every_example_directory_with_an_expected_file_is_listed(self) -> None:
        assert EXAMPLES, "no example has an expected.yml"
        for name in EXAMPLES:
            assert expected_for(name)["example"] == name

    def test_cluster_scoped_ids_resolve_by_type_and_name(self) -> None:
        result = scan_example("k8s-platform")
        resolved = resolve_address(result, "kubernetes_cluster_role.secret-reader")
        assert result.graph.nodes[resolved].resource_type == "kubernetes_cluster_role"

    def test_the_expected_file_for_a_missing_example_fails_loudly(self) -> None:
        with pytest.raises(FileNotFoundError):
            expected_for("no-such-example")

    def test_input_paths_point_at_files_inside_the_example(self, tmp_path: Path) -> None:
        for name in EXAMPLES:
            from tests.helpers.examples import input_paths

            for path in input_paths(name):
                assert path.is_file()
                assert name in path.parts
