"""Tests for infrastructure graph building."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import ThreatCodeError
from threatcode.ir.edges import REACHABILITY, STRUCTURAL, EdgeType, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import NodeCategory, TrustZone
from threatcode.ir.references import ReferenceIndex
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource


class TestInfraGraph:
    def test_from_parsed_creates_nodes(self, simple_s3_parsed: ParsedOutput) -> None:
        graph = InfraGraph.from_parsed(simple_s3_parsed)
        assert graph.node_count == 7

    def test_node_categories(self, simple_s3_graph: InfraGraph) -> None:
        s3_node = simple_s3_graph.get_node("aws_s3_bucket.data")
        assert s3_node is not None
        assert s3_node.category == NodeCategory.STORAGE

        iam_node = simple_s3_graph.get_node("aws_iam_role.lambda_exec")
        assert iam_node is not None
        assert iam_node.category == NodeCategory.IAM

        ec2_node = simple_s3_graph.get_node("aws_instance.web")
        assert ec2_node is not None
        assert ec2_node.category == NodeCategory.COMPUTE

        rds_node = simple_s3_graph.get_node("aws_db_instance.main")
        assert rds_node is not None
        assert rds_node.category == NodeCategory.DATABASE

    def test_trust_zones(self, simple_s3_graph: InfraGraph) -> None:
        s3_node = simple_s3_graph.get_node("aws_s3_bucket.data")
        assert s3_node is not None
        assert s3_node.trust_zone == TrustZone.DATA

        iam_node = simple_s3_graph.get_node("aws_iam_role.lambda_exec")
        assert iam_node is not None
        assert iam_node.trust_zone == TrustZone.MANAGEMENT

    def test_ec2_public_ip_dmz(self, simple_s3_graph: InfraGraph) -> None:
        ec2_node = simple_s3_graph.get_node("aws_instance.web")
        assert ec2_node is not None
        assert ec2_node.trust_zone == TrustZone.DMZ

    def test_dependency_edges(self, simple_s3_graph: InfraGraph) -> None:
        edges = simple_s3_graph.get_edges_for_node("aws_instance.web")
        dep_targets = [e.target for e in edges if e.edge_type.value == "dependency"]
        assert "aws_s3_bucket.data" in dep_targets

    def test_boundary_crossing_edges(self, simple_s3_graph: InfraGraph) -> None:
        crossings = simple_s3_graph.get_boundary_crossing_edges()
        assert len(crossings) > 0
        for edge in crossings:
            assert edge.metadata.get("crosses_trust_boundary") is True

    def test_to_dict(self, simple_s3_graph: InfraGraph) -> None:
        data = simple_s3_graph.to_dict()
        assert "nodes" in data
        assert "edges" in data
        assert len(data["nodes"]) == 7

    def test_nodes_by_zone(self, simple_s3_graph: InfraGraph) -> None:
        zones = simple_s3_graph.nodes_by_zone()
        assert TrustZone.DATA in zones
        assert TrustZone.MANAGEMENT in zones

    def test_stride_element_mapping(self, simple_s3_graph: InfraGraph) -> None:
        s3_node = simple_s3_graph.get_node("aws_s3_bucket.data")
        assert s3_node is not None
        assert s3_node.stride_element == "data_store"

        ec2_node = simple_s3_graph.get_node("aws_instance.web")
        assert ec2_node is not None
        assert ec2_node.stride_element == "process"


# -- Declared zones, boundaries, edges and evidence (design inputs) -----------


def _res(address: str, **kwargs: Any) -> ParsedResource:
    rtype, name = address.split(".", 1)
    return ParsedResource(
        resource_type=rtype, address=address, name=name, provider="design", **kwargs
    )


class TestDeclaredZones:
    def test_declared_zone_overrides_inference(self) -> None:
        # The public-IP heuristic would put this instance in the DMZ
        parsed = ParsedOutput(
            resources=[
                _res(
                    "aws_instance.web",
                    properties={"associate_public_ip_address": True},
                    trust_zone="data",
                )
            ]
        )
        node = InfraGraph.from_parsed(parsed).get_node("aws_instance.web")
        assert node is not None
        assert node.trust_zone == TrustZone.DATA

    def test_no_declared_zone_keeps_inference(self) -> None:
        parsed = ParsedOutput(
            resources=[_res("aws_instance.web", properties={"associate_public_ip_address": True})]
        )
        node = InfraGraph.from_parsed(parsed).get_node("aws_instance.web")
        assert node is not None
        assert node.trust_zone == TrustZone.DMZ

    def test_unknown_declared_zone_raises(self) -> None:
        parsed = ParsedOutput(resources=[_res("aws_instance.web", trust_zone="moon")])
        with pytest.raises(ThreatCodeError, match="unknown trust zone 'moon'"):
            InfraGraph.from_parsed(parsed)


class TestEvidence:
    def test_evidence_and_boundary_reach_the_node(self) -> None:
        parsed = ParsedOutput(
            resources=[_res("design_service.api", evidence="design", boundary="tz-app")]
        )
        graph = InfraGraph.from_parsed(parsed)
        node = graph.get_node("design_service.api")
        assert node is not None
        assert (node.evidence, node.boundary) == ("design", "tz-app")
        as_dict = graph.to_dict()["nodes"]["design_service.api"]
        assert (as_dict["evidence"], as_dict["boundary"]) == ("design", "tz-app")

    def test_defaults_are_config_and_no_boundary(self, simple_s3_graph: InfraGraph) -> None:
        assert all(
            n.evidence == "config" and n.boundary == "" for n in simple_s3_graph.nodes.values()
        )

    def test_unknown_evidence_raises(self) -> None:
        parsed = ParsedOutput(resources=[_res("design_service.api", evidence="rumor")])
        with pytest.raises(ThreatCodeError, match="unknown evidence 'rumor'"):
            InfraGraph.from_parsed(parsed)


class TestDeclaredEdges:
    def test_declared_edge_added_with_type_and_metadata(self) -> None:
        parsed = ParsedOutput(
            resources=[_res("design_service.api"), _res("design_database.orders")],
            edges=[
                ParsedEdge(
                    "design_service.api", "design_database.orders", metadata={"protocol": "tls"}
                )
            ],
        )
        edges = InfraGraph.from_parsed(parsed).edges
        assert len(edges) == 1
        assert edges[0].edge_type == EdgeType.DATA_FLOW
        assert edges[0].metadata["protocol"] == "tls"
        assert edges[0].attributes == {"protocol": "tls"}

    def test_duplicate_of_inferred_edge_merges_metadata(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _res("aws_instance.web", dependencies=["aws_vpc.main"]),
                _res("aws_vpc.main"),
            ],
            edges=[
                ParsedEdge(
                    "aws_instance.web", "aws_vpc.main", "dependency", metadata={"note": "declared"}
                )
            ],
        )
        edges = InfraGraph.from_parsed(parsed).edges
        assert len(edges) == 1
        assert edges[0].metadata["note"] == "declared"
        assert edges[0].attributes == {"note": "declared"}
        assert edges[0].declared is True

    def test_unknown_edge_type_raises(self) -> None:
        parsed = ParsedOutput(
            resources=[_res("design_service.a"), _res("design_service.b")],
            edges=[ParsedEdge("design_service.a", "design_service.b", "telepathy")],
        )
        with pytest.raises(ThreatCodeError, match="unknown type 'telepathy'"):
            InfraGraph.from_parsed(parsed)

    def test_declared_edges_respect_edge_limit(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        monkeypatch.setattr("threatcode.ir.graph.MAX_EDGES", 1)
        parsed = ParsedOutput(
            resources=[
                _res("design_service.a"),
                _res("design_service.b"),
                _res("design_service.c"),
            ],
            edges=[
                ParsedEdge("design_service.a", "design_service.b"),
                ParsedEdge("design_service.b", "design_service.c"),
            ],
        )
        with caplog.at_level(logging.WARNING):
            graph = InfraGraph.from_parsed(parsed)
        assert len(graph.edges) == 1
        assert any("Edge limit" in r.message for r in caplog.records)


class TestBoundaryCrossings:
    def _graph(self, src_boundary: str, tgt_boundary: str) -> InfraGraph:
        return InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    _res("design_service.a", trust_zone="private", boundary=src_boundary),
                    _res("design_service.b", trust_zone="private", boundary=tgt_boundary),
                ],
                edges=[ParsedEdge("design_service.a", "design_service.b")],
            )
        )

    def test_different_boundaries_in_same_zone_cross(self) -> None:
        crossing = self._graph("subnet-a", "subnet-b").get_boundary_crossing_edges()
        assert len(crossing) == 1
        meta = crossing[0].metadata
        assert (meta["source_zone"], meta["target_zone"]) == ("private", "private")
        assert (meta["source_boundary"], meta["target_boundary"]) == ("subnet-a", "subnet-b")

    def test_same_boundary_does_not_cross(self) -> None:
        assert self._graph("subnet-a", "subnet-a").get_boundary_crossing_edges() == []

    def test_one_side_without_boundary_falls_back_to_zones(self) -> None:
        assert self._graph("subnet-a", "").get_boundary_crossing_edges() == []


# -- Source locations, mode and the other node fields --------------------------


def _pr(rtype: str, name: str, module: str = "", **kwargs: Any) -> ParsedResource:
    """A resource whose address is built the Terraform way, with its module prefix."""
    address = f"{module}.{rtype}.{name}" if module else f"{rtype}.{name}"
    return ParsedResource(
        resource_type=rtype, address=address, name=name, provider="aws", module=module, **kwargs
    )


def _edges_of(graph: InfraGraph) -> set[tuple[str, str, str]]:
    return {(e.source, e.target, e.edge_type.value) for e in graph.edges}


class TestNodeFields:
    def test_location_and_mode_reach_the_node(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr(
                    "aws_s3_bucket",
                    "data",
                    source_location="infra/main.tf",
                    start_line=4,
                    end_line=9,
                    mode="data",
                )
            ]
        )
        node = InfraGraph.from_parsed(parsed).get_node("aws_s3_bucket.data")
        assert node is not None
        assert (node.source_file, node.start_line, node.end_line) == ("infra/main.tf", 4, 9)
        assert node.mode == "data"

    def test_defaults_are_unknown_location_managed_and_unknown_exposure(self) -> None:
        node = InfraGraph.from_parsed(ParsedOutput(resources=[_pr("aws_vpc", "main")])).nodes[
            "aws_vpc.main"
        ]
        assert (node.source_file, node.start_line, node.end_line) == ("", None, None)
        assert (node.mode, node.exposure) == ("managed", "unknown")

    def test_legacy_trailing_line_in_source_location_is_split(self) -> None:
        parsed = ParsedOutput(
            resources=[_pr("dockerfile_run", "r", source_location="/app/Dockerfile:12")]
        )
        node = InfraGraph.from_parsed(parsed).nodes["dockerfile_run.r"]
        assert (node.source_file, node.start_line) == ("/app/Dockerfile", 12)

    def test_explicit_start_line_wins_over_the_legacy_suffix(self) -> None:
        parsed = ParsedOutput(
            resources=[_pr("dockerfile_run", "r", source_location="Dockerfile:12", start_line=3)]
        )
        node = InfraGraph.from_parsed(parsed).nodes["dockerfile_run.r"]
        assert (node.source_file, node.start_line) == ("Dockerfile", 3)

    def test_windows_path_is_not_mistaken_for_a_line(self) -> None:
        parsed = ParsedOutput(
            resources=[_pr("aws_vpc", "main", source_location="C:\\infra\\main.tf")]
        )
        node = InfraGraph.from_parsed(parsed).nodes["aws_vpc.main"]
        assert (node.source_file, node.start_line) == ("C:\\infra\\main.tf", None)

    def test_parsed_resource_is_not_rewritten_by_the_graph(self) -> None:
        resource = _pr("dockerfile_run", "r", source_location="Dockerfile:12")
        InfraGraph.from_parsed(ParsedOutput(resources=[resource]))
        assert (resource.source_location, resource.start_line) == ("Dockerfile:12", None)

    def test_unknown_mode_raises(self) -> None:
        parsed = ParsedOutput(resources=[_pr("aws_vpc", "main", mode="ghost")])  # type: ignore[arg-type]
        with pytest.raises(ThreatCodeError, match="unknown mode 'ghost'"):
            InfraGraph.from_parsed(parsed)

    def test_meta_never_reaches_the_node_or_its_properties(self) -> None:
        resource = _pr("aws_instance", "app", properties={"ami": "x"}, meta={"count": 3})
        node = InfraGraph.from_parsed(ParsedOutput(resources=[resource])).nodes["aws_instance.app"]
        assert node.properties == {"ami": "x"}
        assert not hasattr(node, "meta")

    def test_source_file_is_not_in_the_dict_that_feeds_the_llm(self) -> None:
        parsed = ParsedOutput(
            resources=[_pr("aws_vpc", "main", source_location="secret/dir/main.tf", start_line=2)]
        )
        node_dict = InfraGraph.from_parsed(parsed).to_dict()["nodes"]["aws_vpc.main"]
        assert "source_file" not in node_dict
        assert "start_line" not in node_dict
        assert "secret/dir" not in str(node_dict)

    def test_optional_node_attributes_render_only_when_not_default(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(resources=[_pr("aws_vpc", "main"), _pr("aws_vpc", "lookup", mode="data")])
        )
        nodes = graph.to_dict()["nodes"]
        assert "mode" not in nodes["aws_vpc.main"]
        assert "exposure" not in nodes["aws_vpc.main"]
        assert nodes["aws_vpc.lookup"]["mode"] == "data"
        graph.nodes["aws_vpc.main"].exposure = "internet"
        assert graph.to_dict()["nodes"]["aws_vpc.main"]["exposure"] == "internet"


class TestDuplicateAddresses:
    def _graph(self, count: int = 3) -> InfraGraph:
        resources = [
            _pr(
                "kubernetes_job",
                "unknown",
                properties={"image": f"img:{i}"},
                source_location=f"j{i}.yml",
            )
            for i in range(count)
        ]
        return InfraGraph.from_parsed(ParsedOutput(resources=resources))

    def test_every_duplicate_is_kept_and_later_ones_are_suffixed_in_input_order(self) -> None:
        graph = self._graph()
        assert list(graph.nodes) == [
            "kubernetes_job.unknown",
            "kubernetes_job.unknown#2",
            "kubernetes_job.unknown#3",
        ]
        assert [graph.nodes[n].properties["image"] for n in graph.nodes] == [
            "img:0",
            "img:1",
            "img:2",
        ]

    def test_each_duplicate_is_a_diagnostic_naming_the_new_id_and_file(self) -> None:
        graph = self._graph()
        dups = [d for d in graph.diagnostics if d.code == "graph.duplicate_address"]
        assert [d.level for d in dups] == ["warning", "warning"]
        assert "'kubernetes_job.unknown#2'" in dups[0].message
        assert "'kubernetes_job.unknown#3'" in dups[1].message
        assert (dups[0].file, dups[1].file) == ("j1.yml", "j2.yml")

    def test_duplicate_of_maps_each_new_id_to_the_id_it_duplicates(self) -> None:
        graph = self._graph()
        assert graph.duplicate_of == {
            "kubernetes_job.unknown#2": "kubernetes_job.unknown",
            "kubernetes_job.unknown#3": "kubernetes_job.unknown",
        }
        assert graph.duplicate_count == 2

    def test_no_duplicates_means_no_diagnostics_and_a_zero_count(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        assert simple_s3_graph.diagnostics == []
        assert simple_s3_graph.duplicate_count == 0

    def test_a_suffix_that_is_already_taken_is_skipped(self) -> None:
        resources = [
            _pr("aws_vpc", "main"),
            ParsedResource("aws_vpc", "aws_vpc.main#2", "main#2", "aws"),
            _pr("aws_vpc", "main"),
        ]
        graph = InfraGraph.from_parsed(ParsedOutput(resources=resources))
        assert list(graph.nodes) == ["aws_vpc.main", "aws_vpc.main#2", "aws_vpc.main#3"]

    def test_duplicates_count_against_the_node_limit(self) -> None:
        resources = [_pr("aws_vpc", "main") for _ in range(3)]
        with pytest.raises(ThreatCodeError, match="node limit"):
            InfraGraph.from_parsed(ParsedOutput(resources=resources), max_nodes=2)

    def test_a_reference_resolves_to_the_first_holder_of_the_address(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", references={"vpc_id": ["aws_vpc.main.id"]}),
            ]
        )
        assert ("aws_subnet.a", "aws_vpc.main", "containment") in _edges_of(
            InfraGraph.from_parsed(parsed)
        )

    def test_duplicate_nodes_are_independent_in_the_graph(self) -> None:
        graph = self._graph(2)
        assert graph.get_node("kubernetes_job.unknown#2") is not graph.get_node(
            "kubernetes_job.unknown"
        )
        assert graph.node_count == 2


class TestDependencies:
    def test_dependency_resolves_through_the_index(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_instance", "web", dependencies=["aws_vpc.main.id"]),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_instance.web", "aws_vpc.main", "dependency")
        }

    def test_dependency_on_a_counted_resource_reaches_every_instance(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("aws_instance", "aws_instance.app[0]", "app", "aws"),
                ParsedResource("aws_instance", "aws_instance.app[1]", "app", "aws"),
                _pr("aws_lb", "front", dependencies=["aws_instance.app"]),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_lb.front", "aws_instance.app[0]", "dependency"),
            ("aws_lb.front", "aws_instance.app[1]", "dependency"),
        }

    def test_a_resource_never_depends_on_itself_through_fan_out(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource(
                    "aws_instance",
                    "aws_instance.app[0]",
                    "app",
                    "aws",
                    dependencies=["aws_instance.app"],
                ),
                ParsedResource("aws_instance", "aws_instance.app[1]", "app", "aws"),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_instance.app[0]", "aws_instance.app[1]", "dependency")
        }

    def test_dependency_is_resolved_inside_the_referring_module(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_vpc", "main", module="module.net"),
                _pr("aws_subnet", "a", module="module.net", dependencies=["aws_vpc.main"]),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("module.net.aws_subnet.a", "module.net.aws_vpc.main", "dependency")
        }

    @pytest.mark.parametrize("dep", ["var.vpc", "aws_vpc.gone", "module.x.vpc_id", ""])
    def test_unresolvable_dependency_adds_no_edge(self, dep: str) -> None:
        parsed = ParsedOutput(
            resources=[_pr("aws_vpc", "main"), _pr("aws_instance", "web", dependencies=[dep])]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_edge_order_follows_the_dependency_list(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "b"),
                _pr("aws_vpc", "a"),
                _pr("aws_instance", "web", dependencies=["aws_vpc.b", "aws_vpc.a"]),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert [e.target for e in graph.edges] == ["aws_vpc.b", "aws_vpc.a"]


# -- Attachment rules: references become typed edges ---------------------------


class TestAttachmentRules:
    def _two_vpcs(self, *extra: ParsedResource) -> ParsedOutput:
        return ParsedOutput(resources=[_pr("aws_vpc", "prod"), _pr("aws_vpc", "dev"), *extra])

    def test_vpc_reference_binds_the_referenced_vpc_and_never_the_first(self) -> None:
        subnet = _pr(
            "aws_subnet",
            "dev_a",
            properties={"vpc_id": "${aws_vpc.dev.id}"},
            references={"vpc_id": ["aws_vpc.dev.id"]},
        )
        graph = InfraGraph.from_parsed(self._two_vpcs(subnet))
        assert _edges_of(graph) == {("aws_subnet.dev_a", "aws_vpc.dev", "containment")}

    def test_vpc_reference_to_a_node_that_is_not_a_vpc_adds_no_edge(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_subnet", "a"),
                _pr("aws_instance", "web", references={"vpc_id": ["aws_subnet.a.id"]}),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_unresolved_reference_adds_no_edge_and_suppresses_the_heuristic(self) -> None:
        # vpc_id is a variable: the old heuristic would have bound the first VPC
        subnet = _pr(
            "aws_subnet",
            "dev_a",
            properties={"vpc_id": "vpc-0abc"},
            references={"vpc_id": ["var.vpc_id"]},
        )
        assert InfraGraph.from_parsed(self._two_vpcs(subnet)).edges == []

    def test_references_suppress_the_heuristic_for_their_attribute_only(self) -> None:
        # vpc_id is covered by a reference; subnet_ids is a literal and still matches
        instance = _pr(
            "aws_instance",
            "web",
            properties={"vpc_id": "vpc-0abc", "subnet_ids": ["aws_subnet.a"]},
            references={"vpc_id": ["aws_vpc.dev.id"]},
        )
        graph = InfraGraph.from_parsed(self._two_vpcs(_pr("aws_subnet", "a"), instance))
        assert _edges_of(graph) == {
            ("aws_instance.web", "aws_vpc.dev", "containment"),
            ("aws_instance.web", "aws_subnet.a", "containment"),
        }

    def test_subnet_references_bind_subnets_only(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_subnet", "a"),
                _pr("aws_subnet", "b"),
                _pr("aws_vpc", "main"),
                _pr(
                    "aws_lb",
                    "front",
                    references={
                        "subnets": ["aws_subnet.a.id", "aws_subnet.b.id", "aws_vpc.main.id"]
                    },
                ),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_lb.front", "aws_subnet.a", "containment"),
            ("aws_lb.front", "aws_subnet.b", "containment"),
        }

    @pytest.mark.parametrize(
        "attribute",
        [
            "subnet_id",
            "subnet_ids",
            "subnets",
            "vpc_config[].subnet_ids",
            "network_interface[].subnet_id",
        ],
    )
    def test_every_subnet_attribute_is_containment(self, attribute: str) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_subnet", "a"),
                _pr("aws_lambda_function", "fn", references={attribute: ["aws_subnet.a.id"]}),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_lambda_function.fn", "aws_subnet.a", "containment")
        }

    def test_azure_subnet_types_match_the_subnet_suffix(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("azurerm_subnet", "azurerm_subnet.s", "s", "azurerm"),
                _pr(
                    "azurerm_linux_virtual_machine",
                    "vm",
                    references={"subnet_id": ["azurerm_subnet.s.id"]},
                ),
            ]
        )
        assert ("azurerm_linux_virtual_machine.vm", "azurerm_subnet.s", "containment") in _edges_of(
            InfraGraph.from_parsed(parsed)
        )

    @pytest.mark.parametrize(
        "attribute",
        [
            "security_groups",
            "vpc_security_group_ids",
            "security_group_ids",
            "vpc_config[].security_group_ids",
        ],
    )
    def test_security_group_attachment_is_a_dependency_with_a_relation(
        self, attribute: str
    ) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "web"),
                _pr("aws_instance", "app", references={attribute: ["aws_security_group.web.id"]}),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.source, edge.target) == ("aws_instance.app", "aws_security_group.web")
        assert edge.edge_type == EdgeType.DEPENDENCY
        assert edge.relation == "security_group"
        assert edge.metadata["relation"] == "security_group"
        assert edge.declared is False

    def test_security_group_attachment_is_not_network_flow(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "web"),
                _pr(
                    "aws_instance",
                    "app",
                    references={"security_groups": ["aws_security_group.web"]},
                ),
            ]
        )
        assert EdgeType.NETWORK_FLOW not in {
            e.edge_type for e in InfraGraph.from_parsed(parsed).edges
        }

    def test_security_group_attribute_must_name_a_security_group(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_instance", "app", references={"security_groups": ["aws_vpc.main.id"]}),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    @pytest.mark.parametrize(
        "attribute", ["role", "role_arn", "execution_role_arn", "task_role_arn"]
    )
    def test_role_attributes_are_iam_bindings_that_assume_a_role(self, attribute: str) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "exec"),
                _pr(
                    "aws_ecs_task_definition",
                    "task",
                    references={attribute: ["aws_iam_role.exec.arn"]},
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.edge_type == EdgeType.IAM_BINDING
        assert edge.relation == "assumes"
        assert edge.target == "aws_iam_role.exec"

    def test_role_attribute_must_name_a_role(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_policy", "p"),
                _pr("aws_lambda_function", "fn", references={"role": ["aws_iam_policy.p.arn"]}),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_reference_suppresses_the_role_heuristic(self) -> None:
        # The literal role label would match aws_iam_role.legacy; the reference says otherwise
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "legacy"),
                _pr(
                    "aws_iam_instance_profile",
                    "p",
                    properties={"role": "legacy"},
                    references={"role": ["var.role_name"]},
                ),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_instance_profile_is_an_iam_binding_with_its_own_relation(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_instance_profile", "p"),
                _pr(
                    "aws_instance",
                    "web",
                    references={"iam_instance_profile": ["aws_iam_instance_profile.p.name"]},
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.edge_type, edge.relation) == (EdgeType.IAM_BINDING, "instance_profile")

    @pytest.mark.parametrize("attribute", ["kms_key_id", "kms_master_key_id", "kms_key_arn"])
    def test_kms_attributes_are_encrypts_with_dependencies(self, attribute: str) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_kms_key", "k"),
                _pr("aws_s3_bucket", "b", references={attribute: ["aws_kms_key.k.arn"]}),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.edge_type, edge.relation) == (EdgeType.DEPENDENCY, "encrypts_with")

    def test_any_other_attribute_is_a_generic_dependency(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_sqs_queue", "q"),
                _pr(
                    "aws_lambda_function",
                    "fn",
                    references={"environment[].queue": ["aws_sqs_queue.q.url"]},
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.edge_type, edge.relation) == (EdgeType.DEPENDENCY, "references")

    def test_unresolved_references_add_no_edge(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr(
                    "aws_instance",
                    "web",
                    references={"subnet_id": ["aws_subnet.gone.id"], "other": ["local.x", "var.y"]},
                ),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_reference_to_a_counted_resource_reaches_every_instance(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("aws_subnet", "aws_subnet.a[0]", "a", "aws"),
                ParsedResource("aws_subnet", "aws_subnet.a[1]", "a", "aws"),
                _pr("aws_lb", "front", references={"subnets": ["aws_subnet.a"]}),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_lb.front", "aws_subnet.a[0]", "containment"),
            ("aws_lb.front", "aws_subnet.a[1]", "containment"),
        }

    def test_resource_never_links_to_itself(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr(
                    "aws_security_group",
                    "s",
                    references={"security_groups": ["aws_security_group.s.id"]},
                )
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_security_group_rule_referencing_another_group(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "db"),
                _pr(
                    "aws_security_group",
                    "app",
                    references={"ingress[].security_groups": ["aws_security_group.db.id"]},
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.source, edge.target, edge.relation) == (
            "aws_security_group.app",
            "aws_security_group.db",
            "references",
        )

    def test_reference_is_resolved_inside_the_referring_module(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_vpc", "main", module="module.net"),
                _pr(
                    "aws_subnet",
                    "a",
                    module="module.net",
                    references={"vpc_id": ["aws_vpc.main.id"]},
                ),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("module.net.aws_subnet.a", "module.net.aws_vpc.main", "containment")
        }

    def test_reference_with_hcl_interpolation(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", references={"vpc_id": ["${aws_vpc.main.id}"]}),
            ]
        )
        assert ("aws_subnet.a", "aws_vpc.main", "containment") in _edges_of(
            InfraGraph.from_parsed(parsed)
        )

    def test_bare_name_binds_when_exactly_one_node_of_the_required_type_has_it(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("aws_subnet", "aws_subnet.a", "private-a", "aws"),
                _pr("aws_instance", "web", references={"subnet_id": ["private-a"]}),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_instance.web", "aws_subnet.a", "containment")
        }

    def test_ambiguous_bare_name_adds_no_edge_and_records_a_diagnostic(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource(
                    "aws_subnet", "aws_subnet.a", "shared", "aws", source_location="a.tf"
                ),
                ParsedResource("aws_subnet", "aws_subnet.b", "shared", "aws"),
                _pr(
                    "aws_instance",
                    "web",
                    references={"subnet_id": ["shared"]},
                    source_location="web.tf",
                    start_line=7,
                ),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert graph.edges == []
        (diag,) = [d for d in graph.diagnostics if d.code == "graph.ambiguous_reference"]
        assert diag.level == "warning"
        assert "aws_subnet.a" in diag.message and "aws_subnet.b" in diag.message
        assert (diag.file, diag.line) == ("web.tf", 7)

    def test_dependency_and_reference_to_the_same_node_make_one_edge_with_the_relation(
        self,
    ) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "web"),
                _pr(
                    "aws_instance",
                    "app",
                    dependencies=["aws_security_group.web"],
                    references={"security_groups": ["aws_security_group.web.id"]},
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.relation == "security_group"

    def test_specific_relation_is_not_replaced_by_the_generic_one(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "web"),
                _pr(
                    "aws_instance",
                    "app",
                    references={
                        "security_groups": ["aws_security_group.web.id"],
                        "tags.sg": ["aws_security_group.web.name"],
                    },
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.relation == "security_group"

    def test_edge_order_is_stable_across_builds(self) -> None:
        def build() -> list[tuple[str, str]]:
            resources = [
                ParsedResource("aws_subnet", f"aws_subnet.a[{i}]", "a", "aws") for i in (2, 0, 1)
            ]
            resources.append(_pr("aws_lb", "front", references={"subnets": ["aws_subnet.a"]}))
            return [
                (e.source, e.target)
                for e in InfraGraph.from_parsed(ParsedOutput(resources=resources)).edges
            ]

        first = build()
        assert first == build()
        assert [t for _, t in first] == ["aws_subnet.a[0]", "aws_subnet.a[1]", "aws_subnet.a[2]"]

    def test_register_containment_hint_still_works(self) -> None:
        from threatcode.ir import graph as graph_module
        from threatcode.ir.graph import register_containment_hint

        register_containment_hint("scope_id", "custom_scope")
        try:
            parsed = ParsedOutput(
                resources=[
                    _pr("custom_scope", "s"),
                    _pr("custom_thing", "t", properties={"scope_id": "s"}),
                ]
            )
            assert ("custom_thing.t", "custom_scope.s", "containment") in _edges_of(
                InfraGraph.from_parsed(parsed)
            )
        finally:
            graph_module._custom_containment_hints.remove(("scope_id", "custom_scope"))

    def test_registered_hint_is_skipped_for_an_attribute_with_references(self) -> None:
        from threatcode.ir import graph as graph_module
        from threatcode.ir.graph import register_containment_hint

        register_containment_hint("scope_id", "custom_scope")
        try:
            parsed = ParsedOutput(
                resources=[
                    _pr("custom_scope", "s"),
                    _pr(
                        "custom_thing",
                        "t",
                        properties={"scope_id": "s"},
                        references={"scope_id": ["var.scope"]},
                    ),
                ]
            )
            assert InfraGraph.from_parsed(parsed).edges == []
        finally:
            graph_module._custom_containment_hints.remove(("scope_id", "custom_scope"))


class TestLiteralValuesWithoutReferences:
    """Hand-written inputs state addresses, ids and names; a value binds only by resolving."""

    def test_literal_subnet_and_security_group_addresses_make_edges(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_subnet", "a"),
                _pr("aws_security_group", "web"),
                _pr(
                    "aws_instance",
                    "app",
                    properties={
                        "subnet_id": "aws_subnet.a",
                        "vpc_security_group_ids": ["aws_security_group.web"],
                    },
                ),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert _edges_of(graph) == {
            ("aws_instance.app", "aws_subnet.a", "containment"),
            ("aws_instance.app", "aws_security_group.web", "dependency"),
        }

    def test_a_security_group_attachment_is_never_a_network_flow(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "web"),
                _pr(
                    "aws_instance",
                    "app",
                    properties={"vpc_security_group_ids": ["aws_security_group.web"]},
                ),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.edge_type, edge.relation) == (EdgeType.DEPENDENCY, "security_group")
        assert edge.declared is False

    def test_literal_role_label_still_matches_as_the_last_resort(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "exec"),
                _pr("aws_iam_instance_profile", "p", properties={"role": "exec"}),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_iam_instance_profile.p", "aws_iam_role.exec", "iam_binding")
        }

    def test_a_role_name_attribute_wins_over_another_roles_label(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "ops", properties={"name": "deploy"}),
                _pr("aws_iam_role", "deploy", properties={"name": "other"}),
                _pr("aws_iam_instance_profile", "p", properties={"role": "deploy"}),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_iam_instance_profile.p", "aws_iam_role.ops", "iam_binding")
        }

    def test_a_role_arn_resolves_through_the_name_attribute(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "fn", properties={"name": "orders-fn"}),
                _pr(
                    "aws_lambda_function",
                    "orders",
                    properties={"role": "arn:aws:iam::123456789012:role/service/orders-fn"},
                ),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("aws_lambda_function.orders", "aws_iam_role.fn", "iam_binding")
        }

    def test_a_policy_attachment_names_its_policy_and_role(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "r", properties={"name": "r-name"}),
                _pr("aws_iam_policy", "p", properties={"name": "p-name"}),
                _pr(
                    "aws_iam_role_policy_attachment",
                    "a",
                    properties={"role": "r-name", "policy_arn": "aws_iam_policy.p"},
                ),
            ]
        )
        edges = InfraGraph.from_parsed(parsed).edges
        assert {(e.source, e.target, e.relation) for e in edges if e.relation != "has_policy"} == {
            ("aws_iam_role_policy_attachment.a", "aws_iam_role.r", "assumes"),
            ("aws_iam_role_policy_attachment.a", "aws_iam_policy.p", "attaches"),
        }


class TestTwoVpcPlacement:
    """A subnet or security group belongs to the VPC its value names, never to the first VPC."""

    def _vpcs(self, *extra: ParsedResource) -> ParsedOutput:
        return ParsedOutput(
            resources=[
                _pr("aws_vpc", "prod", properties={"id": "vpc-prod0001"}),
                _pr("aws_vpc", "dev", properties={"id": "vpc-dev0001"}),
                *extra,
            ]
        )

    def _ambiguous(self, graph: InfraGraph) -> list[str]:
        return [d.message for d in graph.diagnostics if d.code == "graph.ambiguous_reference"]

    def test_the_dev_subnet_binds_only_to_the_dev_vpc_by_address(self) -> None:
        subnet = _pr("aws_subnet", "dev_a", properties={"vpc_id": "aws_vpc.dev"})
        graph = InfraGraph.from_parsed(self._vpcs(subnet))
        assert _edges_of(graph) == {("aws_subnet.dev_a", "aws_vpc.dev", "containment")}

    def test_the_dev_subnet_binds_only_to_the_dev_vpc_by_id(self) -> None:
        subnet = _pr("aws_subnet", "dev_a", properties={"vpc_id": "vpc-dev0001"})
        graph = InfraGraph.from_parsed(self._vpcs(subnet))
        assert _edges_of(graph) == {("aws_subnet.dev_a", "aws_vpc.dev", "containment")}
        assert self._ambiguous(graph) == []

    def test_the_dev_security_group_binds_only_to_the_dev_vpc(self) -> None:
        group = _pr("aws_security_group", "dev", properties={"vpc_id": "${aws_vpc.dev.id}"})
        graph = InfraGraph.from_parsed(self._vpcs(group))
        assert _edges_of(graph) == {("aws_security_group.dev", "aws_vpc.dev", "containment")}

    def test_an_unresolvable_literal_with_two_candidates_adds_no_edge_and_says_why(self) -> None:
        subnet = _pr(
            "aws_subnet",
            "stray",
            properties={"vpc_id": "vpc-0unknown"},
            source_location="net.tf",
            start_line=12,
        )
        graph = InfraGraph.from_parsed(self._vpcs(subnet))
        assert graph.edges == []
        (diag,) = [d for d in graph.diagnostics if d.code == "graph.ambiguous_reference"]
        # Most likely a VPC outside the input, so information and not a coverage gap
        assert diag.level == "info"
        assert "vpc-0unknown" in diag.message
        assert "aws_vpc.prod" in diag.message and "aws_vpc.dev" in diag.message
        assert "no edge was added" in diag.message
        assert (diag.file, diag.line) == ("net.tf", 12)

    def test_a_literal_vpc_id_binds_the_only_vpc_and_says_how(self) -> None:
        # One candidate leaves nothing to choose: the placement binds it, marked as inferred
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "only"),
                _pr("aws_subnet", "a", properties={"vpc_id": "vpc-somewhere"}),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        (edge,) = graph.edges
        assert (edge.source, edge.target, edge.edge_type) == (
            "aws_subnet.a",
            "aws_vpc.only",
            EdgeType.CONTAINMENT,
        )
        assert edge.attributes == {"binding": "only_candidate"}
        assert self._ambiguous(graph) == []

    def test_the_sole_candidate_is_not_bound_for_a_dangling_address(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "only"),
                _pr("aws_subnet", "a", properties={"vpc_id": "aws_vpc.gone"}),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_the_sole_candidate_is_not_bound_for_a_subnet_or_a_security_group_value(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_subnet", "only"),
                _pr("aws_security_group", "only"),
                _pr(
                    "aws_instance",
                    "i",
                    properties={"subnet_id": "subnet-0abc", "vpc_security_group_ids": ["sg-0abc"]},
                ),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []

    def test_the_sole_candidate_of_another_unit_is_not_bound(self) -> None:
        graph = InfraGraph.from_units(
            [
                ParsedOutput(
                    resources=[_pr("aws_subnet", "a", properties={"vpc_id": "vpc-1"})],
                    source_path="a",
                ),
                ParsedOutput(resources=[_pr("aws_vpc", "main")], source_path="b"),
            ]
        )
        assert graph.edges == []

    def test_an_id_that_two_vpcs_share_is_reported_and_binds_neither(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "a", properties={"id": "vpc-1"}),
                _pr("aws_vpc", "b", properties={"id": "vpc-1"}),
                _pr("aws_subnet", "s", properties={"vpc_id": "vpc-1"}),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert graph.edges == []
        (message,) = self._ambiguous(graph)
        assert "matches several nodes" in message
        assert "aws_vpc.a" in message and "aws_vpc.b" in message
        (diag,) = [d for d in graph.diagnostics if d.code == "graph.ambiguous_reference"]
        assert diag.level == "warning"

    def test_a_dangling_address_is_not_an_ambiguity(self) -> None:
        subnet = _pr("aws_subnet", "a", properties={"vpc_id": "aws_vpc.gone"})
        graph = InfraGraph.from_parsed(self._vpcs(subnet))
        assert graph.edges == []
        assert self._ambiguous(graph) == []

    def test_a_security_group_value_that_names_no_group_among_several_is_reported(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "a"),
                _pr("aws_security_group", "b"),
                _pr("aws_instance", "i", properties={"vpc_security_group_ids": ["sg-0abc"]}),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert graph.edges == []
        assert len(self._ambiguous(graph)) == 1

    def test_an_unmatched_role_or_managed_policy_is_external_and_adds_no_noise(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "a", properties={"name": "a"}),
                _pr("aws_iam_role", "b", properties={"name": "b"}),
                _pr("aws_iam_policy", "p", properties={"name": "p"}),
                _pr("aws_iam_policy", "q", properties={"name": "q"}),
                _pr(
                    "aws_iam_role_policy_attachment",
                    "managed",
                    properties={
                        "role": "someone-elses-role",
                        "policy_arn": "arn:aws:iam::aws:policy/ReadOnlyAccess",
                    },
                ),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert graph.edges == []
        assert self._ambiguous(graph) == []

    def test_a_foreign_provider_attribute_is_not_reported_against_aws_nodes(self) -> None:
        # google_project_iam_member.role is "roles/viewer", which says nothing about aws roles
        parsed = ParsedOutput(
            resources=[
                _pr("aws_iam_role", "a"),
                _pr("aws_iam_role", "b"),
                ParsedResource(
                    "google_project_iam_member",
                    "google_project_iam_member.m",
                    "m",
                    "google",
                    properties={"role": "roles/viewer"},
                ),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert graph.edges == []
        assert self._ambiguous(graph) == []

    def test_the_same_graph_built_from_a_reference_binds_the_same_vpc(self) -> None:
        subnet = _pr("aws_subnet", "dev_a", references={"vpc_id": ["aws_vpc.dev.id"]})
        graph = InfraGraph.from_parsed(self._vpcs(subnet))
        assert _edges_of(graph) == {("aws_subnet.dev_a", "aws_vpc.dev", "containment")}


class TestAzureAndGoogleAttachments:
    def test_a_subnet_is_contained_in_the_virtual_network_it_names(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("azurerm_virtual_network", "azurerm_virtual_network.a", "a", "az"),
                ParsedResource("azurerm_virtual_network", "azurerm_virtual_network.b", "b", "az"),
                ParsedResource(
                    "azurerm_subnet",
                    "azurerm_subnet.s",
                    "s",
                    "az",
                    references={"virtual_network_name": ["azurerm_virtual_network.b.name"]},
                ),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("azurerm_subnet.s", "azurerm_virtual_network.b", "containment")
        }

    def test_a_google_instance_is_contained_in_its_network_and_subnetwork(self) -> None:
        parsed = ParsedOutput(
            resources=[
                ParsedResource("google_compute_network", "google_compute_network.n", "n", "g"),
                ParsedResource(
                    "google_compute_subnetwork", "google_compute_subnetwork.s", "s", "g"
                ),
                ParsedResource(
                    "google_compute_instance",
                    "google_compute_instance.vm",
                    "vm",
                    "g",
                    references={
                        "network_interface[].network": ["google_compute_network.n.id"],
                        "network_interface[].subnetwork": ["google_compute_subnetwork.s.id"],
                    },
                ),
            ]
        )
        assert _edges_of(InfraGraph.from_parsed(parsed)) == {
            ("google_compute_instance.vm", "google_compute_network.n", "containment"),
            ("google_compute_instance.vm", "google_compute_subnetwork.s", "containment"),
        }

    def test_the_dead_vnet_and_network_id_hints_are_gone(self) -> None:
        from threatcode.ir import graph as graph_module

        assert not hasattr(graph_module, "_BUILTIN_CONTAINMENT_HINTS")
        parsed = ParsedOutput(
            resources=[
                ParsedResource("azurerm_virtual_network", "azurerm_virtual_network.a", "a", "az"),
                _pr("custom_thing", "t", properties={"vnet_id": "azurerm_virtual_network.a"}),
            ]
        )
        assert InfraGraph.from_parsed(parsed).edges == []


class TestRegisteredContainmentHint:
    def test_a_hint_binds_by_reference_and_by_unique_name(self) -> None:
        from threatcode.ir import graph as graph_module
        from threatcode.ir.graph import register_containment_hint

        register_containment_hint("scope_id", "custom_scope")
        try:
            parsed = ParsedOutput(
                resources=[
                    _pr("custom_scope", "s"),
                    _pr("custom_scope", "t"),
                    _pr("custom_thing", "by_name", properties={"scope_id": "t"}),
                    _pr("custom_thing", "by_ref", references={"scope_id": ["custom_scope.s.id"]}),
                ]
            )
            assert _edges_of(InfraGraph.from_parsed(parsed)) == {
                ("custom_thing.by_name", "custom_scope.t", "containment"),
                ("custom_thing.by_ref", "custom_scope.s", "containment"),
            }
        finally:
            graph_module._custom_containment_hints.remove(("scope_id", "custom_scope"))

    def test_a_hint_binds_the_only_node_of_its_type_and_never_the_first_of_several(self) -> None:
        from threatcode.ir import graph as graph_module
        from threatcode.ir.graph import register_containment_hint

        register_containment_hint("scope_id", "custom_scope")
        try:
            lone = ParsedOutput(
                resources=[
                    _pr("custom_scope", "first"),
                    _pr("custom_thing", "t", properties={"scope_id": "nobody"}),
                ]
            )
            assert _edges_of(InfraGraph.from_parsed(lone)) == {
                ("custom_thing.t", "custom_scope.first", "containment")
            }
            several = ParsedOutput(
                resources=[
                    _pr("custom_scope", "first"),
                    _pr("custom_scope", "second"),
                    _pr("custom_thing", "t", properties={"scope_id": "nobody"}),
                ]
            )
            graph = InfraGraph.from_parsed(several)
            assert graph.edges == []
            assert [d.code for d in graph.diagnostics] == ["graph.ambiguous_reference"]
        finally:
            graph_module._custom_containment_hints.remove(("scope_id", "custom_scope"))


class TestDeclaredEdgeStrictness:
    def _resources(self) -> list[ParsedResource]:
        return [_res("design_service.api"), _res("design_database.orders")]

    def test_unknown_target_raises_naming_the_edge_and_the_endpoint(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.api", "design_database.gone")],
        )
        with pytest.raises(ThreatCodeError) as excinfo:
            InfraGraph.from_parsed(parsed)
        message = str(excinfo.value)
        assert "design_service.api -> design_database.gone" in message
        assert "unknown target 'design_database.gone'" in message

    def test_unknown_source_raises(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.ghost", "design_database.orders")],
        )
        with pytest.raises(ThreatCodeError, match="unknown source 'design_service.ghost'"):
            InfraGraph.from_parsed(parsed)

    def test_every_dangling_edge_is_listed_in_one_error(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[
                ParsedEdge("design_service.ghost", "design_database.orders"),
                ParsedEdge("design_service.api", "design_database.gone"),
                ParsedEdge("design_service.nope", "design_database.never"),
                ParsedEdge("design_service.api", "design_database.orders"),
            ],
        )
        with pytest.raises(ThreatCodeError) as excinfo:
            InfraGraph.from_parsed(parsed)
        message = str(excinfo.value)
        assert message.startswith("4 declared edge endpoint(s)")
        for fragment in (
            "unknown source 'design_service.ghost'",
            "unknown target 'design_database.gone'",
            "unknown source 'design_service.nope'",
            "unknown target 'design_database.never'",
        ):
            assert fragment in message
        # The one valid edge is not reported
        assert "design_service.api -> design_database.orders" not in message

    def test_error_suggests_the_closest_known_node(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.api", "design_database.order")],
        )
        with pytest.raises(ThreatCodeError, match="closest known: design_database.orders"):
            InfraGraph.from_parsed(parsed)

    def test_suggestions_are_limited_to_the_first_dangling_edges_but_every_edge_is_listed(
        self,
    ) -> None:
        edges = [ParsedEdge("design_service.api", f"design_database.order{i}") for i in range(25)]
        parsed = ParsedOutput(resources=self._resources(), edges=edges)
        with pytest.raises(ThreatCodeError) as excinfo:
            InfraGraph.from_parsed(parsed)
        lines = [ln for ln in str(excinfo.value).splitlines() if "design_database.order" in ln]
        assert len(lines) == 25
        assert sum("closest known" in ln for ln in lines) == 20

    def test_error_offers_the_non_strict_mode(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.api", "zzz.nothing")],
        )
        with pytest.raises(ThreatCodeError, match="strict_edges=False") as excinfo:
            InfraGraph.from_parsed(parsed)
        assert "closest known" not in str(excinfo.value)

    def test_edges_that_are_not_declared_are_skipped_without_error_or_diagnostic(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[
                ParsedEdge("design_service.api", "design_database.gone", declared=False),
                ParsedEdge("design_service.api", "design_database.orders", declared=False),
            ],
        )
        graph = InfraGraph.from_parsed(parsed)
        assert _edges_of(graph) == {("design_service.api", "design_database.orders", "data_flow")}
        assert graph.diagnostics == []

    def test_inferred_edge_that_resolves_is_not_marked_declared(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.api", "design_database.orders", declared=False)],
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.declared is False

    def test_declared_edge_is_marked_declared(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.api", "design_database.orders")],
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.declared is True

    def test_non_strict_mode_builds_the_graph_and_warns_per_endpoint(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[
                ParsedEdge("design_service.api", "design_database.gone"),
                ParsedEdge("design_service.ghost", "design_database.orders"),
                ParsedEdge("design_service.api", "design_database.orders"),
            ],
        )
        graph = InfraGraph.from_parsed(parsed, strict_edges=False)
        assert _edges_of(graph) == {("design_service.api", "design_database.orders", "data_flow")}
        dangling = [d for d in graph.diagnostics if d.code == "graph.dangling_declared_edge"]
        assert [d.level for d in dangling] == ["warning", "warning"]
        assert "unknown target 'design_database.gone'" in dangling[0].message
        assert "unknown source 'design_service.ghost'" in dangling[1].message

    def test_strictness_can_be_set_on_the_constructor_too(self) -> None:
        assert InfraGraph().strict_edges is True
        assert InfraGraph(strict_edges=False).strict_edges is False

    def test_edge_with_both_endpoints_unknown_is_listed_twice(self) -> None:
        parsed = ParsedOutput(resources=self._resources(), edges=[ParsedEdge("a.x", "b.y")])
        with pytest.raises(ThreatCodeError) as excinfo:
            InfraGraph.from_parsed(parsed)
        assert "unknown source 'a.x'" in str(excinfo.value)
        assert "unknown target 'b.y'" in str(excinfo.value)

    def test_unknown_edge_type_still_raises_even_in_non_strict_mode(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[ParsedEdge("design_service.api", "design_database.orders", "telepathy")],
        )
        with pytest.raises(ThreatCodeError, match="unknown type 'telepathy'"):
            InfraGraph.from_parsed(parsed, strict_edges=False)

    def test_relation_comes_from_the_edge_metadata(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[
                ParsedEdge(
                    "design_service.api", "design_database.orders", metadata={"relation": "reads"}
                )
            ],
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.relation == "reads"

    def test_non_string_relation_in_metadata_is_ignored(self) -> None:
        parsed = ParsedOutput(
            resources=self._resources(),
            edges=[
                ParsedEdge("design_service.api", "design_database.orders", metadata={"relation": 5})
            ],
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.relation == ""


# -- Edge fields the parser cannot forge ----------------------------------------


class TestEdgeFields:
    def _graph(self, metadata: dict[str, Any], source_zone: str, target_zone: str) -> InfraGraph:
        return InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    _res("design_service.a", trust_zone=source_zone),
                    _res("design_service.b", trust_zone=target_zone),
                ],
                edges=[ParsedEdge("design_service.a", "design_service.b", metadata=metadata)],
            )
        )

    def test_forged_crossing_between_two_private_nodes_is_not_a_crossing(self) -> None:
        graph = self._graph({"crosses_trust_boundary": True}, "private", "private")
        (edge,) = graph.edges
        assert edge.crosses_boundary is False
        assert edge.crosses_trust_boundary is False
        assert graph.get_boundary_crossing_edges() == []
        assert "crosses_trust_boundary" not in edge.metadata

    def test_forged_zones_are_replaced_by_the_real_ones_on_a_real_crossing(self) -> None:
        graph = self._graph(
            {"crosses_trust_boundary": True, "source_zone": "internet", "target_zone": "internet"},
            "private",
            "data",
        )
        (edge,) = graph.edges
        assert edge.crosses_boundary is True
        assert (edge.source_zone, edge.target_zone) == (TrustZone.PRIVATE, TrustZone.DATA)
        assert (edge.metadata["source_zone"], edge.metadata["target_zone"]) == ("private", "data")

    def test_forged_zone_keys_are_dropped_from_a_non_crossing_edge(self) -> None:
        graph = self._graph(
            {"source_zone": "internet", "target_zone": "data", "source_boundary": "x"},
            "private",
            "private",
        )
        (edge,) = graph.edges
        for key in ("source_zone", "target_zone", "source_boundary", "target_boundary"):
            assert key not in edge.metadata

    def test_parser_attributes_are_kept_untouched_apart_from_the_metadata_view(self) -> None:
        graph = self._graph(
            {"crosses_trust_boundary": True, "protocol": "tls"}, "private", "private"
        )
        (edge,) = graph.edges
        assert edge.attributes == {"crosses_trust_boundary": True, "protocol": "tls"}
        assert edge.metadata == {"protocol": "tls"}

    def test_forged_keys_in_a_repeated_edge_are_also_dropped(self) -> None:
        parsed = ParsedOutput(
            resources=[_res("design_service.a"), _res("design_service.b")],
            edges=[
                ParsedEdge("design_service.a", "design_service.b", metadata={"note": "first"}),
                ParsedEdge(
                    "design_service.a",
                    "design_service.b",
                    metadata={"crosses_trust_boundary": True, "note": "second"},
                ),
            ],
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.crosses_boundary is False
        assert edge.metadata == {"note": "second"}

    def test_typed_fields_describe_a_crossing_edge(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(
                resources=[
                    _res("design_service.a", trust_zone="private", boundary="tz-a"),
                    _res("design_service.b", trust_zone="private", boundary="tz-b"),
                ],
                edges=[ParsedEdge("design_service.a", "design_service.b")],
            )
        )
        (edge,) = graph.edges
        assert edge.crosses_boundary is True
        assert (edge.source_zone, edge.target_zone) == (TrustZone.PRIVATE, TrustZone.PRIVATE)
        assert (edge.source_boundary, edge.target_boundary) == ("tz-a", "tz-b")

    def test_zones_are_filled_in_even_when_the_edge_does_not_cross(self) -> None:
        (edge,) = self._graph({}, "private", "private").edges
        assert edge.crosses_boundary is False
        assert (edge.source_zone, edge.target_zone) == (TrustZone.PRIVATE, TrustZone.PRIVATE)
        # ... but the compatibility metadata keys stay absent, as they always were
        assert "source_zone" not in edge.metadata

    def test_compatibility_keys_stay_populated_for_a_crossing(self) -> None:
        (edge,) = self._graph({}, "dmz", "data").edges
        assert edge.metadata["crosses_trust_boundary"] is True
        assert (edge.metadata["source_zone"], edge.metadata["target_zone"]) == ("dmz", "data")

    def test_inferred_edges_are_not_declared_and_have_no_attributes(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", references={"vpc_id": ["aws_vpc.main"]}),
            ]
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert (edge.declared, edge.attributes) == (False, {})

    def test_declared_edge_upgrades_an_inferred_one_to_declared(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", dependencies=["aws_vpc.main"]),
            ],
            edges=[
                ParsedEdge("aws_subnet.a", "aws_vpc.main", "dependency", metadata={"note": "x"})
            ],
        )
        (edge,) = InfraGraph.from_parsed(parsed).edges
        assert edge.declared is True
        assert edge.attributes == {"note": "x"}


class TestInfraEdgeConstruction:
    """An edge built by hand with the legacy metadata keys gets matching typed fields."""

    def test_legacy_metadata_keys_become_typed_fields(self) -> None:
        edge = InfraEdge(
            "a",
            "b",
            EdgeType.NETWORK_FLOW,
            metadata={
                "crosses_trust_boundary": True,
                "source_zone": "internet",
                "target_zone": "dmz",
                "source_boundary": "x",
                "target_boundary": "y",
            },
        )
        assert edge.crosses_boundary is True
        assert edge.crosses_trust_boundary is True
        assert (edge.source_zone, edge.target_zone) == (TrustZone.INTERNET, TrustZone.DMZ)
        assert (edge.source_boundary, edge.target_boundary) == ("x", "y")

    def test_an_unknown_zone_in_legacy_metadata_becomes_none(self) -> None:
        edge = InfraEdge(
            "a",
            "b",
            EdgeType.DEPENDENCY,
            metadata={"crosses_trust_boundary": True, "source_zone": "moon"},
        )
        assert edge.crosses_boundary is True
        assert edge.source_zone is None

    def test_edge_without_the_key_does_not_cross(self) -> None:
        edge = InfraEdge("a", "b", EdgeType.DEPENDENCY, metadata={"source_zone": "internet"})
        assert edge.crosses_trust_boundary is False
        assert edge.source_zone is None

    def test_defaults(self) -> None:
        edge = InfraEdge("a", "b", EdgeType.DEPENDENCY)
        assert (edge.relation, edge.declared, edge.attributes) == ("", False, {})
        assert (edge.source_boundary, edge.target_boundary) == ("", "")


class TestEdgeTypeGroups:
    def test_structural_and_reachability_partition_the_edge_types(self) -> None:
        assert STRUCTURAL == {EdgeType.CONTAINMENT, EdgeType.DEPENDENCY}
        assert REACHABILITY == {EdgeType.NETWORK_FLOW, EdgeType.DATA_FLOW, EdgeType.IAM_BINDING}
        assert STRUCTURAL.isdisjoint(REACHABILITY)
        assert STRUCTURAL | REACHABILITY == set(EdgeType)


# -- Accessors, diagnostics, the enrich hook and build options ------------------


class TestAccessors:
    def _graph(self) -> InfraGraph:
        parsed = ParsedOutput(
            resources=[
                _res("design_service.a"),
                _res("design_service.b"),
                _res("design_service.c"),
            ],
            edges=[
                ParsedEdge("design_service.a", "design_service.b", "data_flow"),
                ParsedEdge("design_service.a", "design_service.c", "dependency"),
                ParsedEdge("design_service.b", "design_service.c", "network_flow"),
                ParsedEdge("design_service.a", "design_service.b", "dependency"),
            ],
        )
        return InfraGraph.from_parsed(parsed)

    def test_edges_from_and_to_are_in_the_order_added(self) -> None:
        graph = self._graph()
        assert [(e.target, e.edge_type.value) for e in graph.edges_from("design_service.a")] == [
            ("design_service.b", "data_flow"),
            ("design_service.c", "dependency"),
            ("design_service.b", "dependency"),
        ]
        assert [e.source for e in graph.edges_to("design_service.c")] == [
            "design_service.a",
            "design_service.b",
        ]

    def test_successors_are_unique_and_follow_edge_order(self) -> None:
        assert self._graph().successors("design_service.a") == [
            "design_service.b",
            "design_service.c",
        ]

    def test_successors_can_be_limited_to_edge_types(self) -> None:
        graph = self._graph()
        assert graph.successors("design_service.a", [EdgeType.DATA_FLOW]) == ["design_service.b"]
        assert graph.successors("design_service.a", REACHABILITY) == ["design_service.b"]
        assert graph.successors("design_service.a", STRUCTURAL) == [
            "design_service.c",
            "design_service.b",
        ]

    def test_empty_edge_type_filter_matches_nothing(self) -> None:
        assert self._graph().successors("design_service.a", []) == []

    def test_predecessors_mirror_successors(self) -> None:
        graph = self._graph()
        assert graph.predecessors("design_service.c") == ["design_service.a", "design_service.b"]
        assert graph.predecessors("design_service.c", [EdgeType.NETWORK_FLOW]) == [
            "design_service.b"
        ]
        assert graph.predecessors("design_service.a") == []

    def test_direction_is_respected(self) -> None:
        graph = self._graph()
        assert "design_service.a" not in graph.successors("design_service.b")
        assert "design_service.c" not in graph.predecessors("design_service.b")

    def test_unknown_node_has_no_neighbours(self) -> None:
        graph = self._graph()
        assert graph.edges_from("nope") == []
        assert graph.edges_to("nope") == []
        assert graph.successors("nope") == []
        assert graph.predecessors("nope") == []

    def test_accessors_see_edges_added_after_the_first_query(self) -> None:
        graph = self._graph()
        assert graph.successors("design_service.c") == []
        graph._add_edge("design_service.c", "design_service.a", EdgeType.DATA_FLOW)
        assert graph.successors("design_service.c") == ["design_service.a"]

    def test_returned_lists_are_copies(self) -> None:
        graph = self._graph()
        graph.edges_from("design_service.a").clear()
        assert len(graph.edges_from("design_service.a")) == 3


class TestDiagnosticsAndOptions:
    def test_parse_diagnostics_are_carried_into_the_graph(self) -> None:
        note = Diagnostic(
            "warning", "hcl.module_call_skipped", "module.x not expanded", "main.tf", 3
        )
        parsed = ParsedOutput(resources=[_pr("aws_vpc", "main")], diagnostics=[note])
        assert InfraGraph.from_parsed(parsed).diagnostics == [note]

    def test_graph_diagnostics_follow_the_parse_diagnostics(self) -> None:
        note = Diagnostic("info", "parse.zero_resources", "nothing here")
        parsed = ParsedOutput(
            resources=[_pr("aws_vpc", "main"), _pr("aws_vpc", "main")], diagnostics=[note]
        )
        codes = [d.code for d in InfraGraph.from_parsed(parsed).diagnostics]
        assert codes == ["parse.zero_resources", "graph.duplicate_address"]

    def test_options_are_keyword_only(self) -> None:
        with pytest.raises(TypeError):
            InfraGraph.from_parsed(ParsedOutput(), 5)  # type: ignore[misc]
        with pytest.raises(TypeError):
            InfraGraph(5)  # type: ignore[misc]

    def test_from_parsed_passes_the_options_through(self) -> None:
        graph = InfraGraph.from_parsed(ParsedOutput(), max_nodes=7, max_edges=8, strict_edges=False)
        assert (graph.max_nodes, graph.max_edges, graph.strict_edges) == (7, 8, False)

    def test_empty_input_builds_an_empty_graph(self) -> None:
        graph = InfraGraph.from_parsed(ParsedOutput())
        assert (graph.node_count, graph.edges, graph.diagnostics) == (0, [], [])

    def test_to_dict_edge_carries_a_relation_only_when_set(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _pr("aws_security_group", "web"),
                _pr(
                    "aws_instance",
                    "app",
                    references={"security_groups": ["aws_security_group.web"]},
                ),
                _pr("aws_instance", "db", dependencies=["aws_security_group.web"]),
            ]
        )
        edges = InfraGraph.from_parsed(parsed).to_dict()["edges"]
        assert edges[0]["relation"] == "security_group"
        assert "relation" not in edges[1]


class TestEnrichHook:
    def test_enrich_runs_last_with_the_finished_graph_and_an_index_over_all_nodes(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        calls: list[tuple[InfraGraph, ReferenceIndex, int, bool]] = []

        def spy(graph: InfraGraph, index: ReferenceIndex) -> None:
            crossing = graph.get_boundary_crossing_edges()
            calls.append((graph, index, len(graph.edges), bool(crossing)))

        monkeypatch.setattr("threatcode.ir.graph.enrich", spy)
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", references={"vpc_id": ["aws_vpc.main"]}),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert len(calls) == 1
        seen_graph, index, edge_count, _ = calls[0]
        assert seen_graph is graph
        assert edge_count == 1
        assert index.resolve("aws_subnet.a.id") == ["aws_subnet.a"]

    def test_enrich_runs_for_from_units_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        seen: list[int] = []
        monkeypatch.setattr("threatcode.ir.graph.enrich", lambda graph, index: seen.append(1))
        InfraGraph.from_units([ParsedOutput(), ParsedOutput()])
        assert seen == [1]


class TestPassOrder:
    """Enrichment, IAM, exposure and the boundary marking run in that order."""

    def test_the_passes_run_in_order_over_the_finished_edges(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from threatcode.ir import exposure, iam

        calls: list[tuple[str, int, bool]] = []

        def spy(name: str) -> Any:
            def run(graph: InfraGraph, *args: Any) -> None:
                crossed = any(e.crosses_boundary for e in graph.edges)
                calls.append((name, len(graph.edges), crossed))

            return run

        monkeypatch.setattr("threatcode.ir.graph.enrich", spy("enrich"))
        monkeypatch.setattr(iam, "link", spy("iam"))
        monkeypatch.setattr(exposure, "apply", spy("exposure"))
        parsed = ParsedOutput(
            resources=[
                _pr("aws_vpc", "main"),
                _pr("aws_subnet", "a", references={"vpc_id": ["aws_vpc.main"]}),
                _pr("aws_instance", "i", properties={"associate_public_ip_address": True}),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        assert [name for name, _, _ in calls] == ["enrich", "iam", "exposure"]
        # Every pass sees the structural edges, and none sees a crossing yet
        assert all(count == 1 and not crossed for _, count, crossed in calls)
        # The crossings are marked afterwards, from the zones the passes left
        (edge,) = graph.edges
        assert edge.crosses_boundary is False

    def test_a_zone_the_exposure_pass_changes_is_the_zone_the_crossing_compares(self) -> None:
        # A subnet with a route to an internet gateway becomes public (DMZ) in the exposure pass;
        # the instance in it is private, so the containment edge crosses only with the final zone
        parsed = ParsedOutput(
            resources=[
                _pr("aws_internet_gateway", "gw"),
                _pr("aws_route_table", "pub", properties={"route": [_default_route("gw")]}),
                _pr("aws_subnet", "a"),
                _pr(
                    "aws_route_table_association",
                    "a",
                    properties={
                        "subnet_id": "aws_subnet.a",
                        "route_table_id": "aws_route_table.pub",
                    },
                ),
                _pr("aws_instance", "i", properties={"subnet_id": "aws_subnet.a"}),
            ]
        )
        graph = InfraGraph.from_parsed(parsed)
        subnet = graph.get_node("aws_subnet.a")
        assert subnet is not None
        assert (subnet.trust_zone, subnet.exposure) == (TrustZone.DMZ, "internet")
        (edge,) = [e for e in graph.edges if e.source == "aws_instance.i"]
        assert edge.crosses_boundary is True
        assert (edge.source_zone, edge.target_zone) == (TrustZone.PRIVATE, TrustZone.DMZ)


def _default_route(gateway: str) -> dict[str, str]:
    return {"cidr_block": "0.0.0.0/0", "gateway_id": f"aws_internet_gateway.{gateway}"}


class TestFlowEdgeTypes:
    def test_flow_edges_are_the_traffic_carrying_types_only(self) -> None:
        from threatcode.ir.edges import FLOW_EDGE_TYPES

        assert FLOW_EDGE_TYPES == {EdgeType.NETWORK_FLOW, EdgeType.DATA_FLOW}
        assert FLOW_EDGE_TYPES <= REACHABILITY
        assert not FLOW_EDGE_TYPES & STRUCTURAL
        assert EdgeType.IAM_BINDING not in FLOW_EDGE_TYPES


class TestNodeBookkeeping:
    def test_node_formats_record_the_parser_format_of_each_node(self) -> None:
        graph = InfraGraph.from_units(
            [
                ParsedOutput(resources=[_pr("aws_vpc", "a")], format_type="terraform_hcl"),
                ParsedOutput(
                    resources=[_pr("aws_vpc", "b")], format_type="cloudformation", source_path="t"
                ),
            ]
        )
        assert graph.node_formats == {
            "aws_vpc.a": "terraform_hcl",
            "aws_vpc.b": "cloudformation",
        }

    def test_zone_declared_lists_only_the_nodes_whose_zone_the_input_declared(self) -> None:
        parsed = ParsedOutput(
            resources=[
                _res("design_service.api", trust_zone="dmz"),
                _res("design_service.other"),
            ]
        )
        assert InfraGraph.from_parsed(parsed).zone_declared == {"design_service.api"}


class TestExportDict:
    def _graph(self) -> InfraGraph:
        parsed = ParsedOutput(
            resources=[
                _pr(
                    "aws_s3_bucket",
                    "b",
                    properties={"bucket": "secret-bucket-name", "password": "hunter2"},
                    source_location="main.tf",
                    start_line=3,
                    end_line=9,
                ),
                _pr("aws_lambda_function", "f", properties={"role": "unused"}),
            ],
            edges=[
                ParsedEdge(
                    "aws_lambda_function.f",
                    "aws_s3_bucket.b",
                    "data_flow",
                    {"protocol": "https", "ports": (443,)},
                )
            ],
        )
        return InfraGraph.from_parsed(parsed)

    def test_nodes_carry_what_a_reader_needs_and_no_properties(self) -> None:
        data = self._graph().to_export_dict()
        nodes = {n["id"]: n for n in data["nodes"]}
        bucket = nodes["aws_s3_bucket.b"]
        assert bucket == {
            "id": "aws_s3_bucket.b",
            "type": "aws_s3_bucket",
            "name": "b",
            "category": "storage",
            "zone": "data",
            "exposure": "unknown",
            "boundary": "",
            "evidence": "config",
            "stride_element": "data_store",
            "module": "",
            "mode": "managed",
            "source_file": "main.tf",
            "start_line": 3,
            "end_line": 9,
        }
        assert "hunter2" not in str(data)

    def test_properties_are_included_only_on_request(self) -> None:
        graph = self._graph()
        assert "properties" not in graph.to_export_dict()["nodes"][0]
        with_properties = graph.to_export_dict(include_properties=True)
        nodes = {n["id"]: n for n in with_properties["nodes"]}
        assert nodes["aws_s3_bucket.b"]["properties"]["password"] == "hunter2"

    def test_edges_carry_type_relation_attributes_and_the_crossing(self) -> None:
        (edge,) = self._graph().to_export_dict()["edges"]
        assert edge == {
            "source": "aws_lambda_function.f",
            "target": "aws_s3_bucket.b",
            "type": "data_flow",
            "relation": "",
            "declared": True,
            "crosses_boundary": True,
            "source_zone": "private",
            "target_zone": "data",
            "attributes": {"protocol": "https", "ports": [443]},
        }

    def test_the_export_is_json_serialisable_and_stable(self) -> None:
        import json

        first = json.dumps(self._graph().to_export_dict(include_properties=True), sort_keys=True)
        second = json.dumps(self._graph().to_export_dict(include_properties=True), sort_keys=True)
        assert first == second

    def test_nodes_and_edges_are_sorted_whatever_the_input_order(self) -> None:
        forward = ParsedOutput(resources=[_pr("aws_vpc", "a"), _pr("aws_vpc", "b")])
        backward = ParsedOutput(resources=[_pr("aws_vpc", "b"), _pr("aws_vpc", "a")])
        ids = [n["id"] for n in InfraGraph.from_parsed(forward).to_export_dict()["nodes"]]
        assert ids == ["aws_vpc.a", "aws_vpc.b"]
        assert ids == [n["id"] for n in InfraGraph.from_parsed(backward).to_export_dict()["nodes"]]

    def test_to_dict_keeps_its_shape_for_the_redacted_prompt(
        self, simple_s3_graph: InfraGraph
    ) -> None:
        data = simple_s3_graph.to_dict()
        assert set(data) == {"nodes", "edges"}
        node = next(iter(data["nodes"].values()))
        assert "properties" not in node and "source_file" not in node


class TestSubgraph:
    def _graph(self) -> InfraGraph:
        parsed = ParsedOutput(
            resources=[_pr("aws_vpc", "v"), _pr("aws_subnet", "s"), _pr("aws_instance", "i")],
            edges=[
                ParsedEdge("aws_subnet.s", "aws_vpc.v", "containment"),
                ParsedEdge("aws_subnet.s", "aws_vpc.v", "dependency"),
                ParsedEdge("aws_instance.i", "aws_subnet.s", "network_flow", {"ports": [22]}),
            ],
        )
        return InfraGraph.from_parsed(parsed)

    def test_parallel_edges_between_one_pair_are_both_visible(self) -> None:
        view = self._graph().subgraph([EdgeType.CONTAINMENT, EdgeType.DEPENDENCY])
        assert view.number_of_edges("aws_subnet.s", "aws_vpc.v") == 2
        assert set(view["aws_subnet.s"]["aws_vpc.v"]) == {"containment", "dependency"}

    def test_only_the_requested_edge_types_are_kept_and_every_node_is(self) -> None:
        view = self._graph().subgraph([EdgeType.NETWORK_FLOW])
        assert set(view.nodes) == {"aws_vpc.v", "aws_subnet.s", "aws_instance.i"}
        assert [(u, v) for u, v, _ in view.edges(keys=True)] == [("aws_instance.i", "aws_subnet.s")]
        assert view["aws_instance.i"]["aws_subnet.s"]["network_flow"]["attributes"] == {
            "ports": [22]
        }

    def test_an_empty_selection_has_nodes_and_no_edges(self) -> None:
        view = self._graph().subgraph([])
        assert view.number_of_nodes() == 3 and view.number_of_edges() == 0

    def test_the_reachability_subgraph_keeps_the_edges_an_attacker_can_follow(self) -> None:
        view = self._graph().reachability_subgraph()
        assert [(u, v, k) for u, v, k in view.edges(keys=True)] == [
            ("aws_instance.i", "aws_subnet.s", "network_flow")
        ]

    def test_nodes_carry_zone_and_category(self) -> None:
        view = self._graph().subgraph([EdgeType.CONTAINMENT])
        assert view.nodes["aws_vpc.v"]["zone"] == "private"
        assert view.nodes["aws_vpc.v"]["category"] == "network"


class TestNeighbors:
    def _graph(self) -> InfraGraph:
        parsed = ParsedOutput(
            resources=[_pr("aws_vpc", "v"), _pr("aws_subnet", "s"), _pr("aws_instance", "i")],
            edges=[
                ParsedEdge("aws_subnet.s", "aws_vpc.v", "containment"),
                ParsedEdge("aws_subnet.s", "aws_vpc.v", "dependency"),
                ParsedEdge("aws_instance.i", "aws_subnet.s", "network_flow"),
            ],
        )
        return InfraGraph.from_parsed(parsed)

    def test_the_default_is_the_targets_of_outgoing_edges_once_each(self) -> None:
        graph = self._graph()
        assert [n.id for n in graph.get_neighbors("aws_subnet.s")] == ["aws_vpc.v"]
        assert [n.id for n in graph.get_neighbors("aws_vpc.v")] == []

    def test_incoming_and_both_directions(self) -> None:
        graph = self._graph()
        assert [n.id for n in graph.get_neighbors("aws_subnet.s", "in")] == ["aws_instance.i"]
        assert [n.id for n in graph.get_neighbors("aws_subnet.s", "both")] == [
            "aws_vpc.v",
            "aws_instance.i",
        ]

    def test_an_unknown_node_has_no_neighbors(self) -> None:
        assert self._graph().get_neighbors("nope") == []

    def test_get_edges_for_node_still_lists_every_edge_touching_the_node(self) -> None:
        edges = self._graph().get_edges_for_node("aws_subnet.s")
        assert len(edges) == 3


class TestPublicAddEdge:
    def test_it_adds_a_typed_edge_with_a_relation(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(resources=[_pr("aws_vpc", "a"), _pr("aws_vpc", "b")])
        )
        graph.add_edge(
            "aws_vpc.a", "aws_vpc.b", EdgeType.IAM_BINDING, {"x": 1}, relation="can_assume"
        )
        (edge,) = graph.edges
        assert (edge.edge_type, edge.relation, edge.attributes) == (
            EdgeType.IAM_BINDING,
            "can_assume",
            {"x": 1},
        )
        assert edge.declared is False

    def test_a_repeated_edge_keeps_its_place_and_gains_the_new_attributes(self) -> None:
        graph = InfraGraph.from_parsed(
            ParsedOutput(resources=[_pr("aws_vpc", "a"), _pr("aws_vpc", "b")])
        )
        graph.add_edge("aws_vpc.a", "aws_vpc.b", EdgeType.DEPENDENCY, {"x": 1})
        graph.add_edge("aws_vpc.a", "aws_vpc.b", EdgeType.DEPENDENCY, {"y": 2})
        (edge,) = graph.edges
        assert edge.attributes == {"x": 1, "y": 2}

    def test_an_unknown_endpoint_is_an_error(self) -> None:
        graph = InfraGraph.from_parsed(ParsedOutput(resources=[_pr("aws_vpc", "a")]))
        with pytest.raises(ThreatCodeError, match="unknown node"):
            graph.add_edge("aws_vpc.a", "aws_vpc.gone", EdgeType.DEPENDENCY)
        assert graph.edges == []
