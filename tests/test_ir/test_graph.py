"""Tests for infrastructure graph building."""

from __future__ import annotations

import logging
from typing import Any

import pytest

from threatcode.exceptions import ThreatCodeError
from threatcode.ir.edges import EdgeType
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import NodeCategory, TrustZone
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

    def test_edge_to_unknown_node_is_skipped(self) -> None:
        parsed = ParsedOutput(
            resources=[_res("design_service.api")],
            edges=[ParsedEdge("design_service.api", "design_database.gone")],
        )
        assert InfraGraph.from_parsed(parsed).edges == []

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
