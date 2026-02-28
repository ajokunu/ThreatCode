"""Tests for infrastructure graph building."""

from __future__ import annotations

from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import NodeCategory, TrustZone
from threatcode.parsers.base import ParsedOutput


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
