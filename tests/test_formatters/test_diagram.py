"""Tests for SVG diagram formatter."""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree

import pytest
from threatcode.engine.hybrid import HybridEngine
from threatcode.formatters.diagram import format_diagram
from threatcode.ir.edges import EdgeType, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

# ── Helpers ──────────────────────────────────────────────────────────


def _make_graph_with_nodes(
    nodes: list[InfraNode], edges: list[InfraEdge] | None = None,
) -> InfraGraph:
    """Build a minimal InfraGraph from a list of nodes and optional edges."""
    graph = InfraGraph()
    for node in nodes:
        graph._nodes[node.id] = node
        graph._graph.add_node(node.id)
    for edge in edges or []:
        graph._edges.append(edge)
        graph._graph.add_edge(edge.source, edge.target, type=edge.edge_type.value)
    return graph


def _make_report(threats: list[Threat] | None = None, n_resources: int = 0) -> ThreatReport:
    return ThreatReport(
        threats=threats or [],
        scanned_resources=n_resources,
        input_file="test.plan.json",
    )


def _make_threat(resource_address: str, severity: str = "high") -> Threat:
    return Threat(
        id=f"T-{resource_address}",
        title="Test threat",
        description="Test",
        stride_category="spoofing",
        severity=Severity(severity),
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address=resource_address,
    )


SAMPLE_NODES = [
    InfraNode(
        id="aws_internet_gateway.igw",
        resource_type="aws_internet_gateway",
        name="igw",
        category=NodeCategory.NETWORK,
        trust_zone=TrustZone.INTERNET,
    ),
    InfraNode(
        id="aws_lb.alb",
        resource_type="aws_lb",
        name="alb",
        category=NodeCategory.NETWORK,
        trust_zone=TrustZone.DMZ,
    ),
    InfraNode(
        id="aws_lambda_function.api",
        resource_type="aws_lambda_function",
        name="api",
        category=NodeCategory.SERVERLESS,
        trust_zone=TrustZone.PRIVATE,
    ),
    InfraNode(
        id="aws_s3_bucket.data",
        resource_type="aws_s3_bucket",
        name="data",
        category=NodeCategory.STORAGE,
        trust_zone=TrustZone.DATA,
    ),
    InfraNode(
        id="aws_iam_role.exec",
        resource_type="aws_iam_role",
        name="exec",
        category=NodeCategory.IAM,
        trust_zone=TrustZone.MANAGEMENT,
    ),
]

SAMPLE_EDGES = [
    InfraEdge(
        source="aws_internet_gateway.igw",
        target="aws_lb.alb",
        edge_type=EdgeType.NETWORK_FLOW,
        metadata={"crosses_trust_boundary": True, "source_zone": "internet", "target_zone": "dmz"},
    ),
    InfraEdge(
        source="aws_lb.alb",
        target="aws_lambda_function.api",
        edge_type=EdgeType.DEPENDENCY,
    ),
    InfraEdge(
        source="aws_lambda_function.api",
        target="aws_s3_bucket.data",
        edge_type=EdgeType.DATA_FLOW,
        metadata={"crosses_trust_boundary": True, "source_zone": "private", "target_zone": "data"},
    ),
    InfraEdge(
        source="aws_iam_role.exec",
        target="aws_lambda_function.api",
        edge_type=EdgeType.IAM_BINDING,
    ),
]


# ── Tests ────────────────────────────────────────────────────────────


class TestDiagramFormatter:
    def test_svg_is_valid_xml(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report(n_resources=5)
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        assert root.tag == "{http://www.w3.org/2000/svg}svg"

    def test_has_viewbox(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report(n_resources=5)
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        assert "viewBox" in root.attrib

    def test_zones_rendered(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report(n_resources=5)
        svg = format_diagram(report, graph)
        all_zones = [
            TrustZone.INTERNET, TrustZone.DMZ, TrustZone.PRIVATE,
            TrustZone.DATA, TrustZone.MANAGEMENT,
        ]
        for zone in all_zones:
            assert f'class="zone-{zone.value}"' in svg

    def test_nodes_rendered(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report(n_resources=5)
        svg = format_diagram(report, graph)
        for node in SAMPLE_NODES:
            assert f'data-id="{node.id}"' in svg

    def test_node_shapes_by_stride(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)

        # process node (serverless) → rounded rect with rx="6"
        assert 'rx="6"' in svg

        # data_store (storage) → ellipse elements (cylinder)
        assert "<ellipse" in svg

        # data_flow (network) → polygon (diamond)
        assert "<polygon" in svg

        # entity (IAM) → double border: two rects in one node group
        # The entity node has an inner rect offset by 3px
        root = ElementTree.fromstring(svg)
        entity_groups = [
            g for g in root.iter("{http://www.w3.org/2000/svg}g")
            if g.get("data-id") == "aws_iam_role.exec"
        ]
        assert len(entity_groups) == 1
        rects = entity_groups[0].findall("{http://www.w3.org/2000/svg}rect")
        assert len(rects) == 2  # outer + inner border

    def test_edges_rendered(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        paths = [
            p for p in root.iter("{http://www.w3.org/2000/svg}path")
            if p.get("class") == "edge"
        ]
        assert len(paths) == len(SAMPLE_EDGES)

    def test_boundary_crossing_highlighted(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        boundary_paths = [
            p for p in root.iter("{http://www.w3.org/2000/svg}path")
            if p.get("data-boundary") == "true"
        ]
        assert len(boundary_paths) == 2
        for p in boundary_paths:
            assert p.get("stroke") == "#ef4444"

    def test_threat_badges(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [
            _make_threat("aws_s3_bucket.data", "critical"),
            _make_threat("aws_s3_bucket.data", "high"),
            _make_threat("aws_lb.alb", "medium"),
        ]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)

        # S3 node should have badge with count 2
        root = ElementTree.fromstring(svg)
        s3_group = [
            g for g in root.iter("{http://www.w3.org/2000/svg}g")
            if g.get("data-id") == "aws_s3_bucket.data"
        ]
        assert len(s3_group) == 1
        circles = s3_group[0].findall("{http://www.w3.org/2000/svg}circle")
        assert len(circles) == 1
        # Critical color (worst of 2 threats)
        assert circles[0].get("fill") == "#ef4444"

    def test_header_metadata(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [_make_threat("aws_s3_bucket.data")]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert "5 resources" in svg
        assert "1 threats" in svg

    def test_legend_present(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert 'class="legend"' in svg
        assert "data_flow" in svg
        assert "process" in svg
        assert "data_store" in svg
        assert "entity" in svg
        assert "critical" in svg

    def test_empty_graph(self) -> None:
        graph = _make_graph_with_nodes([])
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        assert root.tag == "{http://www.w3.org/2000/svg}svg"

    def test_multi_service_fixture(self) -> None:
        """22-node fixture renders all nodes."""
        from pathlib import Path

        fixture_path = (
            Path(__file__).parent.parent
            / "fixtures" / "terraform" / "multi_service_insecure.plan.json"
        )
        if not fixture_path.exists():
            pytest.skip("multi_service_insecure fixture not available")

        from threatcode.parsers import detect_and_parse

        parsed = detect_and_parse(str(fixture_path))
        graph = InfraGraph.from_parsed(parsed)
        engine = HybridEngine()
        report = engine.analyze(graph, input_file=str(fixture_path))

        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        assert root.tag == "{http://www.w3.org/2000/svg}svg"

        # All nodes rendered
        node_groups = [
            g for g in root.iter("{http://www.w3.org/2000/svg}g")
            if g.get("class") == "node"
        ]
        assert len(node_groups) == graph.node_count
