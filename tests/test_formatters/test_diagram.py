"""Tests for SVG diagram formatter."""

from __future__ import annotations

import xml.etree.ElementTree as ElementTree

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.formatters.diagram import (
    LEGEND_H,
    NODE_W,
    SUMMARY_BAR_H,
    THREAT_TABLE_HEADER_H,
    THREAT_TABLE_ROW_H,
    format_diagram,
)
from threatcode.ir.edges import EdgeType, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

NS = "{http://www.w3.org/2000/svg}"

# -- Helpers ------------------------------------------------------------------


def _make_graph_with_nodes(
    nodes: list[InfraNode],
    edges: list[InfraEdge] | None = None,
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


def _make_threat(
    resource_address: str,
    severity: str = "high",
    title: str = "Test threat",
    stride_category: str = "spoofing",
    source: ThreatSource = ThreatSource.RULE,
) -> Threat:
    return Threat(
        id=f"T-{resource_address}",
        title=title,
        description="Test description",
        stride_category=stride_category,
        severity=Severity(severity),
        source=source,
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


# -- Tests --------------------------------------------------------------------


class TestDiagramFormatter:
    def test_svg_is_valid_xml(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report(n_resources=5)
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        assert root.tag == f"{NS}svg"

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
            TrustZone.INTERNET,
            TrustZone.DMZ,
            TrustZone.PRIVATE,
            TrustZone.DATA,
            TrustZone.MANAGEMENT,
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

        # process node (serverless) -> rounded rect with rx="6"
        assert 'rx="6"' in svg

        # data_store (storage) -> ellipse elements (cylinder)
        assert "<ellipse" in svg

        # data_flow (network) -> polygon (diamond)
        assert "<polygon" in svg

        # entity (IAM) -> double border: two rects in one node group
        root = ElementTree.fromstring(svg)
        entity_groups = [g for g in root.iter(f"{NS}g") if g.get("data-id") == "aws_iam_role.exec"]
        assert len(entity_groups) == 1
        rects = entity_groups[0].findall(f"{NS}rect")
        assert len(rects) == 2  # outer + inner border

    def test_edges_rendered(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        paths = [p for p in root.iter(f"{NS}path") if p.get("class") == "edge"]
        assert len(paths) == len(SAMPLE_EDGES)

    def test_boundary_crossing_highlighted(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        boundary_paths = [p for p in root.iter(f"{NS}path") if p.get("data-boundary") == "true"]
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

        root = ElementTree.fromstring(svg)
        s3_group = [g for g in root.iter(f"{NS}g") if g.get("data-id") == "aws_s3_bucket.data"]
        assert len(s3_group) == 1
        circles = s3_group[0].findall(f"{NS}circle")
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
        assert "Generated by ThreatCode" in svg

    def test_empty_graph(self) -> None:
        graph = _make_graph_with_nodes([])
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        assert root.tag == f"{NS}svg"

    def test_multi_service_fixture(self) -> None:
        """22-node fixture renders all nodes."""
        from pathlib import Path

        fixture_path = (
            Path(__file__).parent.parent
            / "fixtures"
            / "terraform"
            / "multi_service_insecure.plan.json"
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
        assert root.tag == f"{NS}svg"

        node_groups = [g for g in root.iter(f"{NS}g") if g.get("class") == "node"]
        assert len(node_groups) == graph.node_count


class TestNodeTooltips:
    def test_node_has_title_element(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        node_groups = [g for g in root.iter(f"{NS}g") if g.get("class") == "node"]
        for ng in node_groups:
            titles = ng.findall(f"{NS}title")
            assert len(titles) == 1, f"Node {ng.get('data-id')} missing <title>"

    def test_tooltip_contains_node_id(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES[:1])  # just igw
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        ng = [g for g in root.iter(f"{NS}g") if g.get("data-id") == "aws_internet_gateway.igw"][0]
        title_text = ng.find(f"{NS}title").text
        assert "aws_internet_gateway.igw" in title_text

    def test_tooltip_contains_threat_details(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [
            _make_threat("aws_s3_bucket.data", "critical", "S3 public access"),
        ]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        s3_group = [g for g in root.iter(f"{NS}g") if g.get("data-id") == "aws_s3_bucket.data"][0]
        title_text = s3_group.find(f"{NS}title").text
        assert "1 threats:" in title_text
        assert "S3 public access" in title_text
        assert "CRITICAL" in title_text


class TestNodeLabels:
    def test_resource_type_displayed(self) -> None:
        """Node shows resource type (e.g., aws_s3_bucket) not category label."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        # Resource types should appear in the SVG as the top label
        assert "aws_s3_bucket" in svg
        assert "aws_lambda_function" in svg
        assert "aws_iam_role" in svg

    def test_short_name_displayed(self) -> None:
        """Node shows short name (last segment) prominently."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        for node in SAMPLE_NODES:
            short = node.id.rsplit(".", 1)[-1]
            assert short in svg

    def test_wider_nodes(self) -> None:
        """Nodes use NODE_W=160 (wider than old 130)."""
        assert NODE_W == 160


class TestEdgeLabels:
    def test_boundary_edges_have_labels(self) -> None:
        """Boundary-crossing edges show zone transition labels."""
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert 'class="edge-label"' in svg
        assert "INTERNET" in svg
        assert "DMZ" in svg

    def test_non_boundary_edges_no_labels(self) -> None:
        """Non-boundary edges should not have edge labels."""
        nodes = SAMPLE_NODES[:2]  # igw + alb
        edges = [
            InfraEdge(
                source="aws_internet_gateway.igw",
                target="aws_lb.alb",
                edge_type=EdgeType.DEPENDENCY,
            ),
        ]
        graph = _make_graph_with_nodes(nodes, edges)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert 'class="edge-label"' not in svg


class TestEdgeTooltips:
    def test_edge_groups_have_title(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        edge_groups = [g for g in root.iter(f"{NS}g") if g.get("class") == "edge-group"]
        assert len(edge_groups) == len(SAMPLE_EDGES)
        for eg in edge_groups:
            titles = eg.findall(f"{NS}title")
            assert len(titles) == 1

    def test_boundary_tooltip_text(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "Trust boundary crossing" in svg


class TestSummaryBar:
    def test_summary_bar_present(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert 'class="summary-bar"' in svg

    def test_summary_bar_shows_counts(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [
            _make_threat("aws_s3_bucket.data", "critical"),
            _make_threat("aws_s3_bucket.data", "high"),
            _make_threat("aws_lb.alb", "medium"),
        ]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert "1 Critical" in svg
        assert "1 High" in svg
        assert "1 Medium" in svg
        assert "Total: 3 threats" in svg

    def test_summary_bar_height_constant(self) -> None:
        assert SUMMARY_BAR_H == 32


class TestThreatTable:
    def test_threat_table_present_with_threats(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [_make_threat("aws_s3_bucket.data", "critical", "Public access")]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert 'class="threat-table"' in svg
        assert "Threat Findings" in svg

    def test_threat_table_absent_without_threats(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert 'class="threat-table"' not in svg

    def test_threat_table_contains_all_threats(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [
            _make_threat("aws_s3_bucket.data", "critical", "Public access"),
            _make_threat("aws_lb.alb", "high", "No WAF"),
            _make_threat("aws_lambda_function.api", "medium", "No auth"),
        ]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert "Public access" in svg
        assert "No WAF" in svg
        assert "No auth" in svg

    def test_threat_table_header_row(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [_make_threat("aws_s3_bucket.data")]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert "Severity" in svg
        assert "Resource" in svg
        assert "STRIDE Category" in svg
        assert "Source" in svg

    def test_threat_table_sorted_by_severity(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [
            _make_threat("aws_lb.alb", "low", "Low sev issue"),
            _make_threat("aws_s3_bucket.data", "critical", "Critical sev issue"),
            _make_threat("aws_lambda_function.api", "high", "High sev issue"),
        ]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        # Find positions within the threat-table section only
        table_start = svg.index('class="threat-table"')
        table_svg = svg[table_start:]
        crit_pos = table_svg.index("Critical sev issue")
        high_pos = table_svg.index("High sev issue")
        low_pos = table_svg.index("Low sev issue")
        assert crit_pos < high_pos < low_pos

    def test_threat_table_row_constants(self) -> None:
        assert THREAT_TABLE_ROW_H == 20
        assert THREAT_TABLE_HEADER_H == 28


class TestLegendOverhaul:
    def test_legend_has_node_shapes_section(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "Node Shapes" in svg
        assert "Process" in svg
        assert "Data Store" in svg
        assert "Data Flow" in svg
        assert "External Entity" in svg

    def test_legend_has_edge_types_section(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "Edge Types" in svg
        assert "Dependency" in svg
        assert "Containment" in svg
        assert "Network Flow" in svg
        assert "IAM Binding" in svg
        assert "Trust Boundary Crossing" in svg

    def test_legend_has_severity_badges_section(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "Severity Badges" in svg
        assert "Badge number = threat count on resource" in svg

    def test_legend_uses_mini_svg_shapes(self) -> None:
        """Legend contains actual SVG shape elements, not Unicode chars."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        root = ElementTree.fromstring(svg)
        legend = [g for g in root.iter(f"{NS}g") if g.get("class") == "legend"][0]
        # Should have actual shape elements in legend
        assert legend.findall(f".//{NS}rect")  # for process + entity shapes
        assert legend.findall(f".//{NS}ellipse")  # for data store shape
        assert legend.findall(f".//{NS}polygon")  # for data flow shape
        assert legend.findall(f".//{NS}line")  # for edge line samples

    def test_legend_height_constant(self) -> None:
        assert LEGEND_H == 140

    def test_no_unicode_box_chars(self) -> None:
        """Legend should NOT contain old Unicode box-drawing characters."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        # Old Unicode chars that were in the original legend
        assert "\u256d\u256e" not in svg  # ╭╮
        assert "\u2503\u2503" not in svg  # ┃┃
        assert "\u250c\u2510" not in svg  # ┌┐


class TestCSSStyles:
    def test_style_element_present(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "<style>" in svg
        assert "</style>" in svg

    def test_hover_rules_present(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert ".node:hover" in svg
        assert ".edge:hover" in svg
        assert ".threat-row:hover" in svg
        assert "cursor: pointer" in svg
