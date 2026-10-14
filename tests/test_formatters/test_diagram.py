"""Tests for SVG diagram formatter."""

from __future__ import annotations

import json
import re
import time
import xml.etree.ElementTree as ElementTree
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from threatcode.engine.hybrid import HybridEngine
from threatcode.formatters.diagram import (
    ATTACK_PATH_MAX_PATHS,
    CROSSING_WIDTH,
    EDGE_STYLES,
    LEGEND_H,
    NODE_TYPE_FONT,
    NODE_TYPE_MAX_CHARS,
    NODE_W,
    SEVERITY_COLORS,
    SUMMARY_BAR_H,
    TABLE_DESCRIPTION_LINES,
    THREAT_TABLE_HEADER_H,
    THREAT_TABLE_ROW_H,
    format_diagram,
)
from threatcode.formatters.diagram_routing import Rect, polyline_to_path
from threatcode.ir.edges import EdgeType, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.models.attack_path import AttackHop, AttackPath
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
    graph._edges.extend(edges or [])
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

        # network plumbing -> a box with a dashed outline, never a diamond
        root = ElementTree.fromstring(svg)
        (alb,) = [g for g in root.iter(f"{NS}g") if g.get("data-id") == "aws_lb.alb"]
        assert not alb.findall(f"{NS}polygon")
        (outline,) = alb.findall(f"{NS}rect")
        assert outline.get("stroke-dasharray")

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

    def test_a_crossing_flow_keeps_the_look_of_its_type_and_gets_a_zone_label(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        svg = format_diagram(_make_report(), graph)
        root = ElementTree.fromstring(svg)
        crossing = [p for p in root.iter(f"{NS}path") if p.get("data-boundary") == "true"]
        assert sorted(p.get("data-type") or "" for p in crossing) == ["data_flow", "network_flow"]
        for p in crossing:
            color, _, _ = EDGE_STYLES[EdgeType(p.get("data-type"))]
            assert p.get("stroke") == color
            assert p.get("stroke-width") == CROSSING_WIDTH
            assert p.get("filter") is None
        assert sorted(re.findall(r'class="edge-label">(.*?)</text>', svg)) == [
            "INTERNET \u2192 DMZ",
            "PRIVATE \u2192 DATA",
        ]

    def test_a_reference_that_spans_two_zones_is_not_a_crossing(self) -> None:
        """FV-09: a Terraform reference is wiring, not traffic across a trust boundary."""
        nodes = SAMPLE_NODES[:2]
        edges = [
            InfraEdge(
                source="aws_internet_gateway.igw",
                target="aws_lb.alb",
                edge_type=edge_type,
                metadata={
                    "crosses_trust_boundary": True,
                    "source_zone": "internet",
                    "target_zone": "dmz",
                },
            )
            for edge_type in (EdgeType.DEPENDENCY, EdgeType.IAM_BINDING)
        ]
        svg = format_diagram(_make_report(), _make_graph_with_nodes(nodes, edges))
        root = ElementTree.fromstring(svg)
        assert not [p for p in root.iter(f"{NS}path") if p.get("data-boundary") == "true"]
        assert 'class="edge-label"' not in svg

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
        assert circles[0].get("fill") == SEVERITY_COLORS["critical"]

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
        assert len(node_groups) == len(graph.nodes)


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
        """Nodes are wide enough for the longest type caption at the caption's font size."""
        assert NODE_W == 176
        assert NODE_TYPE_MAX_CHARS * NODE_TYPE_FONT * 0.55 <= NODE_W - 12


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
        assert "Description" in svg
        assert "CK Technique" in svg  # ATT&CK rendered as ATT&amp;CK
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
        assert "Data store" in svg
        assert "Network (network, cdn, dns, messaging)" in svg
        assert "External entity" in svg

    def test_legend_has_edge_types_section(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "Edge Types" in svg
        assert "Dependency" in svg
        assert "Container (nested frame)" in svg
        assert "Network flow" in svg
        assert "IAM binding" in svg
        assert "Attack path hop" in svg
        assert "Attack path number" in svg
        assert "Trust boundary crossing (flow)" in svg

    def test_legend_has_severity_badges_section(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert "Severity Badges" in svg
        assert "Badge number = threat count" in svg

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
        assert legend.findall(f".//{NS}polygon")  # for the arrow heads
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

    def test_attack_path_marker_css(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report()
        svg = format_diagram(report, graph)
        assert ".attack-path-marker" in svg


# -- Attack path fixtures -----------------------------------------------------

# A chain of directed hops over the sample graph: igw -> alb -> api -> data
_CHAIN = [
    "aws_internet_gateway.igw",
    "aws_lb.alb",
    "aws_lambda_function.api",
    "aws_s3_bucket.data",
]


def _chain_path(
    node_ids: list[str] = _CHAIN,
    severity: Severity = Severity.HIGH,
    enabled_by: dict[str, list[str]] | None = None,
) -> AttackPath:
    hops = []
    for i, node_id in enumerate(node_ids):
        last = i == len(node_ids) - 1
        hops.append(
            AttackHop(
                node_id=node_id,
                edge_type_to_next=None if last else "network_flow",
                via={} if last else {"ports": [443]},
                enabled_by=(enabled_by or {}).get(node_id, []),
            )
        )
    return AttackPath(
        id="p-" + "-".join(node_ids)[:20],
        entry=node_ids[0],
        target=node_ids[-1],
        hops=hops,
        severity=severity,
        score=7.5,
        rationale="Internet reaches the bucket through the load balancer",
    )


def _paths_svg(
    paths: list[AttackPath],
    threats: list[Threat] | None = None,
    nodes: list[InfraNode] | None = None,
    edges: list[InfraEdge] | None = None,
) -> str:
    graph = _make_graph_with_nodes(nodes or SAMPLE_NODES, edges or SAMPLE_EDGES)
    report = _make_report(threats=threats, n_resources=5)
    report.attack_paths = paths
    return format_diagram(report, graph)


def _groups(svg: str, css_class: str) -> list[ElementTree.Element]:
    root = ElementTree.fromstring(svg)
    return [g for g in root.iter(f"{NS}g") if g.get("class") == css_class]


class TestAttackPaths:
    def test_paths_drawn_hop_by_hop_in_order(self) -> None:
        svg = _paths_svg([_chain_path()])
        (group,) = _groups(svg, "attack-path")
        boxes = [r for r in group.iter(f"{NS}rect")]
        assert len(boxes) == len(_CHAIN)
        xs = [float(r.get("x", 0)) for r in boxes]
        assert xs == sorted(xs)
        text = " ".join("".join(t.itertext()) for t in group.iter(f"{NS}text"))
        positions = [text.index(name) for name in ("igw", "alb", "api", "data")]
        assert positions == sorted(positions)

    def test_arrows_and_markers_follow_path_severity(self) -> None:
        svg = _paths_svg([_chain_path(severity=Severity.CRITICAL)])
        (group,) = _groups(svg, "attack-path")
        lines = list(group.iter(f"{NS}line"))
        assert len(lines) == len(_CHAIN) - 1
        for line in lines:
            assert line.get("stroke") == SEVERITY_COLORS["critical"]
            assert "arrow-path-critical" in (line.get("marker-end") or "")
        root = ElementTree.fromstring(svg)
        marker_ids = {m.get("id") or "" for m in root.iter(f"{NS}marker")}
        assert any(m.endswith("arrow-path-critical") for m in marker_ids)
        assert any(m.endswith("arrow-path-low") for m in marker_ids)

    def test_each_severity_has_its_own_arrow_colour(self) -> None:
        svg = _paths_svg(
            [_chain_path(severity=Severity.LOW), _chain_path(_CHAIN[:3], Severity.HIGH)]
        )
        groups = _groups(svg, "attack-path")
        colours = {g.get("data-severity"): next(g.iter(f"{NS}line")).get("stroke") for g in groups}
        assert colours == {"low": SEVERITY_COLORS["low"], "high": SEVERITY_COLORS["high"]}

    def test_edge_labels_use_hop_edge_type_and_ports(self) -> None:
        svg = _paths_svg([_chain_path()])
        (group,) = _groups(svg, "attack-path")
        text = " ".join("".join(t.itertext()) for t in group.iter(f"{NS}text"))
        assert "HTTPS 443" in text
        assert "network_flow" not in text

    def test_edge_markers_only_on_directed_hops(self) -> None:
        """The path marks the connector that points along its hops."""
        svg = _paths_svg([_chain_path()])
        assert 'class="attack-path-marker"' in svg

    def test_reverse_connector_is_not_marked(self) -> None:
        """A hop a -> b does not light up a graph that only has b -> a: it draws its own."""
        reverse = [
            InfraEdge(
                source="aws_lb.alb",
                target="aws_internet_gateway.igw",
                edge_type=EdgeType.NETWORK_FLOW,
            ),
        ]
        path = _chain_path(["aws_internet_gateway.igw", "aws_lb.alb"])
        svg = _paths_svg([path], edges=reverse)
        root = ElementTree.fromstring(svg)
        tips = {
            (g.find(f"{NS}title").text or "").splitlines()[0]: g.find(f"{NS}path")  # type: ignore[union-attr]
            for g in root.iter(f"{NS}g")
            if g.get("class") == "edge-group"
        }
        hop = tips["aws_internet_gateway.igw \u2192 aws_lb.alb"]
        back = tips["aws_lb.alb \u2192 aws_internet_gateway.igw"]
        assert hop is not None and hop.get("data-path") == "1"
        assert back is not None and back.get("data-path") is None
        # The path section still names both nodes
        assert len(_groups(svg, "attack-path")) == 1

    def test_caption_names_the_enabling_finding(self) -> None:
        threat = _make_threat("aws_lb.alb", "high", "No WAF protection")
        threat.id = "T-waf"
        path = _chain_path(enabled_by={"aws_lb.alb": ["T-waf"]})
        svg = _paths_svg([path], threats=[threat])
        (group,) = _groups(svg, "attack-path")
        text = " ".join("".join(t.itertext()) for t in group.iter(f"{NS}text"))
        assert "No WAF protection" in text

    def test_caption_font_is_readable_and_not_cut_at_18_characters(self) -> None:
        long_title = "Trust boundary crossing without any encryption"
        threat = _make_threat("aws_lb.alb", "high", long_title)
        threat.id = "T-long"
        path = _chain_path(enabled_by={"aws_lb.alb": ["T-long"]})
        svg = _paths_svg([path], threats=[threat])
        (group,) = _groups(svg, "attack-path")
        sizes = [float(t.get("font-size", "0")) for t in group.iter(f"{NS}text")]
        assert min(sizes) >= 9
        text = " ".join("".join(t.itertext()) for t in group.iter(f"{NS}text"))
        assert "Trust boundary crossing" in text

    def test_blocks_are_spaced(self) -> None:
        svg = _paths_svg([_chain_path(), _chain_path(_CHAIN[:3], Severity.MEDIUM)])
        first, second = _groups(svg, "attack-path")
        y1 = float(next(first.iter(f"{NS}rect")).get("y", 0))
        y2 = float(next(second.iter(f"{NS}rect")).get("y", 0))
        assert y2 - y1 >= 80

    def test_no_paths_shows_a_note_and_no_path(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)
        svg = format_diagram(_make_report(), graph)
        assert "No attack paths found" in svg
        assert _groups(svg, "attack-path") == []
        assert 'class="attack-path-marker"' not in svg

    def test_hub_without_paths_draws_no_invented_path(self) -> None:
        """Two subnets joined only by a VPC that contains them yield the note, not a path."""
        nodes = [
            InfraNode("aws_vpc.hub", "aws_vpc", "hub", NodeCategory.NETWORK, TrustZone.PRIVATE),
            InfraNode("aws_lb.alb", "aws_lb", "alb", NodeCategory.NETWORK, TrustZone.DMZ),
            InfraNode("aws_subnet.pub", "aws_subnet", "pub", NodeCategory.NETWORK, TrustZone.DMZ),
            InfraNode(
                "aws_subnet.priv", "aws_subnet", "priv", NodeCategory.NETWORK, TrustZone.PRIVATE
            ),
            InfraNode(
                "aws_rds_cluster.db", "aws_rds_cluster", "db", NodeCategory.DATABASE, TrustZone.DATA
            ),
        ]
        containment = [
            InfraEdge("aws_subnet.pub", "aws_vpc.hub", EdgeType.CONTAINMENT),
            InfraEdge("aws_subnet.priv", "aws_vpc.hub", EdgeType.CONTAINMENT),
            InfraEdge("aws_lb.alb", "aws_subnet.pub", EdgeType.CONTAINMENT),
            InfraEdge("aws_rds_cluster.db", "aws_subnet.priv", EdgeType.CONTAINMENT),
        ]
        threats = [_make_threat(n.id) for n in nodes]
        graph = _make_graph_with_nodes(nodes, containment)
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert "No attack paths found" in svg
        assert _groups(svg, "attack-path") == []

    def test_only_report_paths_are_drawn(self) -> None:
        """The drawn paths are exactly the report's, in the report's order."""
        paths = [_chain_path(severity=Severity.HIGH), _chain_path(_CHAIN[:2], Severity.LOW)]
        svg = _paths_svg(paths)
        groups = _groups(svg, "attack-path")
        assert [g.get("data-severity") for g in groups] == ["high", "low"]

    def test_max_limit_with_overflow_note(self) -> None:
        assert ATTACK_PATH_MAX_PATHS == 5
        paths = [_chain_path(_CHAIN[: 2 + i % 2], Severity.MEDIUM) for i in range(7)]
        for i, path in enumerate(paths):
            path.id = f"p{i}"
        svg = _paths_svg(paths)
        assert len(_groups(svg, "attack-path")) == ATTACK_PATH_MAX_PATHS
        assert "2 more attack paths not shown" in svg

    def test_attack_paths_valid_xml(self) -> None:
        svg = _paths_svg([_chain_path()])
        assert ElementTree.fromstring(svg).tag == f"{NS}svg"

    def test_canvas_widens_for_a_long_path(self) -> None:
        ids = [f"aws_instance.n{i}" for i in range(9)]
        nodes = [
            InfraNode(i, "aws_instance", i.split(".")[1], NodeCategory.COMPUTE, TrustZone.PRIVATE)
            for i in ids
        ]
        svg = _paths_svg([_chain_path(ids)], nodes=nodes, edges=[])
        root = ElementTree.fromstring(svg)
        width = float(root.get("viewBox", "").split()[2])
        assert width >= 9 * 120 + 8 * 84


class TestNoPrivateGraphAccess:
    def test_renderer_never_reads_the_private_graph(self) -> None:
        source = Path(__file__).parent.parent.parent / "src/threatcode/formatters/diagram.py"
        assert "._graph" not in source.read_text(encoding="utf-8")

    def test_renderer_has_no_path_search(self) -> None:
        source = Path(__file__).parent.parent.parent / "src/threatcode/formatters/diagram.py"
        text = source.read_text(encoding="utf-8")
        assert "shortest_path" not in text
        assert "networkx" not in text


class TestExpandedThreatTable:
    def test_description_column_present(self) -> None:
        """Threat table includes the Description column."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [_make_threat("aws_s3_bucket.data", "critical", "Public access")]
        report = _make_report(threats=threats, n_resources=5)
        svg = format_diagram(report, graph)
        assert "Description" in svg
        assert 'class="threat-desc"' in svg

    def test_long_description_wraps_and_cuts_only_the_last_line(self) -> None:
        """A long description wraps onto lines; only an overflowing last line gets an ellipsis."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        long_desc = " ".join(f"word{i}" for i in range(120))
        threat = Threat(
            id="T-long",
            title="Long desc threat",
            description=long_desc,
            stride_category="spoofing",
            severity=Severity("high"),
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket.data",
        )
        svg = format_diagram(_make_report(threats=[threat], n_resources=5), graph)
        root = ElementTree.fromstring(svg)
        (cell,) = [t for t in root.iter(f"{NS}text") if t.get("class") == "threat-desc"]
        lines = [ts.text or "" for ts in cell.iter(f"{NS}tspan")]
        assert 2 <= len(lines) <= TABLE_DESCRIPTION_LINES
        assert lines[-1].endswith("...")
        assert not any(line.endswith("...") for line in lines[:-1])
        assert lines[0].startswith("word0 word1")
        # The full text stays available in the row tooltip
        assert long_desc in svg

    def test_mitre_technique_with_name(self) -> None:
        """ATT&CK column shows technique ID and name for known techniques."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threat = Threat(
            id="T-mitre",
            title="S3 data exposure",
            description="Data exposed",
            stride_category="information_disclosure",
            severity=Severity("critical"),
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket.data",
            mitre_techniques=["T1530"],
        )
        report = _make_report(threats=[threat], n_resources=5)
        svg = format_diagram(report, graph)
        assert "T1530" in svg
        # The technique name wraps instead of being cut
        assert "Data from Cloud Storage" in _row_texts(svg)[0][4]

    def test_unknown_mitre_id_fallback(self) -> None:
        """Unknown technique IDs are shown as-is without a name."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threat = Threat(
            id="T-unknown-mitre",
            title="Unknown technique",
            description="desc",
            stride_category="spoofing",
            severity=Severity("high"),
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket.data",
            mitre_techniques=["T9999"],
        )
        report = _make_report(threats=[threat], n_resources=5)
        svg = format_diagram(report, graph)
        assert "T9999" in svg

    def test_empty_techniques_dash(self) -> None:
        """Threats with no MITRE techniques show a dash."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threat = _make_threat("aws_s3_bucket.data", "high", "No MITRE")
        report = _make_report(threats=[threat], n_resources=5)
        svg = format_diagram(report, graph)
        # The threat-mitre cell should contain "-"
        assert 'class="threat-mitre"' in svg
        # Find the mitre cell content - it should be just "-"
        import re

        mitre_cells = re.findall(r'class="threat-mitre">(.*?)</text>', svg)
        assert any(cell == "-" for cell in mitre_cells)

    def test_mitigation_in_tooltip(self) -> None:
        """Row tooltip includes mitigation text when present."""
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threat = Threat(
            id="T-mit",
            title="Vuln",
            description="Vulnerable config",
            stride_category="tampering",
            severity=Severity("high"),
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket.data",
            mitigation="Enable encryption at rest",
        )
        report = _make_report(threats=[threat], n_resources=5)
        svg = format_diagram(report, graph)
        assert "Mitigation: Enable encryption at rest" in svg


def _row_texts(svg: str) -> list[list[str]]:
    """Text of each cell of each findings row; the lines of a wrapped cell joined by a space."""
    root = ElementTree.fromstring(svg)
    rows = []
    for group in root.iter(f"{NS}g"):
        if group.get("class") == "threat-row":
            rows.append([" ".join(t.itertext()).strip() for t in group.iter(f"{NS}text")])
    return rows


def _row_cells(svg: str) -> list[list[ElementTree.Element]]:
    root = ElementTree.fromstring(svg)
    return [
        list(group.iter(f"{NS}text"))
        for group in root.iter(f"{NS}g")
        if group.get("class") == "threat-row"
    ]


def _lines(cell: ElementTree.Element) -> list[str]:
    spans = list(cell.iter(f"{NS}tspan"))
    return [s.text or "" for s in spans] if spans else [cell.text or ""]


class TestThreatTableFit:
    """Cells in the findings table wrap instead of cutting the identifying part."""

    def _long_threat(self) -> Threat:
        return Threat(
            id="T-1",
            title="Trust boundary crossing: internet -> private network segment",
            description="word " * 80,
            stride_category="elevation_of_privilege",
            severity=Severity.MEDIUM,
            source=ThreatSource.RULE,
            resource_type="aws_s3_bucket",
            resource_address="aws_s3_bucket." + "x" * 80,
            mitre_techniques=["T1552.001", "T1195.002", "T1611"],
        )

    def test_text_fits_column_width(self) -> None:
        svg = format_diagram(
            _make_report([self._long_threat()], 1), _make_graph_with_nodes(SAMPLE_NODES[:1])
        )
        (cells,) = _row_cells(svg)
        assert (cells[0].text or "") == "MEDIUM"
        # Each line's rendered width (at a generous 0.55em per glyph) ends before the next column
        for cell, nxt in zip(cells, cells[1:], strict=False):
            font = float(cell.get("font-size", "9"))
            widest = max(len(line) for line in _lines(cell))
            assert float(cell.get("x", "0")) + widest * font * 0.55 < float(nxt.get("x", "0"))

    def test_title_target_zone_is_never_lost(self) -> None:
        svg = format_diagram(
            _make_report([self._long_threat()], 1), _make_graph_with_nodes(SAMPLE_NODES[:1])
        )
        title = _row_texts(svg)[0][2]
        assert "internet -> private network segment" in title
        assert "..." not in title

    def test_wrapped_row_is_taller_than_a_single_line_row(self) -> None:
        short = _make_threat("aws_s3_bucket.data", "high", "Short")
        graph = _make_graph_with_nodes(SAMPLE_NODES[:1])
        one = ElementTree.fromstring(format_diagram(_make_report([short], 1), graph))
        many = ElementTree.fromstring(format_diagram(_make_report([self._long_threat()], 1), graph))

        def row_height(root: ElementTree.Element) -> float:
            row = next(g for g in root.iter(f"{NS}g") if g.get("class") == "threat-row")
            return float(next(row.iter(f"{NS}rect")).get("height", "0"))

        assert row_height(one) == THREAT_TABLE_ROW_H
        assert row_height(many) > THREAT_TABLE_ROW_H

    def test_long_address_breaks_after_a_separator(self) -> None:
        threat = _make_threat("aws_s3_bucket.some_long_bucket_name_for_customer_exports")
        svg = format_diagram(_make_report([threat], 1), _make_graph_with_nodes(SAMPLE_NODES[:1]))
        (cells,) = _row_cells(svg)
        lines = _lines(cells[1])
        assert len(lines) >= 2
        assert "".join(lines).startswith("aws_s3_bucket.some_long")
        assert "...".join(lines) not in "".join(lines)

    def test_header_has_a_timestamp_at_minute_resolution(self) -> None:
        report = _make_report([], 3)
        report.timestamp = "2026-10-07T12:34:56.789012+00:00"
        svg = format_diagram(report, _make_graph_with_nodes(SAMPLE_NODES[:1]))
        assert "3 resources \u00b7 0 threats \u00b7 2026-10-07 12:34 UTC" in svg
        assert "12:34:56" not in svg

    def test_header_omits_an_empty_timestamp(self) -> None:
        report = _make_report([], 3)
        report.timestamp = ""
        svg = format_diagram(report, _make_graph_with_nodes(SAMPLE_NODES[:1]))
        assert ">3 resources \u00b7 0 threats</text>" in svg


class TestMaxRows:
    def _many(self, n: int) -> list[Threat]:
        return [_make_threat("aws_s3_bucket.data", "low", f"Finding number {i}") for i in range(n)]

    def test_default_caps_the_table_with_an_overflow_row(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        report = _make_report(self._many(660), 5)
        svg = format_diagram(report, graph)
        assert len(_row_texts(svg)) == 200
        assert "460 more threats not shown; see JSON/SARIF report" in svg
        assert len(svg) < 1_500_000

    def test_below_the_cap_has_no_overflow_row(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        svg = format_diagram(_make_report(self._many(30), 5), graph)
        assert len(_row_texts(svg)) == 30
        assert "more threats not shown" not in svg

    def test_max_rows_is_adjustable_and_header_still_counts_all(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        svg = format_diagram(_make_report(self._many(12), 5), graph, max_rows=5)
        assert len(_row_texts(svg)) == 5
        assert "7 more threats not shown" in svg
        assert "12 threats" in svg

    def test_the_rows_kept_are_the_most_severe(self) -> None:
        graph = _make_graph_with_nodes(SAMPLE_NODES)
        threats = [
            *self._many(5),
            _make_threat("aws_s3_bucket.data", "critical", "The critical one"),
        ]
        svg = format_diagram(_make_report(threats, 5), graph, max_rows=2)
        assert any("The critical one" in cells[2] for cells in _row_texts(svg))


# -- Edge routing and label placement -----------------------------------------

_FIXTURE_PATH = (
    Path(__file__).parent.parent / "fixtures" / "terraform" / "multi_service_insecure.plan.json"
)

Box = tuple[float, float, float, float]  # x0, y0, x1, y1


def _fixture_svg() -> str:
    from threatcode.parsers import detect_and_parse

    if not _FIXTURE_PATH.exists():
        pytest.skip("multi_service_insecure fixture not available")
    graph = InfraGraph.from_parsed(detect_and_parse(str(_FIXTURE_PATH)))
    report = HybridEngine().analyze(graph, input_file=str(_FIXTURE_PATH))
    return format_diagram(report, graph)


def _span(xs: list[float], ys: list[float]) -> Box:
    return (min(xs), min(ys), max(xs), max(ys))


def _node_boxes(root: ElementTree.Element, badges: bool = False) -> dict[str, Box]:
    """Bounding box of every node shape, or of its threat badge when ``badges``."""
    boxes: dict[str, Box] = {}
    for g in root.iter(f"{NS}g"):
        if g.get("class") != "node":
            continue
        xs: list[float] = []
        ys: list[float] = []
        for el in g:
            tag = el.tag.removeprefix(NS)
            if badges:
                if tag == "circle":
                    cx, cy, r = (float(el.get(a, 0)) for a in ("cx", "cy", "r"))
                    xs += [cx - r, cx + r]
                    ys += [cy - r, cy + r]
            elif tag == "rect":
                x, y = float(el.get("x", 0)), float(el.get("y", 0))
                xs += [x, x + float(el.get("width", 0))]
                ys += [y, y + float(el.get("height", 0))]
            elif tag == "ellipse":
                cx, cy, rx, ry = (float(el.get(a, 0)) for a in ("cx", "cy", "rx", "ry"))
                xs += [cx - rx, cx + rx]
                ys += [cy - ry, cy + ry]
            elif tag == "polygon":
                for pair in el.get("points", "").split():
                    px, py = pair.split(",")
                    xs.append(float(px))
                    ys.append(float(py))
        if xs:
            boxes[g.get("data-id", "")] = _span(xs, ys)
    return boxes


def _label_boxes(root: ElementTree.Element) -> list[Box]:
    boxes: list[Box] = []
    for r in root.iter(f"{NS}rect"):
        if r.get("class") == "edge-label-bg":
            x, y = float(r.get("x", 0)), float(r.get("y", 0))
            boxes.append((x, y, x + float(r.get("width", 0)), y + float(r.get("height", 0))))
    return boxes


def _boxes_overlap(a: Box, b: Box) -> bool:
    return a[0] < b[2] and b[0] < a[2] and a[1] < b[3] and b[1] < a[3]


def _path_points(d: str) -> list[tuple[float, float]]:
    """Every coordinate in an M/L/Q path, control points included (conservative)."""
    nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", d)]
    return list(zip(nums[0::2], nums[1::2], strict=True))


def _edge_node_crossings(svg: str) -> list[tuple[str, str]]:
    """(edge tooltip, node id) for each edge segment that enters an unrelated node."""
    root = ElementTree.fromstring(svg)
    node_rects = {
        node_id: Rect(x0, y0, x1 - x0, y1 - y0)
        for node_id, (x0, y0, x1, y1) in _node_boxes(root).items()
    }
    hits: list[tuple[str, str]] = []
    for g in root.iter(f"{NS}g"):
        if g.get("class") != "edge-group":
            continue
        path = g.find(f"{NS}path")
        title = g.find(f"{NS}title")
        assert path is not None and title is not None
        points = _path_points(path.get("d", ""))
        start, end = points[0], points[-1]
        for node_id, rect in node_rects.items():
            # Endpoints sit on their own node's outline; skip the edge's two nodes
            own = rect.expand(1)
            if Rect(start[0], start[1], 0, 0).intersects(own) or Rect(
                end[0], end[1], 0, 0
            ).intersects(own):
                continue
            if any(rect.intersects_segment(a, b) for a, b in zip(points, points[1:])):
                hits.append((title.text or "", node_id))
    return hits


# INTERNET -> PRIVATE flow whose straight line is blocked by two DMZ nodes
_SKIP_LANE_NODES = [
    InfraNode(
        id="aws_internet_gateway.igw",
        resource_type="aws_internet_gateway",
        name="igw",
        category=NodeCategory.NETWORK,
        trust_zone=TrustZone.INTERNET,
    ),
    InfraNode(
        id="aws_instance.web",
        resource_type="aws_instance",
        name="web",
        category=NodeCategory.COMPUTE,
        trust_zone=TrustZone.DMZ,
    ),
    InfraNode(
        id="aws_instance.bastion",
        resource_type="aws_instance",
        name="bastion",
        category=NodeCategory.COMPUTE,
        trust_zone=TrustZone.DMZ,
    ),
    InfraNode(
        id="aws_instance.app",
        resource_type="aws_instance",
        name="app",
        category=NodeCategory.COMPUTE,
        trust_zone=TrustZone.PRIVATE,
    ),
    InfraNode(
        id="aws_vpc.main",
        resource_type="aws_vpc",
        name="main",
        category=NodeCategory.NETWORK,
        trust_zone=TrustZone.PRIVATE,
    ),
]

_SKIP_LANE_EDGES = [
    InfraEdge(
        source="aws_internet_gateway.igw",
        target="aws_vpc.main",
        edge_type=edge_type,
        metadata={
            "crosses_trust_boundary": True,
            "source_zone": "internet",
            "target_zone": "private",
        },
    )
    for edge_type in (EdgeType.NETWORK_FLOW, EdgeType.DATA_FLOW)
]


def _skip_lane_svg() -> str:
    graph = _make_graph_with_nodes(_SKIP_LANE_NODES, _SKIP_LANE_EDGES)
    threats = [_make_threat(n.id) for n in _SKIP_LANE_NODES]
    return format_diagram(_make_report(threats=threats, n_resources=5), graph)


class TestEdgeLabelPlacement:
    @pytest.mark.parametrize("svg_factory", [_fixture_svg, _skip_lane_svg])
    def test_labels_do_not_intersect_nodes(self, svg_factory: Callable[[], str]) -> None:
        root = ElementTree.fromstring(svg_factory())
        labels = _label_boxes(root)
        assert labels
        nodes = _node_boxes(root)
        badges = _node_boxes(root, badges=True)
        assert badges
        for label in labels:
            for node_id, node in nodes.items():
                assert not _boxes_overlap(label, node), f"label {label} covers {node_id}"
            for node_id, badge in badges.items():
                assert not _boxes_overlap(label, badge), f"label {label} covers {node_id} badge"

    @pytest.mark.parametrize("svg_factory", [_fixture_svg, _skip_lane_svg])
    def test_labels_do_not_intersect_each_other(self, svg_factory: Callable[[], str]) -> None:
        labels = _label_boxes(ElementTree.fromstring(svg_factory()))
        for i, a in enumerate(labels):
            for b in labels[i + 1 :]:
                assert not _boxes_overlap(a, b)

    def test_labels_inside_canvas(self) -> None:
        root = ElementTree.fromstring(_fixture_svg())
        _, _, width, height = (float(v) for v in root.get("viewBox", "").split())
        for x0, y0, x1, y1 in _label_boxes(root):
            assert 0 <= x0 and x1 <= width and 0 <= y0 and y1 <= height

    def test_labels_drawn_above_nodes(self) -> None:
        """Labels render after every node so no node box can paint over them."""
        svg = _fixture_svg()
        assert svg.index('class="edge-overlays"') > svg.rindex('class="node"')

    def test_labels_have_opaque_background(self) -> None:
        root = ElementTree.fromstring(_fixture_svg())
        bgs = [r for r in root.iter(f"{NS}rect") if r.get("class") == "edge-label-bg"]
        assert bgs
        for bg in bgs:
            assert bg.get("fill") == "#ffffff"
            assert bg.get("opacity") is None

    def test_parallel_edges_share_one_label(self) -> None:
        """A network flow and a data flow between the same pair yield a single label."""
        svg = _fixture_svg()
        texts = re.findall(r'class="edge-label">(.*?)</text>', svg)
        # One label per transition, however many connectors cross it (FV-09)
        assert texts
        assert len({t.split(" x")[0] for t in texts}) == len(texts)

        root = ElementTree.fromstring(_skip_lane_svg())
        assert len(_label_boxes(root)) == 1
        # Both flows run between the same two nodes, so they are one connector
        paths = [p for p in root.iter(f"{NS}path") if p.get("class") == "edge"]
        assert len(paths) == 1


class TestEdgeRouting:
    @pytest.mark.parametrize("svg_factory", [_fixture_svg, _skip_lane_svg])
    def test_edges_avoid_unrelated_nodes(self, svg_factory: Callable[[], str]) -> None:
        assert _edge_node_crossings(svg_factory()) == []

    def test_straight_vertical_edge(self) -> None:
        """Nodes stacked in one column connect with a straight vertical line."""
        nodes = [SAMPLE_NODES[0], SAMPLE_NODES[1]]  # igw (INTERNET) above alb (DMZ)
        graph = _make_graph_with_nodes(nodes, [SAMPLE_EDGES[0]])
        root = ElementTree.fromstring(format_diagram(_make_report(), graph))
        path = next(p for p in root.iter(f"{NS}path") if p.get("class") == "edge")
        points = _path_points(path.get("d", ""))
        assert len({x for x, _ in points}) == 1

    def test_glow_filter_survives_straight_lines(self) -> None:
        """A bbox-relative filter region clips zero-height lines; use user space."""
        root = ElementTree.fromstring(_skip_lane_svg())
        glow = next(f for f in root.iter(f"{NS}filter") if (f.get("id") or "").endswith("-glow"))
        assert glow.get("filterUnits") == "userSpaceOnUse"

    def test_rect_segment_intersection(self) -> None:
        rect = Rect(10, 10, 20, 20)
        assert rect.intersects_segment((0, 20), (40, 20))
        assert rect.intersects_segment((15, 0), (15, 15))
        assert not rect.intersects_segment((0, 5), (40, 5))
        assert not rect.intersects_segment((10, 0), (10, 40))  # grazes the edge
        assert not rect.intersects_segment((0, 0), (5, 5))

    def test_polyline_rounded_corners(self) -> None:
        d = polyline_to_path([(0, 0), (0, 20), (30, 20)])
        assert d == "M0.0,0.0 L0.0,14.0 Q0.0,20.0 6.0,20.0 L30.0,20.0"


# -- Containment as nesting ---------------------------------------------------


def _node(
    node_id: str, zone: TrustZone, category: NodeCategory = NodeCategory.COMPUTE
) -> InfraNode:
    rtype = node_id.split(".")[0]
    return InfraNode(node_id, rtype, node_id.split(".")[1], category, zone)


def _vpc_graph() -> InfraGraph:
    """A VPC with two subnets, an instance in each and a database in the private subnet."""
    nodes = [
        _node("aws_vpc.main", TrustZone.PRIVATE, NodeCategory.NETWORK),
        _node("aws_subnet.pub", TrustZone.DMZ, NodeCategory.NETWORK),
        _node("aws_subnet.priv", TrustZone.PRIVATE, NodeCategory.NETWORK),
        _node("aws_instance.web", TrustZone.DMZ),
        _node("aws_instance.app", TrustZone.PRIVATE),
        _node("aws_db_instance.db", TrustZone.DATA, NodeCategory.DATABASE),
        _node("aws_internet_gateway.igw", TrustZone.INTERNET, NodeCategory.NETWORK),
    ]
    edges = [
        InfraEdge("aws_subnet.pub", "aws_vpc.main", EdgeType.CONTAINMENT),
        InfraEdge("aws_subnet.priv", "aws_vpc.main", EdgeType.CONTAINMENT),
        InfraEdge("aws_instance.web", "aws_subnet.pub", EdgeType.CONTAINMENT),
        InfraEdge("aws_instance.app", "aws_subnet.priv", EdgeType.CONTAINMENT),
        InfraEdge("aws_db_instance.db", "aws_subnet.priv", EdgeType.CONTAINMENT),
        InfraEdge("aws_internet_gateway.igw", "aws_vpc.main", EdgeType.CONTAINMENT),
        InfraEdge("aws_internet_gateway.igw", "aws_instance.web", EdgeType.NETWORK_FLOW),
        InfraEdge("aws_instance.web", "aws_instance.app", EdgeType.NETWORK_FLOW),
        InfraEdge("aws_instance.app", "aws_db_instance.db", EdgeType.DATA_FLOW),
    ]
    return _make_graph_with_nodes(nodes, edges)


def _frames(svg: str) -> dict[str, list[Rect]]:
    found: dict[str, list[Rect]] = {}
    root = ElementTree.fromstring(svg)
    for g in root.iter(f"{NS}g"):
        if g.get("class") != "frame":
            continue
        r = g.find(f"{NS}rect")
        assert r is not None
        found.setdefault(g.get("data-id", ""), []).append(
            Rect(*(float(r.get(a, 0)) for a in ("x", "y", "width", "height")))
        )
    return found


class TestContainmentFrames:
    def test_containers_become_labelled_frames(self) -> None:
        svg = format_diagram(_make_report(), _vpc_graph())
        frames = _frames(svg)
        assert set(frames) == {"aws_vpc.main", "aws_subnet.pub", "aws_subnet.priv"}
        root = ElementTree.fromstring(svg)
        labels = [g for g in root.iter(f"{NS}g") if g.get("class") == "frame-label"]
        assert len(labels) == sum(len(v) for v in frames.values())
        for g in labels:
            label = " ".join(t.text or "" for t in g.iter(f"{NS}text"))
            assert g.get("data-id") in label

    def test_no_containment_connectors(self) -> None:
        svg = format_diagram(_make_report(), _vpc_graph())
        root = ElementTree.fromstring(svg)
        types = [p.get("data-type") for p in root.iter(f"{NS}path") if p.get("class") == "edge"]
        assert "containment" not in types
        assert sorted(types) == ["data_flow", "network_flow", "network_flow"]

    def test_container_nodes_are_frames_not_boxes(self) -> None:
        svg = format_diagram(_make_report(), _vpc_graph())
        root = ElementTree.fromstring(svg)
        ids = {g.get("data-id") for g in root.iter(f"{NS}g") if g.get("class") == "node"}
        assert ids == {
            "aws_instance.web",
            "aws_instance.app",
            "aws_db_instance.db",
            "aws_internet_gateway.igw",
        }

    def test_frame_surrounds_its_members_and_nests(self) -> None:
        svg = format_diagram(_make_report(), _vpc_graph())
        frames = _frames(svg)
        root = ElementTree.fromstring(svg)
        boxes = _node_boxes(root)
        web = Rect(*_as_rect(boxes["aws_instance.web"]))
        app = Rect(*_as_rect(boxes["aws_instance.app"]))
        assert any(f.contains(web) for f in frames["aws_subnet.pub"])
        assert any(f.contains(app) for f in frames["aws_subnet.priv"])
        # The VPC frame encloses the subnet frames of the lane it shares
        pub_frame = frames["aws_subnet.pub"][0]
        assert any(f.contains(pub_frame) for f in frames["aws_vpc.main"])

    def test_frame_holds_no_stranger(self) -> None:
        svg = format_diagram(_make_report(), _vpc_graph())
        frames = _frames(svg)
        boxes = _node_boxes(ElementTree.fromstring(svg))
        members = {
            "aws_subnet.pub": {"aws_instance.web"},
            "aws_subnet.priv": {"aws_instance.app", "aws_db_instance.db"},
            "aws_vpc.main": {
                "aws_instance.web",
                "aws_instance.app",
                "aws_db_instance.db",
                "aws_internet_gateway.igw",
            },
        }
        for container, allowed in members.items():
            for node_id, box in boxes.items():
                inside = any(f.contains(Rect(*_as_rect(box))) for f in frames[container])
                assert inside == (node_id in allowed), (container, node_id)

    def test_container_threats_show_on_the_frame(self) -> None:
        threats = [_make_threat("aws_vpc.main", "medium", "VPC without flow logs")]
        svg = format_diagram(_make_report(threats, 7), _vpc_graph())
        root = ElementTree.fromstring(svg)
        frames = [
            g
            for g in root.iter(f"{NS}g")
            if g.get("class") == "frame" and g.get("data-id") == "aws_vpc.main"
        ]
        assert len(frames) >= 2
        for frame in frames:
            title = frame.find(f"{NS}title")
            assert title is not None and "VPC without flow logs" in (title.text or "")
        # One badge for the container, on its first frame only
        assert sum(len(f.findall(f"{NS}circle")) for f in frames) == 1

    def test_empty_container_stays_a_node(self) -> None:
        graph = _make_graph_with_nodes(
            [_node("aws_vpc.lonely", TrustZone.PRIVATE, NodeCategory.NETWORK)]
        )
        svg = format_diagram(_make_report(), graph)
        assert _frames(svg) == {}
        assert 'data-id="aws_vpc.lonely"' in svg

    def test_containment_cycle_does_not_hang(self) -> None:
        nodes = [
            _node("aws_vpc.a", TrustZone.PRIVATE, NodeCategory.NETWORK),
            _node("aws_subnet.b", TrustZone.PRIVATE, NodeCategory.NETWORK),
            _node("aws_instance.c", TrustZone.PRIVATE),
        ]
        edges = [
            InfraEdge("aws_subnet.b", "aws_vpc.a", EdgeType.CONTAINMENT),
            InfraEdge("aws_vpc.a", "aws_subnet.b", EdgeType.CONTAINMENT),
            InfraEdge("aws_instance.c", "aws_subnet.b", EdgeType.CONTAINMENT),
        ]
        svg = format_diagram(_make_report(), _make_graph_with_nodes(nodes, edges))
        assert ElementTree.fromstring(svg).tag == f"{NS}svg"

    def test_legend_shows_a_frame_sample(self) -> None:
        svg = format_diagram(_make_report(), _vpc_graph())
        assert "Container (nested frame)" in svg

    def test_realistic_plan_has_frames_and_valid_xml(self) -> None:
        from threatcode.parsers import detect_and_parse

        path = _REPO_ROOT / "tests/fixtures/realistic/01_aws_ecommerce_platform.json"
        graph = InfraGraph.from_parsed(detect_and_parse(str(path)))
        report = HybridEngine().analyze(graph, input_file=str(path))
        svg = format_diagram(report, graph)
        assert _frames(svg)
        root = ElementTree.fromstring(svg)
        types = [p.get("data-type") for p in root.iter(f"{NS}path") if p.get("class") == "edge"]
        assert "containment" not in types


def _as_rect(box: Box) -> tuple[float, float, float, float]:
    return (box[0], box[1], box[2] - box[0], box[3] - box[1])


class TestAnchorSpread:
    def _hub_svg(self, n: int = 8) -> str:
        nodes = [_node("aws_lb.hub", TrustZone.PRIVATE, NodeCategory.COMPUTE)]
        edges = []
        for i in range(n):
            src = _node(f"aws_instance.s{i}", TrustZone.DMZ)
            nodes.append(src)
            edges.append(InfraEdge(src.id, "aws_lb.hub", EdgeType.NETWORK_FLOW))
        return format_diagram(_make_report(), _make_graph_with_nodes(nodes, edges))

    def test_incoming_connectors_end_at_distinct_anchors(self) -> None:
        root = ElementTree.fromstring(self._hub_svg())
        ends = []
        for p in root.iter(f"{NS}path"):
            if p.get("class") == "edge":
                ends.append(_path_points(p.get("d", ""))[-1])
        assert len(ends) == 8
        assert len(set(ends)) == 8

    def test_arrowheads_do_not_stack(self) -> None:
        root = ElementTree.fromstring(self._hub_svg())
        ends = sorted(
            _path_points(p.get("d", ""))[-1]
            for p in root.iter(f"{NS}path")
            if p.get("class") == "edge"
        )
        # Arrowheads are 9 px wide: neighbours on one side are at least 8 px apart
        xs = [x for x, _ in ends]
        gaps = [b - a for a, b in zip(xs, xs[1:], strict=False) if b != a]
        assert min(gaps) >= 8

    def test_arrow_markers_have_a_fixed_size(self) -> None:
        root = ElementTree.fromstring(self._hub_svg())
        markers = list(root.iter(f"{NS}marker"))
        assert markers
        assert all(m.get("markerUnits") == "userSpaceOnUse" for m in markers)


# -- Dockerfile stages --------------------------------------------------------

_DOCKER_DIR = Path(__file__).parent.parent / "fixtures" / "docker"


def _docker_render(name: str, **kwargs: bool) -> tuple[str, InfraGraph]:
    from threatcode.parsers import detect_and_parse

    path = _DOCKER_DIR / name
    graph = InfraGraph.from_parsed(detect_and_parse(str(path)))
    report = HybridEngine().analyze(graph, input_file=str(path))
    return format_diagram(report, graph, **kwargs), graph  # type: ignore[arg-type]


def _node_ids(svg: str) -> list[str]:
    root = ElementTree.fromstring(svg)
    return [g.get("data-id", "") for g in root.iter(f"{NS}g") if g.get("class") == "node"]


class TestDockerStages:
    def test_large_stage_collapses_into_one_node(self) -> None:
        svg, graph = _docker_render("insecure.Dockerfile")
        ids = _node_ids(svg)
        assert graph.node_count >= 16
        assert len(ids) < 5
        assert "dockerfile.stage.0" in ids
        assert not any(i.startswith("dockerfile.run.") for i in ids)

    def test_stage_tooltip_carries_instruction_findings(self) -> None:
        svg, graph = _docker_render("insecure.Dockerfile")
        report_threats = [
            t
            for t in HybridEngine().analyze(graph, input_file="x").threats
            if re.fullmatch(r"dockerfile\.[a-z]+\.\d+", t.resource_address)
        ]
        assert report_threats
        root = ElementTree.fromstring(svg)
        stage = next(
            g
            for g in root.iter(f"{NS}g")
            if g.get("class") == "node" and g.get("data-id") == "dockerfile.stage.0"
        )
        tooltip = stage.find(f"{NS}title").text or ""  # type: ignore[union-attr]
        assert "instructions folded into this stage" in tooltip
        assert any(t.title in tooltip for t in report_threats)
        # The badge counts the folded findings
        count = int(stage.findall(f"{NS}text")[-1].text or "0")
        assert count >= len(report_threats)

    def test_expand_option_draws_every_instruction(self) -> None:
        svg, graph = _docker_render("insecure.Dockerfile", expand_docker=True)
        ids = _node_ids(svg)
        assert "dockerfile.run.3" in ids
        assert len(ids) == graph.node_count - 1  # the stage is a frame around its instructions
        assert "dockerfile.stage.0" in _frames(svg)

    def test_small_stage_stays_expanded_and_big_one_collapses(self) -> None:
        svg, _ = _docker_render("multistage.Dockerfile")
        ids = _node_ids(svg)
        # builder has 6 instructions (not more than 6): a frame around its instructions
        assert "dockerfile.run.3" in ids
        assert "dockerfile.stage.builder" in _frames(svg)
        # the final stage has 8: one node
        assert "dockerfile.stage.1" in ids
        assert "dockerfile.user.12" not in ids

    def test_stage_to_stage_edge_is_drawn(self) -> None:
        svg, _ = _docker_render("multistage.Dockerfile")
        root = ElementTree.fromstring(svg)
        tips = [
            (g.find(f"{NS}title").text or "")  # type: ignore[union-attr]
            for g in root.iter(f"{NS}g")
            if g.get("class") == "edge-group"
        ]
        assert any("copy from" in t and "dockerfile.stage.1" in t for t in tips)

    def test_no_edge_is_lost_to_collapse(self) -> None:
        svg, _ = _docker_render("insecure.Dockerfile")
        root = ElementTree.fromstring(svg)
        for p in root.iter(f"{NS}path"):
            if p.get("class") == "edge":
                assert p.get("data-type") != "containment"
        assert ElementTree.fromstring(svg).tag == f"{NS}svg"


# -- Scale --------------------------------------------------------------------

_ZONES = [
    TrustZone.INTERNET,
    TrustZone.DMZ,
    TrustZone.PRIVATE,
    TrustZone.DATA,
    TrustZone.MANAGEMENT,
]


def _boundary_heavy_graph(total: int, types: int = 1) -> tuple[InfraGraph, list[Threat]]:
    """Every node crosses into the next zone twice, so every connector carries a label."""
    per = total // len(_ZONES)
    nodes = []
    for zi, zone in enumerate(_ZONES):
        for i in range(per):
            nodes.append(
                InfraNode(
                    f"res_{zi}.n{i}",
                    f"type_{i % types}",
                    f"n{i}",
                    NodeCategory.COMPUTE if i % 2 else NodeCategory.NETWORK,
                    zone,
                )
            )
    edges = []
    for zi in range(len(_ZONES) - 1):
        for i in range(per):
            for offset in (0, 7):
                edges.append(
                    InfraEdge(
                        f"res_{zi}.n{i}",
                        f"res_{zi + 1}.n{(i + offset) % per}",
                        EdgeType.NETWORK_FLOW,
                        metadata={
                            "crosses_trust_boundary": True,
                            "source_zone": _ZONES[zi].value,
                            "target_zone": _ZONES[zi + 1].value,
                        },
                    )
                )
    return _make_graph_with_nodes(nodes, edges), [_make_threat(n.id) for n in nodes[::3]]


class TestScale:
    def test_300_node_boundary_heavy_plan_renders_in_subquadratic_time(self) -> None:
        # An absolute wall-clock bound fails on a loaded or traced (coverage) runner, so compare
        # two sizes measured back to back: linear growth scales about 4x for 4x the input,
        # quadratic about 16x. The best of three runs drops scheduler noise.
        def best_of_three(total: int) -> float:
            graph, threats = _boundary_heavy_graph(total)
            report = _make_report(threats, total)
            runs = []
            for _ in range(3):
                start = time.perf_counter()
                format_diagram(report, graph, lod_threshold=None)
                runs.append(time.perf_counter() - start)
            return min(runs)

        small = best_of_three(75)
        large = best_of_three(300)
        assert large < 10 * max(small, 0.01), f"{large:.2f}s for 300 nodes, {small:.2f}s for 75"
        graph, threats = _boundary_heavy_graph(300)
        report = _make_report(threats, 300)
        svg = format_diagram(report, graph, lod_threshold=None)
        root = ElementTree.fromstring(svg)
        # One label per distinct zone transition, not one per crossing connector
        labels = re.findall(r'class="edge-label">(.*?)</text>', svg)
        assert labels and len({t.split(" x")[0] for t in labels}) == len(labels)
        assert len(_label_boxes(root)) == len(labels)
        assert len(_node_boxes(root)) == 300

    def test_the_track_order_search_matches_a_plain_count_of_crossings(self) -> None:
        import itertools
        import random

        from threatcode.formatters import diagram_routing as routing

        def plain_count(runs: list[Any], colors: list[int], ys: list[float]) -> int:
            count = 0
            for i, a in enumerate(runs):
                for j, b in enumerate(runs):
                    if i == j or a.key == b.key:
                        continue
                    for x, direction in b.stubs:
                        if a.lo + 0.5 < x < a.hi - 0.5:
                            above = ys[colors[i]] < ys[colors[j]]
                            if (direction == routing._UP and above) or (
                                direction == routing._DOWN and not above
                            ):
                                count += 1
            return count

        rng = random.Random(7)
        for case in range(150):
            n = rng.randint(2, 5)
            runs = []
            for i in range(rng.randint(2, 14)):
                lo = rng.uniform(0, 300)
                hi = lo + rng.uniform(1, 200)
                stubs = tuple(
                    (
                        rng.choice([lo, hi, rng.uniform(lo, hi)]),
                        rng.choice([routing._UP, routing._DOWN]),
                    )
                    for _ in range(2)
                )
                runs.append(routing._Run(lo, hi, (f"k{i // 2}", "t"), 1 + i % 2, stubs))
            colors = [rng.randrange(n) for _ in runs]
            slots = sorted(rng.sample(range(100), n))
            ys = [float(y) for y in slots]
            chosen = routing._least_crossing_order(runs, colors, ys)
            best = min(
                plain_count(runs, colors, [ys[o] for o in order])
                for order in itertools.permutations(range(n))
            )
            assert plain_count(runs, colors, [ys[o] for o in chosen]) == best, case

    def test_default_render_of_300_nodes_is_fast_and_collapsed(self) -> None:
        graph, threats = _boundary_heavy_graph(300)
        start = time.perf_counter()
        svg = format_diagram(_make_report(threats, 300), graph)
        assert time.perf_counter() - start < 3.0
        assert ElementTree.fromstring(svg).tag == f"{NS}svg"

    def test_large_input_collapses_by_zone_and_type_with_a_notice(
        self, caplog: pytest.LogCaptureFixture
    ) -> None:
        graph, threats = _boundary_heavy_graph(200, types=2)
        report = _make_report(threats, 200)
        with caplog.at_level("WARNING", logger="threatcode.formatters.diagram"):
            svg = format_diagram(report, graph, lod_threshold=100)
        root = ElementTree.fromstring(svg)
        ids = _node_ids(svg)
        assert len(ids) == 10  # five zones x two types
        assert all(i.startswith("group.") for i in ids)
        assert "Large input: 200 resources collapsed into 10 groups" in svg
        assert any("collapsed 200 resources" in r.message for r in caplog.records)
        assert _groups(svg, "lod-notice")
        # Findings stay in the table and the header still counts everything
        assert len(_row_texts(svg)) == len(threats)
        assert "200 resources" in svg
        assert root.tag == f"{NS}svg"

    def test_collapsed_group_tooltip_lists_members_and_threats(self) -> None:
        graph, threats = _boundary_heavy_graph(200, types=1)
        svg = format_diagram(_make_report(threats, 200), graph, lod_threshold=100)
        root = ElementTree.fromstring(svg)
        group = next(g for g in root.iter(f"{NS}g") if g.get("data-id") == "group.dmz.type_0")
        tooltip = group.find(f"{NS}title").text or ""  # type: ignore[union-attr]
        assert "40 x type_0" in tooltip
        assert "res_1.n0" in tooltip
        assert "and 28 more" in tooltip
        assert "threats:" in tooltip

    def test_below_the_threshold_nothing_collapses(self, caplog: pytest.LogCaptureFixture) -> None:
        graph, threats = _boundary_heavy_graph(50)
        with caplog.at_level("WARNING", logger="threatcode.formatters.diagram"):
            svg = format_diagram(_make_report(threats, 50), graph)
        assert len(_node_ids(svg)) == 50
        assert not _groups(svg, "lod-notice")
        assert not caplog.records

    def test_most_labels_clear_obstacles_on_a_dense_plan(self) -> None:
        """Labels that find a free spot never cover a node; only crowded ones fall back."""
        graph, threats = _boundary_heavy_graph(50)
        root = ElementTree.fromstring(
            format_diagram(_make_report(threats, 50), graph, lod_threshold=None)
        )
        nodes = _node_boxes(root)
        labels = _label_boxes(root)
        covering = [
            label for label in labels if any(_boxes_overlap(label, node) for node in nodes.values())
        ]
        assert labels
        assert len(covering) <= len(labels) * 0.1, covering


class TestSpatialIndex:
    def test_queries_return_only_nearby_items_in_insertion_order(self) -> None:
        from threatcode.formatters.diagram_routing import SpatialIndex

        index = SpatialIndex(cell=50)
        near = Rect(10, 10, 20, 20)
        far = Rect(900, 900, 20, 20)
        index.add_rect(far)
        index.add_rect(near)
        assert index.rects_near(Rect(0, 0, 60, 60)) == [near]
        assert index.rects_near(Rect(0, 0, 2000, 2000)) == [far, near]
        index.add_segment((0, 5), (400, 5), "a")
        assert index.segments_near(Rect(300, 0, 10, 10)) == [((0, 5), (400, 5), "a")]
        assert index.segments_near(Rect(300, 500, 10, 10)) == []

    def test_place_on_route_matches_a_flat_list(self) -> None:
        from threatcode.formatters.diagram_routing import SpatialIndex, place_on_route

        points = [(0.0, 100.0), (400.0, 100.0)]
        obstacles = [Rect(150, 80, 100, 40)]
        bounds = Rect(0, 0, 500, 200)
        flat = place_on_route(points, (60, 16), obstacles, bounds, [])
        index = SpatialIndex()
        index.add_rect(obstacles[0])
        indexed = place_on_route(points, (60, 16), index, bounds, SpatialIndex())
        assert flat == indexed
        assert flat is not None
        assert not flat.intersects(obstacles[0])

    def test_candidate_cap_bounds_the_work(self) -> None:
        from threatcode.formatters.diagram_routing import place_on_route

        points = [(0.0, 10.0), (100000.0, 10.0)]
        tried = []

        class Counting(list[Rect]):
            def __iter__(self):  # type: ignore[no-untyped-def]
                tried.append(1)
                return super().__iter__()

        found = place_on_route(
            points, (40, 10), Counting(), Rect(-10, 0, 200000, 50), [], max_candidates=32
        )
        assert found is not None


# -- Determinism, accessibility and ids ---------------------------------------


def _doc(report_input: str = "test.plan.json") -> tuple[ThreatReport, InfraGraph]:
    report = _make_report(
        [_make_threat("aws_lb.alb", "high", "No WAF"), _make_threat("aws_s3_bucket.data")], 5
    )
    report.input_file = report_input
    report.timestamp = ""
    report.attack_paths = [_chain_path()]
    return report, _make_graph_with_nodes(SAMPLE_NODES, SAMPLE_EDGES)


class TestDeterminism:
    def test_two_renders_are_byte_identical(self) -> None:
        a = format_diagram(*_doc())
        b = format_diagram(*_doc())
        assert a == b
        assert a.encode() == b.encode()

    def test_a_realistic_plan_renders_identically_twice(self) -> None:
        assert _fixture_svg() == _fixture_svg()

    def test_identical_with_the_timestamp_omitted_across_clock_changes(self) -> None:
        first, graph = _doc()
        second, _ = _doc()
        first.timestamp = second.timestamp = ""
        assert format_diagram(first, graph) == format_diagram(second, graph)

    def test_summary_state_does_not_leak_between_renders(self) -> None:
        report, graph = _doc()
        assert format_diagram(report, graph) == format_diagram(report, graph)


class TestAccessibility:
    def test_root_has_role_title_and_description(self) -> None:
        svg = format_diagram(*_doc())
        root = ElementTree.fromstring(svg)
        assert root.get("role") == "img"
        title = root.find(f"{NS}title")
        desc = root.find(f"{NS}desc")
        assert title is not None and "ThreatCode threat model" in (title.text or "")
        assert desc is not None and "2 threats" in (desc.text or "")
        assert "1 attack paths" in (desc.text or "")
        labelled = (root.get("aria-labelledby") or "").split()
        assert labelled == [title.get("id"), desc.get("id")]

    def test_title_and_desc_come_first(self) -> None:
        root = ElementTree.fromstring(format_diagram(*_doc()))
        assert [c.tag for c in list(root)[:3]] == [f"{NS}title", f"{NS}desc", f"{NS}defs"]

    def test_title_names_the_input_file_only(self) -> None:
        report, graph = _doc("/home/someone/private/stack/main.plan.json")
        title = ElementTree.fromstring(format_diagram(report, graph)).find(f"{NS}title")
        assert title is not None
        assert "main.plan.json" in (title.text or "")
        assert "someone" not in (title.text or "")

    def test_font_stack_falls_back_to_system_fonts(self) -> None:
        root = ElementTree.fromstring(format_diagram(*_doc()))
        family = root.get("font-family") or ""
        for font in ("system-ui", "Segoe UI", "Helvetica", "Arial", "sans-serif"):
            assert font in family


_NCNAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_.-]*$")


class TestScopedIds:
    def test_every_def_id_carries_the_document_prefix(self) -> None:
        root = ElementTree.fromstring(format_diagram(*_doc()))
        defs = root.find(f"{NS}defs")
        assert defs is not None
        ids = [e.get("id") for e in defs.iter() if e.get("id")]
        assert ids
        prefix = (root.find(f"{NS}title").get("id") or "").split("-")[0]  # type: ignore[union-attr]
        for def_id in ids:
            assert def_id and def_id.startswith(prefix + "-")
            assert _NCNAME.match(def_id)

    def test_prefix_differs_between_inputs_and_is_stable_for_one(self) -> None:
        def prefix(name: str) -> str:
            root = ElementTree.fromstring(format_diagram(*_doc(name)))
            return (root.find(f"{NS}title").get("id") or "").split("-")[0]  # type: ignore[union-attr]

        assert prefix("a.tf") == prefix("a.tf")
        assert prefix("a.tf") != prefix("b.tf")

    def test_every_reference_points_at_a_defined_id(self) -> None:
        svg = format_diagram(*_doc())
        defined = set(re.findall(r'id="([^"]+)"', svg))
        for ref in re.findall(r"url\(#([^)]+)\)", svg):
            assert ref in defined, ref
        assert "url(#shadow)" not in svg and "url(#glow)" not in svg

    def test_element_ids_from_addresses_are_valid_unique_names(self) -> None:
        nodes = [
            InfraNode(
                "aws_instance.app[0]",
                "aws_instance",
                "app[0]",
                NodeCategory.COMPUTE,
                TrustZone.PRIVATE,
            ),
            InfraNode(
                'aws_instance.app["a b"]',
                "aws_instance",
                "x",
                NodeCategory.COMPUTE,
                TrustZone.PRIVATE,
            ),
            InfraNode(
                "module.m.aws_instance.x",
                "aws_instance",
                "x",
                NodeCategory.COMPUTE,
                TrustZone.PRIVATE,
            ),
            InfraNode(
                "aws_instance.<script>&'\"",
                "aws_instance",
                "x",
                NodeCategory.COMPUTE,
                TrustZone.PRIVATE,
            ),
        ]
        svg = format_diagram(_make_report(), _make_graph_with_nodes(nodes))
        root = ElementTree.fromstring(svg)
        ids = [e.get("id") for e in root.iter() if e.get("id")]
        assert len(ids) == len(set(ids))
        for element_id in ids:
            assert element_id and _NCNAME.match(element_id), element_id
        # The raw address stays in data-id, escaped by the XML writer
        assert any(g.get("data-id") == 'aws_instance.app["a b"]' for g in root.iter(f"{NS}g"))

    def test_path_group_ids_are_valid(self) -> None:
        root = ElementTree.fromstring(format_diagram(*_doc()))
        for g in root.iter(f"{NS}g"):
            if g.get("class") == "attack-path":
                assert _NCNAME.match(g.get("id") or "")


# -- Every golden input renders well-formed SVG -------------------------------

_GOLDEN_DIR = Path(__file__).parent.parent / "fixtures" / "golden"
_REPO_ROOT = Path(__file__).parent.parent.parent


def _golden_inputs() -> list[str]:
    found = []
    for meta in sorted(_GOLDEN_DIR.glob("*/meta.json")):
        found.append(json.loads(meta.read_text(encoding="utf-8"))["input"])
    return found


@pytest.mark.parametrize("relpath", _golden_inputs())
def test_golden_inputs_render_well_formed_svg(relpath: str) -> None:
    from threatcode.parsers import detect_and_parse

    path = _REPO_ROOT / relpath
    if not path.exists():
        pytest.skip(f"{relpath} not available")
    graph = InfraGraph.from_parsed(detect_and_parse(str(path)))
    report = HybridEngine().analyze(graph, input_file=str(path))
    svg = format_diagram(report, graph)
    root = ElementTree.fromstring(svg)
    assert root.tag == f"{NS}svg"
    ids = [e.get("id") for e in root.iter() if e.get("id")]
    assert len(ids) == len(set(ids)), "duplicate element id"
    # No connector is drawn for containment, and every node drawn exists in the graph
    for p in root.iter(f"{NS}path"):
        assert p.get("data-type") != "containment"
    for g in root.iter(f"{NS}g"):
        if g.get("class") == "node":
            assert graph.get_node(g.get("data-id", "")) is not None
    # Without attack paths in the report the diagram says so
    if not report.attack_paths:
        assert "No attack paths found" in svg
