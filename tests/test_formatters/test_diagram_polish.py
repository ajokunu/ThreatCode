"""The SVG diagram on the three example stacks and on hand-built graphs: what a reader sees.

Each class pins one family of the problems the final polish pass found by rendering the diagram
for real inputs and looking at it: edges that do not say which are attack paths, nodes that read
alike, text clipped or hard to read, ids that collide when two diagrams share a page.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ElementTree
from collections.abc import Iterator
from functools import cache
from pathlib import Path
from typing import Any

import pytest

import threatcode
from threatcode.formatters.diagram import (
    ATTACK_PATH_MAX_ENABLERS,
    NODE_NAME_MAX_CHARS,
    NODE_TYPE_MAX_CHARS,
    SEVERITY_COLORS,
    ZONE_COLORS,
    ZONE_TITLE_COLORS,
    format_diagram,
)
from threatcode.formatters.diagram_routing import Rect
from threatcode.ir.edges import EdgeType, InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

NS = "{http://www.w3.org/2000/svg}"
REPO = Path(__file__).resolve().parents[2]
EXAMPLES = ("aws-webapp", "k8s-platform", "agent-workstation")


@cache
def example_svg(name: str) -> str:
    settings: dict[str, Any] = {"no_timestamp": True}
    if name == "aws-webapp":
        settings["ingest"] = [str(REPO / "examples/aws-webapp/scanner/trivy-app-image.json")]
    return threatcode.analyze(REPO / "examples" / name, **settings).to_svg()


def root_of(svg: str) -> ElementTree.Element:
    return ElementTree.fromstring(svg)


def groups(root: ElementTree.Element, css: str) -> list[ElementTree.Element]:
    return [g for g in root.iter(f"{NS}g") if g.get("class") == css]


def texts_of(element: ElementTree.Element) -> list[str]:
    """The text of each ``<text>``, the lines of a wrapped one joined by a space."""
    return [" ".join(t.itertext()) for t in element.iter(f"{NS}text")]


def node(
    node_id: str,
    zone: TrustZone = TrustZone.PRIVATE,
    category: NodeCategory = NodeCategory.COMPUTE,
    rtype: str = "",
) -> InfraNode:
    kind = rtype or node_id.split(".")[0]
    return InfraNode(node_id, kind, node_id.split(".", 1)[1], category, zone)


def graph_of(nodes: list[InfraNode], edges: list[InfraEdge] | None = None) -> InfraGraph:
    graph = InfraGraph()
    for item in nodes:
        graph._nodes[item.id] = item
    graph._edges.extend(edges or [])
    return graph


def crossing(source: str, target: str, src: str, tgt: str, kind: EdgeType) -> InfraEdge:
    return InfraEdge(
        source,
        target,
        kind,
        metadata={"crosses_trust_boundary": True, "source_zone": src, "target_zone": tgt},
    )


def threat_on(
    address: str,
    severity: str = "high",
    title: str = "A finding",
    threat_id: str = "",
    **fields: Any,
) -> Threat:
    return Threat(
        id=threat_id or f"T-{address}-{title}",
        title=title,
        description=fields.pop("description", "Test description"),
        stride_category=fields.pop("stride_category", "tampering"),
        severity=Severity(severity),
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address=address,
        **fields,
    )


def render(
    nodes: list[InfraNode],
    edges: list[InfraEdge] | None = None,
    threats: list[Threat] | None = None,
    paths: list[AttackPath] | None = None,
    input_file: str = "test.plan.json",
) -> str:
    report = ThreatReport(
        threats=threats or [], scanned_resources=len(nodes), input_file=input_file
    )
    report.attack_paths = paths or []
    return format_diagram(report, graph_of(nodes, edges))


def path_of(
    *hops: AttackHop, severity: Severity = Severity.HIGH, rationale: str = "A path."
) -> AttackPath:
    return AttackPath(
        id="p-" + "-".join(h.node_id for h in hops)[:30],
        entry=hops[0].node_id,
        target=hops[-1].node_id,
        hops=list(hops),
        severity=severity,
        score=7.0,
        rationale=rationale,
    )


def hop(
    node_id: str,
    edge: str | None = "network_flow",
    *,
    via: dict[str, Any] | None = None,
    enabled_by: list[str] | None = None,
    techniques: list[str] | None = None,
    resource_type: str = "",
) -> AttackHop:
    return AttackHop(
        node_id=node_id,
        resource_type=resource_type,
        edge_type_to_next=edge,
        via=via or {},
        enabled_by=enabled_by or [],
        techniques=techniques or [],
    )


# -- Geometry helpers -----------------------------------------------------------


def number_pairs(d: str) -> list[tuple[float, float]]:
    nums = [float(n) for n in re.findall(r"-?\d+(?:\.\d+)?", d)]
    return list(zip(nums[0::2], nums[1::2], strict=True))


def rect_of(element: ElementTree.Element) -> Rect:
    return Rect(*(float(element.get(a, 0)) for a in ("x", "y", "width", "height")))


def edge_polylines(root: ElementTree.Element) -> list[list[tuple[float, float]]]:
    return [
        number_pairs(p.get("d", ""))
        for p in root.iter(f"{NS}path")
        if (p.get("class") or "").startswith("edge")
    ]


# -- Contrast -------------------------------------------------------------------


def _channel(value: int) -> float:
    c = value / 255
    return c / 12.92 if c <= 0.03928 else ((c + 0.055) / 1.055) ** 2.4


def _rgb(color: str) -> tuple[int, int, int]:
    color = color.lstrip("#")
    if len(color) == 3:
        color = "".join(ch * 2 for ch in color)
    return int(color[0:2], 16), int(color[2:4], 16), int(color[4:6], 16)


def luminance(color: str) -> float:
    r, g, b = _rgb(color)
    return 0.2126 * _channel(r) + 0.7152 * _channel(g) + 0.0722 * _channel(b)


def contrast(fg: str, bg: str) -> float:
    light, dark = sorted((luminance(fg), luminance(bg)), reverse=True)
    return (light + 0.05) / (dark + 0.05)


def _blend(fg: str, bg: str, alpha: float) -> str:
    mixed = [round(f * alpha + b * (1 - alpha)) for f, b in zip(_rgb(fg), _rgb(bg), strict=True)]
    return "#{:02x}{:02x}{:02x}".format(*mixed)


def _hex(value: str | None) -> str | None:
    return value if value and re.fullmatch(r"#[0-9a-fA-F]{3}|#[0-9a-fA-F]{6}", value) else None


def text_contrasts(svg: str) -> Iterator[tuple[str, str, str, float]]:
    """(text, ink, background, ratio) for every text, the background found by paint order.

    The background is the last filled rectangle or circle drawn under the text's centre,
    blended with what was under it when it is translucent.
    """
    shapes: list[tuple[Rect, str, float]] = []

    def background(x: float, y: float) -> str:
        color = "#ffffff"
        for rect, fill, alpha in shapes:
            if rect.x <= x <= rect.right and rect.y <= y <= rect.bottom:
                color = _blend(fill, color, alpha) if alpha < 1 else fill
        return color

    for element in ElementTree.fromstring(svg).iter():
        tag = element.tag.removeprefix(NS)
        fill = _hex(element.get("fill"))
        alpha = float(element.get("fill-opacity") or element.get("opacity") or 1)
        if tag == "rect" and fill:
            shapes.append((rect_of(element), fill, alpha))
        elif tag == "circle" and fill:
            cx, cy, r = (float(element.get(a, 0)) for a in ("cx", "cy", "r"))
            shapes.append((Rect(cx - r, cy - r, 2 * r, 2 * r), fill, alpha))
        elif tag == "text":
            size = float(element.get("font-size") or 16)
            x, y = float(element.get("x", 0)), float(element.get("y", 0))
            anchor = element.get("text-anchor", "start")
            x += {"middle": 0.0, "end": -2.0}.get(anchor, 2.0)
            bg = background(x, y - size * 0.35)
            ink = _hex(element.get("fill")) or "#000000"
            yield "".join(element.itertext()), ink, bg, contrast(ink, bg)


class TestContrast:
    """FV-14: every piece of text reads against what it is written on."""

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_text_has_at_least_4_5_to_1(self, name: str) -> None:
        poor = [
            (text, ink, bg, round(ratio, 2))
            for text, ink, bg, ratio in text_contrasts(example_svg(name))
            if ratio < 4.5 and text.strip()
        ]
        assert poor == []

    def test_zone_titles_are_dark_variants_of_the_zone_hue(self) -> None:
        for zone, ink in ZONE_TITLE_COLORS.items():
            assert contrast(ink, ZONE_COLORS[zone][0]) >= 4.5, zone
        # The pastel border color alone is what made them unreadable
        for zone, (fill, border) in ZONE_COLORS.items():
            assert contrast(border, fill) < 3, zone

    def test_the_zone_titles_are_drawn_in_those_colors(self) -> None:
        svg = example_svg("aws-webapp")
        inks = {
            "".join(t.itertext()): t.get("fill")
            for g in groups(root_of(svg), "zone-internet")
            for t in g.iter(f"{NS}text")
        }
        assert inks == {"INTERNET": ZONE_TITLE_COLORS[TrustZone.INTERNET]}

    def test_node_type_captions_are_at_least_9px(self) -> None:
        root = root_of(example_svg("aws-webapp"))
        for g in groups(root, "node"):
            caption = g.findall(f"{NS}text")[0]
            assert float(caption.get("font-size", "0")) >= 9
            assert contrast(caption.get("fill", "#000"), "#ffffff") >= 4.5

    def test_a_medium_badge_is_not_white_on_yellow(self) -> None:
        svg = render(
            [node("aws_instance.a")],
            threats=[threat_on("aws_instance.a", "medium"), threat_on("aws_instance.a", "low")],
        )
        poor = [t for t in text_contrasts(svg) if t[3] < 4.5 and t[0].strip()]
        assert poor == []
        assert SEVERITY_COLORS["medium"] in svg


# -- The overlay of attack paths ------------------------------------------------


def _chain() -> tuple[list[InfraNode], list[InfraEdge], AttackPath]:
    nodes = [
        node("aws_internet_gateway.igw", TrustZone.INTERNET, NodeCategory.NETWORK),
        node("aws_lb.front", TrustZone.DMZ, NodeCategory.NETWORK),
        node("aws_instance.app", TrustZone.PRIVATE),
        node("aws_s3_bucket.data", TrustZone.DATA, NodeCategory.STORAGE),
        node("aws_security_group.web", TrustZone.DMZ, NodeCategory.NETWORK),
        node("aws_iam_role.app", TrustZone.MANAGEMENT, NodeCategory.IAM),
    ]
    edges = [
        crossing(
            "aws_internet_gateway.igw", "aws_lb.front", "internet", "dmz", EdgeType.NETWORK_FLOW
        ),
        crossing("aws_lb.front", "aws_instance.app", "dmz", "private", EdgeType.NETWORK_FLOW),
        crossing("aws_instance.app", "aws_s3_bucket.data", "private", "data", EdgeType.DATA_FLOW),
        # references that merely run between zones
        crossing("aws_lb.front", "aws_security_group.web", "dmz", "dmz", EdgeType.DEPENDENCY),
        crossing(
            "aws_instance.app", "aws_iam_role.app", "private", "management", EdgeType.DEPENDENCY
        ),
        crossing(
            "aws_instance.app", "aws_security_group.web", "private", "dmz", EdgeType.DEPENDENCY
        ),
    ]
    path = path_of(
        hop("aws_internet_gateway.igw", via={"ports": ["443"]}),
        hop("aws_lb.front", via={"ports": ["8080"]}),
        hop("aws_instance.app", "data_flow", via={"relation": "reads_secret"}),
        hop("aws_s3_bucket.data", None),
        severity=Severity.CRITICAL,
    )
    return nodes, edges, path


class TestPathOverlay:
    """FV-09 and FV-12: attack path hops are the one emphasised thing, and they are numbered."""

    def svg(self) -> str:
        nodes, edges, path = _chain()
        return render(nodes, edges, paths=[path])

    def edge_paths(self, svg: str) -> list[ElementTree.Element]:
        return [
            p for p in root_of(svg).iter(f"{NS}path") if (p.get("class") or "").startswith("edge")
        ]

    def test_only_the_hops_of_a_path_are_thick_and_glow(self) -> None:
        paths = self.edge_paths(self.svg())
        hops = [p for p in paths if p.get("data-path")]
        others = [p for p in paths if not p.get("data-path")]
        assert len(hops) == 3 and len(others) == 3
        for p in hops:
            assert p.get("stroke") == SEVERITY_COLORS["critical"]
            assert float(p.get("stroke-width", "0")) >= 2.5
        for p in others:
            assert float(p.get("stroke-width", "9")) <= 1.6
            assert p.get("filter") is None
            assert p.get("stroke") != SEVERITY_COLORS["critical"]

    def test_hops_glow(self) -> None:
        hops = [p for p in self.edge_paths(self.svg()) if p.get("data-path")]
        assert all("-glow" in (p.get("filter") or "") for p in hops)

    def test_a_reference_between_zones_is_muted_and_unlabelled(self) -> None:
        svg = self.svg()
        references = [p for p in self.edge_paths(svg) if p.get("data-type") == "dependency"]
        assert len(references) == 3
        for p in references:
            assert p.get("data-boundary") == "false"
            assert p.get("stroke") == "#94a3b8" and p.get("stroke-width") == "1"
        labels = re.findall(r'class="edge-label">(.*?)</text>', svg)
        assert not any("MANAGEMENT" in label for label in labels)

    def test_hops_are_drawn_after_every_other_connector(self) -> None:
        svg = self.svg()
        kinds = [
            "hop" if 'data-path="' in group else "other"
            for group in svg.split('<g class="edge-group">')[1:]
        ]
        assert kinds == sorted(kinds, key=lambda k: k == "hop")

    def test_every_connector_tooltip_names_both_ends(self) -> None:
        root = root_of(self.svg())
        for g in groups(root, "edge-group"):
            path = g.find(f"{NS}path")
            title = g.find(f"{NS}title")
            assert path is not None and title is not None
            first = (title.text or "").splitlines()[0]
            assert re.fullmatch(r"\S+ → \S+", first), first
        assert any(
            "aws_internet_gateway.igw → aws_lb.front" in (g.findtext(f"{NS}title") or "")
            for g in groups(root, "edge-group")
        )

    def test_a_hop_tooltip_says_which_path_and_step(self) -> None:
        root = root_of(self.svg())
        tooltip = next(
            g.findtext(f"{NS}title") or ""
            for g in groups(root, "edge-group")
            if "aws_lb.front → aws_instance.app" in (g.findtext(f"{NS}title") or "")
        )
        assert "Attack path 1 (critical), step 2 of 3" in tooltip
        assert "Network Flow: tcp/8080" in tooltip
        assert "Crosses a trust boundary: dmz → private" in tooltip

    def test_zone_labels_are_amber_and_not_red(self) -> None:
        root = root_of(self.svg())
        for g in groups(root, "edge-label-group"):
            rect = g.find(f"{NS}rect")
            assert rect is not None and rect.get("stroke") not in SEVERITY_COLORS.values()

    def test_path_badges_are_outlined_squares_with_a_p(self) -> None:
        root = root_of(self.svg())
        badges = groups(root, "attack-path-marker")
        assert len(badges) == 3
        for badge in badges:
            assert badge.find(f"{NS}circle") is None
            rect = badge.find(f"{NS}rect")
            assert rect is not None and rect.get("fill") == "#ffffff"
            assert rect.get("stroke") == SEVERITY_COLORS["critical"]
            assert re.fullmatch(r"P\d", "".join(badge.find(f"{NS}text").itertext()))  # type: ignore[union-attr]

    def test_a_severity_badge_stays_round_next_to_the_square_path_badges(self) -> None:
        nodes, edges, path = _chain()
        root = root_of(render(nodes, edges, [threat_on("aws_lb.front")], [path]))
        (front,) = [g for g in groups(root, "node") if g.get("data-id") == "aws_lb.front"]
        (badge,) = front.findall(f"{NS}circle")
        assert badge.get("r") == "7"
        assert groups(root, "attack-path-marker")

    def test_badges_stay_off_nodes_zone_borders_and_each_other(self) -> None:
        root = root_of(self.svg())
        badges = [rect_of(b.find(f"{NS}rect")) for b in groups(root, "attack-path-marker")]  # type: ignore[arg-type]
        nodes = [rect_of(r) for g in groups(root, "node") for r in g.findall(f"{NS}rect")[:1]]
        borders = [
            float(g.find(f"{NS}rect").get("y", 0))  # type: ignore[union-attr]
            for g in root.iter(f"{NS}g")
            if (g.get("class") or "").startswith("zone-")
        ][1:]
        for badge in badges:
            assert not any(badge.intersects(n) for n in nodes), badge
            assert not any(badge.y < b < badge.bottom for b in borders), badge
        for i, one in enumerate(badges):
            assert not any(one.intersects(other) for other in badges[i + 1 :])

    def test_legend_explains_the_numbers(self) -> None:
        svg = self.svg()
        assert "Attack path number (listed below)" in svg
        assert "Attack path hop (color = severity)" in svg

    @pytest.mark.parametrize(
        ("numbers", "text"),
        [
            ([1], "P1"),
            ([1, 3], "P1 P3"),
            ([1, 2], "P1 P2"),
            ([1, 2, 3], "P1-P3"),
            ([1, 2, 3, 5], "P1-P3 P5"),
        ],
    )
    def test_path_numbers_read_as_ranges(self, numbers: list[int], text: str) -> None:
        from threatcode.formatters.diagram import _path_badge_text

        assert _path_badge_text(numbers) == text

    def test_a_hop_the_graph_has_no_connector_for_is_still_drawn(self) -> None:
        nodes = [node("a.one", TrustZone.DMZ), node("b.two", TrustZone.PRIVATE)]
        path = path_of(hop("a.one"), hop("b.two", None))
        root = root_of(render(nodes, [], paths=[path]))
        (connector,) = [p for p in root.iter(f"{NS}path") if p.get("data-path")]
        assert connector.get("data-type") == "network_flow"

    def test_a_hop_through_an_unknown_node_does_not_break_the_drawing(self) -> None:
        nodes = [node("a.one", TrustZone.DMZ)]
        path = path_of(hop("a.one"), hop("ghost.node", None))
        root = root_of(render(nodes, [], paths=[path]))
        assert not [p for p in root.iter(f"{NS}path") if p.get("data-path")]

    def test_the_worst_path_decides_the_color_of_a_shared_hop(self) -> None:
        nodes, edges, critical = _chain()
        low = path_of(
            hop("aws_internet_gateway.igw", via={"ports": ["443"]}),
            hop("aws_lb.front", None),
            severity=Severity.LOW,
        )
        root = root_of(render(nodes, edges, paths=[low, critical]))
        shared = [p for p in root.iter(f"{NS}path") if p.get("data-path") == "1 2"]
        assert shared and shared[0].get("stroke") == SEVERITY_COLORS["critical"]


class TestZoneLabels:
    """FV-09: one label per zone transition, with the number of connectors that cross."""

    def graph(self, count: int) -> tuple[list[InfraNode], list[InfraEdge]]:
        nodes = [node("aws_lb.front", TrustZone.DMZ, NodeCategory.NETWORK)]
        edges: list[InfraEdge] = []
        for i in range(count):
            nodes.append(node(f"aws_instance.app{i}", TrustZone.PRIVATE))
            edges.append(
                crossing(
                    "aws_lb.front", f"aws_instance.app{i}", "dmz", "private", EdgeType.NETWORK_FLOW
                )
            )
        return nodes, edges

    def test_seven_crossings_of_one_transition_are_one_label(self) -> None:
        svg = render(*self.graph(7))
        assert re.findall(r'class="edge-label">(.*?)</text>', svg) == ["DMZ → PRIVATE x7"]

    def test_one_crossing_has_no_count(self) -> None:
        svg = render(*self.graph(1))
        assert re.findall(r'class="edge-label">(.*?)</text>', svg) == ["DMZ → PRIVATE"]

    def test_the_label_tooltip_lists_the_connectors(self) -> None:
        root = root_of(render(*self.graph(3)))
        (label,) = groups(root, "edge-label-group")
        tooltip = label.findtext(f"{NS}title") or ""
        assert "3 connections cross this boundary" in tooltip
        for i in range(3):
            assert f"aws_lb.front → aws_instance.app{i}" in tooltip

    def test_a_long_list_is_cut_with_a_count(self) -> None:
        root = root_of(render(*self.graph(14)))
        (label,) = groups(root, "edge-label-group")
        assert "... and 4 more" in (label.findtext(f"{NS}title") or "")

    def test_a_different_transition_gets_its_own_label(self) -> None:
        nodes, edges = self.graph(2)
        nodes.append(node("aws_s3_bucket.d", TrustZone.DATA, NodeCategory.STORAGE))
        edges.append(
            crossing("aws_instance.app0", "aws_s3_bucket.d", "private", "data", EdgeType.DATA_FLOW)
        )
        labels = re.findall(r'class="edge-label">(.*?)</text>', render(nodes, edges))
        assert sorted(labels) == ["DMZ → PRIVATE x2", "PRIVATE → DATA"]

    def test_the_aws_example_has_one_label_per_transition(self) -> None:
        labels = re.findall(r'class="edge-label">(.*?)</text>', example_svg("aws-webapp"))
        names = [label.split(" x")[0] for label in labels]
        assert len(names) == len(set(names))
        assert len(labels) <= 6


class TestMergedConnectors:
    """FV-13: two edges between the same nodes are one connector, not two on the same line."""

    def test_a_reference_and_an_iam_binding_are_one_arrow(self) -> None:
        nodes = [node("aws_iam_role_policy.p", rtype="aws_iam_role_policy"), node("aws_iam_role.r")]
        edges = [
            InfraEdge(
                "aws_iam_role_policy.p",
                "aws_iam_role.r",
                EdgeType.DEPENDENCY,
                relation="references",
            ),
            InfraEdge(
                "aws_iam_role_policy.p", "aws_iam_role.r", EdgeType.IAM_BINDING, relation="assumes"
            ),
        ]
        root = root_of(render(nodes, edges))
        (edge,) = [p for p in root.iter(f"{NS}path") if (p.get("class") or "").startswith("edge")]
        assert edge.get("data-type") == "iam_binding"  # the stronger of the two decides
        (group,) = groups(root, "edge-group")
        tooltip = group.findtext(f"{NS}title") or ""
        assert "Dependency" in tooltip and "IAM Binding: assumes" in tooltip

    def test_no_two_connectors_share_a_route(self) -> None:
        for name in EXAMPLES:
            routes = [tuple(line) for line in edge_polylines(root_of(example_svg(name)))]
            assert len(routes) == len(set(routes)), name

    def test_a_flow_outranks_a_reference_and_a_binding(self) -> None:
        nodes = [node("a.one"), node("b.two")]
        edges = [
            InfraEdge("a.one", "b.two", EdgeType.DEPENDENCY),
            InfraEdge("a.one", "b.two", EdgeType.NETWORK_FLOW),
            InfraEdge("a.one", "b.two", EdgeType.IAM_BINDING),
        ]
        (edge,) = [
            p
            for p in root_of(render(nodes, edges)).iter(f"{NS}path")
            if (p.get("class") or "").startswith("edge")
        ]
        assert edge.get("data-type") == "network_flow"


# -- Names ----------------------------------------------------------------------


def _name_of(g: ElementTree.Element) -> str:
    return "".join(g.findall(f"{NS}text")[1].itertext())


def _caption_of(g: ElementTree.Element) -> str:
    return "".join(g.findall(f"{NS}text")[0].itertext())


class TestNodeNames:
    """FV-10 and RW-13: resources that share a name are told apart, and nothing is cut where
    the distinguishing part lives."""

    def test_no_two_nodes_of_the_aws_example_read_alike(self) -> None:
        root = root_of(example_svg("aws-webapp"))
        labels = [(_caption_of(g), _name_of(g)) for g in groups(root, "node")]
        assert len(labels) == len(set(labels))
        names = [name for _, name in labels]
        assert len(names) == len(set(names))

    def test_the_four_apps_of_the_aws_example_say_what_they_are(self) -> None:
        names = {_name_of(g) for g in groups(root_of(example_svg("aws-webapp")), "node")}
        assert {"role.app", "profile.app", "sg.app", "target_group.app"} <= names

    def test_the_three_storefronts_of_the_k8s_example_say_what_they_are(self) -> None:
        names = {_name_of(g) for g in groups(root_of(example_svg("k8s-platform")), "node")}
        assert {"ingress/storefront", "service/storefront", "deployment/storefront"} <= names

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_no_type_caption_of_an_example_is_cut(self, name: str) -> None:
        for g in groups(root_of(example_svg(name)), "node"):
            assert "..." not in _caption_of(g), _caption_of(g)

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_name_and_caption_fits_its_node(self, name: str) -> None:
        for g in groups(root_of(example_svg(name)), "node"):
            assert len(_name_of(g)) <= NODE_NAME_MAX_CHARS
            assert len(_caption_of(g)) <= NODE_TYPE_MAX_CHARS

    def test_a_long_type_keeps_both_ends_of_the_caption(self) -> None:
        long_type = "aws_ecrpublic_authorization_token_for_everything"
        svg = render([node(f"{long_type}.t", rtype=long_type)])
        caption = _caption_of(groups(root_of(svg), "node")[0])
        assert len(caption) <= NODE_TYPE_MAX_CHARS
        assert caption.startswith("aws_ecr") and caption.endswith("everything") and "..." in caption

    def test_a_template_resource_keeps_its_logical_name(self) -> None:
        address = (
            "python3.10/step-func-conn/{{cookiecutter.project_name}}/template.yaml::StateMachine"
        )
        svg = render([node(f"x.{address}", rtype="aws_stepfunctions_state_machine")])
        assert _name_of(groups(root_of(svg), "node")[0]).endswith("StateMachine")

    def test_the_node_tooltip_still_has_the_full_address(self) -> None:
        address = "aws_s3_bucket." + "very_long_bucket_name_" * 4
        svg = render([node(address, TrustZone.DATA, NodeCategory.STORAGE)])
        (g,) = groups(root_of(svg), "node")
        assert (g.findtext(f"{NS}title") or "").startswith(address)

    def test_the_internet_is_an_external_entity_not_a_network_box(self) -> None:
        root = root_of(example_svg("aws-webapp"))
        (internet,) = [g for g in groups(root, "node") if g.get("data-id") == "internet"]
        rects = internet.findall(f"{NS}rect")
        assert len(rects) == 2  # the double border of an entity
        assert not internet.findall(f"{NS}polygon")


class TestSettingsFolding:
    """FV-10: a bucket's settings are not three more cylinders named like the bucket."""

    def graph(self) -> tuple[list[InfraNode], list[InfraEdge]]:
        store = NodeCategory.STORAGE
        nodes = [
            node("aws_s3_bucket.data", TrustZone.DATA, store),
            node(
                "aws_s3_bucket_public_access_block.data",
                TrustZone.DATA,
                store,
                "aws_s3_bucket_public_access_block",
            ),
            node(
                "aws_s3_bucket_server_side_encryption_configuration.data",
                TrustZone.DATA,
                store,
                "aws_s3_bucket_server_side_encryption_configuration",
            ),
            node(
                "aws_iam_role_policy.p",
                TrustZone.MANAGEMENT,
                NodeCategory.IAM,
                "aws_iam_role_policy",
            ),
            node("aws_iam_role.r", TrustZone.MANAGEMENT, NodeCategory.IAM),
            node("aws_instance.app"),
        ]
        edges = [
            InfraEdge(
                "aws_s3_bucket_public_access_block.data", "aws_s3_bucket.data", EdgeType.DEPENDENCY
            ),
            InfraEdge(
                "aws_s3_bucket_server_side_encryption_configuration.data",
                "aws_s3_bucket.data",
                EdgeType.DEPENDENCY,
            ),
            InfraEdge("aws_iam_role_policy.p", "aws_iam_role.r", EdgeType.DEPENDENCY),
            InfraEdge(
                "aws_instance.app", "aws_s3_bucket_public_access_block.data", EdgeType.NETWORK_FLOW
            ),
        ]
        return nodes, edges

    def test_the_settings_are_folded_into_the_bucket(self) -> None:
        nodes, edges = self.graph()
        ids = {g.get("data-id") for g in groups(root_of(render(nodes, edges)), "node")}
        assert "aws_s3_bucket.data" in ids
        assert not any("public_access_block" in (i or "") for i in ids)
        assert not any("encryption" in (i or "") for i in ids)

    def test_a_policy_of_a_role_is_not_a_setting_of_a_data_store(self) -> None:
        nodes, edges = self.graph()
        ids = {g.get("data-id") for g in groups(root_of(render(nodes, edges)), "node")}
        assert {"aws_iam_role_policy.p", "aws_iam_role.r"} <= ids

    def test_their_findings_show_on_the_bucket(self) -> None:
        nodes, edges = self.graph()
        threats = [
            threat_on("aws_s3_bucket.data", "low", "Own finding"),
            threat_on("aws_s3_bucket_public_access_block.data", "critical", "Block is open"),
        ]
        root = root_of(render(nodes, edges, threats))
        (bucket,) = [g for g in groups(root, "node") if g.get("data-id") == "aws_s3_bucket.data"]
        (badge,) = bucket.findall(f"{NS}circle")
        assert badge.get("fill") == SEVERITY_COLORS["critical"]
        assert "2" in texts_of(bucket)
        tooltip = bucket.findtext(f"{NS}title") or ""
        assert "Settings folded into this resource (2)" in tooltip
        assert "CRITICAL - Block is open" in tooltip

    def test_a_connector_to_a_setting_goes_to_the_bucket(self) -> None:
        nodes, edges = self.graph()
        root = root_of(render(nodes, edges))
        titles = [g.findtext(f"{NS}title") or "" for g in groups(root, "edge-group")]
        assert any(t.startswith("aws_instance.app → aws_s3_bucket.data") for t in titles)

    def test_the_aws_example_has_one_node_for_the_customer_data_bucket(self) -> None:
        ids = [g.get("data-id") for g in groups(root_of(example_svg("aws-webapp")), "node")]
        assert [i for i in ids if "customer_data" in (i or "")] == ["aws_s3_bucket.customer_data"]

    def test_a_cycle_of_settings_leaves_the_nodes_alone(self) -> None:
        store = NodeCategory.STORAGE
        nodes = [
            node("aws_x.a", TrustZone.DATA, store, "aws_x"),
            node("aws_x_y.a", TrustZone.DATA, store, "aws_x_y"),
        ]
        edges = [
            InfraEdge("aws_x_y.a", "aws_x.a", EdgeType.DEPENDENCY),
            InfraEdge("aws_x.a", "aws_x_y.a", EdgeType.DEPENDENCY),
        ]
        ids = {g.get("data-id") for g in groups(root_of(render(nodes, edges)), "node")}
        assert "aws_x.a" in ids


# -- The strips below the diagram -----------------------------------------------


def _strip_texts(svg: str, index: int = 0) -> list[str]:
    return texts_of(groups(root_of(svg), "attack-path")[index])


class TestAttackPathStrips:
    """FV-11: a strip says all of what the path says."""

    RATIONALE = (
        "The internet reaches aws_lb.front on tcp/443, then 4 more hops, and ends at "
        "aws_s3_bucket.customer_data (data store); 3 findings enable it, the worst being "
        "CVE-2022-37434: zlib: heap-based buffer over-read and overflow in inflate() in "
        "inflate.c via a large gzip header extra field (critical)."
    )

    def svg(self, **kwargs: Any) -> str:
        nodes = [node(f"aws_instance.n{i}") for i in range(4)]
        threats = [
            threat_on("aws_instance.n1", "low", "Open group", "sg", rule_id="SG_OPEN"),
            threat_on("aws_instance.n2", "critical", "Bad image", "cve", rule_id="trivy:CVE-1"),
            threat_on("aws_instance.n2", "high", "IMDS allows v1", "imds", rule_id="EC2_IMDSV1"),
        ]
        path = path_of(
            hop("aws_instance.n0", via={"ports": ["443"]}, enabled_by=["sg"]),
            hop("aws_instance.n1", via={"ports": ["8080"]}, enabled_by=["sg"]),
            hop(
                "aws_instance.n2",
                "iam_binding",
                via={"relation": "assumes"},
                enabled_by=["imds", "cve"],
                techniques=["T1552.005"],
            ),
            hop("aws_instance.n3", None),
            rationale=kwargs.get("rationale", self.RATIONALE),
        )
        return render(nodes, [], threats, [path])

    def test_the_rationale_is_written_in_full_over_a_few_lines(self) -> None:
        group = groups(root_of(self.svg()), "attack-path")[0]
        (block,) = [
            t
            for t in group.iter(f"{NS}text")
            if "".join(t.itertext()).startswith("The internet reaches")
        ]
        lines = ["".join(span.itertext()) for span in block.iter(f"{NS}tspan")]
        assert len(lines) == 2
        assert " ".join(lines) == self.RATIONALE
        assert not any(line.endswith("...") for line in lines)

    def test_a_very_long_rationale_ends_in_an_ellipsis_on_the_last_line_only(self) -> None:
        svg = self.svg(rationale="word " * 400)
        spans = [
            "".join(s.itertext()) for s in groups(root_of(svg), "attack-path")[0].iter(f"{NS}tspan")
        ]
        rationale_lines = [s for s in spans if s.startswith("word")]
        assert len(rationale_lines) == 3
        assert rationale_lines[-1].endswith("...") and not rationale_lines[0].endswith("...")

    def test_every_enabler_is_listed_with_its_rule_id_and_title(self) -> None:
        joined = " ".join(_strip_texts(self.svg()))
        assert "SG_OPEN: Open group" in joined
        assert "EC2_IMDSV1: IMDS allows v1" in joined
        assert "trivy:CVE-1: Bad image" in joined

    def test_a_finding_on_two_hops_in_a_row_is_listed_once(self) -> None:
        joined = " ".join(_strip_texts(self.svg()))
        assert joined.count("SG_OPEN") == 1

    def test_more_findings_than_fit_are_counted(self) -> None:
        count = ATTACK_PATH_MAX_ENABLERS + 3
        nodes = [node("a.one"), node("b.two")]
        threats = [
            threat_on("a.one", "high", f"Finding {i}", f"t{i}", rule_id=f"RULE_{i}")
            for i in range(count)
        ]
        path = path_of(hop("a.one", enabled_by=[t.id for t in threats]), hop("b.two", None))
        svg = render(nodes, [], threats, [path])
        joined = " ".join(_strip_texts(svg))
        assert "+3 more findings" in joined
        # ... and the hop's tooltip has every one of them
        tooltip = groups(root_of(svg), "attack-path-hop")[0].findtext(f"{NS}title") or ""
        assert all(f"RULE_{i}" in tooltip for i in range(count))

    def test_the_techniques_of_a_hop_are_under_it(self) -> None:
        assert "ATT&CK T1552.005" in _strip_texts(self.svg())

    def test_the_edges_between_hops_are_in_words(self) -> None:
        joined = " ".join(_strip_texts(self.svg()))
        assert "HTTPS 443" in joined and "tcp/8080" in joined and "assumes" in joined
        for token in ("network_flow", "iam_binding"):
            assert token not in joined
        # The words of an arrow are never the bare tokens the engine writes
        texts = _strip_texts(self.svg())
        assert "iam" not in texts and "data" not in texts

    def test_the_box_holds_the_full_address(self) -> None:
        nodes = [
            node("kubernetes_ingress.platform.storefront"),
            node("kubernetes_service.platform.storefront"),
        ]
        path = path_of(hop(nodes[0].id), hop(nodes[1].id, None))
        group = groups(root_of(render(nodes, [], paths=[path])), "attack-path")[0]
        joined = " ".join(texts_of(group)).replace("  ", " ")
        assert "kubernetes_ingress. platform.storefront" in joined
        assert "kubernetes_service. platform.storefront" in joined

    def test_three_boxes_of_one_name_are_told_apart(self) -> None:
        ids = [
            "kubernetes_ingress.platform.storefront",
            "kubernetes_service.platform.storefront",
            "kubernetes_deployment.platform.storefront",
        ]
        nodes = [node(i) for i in ids]
        path = path_of(hop(ids[0]), hop(ids[1]), hop(ids[2], None))
        group = groups(root_of(render(nodes, [], paths=[path])), "attack-path")[0]
        boxes = [t for t in texts_of(group) if "storefront" in t]
        assert len(boxes) == 3 and len(set(boxes)) == 3

    def test_each_hop_tooltip_has_the_address_zone_and_what_it_does_next(self) -> None:
        group = groups(root_of(self.svg()), "attack-path-hop")[2]
        tooltip = group.findtext(f"{NS}title") or ""
        assert tooltip.splitlines()[0] == "aws_instance.n2"
        assert "Then: assumes the next hop" in tooltip
        assert "Enabled by CRITICAL - trivy:CVE-1: Bad image" in tooltip
        assert "ATT&CK: T1552.005" in tooltip

    def test_a_strip_grows_with_its_captions_and_the_next_one_starts_below(self) -> None:
        nodes = [node("a.one"), node("b.two"), node("c.three")]
        threats = [
            threat_on(
                "a.one", "high", f"A fairly long finding title number {i}", f"t{i}", rule_id=f"R{i}"
            )
            for i in range(3)
        ]
        tall = path_of(hop("a.one", enabled_by=[t.id for t in threats]), hop("b.two", None))
        flat = path_of(hop("a.one"), hop("c.three", None))
        root = root_of(render(nodes, [], threats, [tall, flat]))
        first, second = groups(root, "attack-path")
        text_bottoms = [float(t.get("y", 0)) for t in first.iter(f"{NS}text")]
        second_top = min(float(r.get("y", 0)) for r in second.iter(f"{NS}rect"))
        assert second_top > max(text_bottoms)

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_nothing_in_a_strip_runs_off_the_canvas(self, name: str) -> None:
        root = root_of(example_svg(name))
        width = float(root.get("viewBox", "").split()[2])
        for text in groups(root, "attack-path")[0].iter(f"{NS}text"):
            size = float(text.get("font-size", "9"))
            spans = ["".join(s.itertext()) for s in text.iter(f"{NS}tspan")]
            lines = spans or ["".join(text.itertext())]
            reach = max(len(line) for line in lines) * size * 0.55
            x = float(text.get("x", 0))
            if text.get("text-anchor") == "middle":
                assert x - reach / 2 >= 0 and x + reach / 2 <= width, lines
            else:
                assert x >= 0 and x + reach <= width, lines

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_no_strip_text_of_an_example_is_cut_mid_word(self, name: str) -> None:
        joined = " ".join(texts_of(groups(root_of(example_svg(name)), "attack-paths")[0]))
        assert "CVE-2022-374..." not in joined and "3 findin..." not in joined


# -- The findings table ---------------------------------------------------------


def _rows(svg: str) -> list[list[str]]:
    return [
        [" ".join(t.itertext()).strip() for t in g.iter(f"{NS}text")]
        for g in groups(root_of(svg), "threat-row")
    ]


class TestFindingsTable:
    """FV-16: the table cuts at a sentence, speaks in words and says where a finding is."""

    def render(self, *threats: Threat, graph_nodes: list[InfraNode] | None = None) -> str:
        return render(
            graph_nodes or [node(t.resource_address) for t in threats[:1]], threats=list(threats)
        )

    def test_the_description_is_its_first_sentence(self) -> None:
        svg = self.render(
            threat_on(
                "aws_instance.a",
                description="Traffic crosses a boundary. Nothing checks it. The container_findings "
                "property of the workload names them.",
            )
        )
        (cells,) = _rows(svg)
        assert cells[3] == "Traffic crosses a boundary."
        assert "container_findings" not in svg.split("threat-table")[1].split("<title>")[0]

    def test_a_sentence_that_fits_is_never_cut(self) -> None:
        svg = self.render(threat_on("aws_instance.a", description="Short one. Second."))
        assert _rows(svg)[0][3] == "Short one."

    def test_internal_edge_type_tokens_read_as_words(self) -> None:
        svg = self.render(
            threat_on("aws_instance.a", description="Crosses a trust boundary (network_flow) now.")
        )
        assert "(network traffic)" in _rows(svg)[0][3]
        assert "network_flow" not in svg.split("Threat Findings")[1]

    def test_there_is_a_location_column(self) -> None:
        svg = self.render(
            threat_on("aws_instance.a", location_file="infra/main.tf", location_start_line=12)
        )
        assert "Location" in texts_of(groups(root_of(svg), "threat-table")[0])
        assert "infra/main.tf:12" in _rows(svg)[0]

    def test_a_location_comes_from_the_node_when_the_finding_has_none(self) -> None:
        n = node("aws_instance.a")
        n.source_file, n.start_line = "main.tf", 7
        svg = render([n], threats=[threat_on("aws_instance.a")])
        assert "main.tf:7" in _rows(svg)[0]

    def test_a_finding_that_nothing_places_has_a_dash(self) -> None:
        cells = _rows(self.render(threat_on("aws_instance.a")))[0]
        assert cells[-2] == "-"  # the location; the last cell is the source

    def test_findings_with_one_root_cause_on_one_resource_are_one_row(self) -> None:
        threats = [
            threat_on(
                "k.deploy", "high", f"Hardening {i}", f"t{i}", root_cause="container-hardening"
            )
            for i in range(3)
        ]
        threats.append(threat_on("k.deploy", "low", "Other", "other"))
        svg = render([node("k.deploy")], threats=threats)
        rows = _rows(svg)
        assert len(rows) == 2
        assert rows[0][2] == "Hardening 0 (+2 related: container hardening)"
        assert "Threat Findings (4), 2 rows after grouping by root cause" in svg

    def test_a_group_row_tooltip_lists_every_member(self) -> None:
        threats = [
            threat_on("k.deploy", "high", f"Hardening {i}", f"t{i}", root_cause="c")
            for i in range(3)
        ]
        root = root_of(render([node("k.deploy")], threats=threats))
        (row,) = groups(root, "threat-row")
        tooltip = row.findtext(f"{NS}title") or ""
        assert all(f"Hardening {i}" in tooltip for i in range(3))

    def test_the_overflow_counts_findings_not_rows(self) -> None:
        threats = [
            threat_on("k.deploy", "high", f"T{i}", f"t{i}", root_cause="c") for i in range(4)
        ] + [threat_on(f"k.n{i}", "low", f"Own {i}", f"o{i}") for i in range(5)]
        svg = format_diagram(
            _report(threats),
            graph_of([node("k.deploy")] + [node(f"k.n{i}") for i in range(5)]),
            max_rows=2,
        )
        assert "4 more threats not shown" in svg

    def test_the_severity_of_a_group_is_its_worst(self) -> None:
        threats = [
            threat_on("k.d", "low", "Low one", "l", root_cause="c"),
            threat_on("k.d", "critical", "Crit one", "c", root_cause="c"),
        ]
        (row,) = _rows(render([node("k.d")], threats=threats))
        assert row[0] == "CRITICAL" and row[2].startswith("Crit one")

    def test_a_long_address_breaks_where_the_type_ends(self) -> None:
        address = "aws_sns_topic.orders_notifications_for_the_orders_service_v2"
        svg = render(
            [node(address, TrustZone.DATA, NodeCategory.SECRET)], threats=[threat_on(address)]
        )
        (row,) = groups(root_of(svg), "threat-row")
        lines = ["".join(s.itertext()) for s in row.iter(f"{NS}tspan")]
        assert "aws_sns_topic." in lines

    def test_the_table_is_ordered_worst_first(self) -> None:
        threats = [threat_on("a.x", "low", "L", "l"), threat_on("a.x", "critical", "C", "c")]
        assert [r[0] for r in _rows(render([node("a.x")], threats=threats))] == ["CRITICAL", "LOW"]


def _report(threats: list[Threat]) -> ThreatReport:
    return ThreatReport(threats=threats, scanned_resources=1, input_file="t.json")


# -- Ids ------------------------------------------------------------------------


class TestDocumentIds:
    """FV-17: two diagrams in one page do not share an id."""

    def ids(self, svg: str) -> set[str]:
        return {e.get("id", "") for e in root_of(svg).iter() if e.get("id")}

    def test_two_scans_of_one_input_name_differ(self) -> None:
        one = render([node("a.x")], threats=[threat_on("a.x", title="One")], input_file=".")
        two = render([node("a.x")], threats=[threat_on("a.x", title="Two")], input_file=".")
        assert self.ids(one).isdisjoint(self.ids(two))

    def test_the_same_report_renders_the_same_ids(self) -> None:
        a = render([node("a.x")], threats=[threat_on("a.x")], input_file=".")
        b = render([node("a.x")], threats=[threat_on("a.x")], input_file=".")
        assert a == b

    def test_a_different_graph_under_one_name_differs(self) -> None:
        one = render([node("a.x")], input_file=".")
        two = render([node("a.x"), node("a.y")], input_file=".")
        assert self.ids(one).isdisjoint(self.ids(two))

    def test_the_three_examples_share_no_id(self) -> None:
        sets = [self.ids(example_svg(name)) for name in EXAMPLES]
        for i, one in enumerate(sets):
            for other in sets[i + 1 :]:
                assert one.isdisjoint(other)

    def test_inlining_two_reports_gives_no_duplicate_id(self) -> None:
        page = example_svg("aws-webapp") + example_svg("k8s-platform")
        ids = re.findall(r'(?<![\w-])id="([^"]+)"', page)
        assert len(ids) == len(set(ids))

    def test_an_aria_reference_points_at_the_own_document(self) -> None:
        svg = example_svg("k8s-platform")
        root = root_of(svg)
        for ref in (root.get("aria-labelledby") or "").split():
            assert f'id="{ref}"' in svg

    def test_the_time_of_the_scan_does_not_change_the_ids(self) -> None:
        def make(stamp: str) -> str:
            report = _report([threat_on("a.x")])
            report.timestamp = stamp
            return format_diagram(report, graph_of([node("a.x")]))

        first, second = make("2026-01-01T00:00:00+00:00"), make("2027-06-01T12:00:00+00:00")
        assert self.ids(first) == self.ids(second)


# -- Frames ---------------------------------------------------------------------


class TestFrameLabels:
    """FV-13: a frame drawn in several places says which part, and no line runs through a label."""

    def graph(self) -> InfraGraph:
        nodes = [
            node("aws_vpc.main", TrustZone.PRIVATE, NodeCategory.NETWORK),
            node("aws_internet_gateway.igw", TrustZone.INTERNET, NodeCategory.NETWORK),
            node("aws_lb.front", TrustZone.DMZ, NodeCategory.NETWORK),
            node("aws_instance.app", TrustZone.PRIVATE),
        ]
        edges = [
            InfraEdge(n, "aws_vpc.main", EdgeType.CONTAINMENT)
            for n in ("aws_internet_gateway.igw", "aws_lb.front", "aws_instance.app")
        ]
        return graph_of(nodes, edges)

    def labels(self, svg: str) -> list[str]:
        return ["".join(g.itertext()) for g in groups(root_of(svg), "frame-label")]

    def test_a_container_in_three_zones_has_three_different_labels(self) -> None:
        svg = format_diagram(_report([]), self.graph())
        assert sorted(self.labels(svg)) == [
            "aws_vpc.main (dmz)",
            "aws_vpc.main (internet)",
            "aws_vpc.main (private)",
        ]

    def test_a_container_in_one_zone_keeps_its_plain_name(self) -> None:
        graph = graph_of(
            [node("aws_vpc.main", TrustZone.PRIVATE, NodeCategory.NETWORK), node("aws_instance.a")],
            [InfraEdge("aws_instance.a", "aws_vpc.main", EdgeType.CONTAINMENT)],
        )
        assert self.labels(format_diagram(_report([]), graph)) == ["aws_vpc.main"]

    def test_labels_are_drawn_above_the_connectors_and_nodes(self) -> None:
        graph = self.graph()
        graph._edges.append(
            crossing("aws_lb.front", "aws_instance.app", "dmz", "private", EdgeType.NETWORK_FLOW)
        )
        svg = format_diagram(_report([]), graph)
        assert svg.index('class="frame-labels"') > svg.rindex('class="node"')
        assert svg.index('class="frame-labels"') > svg.rindex('class="edge-group"')

    def test_a_label_sits_on_a_backing(self) -> None:
        root = root_of(format_diagram(_report([]), self.graph()))
        for label in groups(root, "frame-label"):
            backing = label.find(f"{NS}rect")
            assert backing is not None and backing.get("fill") == "#ffffff"

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_a_label_is_only_crossed_where_its_frame_has_no_free_spot(self, name: str) -> None:
        """A label that a connector runs through had nowhere clear to go along its frame."""
        root = root_of(example_svg(name))
        lines = edge_polylines(root)
        frames = [(g.get("data-id"), rect_of(g.find(f"{NS}rect"))) for g in groups(root, "frame")]  # type: ignore[arg-type]

        def crossed(box: Rect) -> bool:
            return any(
                box.expand(1).intersects_segment(a, b)
                for points in lines
                for a, b in zip(points, points[1:], strict=False)
            )

        for label in groups(root, "frame-label"):
            box = rect_of(label.find(f"{NS}rect"))  # type: ignore[arg-type]
            if not crossed(box):
                continue
            (frame,) = [
                r
                for fid, r in frames
                if fid == label.get("data-id") and r.contains(box.expand(-0.5))
            ]
            slots = range(int(frame.x + 6), int(frame.right - box.w - 6) + 1)
            assert slots and all(crossed(Rect(x, box.y, box.w, box.h)) for x in slots), "".join(
                label.itertext()
            )

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_frame_labels_do_not_overlap_each_other(self, name: str) -> None:
        root = root_of(example_svg(name))
        boxes = [rect_of(g.find(f"{NS}rect")) for g in groups(root, "frame-label")]  # type: ignore[arg-type]
        for i, one in enumerate(boxes):
            assert not any(one.intersects(other) for other in boxes[i + 1 :])


# -- Legend and layout ----------------------------------------------------------


class TestLegendAndLayout:
    """FV-15: the legend describes the shapes drawn, and the diagram uses its width."""

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_no_node_is_a_diamond(self, name: str) -> None:
        for g in groups(root_of(example_svg(name)), "node"):
            assert not g.findall(f"{NS}polygon")

    def test_a_network_component_is_drawn_the_way_the_legend_shows_it(self) -> None:
        root = root_of(example_svg("aws-webapp"))
        legend = groups(root, "legend")[0]
        dashed_in_legend = [r for r in legend.iter(f"{NS}rect") if r.get("stroke-dasharray")]
        assert dashed_in_legend
        (sample,) = dashed_in_legend
        (alb,) = [g for g in groups(root, "node") if g.get("data-id") == "aws_lb.front"]
        outline = alb.findall(f"{NS}rect")[0]
        assert outline.get("stroke") == sample.get("stroke")
        assert "Network (network, cdn, dns, messaging)" in texts_of(legend)

    def test_a_network_flow_is_drawn_as_the_legend_says(self) -> None:
        from threatcode.formatters.diagram import EDGE_STYLES

        color, _, dash = EDGE_STYLES[EdgeType.NETWORK_FLOW]
        legend = groups(root_of(example_svg("k8s-platform")), "legend")[0]
        samples = [
            line
            for line in legend.iter(f"{NS}line")
            if line.get("stroke") == color and line.get("stroke-dasharray") == dash
        ]
        assert samples

    def test_every_legend_entry_is_something_the_diagram_can_draw(self) -> None:
        legend = " ".join(texts_of(groups(root_of(example_svg("aws-webapp")), "legend")[0]))
        for entry in ("Process", "Data store", "Network", "External entity", "Container"):
            assert entry in legend
        assert "Data Flow (network" not in legend

    def test_the_nodes_of_a_lane_use_the_width_of_a_long_path(self) -> None:
        nodes = [node(f"aws_instance.n{i}") for i in range(14)]
        hops = [hop(f"aws_instance.n{i}") for i in range(8)]
        hops.append(hop("aws_instance.n8", None))
        svg = render(nodes, [], paths=[path_of(*hops)])
        root = root_of(svg)
        xs = {float(g.findall(f"{NS}rect")[0].get("x", 0)) for g in groups(root, "node")}
        assert len(xs) > 5  # more than the five columns a narrow canvas gets
        width = float(root.get("viewBox", "").split()[2])
        rights = [float(g.findall(f"{NS}rect")[0].get("x", 0)) + 176 for g in groups(root, "node")]
        assert max(rights) <= width

    def test_a_narrow_diagram_keeps_five_columns(self) -> None:
        nodes = [node(f"aws_instance.n{i}") for i in range(12)]
        root = root_of(render(nodes))
        xs = {float(g.findall(f"{NS}rect")[0].get("x", 0)) for g in groups(root, "node")}
        assert len(xs) == 5

    @pytest.mark.parametrize(
        ("name", "ratio"), [("aws-webapp", 2.1), ("k8s-platform", 1.6), ("agent-workstation", 1.4)]
    )
    def test_the_examples_are_not_absurdly_tall(self, name: str, ratio: float) -> None:
        width, height = (
            float(v) for v in root_of(example_svg(name)).get("viewBox", "").split()[2:]
        )
        assert height / width < ratio, (name, width, height)


# -- Whole diagrams -------------------------------------------------------------


class TestExamplesAsAWhole:
    """FR-21: the diagram was rendered and looked at; these are the checks that came out of it."""

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_it_is_well_formed_and_titled(self, name: str) -> None:
        root = root_of(example_svg(name))
        assert root.tag == f"{NS}svg"
        title = root.find(f"{NS}title")
        assert title is not None and (title.text or "").startswith("ThreatCode threat model of")

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_no_nodes_overlap(self, name: str) -> None:
        root = root_of(example_svg(name))
        boxes = [rect_of(g.findall(f"{NS}rect")[0]) for g in groups(root, "node")]
        for i, one in enumerate(boxes):
            assert not any(one.intersects(other) for other in boxes[i + 1 :]), name

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_every_attack_path_hop_is_on_the_diagram(self, name: str) -> None:
        svg = example_svg(name)
        root = root_of(svg)
        drawn = {
            tuple((g.findtext(f"{NS}title") or "").splitlines()[0].split(" → "))
            for g in groups(root, "edge-group")
            if g.find(f"{NS}path").get("data-path")  # type: ignore[union-attr]
        }
        report = threatcode.analyze(
            REPO / "examples" / name,
            no_timestamp=True,
            **(
                {"ingest": [str(REPO / "examples/aws-webapp/scanner/trivy-app-image.json")]}
                if name == "aws-webapp"
                else {}
            ),
        ).report
        assert report.attack_paths
        node_ids = {g.get("data-id") for g in groups(root, "node")}
        for path in report.attack_paths:
            for here, there in zip(path.hops, path.hops[1:], strict=False):
                if here.node_id in node_ids and there.node_id in node_ids:
                    assert (here.node_id, there.node_id) in drawn, (name, here.node_id)

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_only_connectors_of_a_path_carry_a_path_badge(self, name: str) -> None:
        root = root_of(example_svg(name))
        on_path = sum(1 for p in root.iter(f"{NS}path") if p.get("data-path"))
        assert len(groups(root, "attack-path-marker")) == on_path

    @pytest.mark.parametrize("name", EXAMPLES)
    def test_no_text_sits_outside_the_canvas(self, name: str) -> None:
        root = root_of(example_svg(name))
        width, height = (float(v) for v in root.get("viewBox", "").split()[2:])
        for text in root.iter(f"{NS}text"):
            x, y = float(text.get("x", 0)), float(text.get("y", 0))
            assert 0 <= x <= width and 0 <= y <= height, "".join(text.itertext())

    def test_the_example_scans_still_have_their_numbers_in_the_header(self) -> None:
        svg = example_svg("aws-webapp")
        assert "28 resources" in svg and "14 threats" in svg
