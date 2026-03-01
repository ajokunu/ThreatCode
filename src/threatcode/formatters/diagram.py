"""SVG threat model diagram renderer — data flow diagrams with trust zone swim lanes."""

from __future__ import annotations

from html import escape
from typing import TYPE_CHECKING, Any

from threatcode.ir.edges import EdgeType
from threatcode.ir.nodes import NodeCategory, TrustZone

if TYPE_CHECKING:
    from threatcode.ir.edges import InfraEdge
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.report import ThreatReport
    from threatcode.models.threat import Threat

# Layout constants
NODE_W = 130
NODE_H = 54
NODE_GAP_X = 36
NODE_GAP_Y = 24
LANE_PAD_X = 80
LANE_PAD_Y = 20
HEADER_H = 44
LEGEND_H = 56
MIN_LANE_H = 90
MAX_NODES_PER_ROW = 5
CANVAS_PAD = 20

ZONE_ORDER = [
    TrustZone.INTERNET,
    TrustZone.DMZ,
    TrustZone.PRIVATE,
    TrustZone.DATA,
    TrustZone.MANAGEMENT,
]

ZONE_COLORS: dict[TrustZone, tuple[str, str]] = {
    TrustZone.INTERNET: ("#fef2f2", "#fca5a5"),
    TrustZone.DMZ: ("#fff7ed", "#fdba74"),
    TrustZone.PRIVATE: ("#eff6ff", "#93c5fd"),
    TrustZone.DATA: ("#f0fdf4", "#86efac"),
    TrustZone.MANAGEMENT: ("#faf5ff", "#c4b5fd"),
}

ZONE_LABELS: dict[TrustZone, str] = {
    TrustZone.INTERNET: "INTERNET",
    TrustZone.DMZ: "DMZ",
    TrustZone.PRIVATE: "PRIVATE",
    TrustZone.DATA: "DATA",
    TrustZone.MANAGEMENT: "MANAGEMENT",
}

EDGE_STYLES: dict[EdgeType, tuple[str, str, str]] = {
    # (color, width, dash)
    EdgeType.DEPENDENCY: ("#94a3b8", "1", ""),
    EdgeType.CONTAINMENT: ("#64748b", "1.5", ""),
    EdgeType.NETWORK_FLOW: ("#3b82f6", "1", "4,3"),
    EdgeType.IAM_BINDING: ("#f97316", "1", "2,2"),
    EdgeType.DATA_FLOW: ("#22c55e", "1.5", ""),
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#94a3b8",
}

# STRIDE element → shape mapping
_PROCESS_CATEGORIES = {
    NodeCategory.COMPUTE,
    NodeCategory.SERVERLESS,
    NodeCategory.CONTAINER,
    NodeCategory.MONITORING,
    NodeCategory.UNKNOWN,
}
_DATA_STORE_CATEGORIES = {NodeCategory.STORAGE, NodeCategory.DATABASE}
_DATA_FLOW_CATEGORIES = {
    NodeCategory.NETWORK, NodeCategory.CDN, NodeCategory.DNS, NodeCategory.MESSAGING,
}
_ENTITY_CATEGORIES = {NodeCategory.IAM}

FONT_FAMILY = '"Inter", "Segoe UI", system-ui, sans-serif'


class DiagramRenderer:
    """Renders a threat model data flow diagram as SVG."""

    def __init__(self, report: ThreatReport, graph: InfraGraph) -> None:
        self.report = report
        self.graph = graph
        # Layout state — populated by _compute_layout
        self._node_positions: dict[str, tuple[float, float]] = {}
        self._zone_lanes: list[tuple[TrustZone, float, float, list[Any]]] = []
        self._canvas_w = 0.0
        self._canvas_h = 0.0

    def render(self) -> str:
        self._compute_layout()
        parts: list[str] = []
        parts.append(self._svg_open())
        parts.append(self._svg_defs())
        parts.append(self._svg_header())
        for zone, y, h, nodes in self._zone_lanes:
            parts.append(self._svg_zone_lane(zone, y, h, nodes))
        for edge in self.graph.edges:
            svg = self._svg_edge(edge)
            if svg:
                parts.append(svg)
        for node_id, (x, y) in self._node_positions.items():
            node = self.graph.get_node(node_id)
            if node:
                parts.append(self._svg_node(node, x, y))
        parts.append(self._svg_legend(self._canvas_h - LEGEND_H))
        parts.append("</svg>")
        return "\n".join(parts)

    # ── Layout ──────────────────────────────────────────────────────

    def _compute_layout(self) -> None:
        zones_map = self.graph.nodes_by_zone()
        y_cursor = HEADER_H + CANVAS_PAD
        max_lane_w = 0.0

        for zone in ZONE_ORDER:
            nodes = zones_map.get(zone, [])
            if not nodes:
                continue
            n = len(nodes)
            cols = min(n, MAX_NODES_PER_ROW)
            rows = (n + MAX_NODES_PER_ROW - 1) // MAX_NODES_PER_ROW
            lane_h = max(MIN_LANE_H, rows * (NODE_H + NODE_GAP_Y) + LANE_PAD_Y * 2)
            lane_w = LANE_PAD_X + cols * (NODE_W + NODE_GAP_X) + NODE_GAP_X

            # Position nodes within lane
            for i, node in enumerate(nodes):
                col = i % MAX_NODES_PER_ROW
                row = i // MAX_NODES_PER_ROW
                nx = LANE_PAD_X + NODE_GAP_X + col * (NODE_W + NODE_GAP_X)
                ny = y_cursor + LANE_PAD_Y + row * (NODE_H + NODE_GAP_Y)
                self._node_positions[node.id] = (nx, ny)

            self._zone_lanes.append((zone, y_cursor, lane_h, nodes))
            y_cursor += lane_h
            max_lane_w = max(max_lane_w, lane_w)

        # Handle empty graph
        if not self._zone_lanes:
            max_lane_w = 400

        self._canvas_w = max(max_lane_w + CANVAS_PAD * 2, 400)
        self._canvas_h = y_cursor + LEGEND_H + CANVAS_PAD

    def _threats_for_node(self, node_id: str) -> list[Threat]:
        return [t for t in self.report.threats if t.resource_address == node_id]

    # ── SVG building blocks ─────────────────────────────────────────

    def _svg_open(self) -> str:
        w = self._canvas_w
        h = self._canvas_h
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {w:.0f} {h:.0f}" '
            f'width="{w:.0f}" height="{h:.0f}" '
            f'font-family={_quote(FONT_FAMILY)}>'
        )

    def _svg_defs(self) -> str:
        return (
            "<defs>"
            # Drop shadow filter
            '<filter id="shadow" x="-4%" y="-4%" width="108%" height="116%">'
            '<feDropShadow dx="0" dy="1" stdDeviation="2" flood-opacity="0.08"/>'
            "</filter>"
            # Glow filter for boundary-crossing edges
            '<filter id="glow" x="-10%" y="-10%" width="120%" height="120%">'
            '<feGaussianBlur stdDeviation="2" result="blur"/>'
            '<feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>'
            "</filter>"
            # Arrow markers per edge type
            + self._svg_arrow_markers()
            + "</defs>"
        )

    def _svg_arrow_markers(self) -> str:
        markers: list[str] = []
        for etype, (color, _, _) in EDGE_STYLES.items():
            mid = f"arrow-{etype.value}"
            markers.append(
                f'<marker id="{mid}" viewBox="0 0 10 7" refX="10" refY="3.5" '
                f'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
                f'<polygon points="0 0, 10 3.5, 0 7" fill="{color}"/>'
                f"</marker>"
            )
        # Boundary crossing marker (red)
        markers.append(
            '<marker id="arrow-boundary" viewBox="0 0 10 7" refX="10" refY="3.5" '
            'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
            '<polygon points="0 0, 10 3.5, 0 7" fill="#ef4444"/>'
            "</marker>"
        )
        return "".join(markers)

    def _svg_header(self) -> str:
        w = self._canvas_w
        n_res = self.report.scanned_resources or self.graph.node_count
        n_threats = len(self.report.threats)
        title = "ThreatCode Threat Model"
        meta = f"{n_res} resources \u00b7 {n_threats} threats"
        ts = self.report.timestamp[:19] if self.report.timestamp else ""
        return (
            f'<rect x="0" y="0" width="{w:.0f}" height="{HEADER_H}" fill="#1e293b" rx="0"/>'
            f'<text x="16" y="{HEADER_H // 2 + 5}" fill="#ffffff" '
            f'font-size="14" font-weight="600">{_esc(title)}</text>'
            f'<text x="{w - 16}" y="{HEADER_H // 2 + 5}" fill="#94a3b8" '
            f'font-size="11" text-anchor="end">{_esc(meta)}  {_esc(ts)}</text>'
        )

    def _svg_zone_lane(self, zone: TrustZone, y: float, h: float, nodes: list[Any]) -> str:
        w = self._canvas_w
        fill, border = ZONE_COLORS.get(zone, ("#f8fafc", "#cbd5e1"))
        label = ZONE_LABELS.get(zone, zone.value.upper())
        return (
            f'<g class="zone-{zone.value}">'
            f'<rect x="0" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" '
            f'fill="{fill}" stroke="{border}" stroke-width="1"/>'
            f'<text x="12" y="{y + 24:.0f}" fill="{border}" '
            f'font-size="10" font-weight="600" letter-spacing="0.5">{_esc(label)}</text>'
            f"</g>"
        )

    def _svg_node(self, node: Any, x: float, y: float) -> str:
        threats = self._threats_for_node(node.id)
        cat = node.category
        # Select shape
        if cat in _DATA_STORE_CATEGORIES:
            shape = self._svg_node_datastore(x, y, NODE_W, NODE_H)
        elif cat in _DATA_FLOW_CATEGORIES:
            shape = self._svg_node_dataflow(x, y, NODE_W, NODE_H)
        elif cat in _ENTITY_CATEGORIES:
            shape = self._svg_node_entity(x, y, NODE_W, NODE_H)
        else:
            shape = self._svg_node_process(x, y, NODE_W, NODE_H)

        # Short name: last segment after dot
        short_name = node.name if "." not in node.id else node.id.rsplit(".", 1)[-1]
        cat_label = cat.value

        parts = [
            f'<g class="node" data-id="{_esc(node.id)}" filter="url(#shadow)">',
            shape,
            # Category label (top-left)
            f'<text x="{x + 8:.0f}" y="{y + 14:.0f}" fill="#94a3b8" '
            f'font-size="8">{_esc(cat_label)}</text>',
            # Resource name (center)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + NODE_H / 2 + 5:.0f}" '
            f'fill="#1e293b" font-size="11" font-weight="500" text-anchor="middle">'
            f"{_esc(short_name)}</text>",
        ]

        if threats:
            worst = max(threats, key=lambda t: t.severity.rank)
            badge = self._svg_threat_badge(
                x + NODE_W - 10, y - 4, len(threats), worst.severity.value,
            )
            parts.append(badge)

        parts.append("</g>")
        return "\n".join(parts)

    def _svg_node_process(self, x: float, y: float, w: float, h: float) -> str:
        return (
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{w}" height="{h}" '
            f'rx="6" ry="6" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
        )

    def _svg_node_datastore(self, x: float, y: float, w: float, h: float) -> str:
        ry = 6
        return (
            f'<rect x="{x:.0f}" y="{y + ry:.0f}" width="{w}" height="{h - ry * 2}" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
            f'<ellipse cx="{x + w / 2:.0f}" cy="{y + ry:.0f}" rx="{w / 2}" ry="{ry}" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
            f'<ellipse cx="{x + w / 2:.0f}" cy="{y + h - ry:.0f}" rx="{w / 2}" ry="{ry}" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
        )

    def _svg_node_dataflow(self, x: float, y: float, w: float, h: float) -> str:
        cx = x + w / 2
        cy = y + h / 2
        hw = w / 2
        hh = h / 2
        points = f"{cx},{cy - hh} {cx + hw},{cy} {cx},{cy + hh} {cx - hw},{cy}"
        return (
            f'<polygon points="{points}" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
        )

    def _svg_node_entity(self, x: float, y: float, w: float, h: float) -> str:
        return (
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{w}" height="{h}" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'
            f'<rect x="{x + 3:.0f}" y="{y + 3:.0f}" width="{w - 6}" height="{h - 6}" '
            f'fill="none" stroke="#cbd5e1" stroke-width="1"/>'
        )

    def _svg_threat_badge(self, x: float, y: float, count: int, severity: str) -> str:
        color = SEVERITY_COLORS.get(severity, "#94a3b8")
        return (
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="7" fill="{color}"/>'
            f'<text x="{x:.0f}" y="{y + 3.5:.0f}" fill="#ffffff" '
            f'font-size="9" font-weight="600" text-anchor="middle">{count}</text>'
        )

    def _svg_edge(self, edge: InfraEdge) -> str:
        src_pos = self._node_positions.get(edge.source)
        tgt_pos = self._node_positions.get(edge.target)
        if not src_pos or not tgt_pos:
            return ""

        x1 = src_pos[0] + NODE_W / 2
        y1 = src_pos[1] + NODE_H
        x2 = tgt_pos[0] + NODE_W / 2
        y2 = tgt_pos[1]

        path_d = self._bezier(x1, y1, x2, y2)

        is_boundary = edge.crosses_trust_boundary
        if is_boundary:
            color = "#ef4444"
            width = "2"
            dash = ""
            marker = "url(#arrow-boundary)"
            filt = ' filter="url(#glow)"'
        else:
            color, width, dash = EDGE_STYLES.get(edge.edge_type, ("#94a3b8", "1", ""))
            marker = f"url(#arrow-{edge.edge_type.value})"
            filt = ""

        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        return (
            f'<path d="{path_d}" fill="none" stroke="{color}" '
            f'stroke-width="{width}"{dash_attr} '
            f'marker-end="{marker}"{filt} '
            f'class="edge" data-type="{edge.edge_type.value}" '
            f'data-boundary="{str(is_boundary).lower()}"/>'
        )

    def _svg_legend(self, y: float) -> str:
        w = self._canvas_w
        lx = 16.0
        items: list[str] = [
            f'<rect x="0" y="{y:.0f}" width="{w:.0f}" height="{LEGEND_H}" fill="#f8fafc"/>',
            f'<line x1="0" y1="{y:.0f}" x2="{w:.0f}" y2="{y:.0f}" '
            f'stroke="#e2e8f0" stroke-width="1"/>',
        ]

        ly = y + 20
        # Node shapes
        shapes = [
            ("\u25c7 data_flow", "#3b82f6"),
            ("\u256d\u256e process", "#64748b"),
            ("\u2503\u2503 data_store", "#22c55e"),
            ("\u250c\u2510 entity", "#f97316"),
        ]
        for label, color in shapes:
            items.append(
                f'<text x="{lx:.0f}" y="{ly:.0f}" fill="{color}" '
                f'font-size="9" font-weight="500">{_esc(label)}</text>'
            )
            lx += 90

        # Severity colors
        ly2 = y + 40
        lx2 = 16.0
        for sev, color in [
            ("critical", "#ef4444"),
            ("high", "#f97316"),
            ("medium", "#eab308"),
            ("low", "#3b82f6"),
        ]:
            items.append(
                f'<circle cx="{lx2 + 4:.0f}" cy="{ly2 - 3:.0f}" r="4" fill="{color}"/>'
            )
            items.append(
                f'<text x="{lx2 + 12:.0f}" y="{ly2:.0f}" fill="#64748b" '
                f'font-size="9">{sev}</text>'
            )
            lx2 += 72

        items.append(
            f'<text x="{w - 16:.0f}" y="{ly:.0f}" fill="#cbd5e1" '
            f'font-size="9" text-anchor="end">Generated by ThreatCode</text>'
        )

        return f'<g class="legend">{"".join(items)}</g>'

    # ── Geometry helpers ────────────────────────────────────────────

    def _bezier(self, x1: float, y1: float, x2: float, y2: float) -> str:
        dy = abs(y2 - y1)
        if dy < 10:
            # Same-zone: shallow curve
            offset = 20.0
        else:
            offset = dy * 0.4
        cy1 = y1 + offset
        cy2 = y2 - offset
        return f"M{x1:.1f},{y1:.1f} C{x1:.1f},{cy1:.1f} {x2:.1f},{cy2:.1f} {x2:.1f},{y2:.1f}"


def _esc(text: str) -> str:
    """XML-escape text for safe SVG embedding."""
    return escape(str(text))


def _quote(text: str) -> str:
    """Quote an attribute value."""
    return f'"{_esc(text)}"'


def format_diagram(report: ThreatReport, graph: InfraGraph) -> str:
    """Format a threat report + graph as an SVG data flow diagram."""
    return DiagramRenderer(report, graph).render()
