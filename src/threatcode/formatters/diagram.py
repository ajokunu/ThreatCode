"""SVG threat model diagram renderer — data flow diagrams with trust zone swim lanes."""

from __future__ import annotations

import logging
from html import escape
from typing import TYPE_CHECKING, Any

import networkx as nx

from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.ir.edges import EdgeType
from threatcode.ir.nodes import NodeCategory, TrustZone

if TYPE_CHECKING:
    from threatcode.ir.edges import InfraEdge
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.report import ThreatReport
    from threatcode.models.threat import Threat

logger = logging.getLogger(__name__)

# Layout constants
NODE_W = 160
NODE_H = 54
NODE_GAP_X = 36
NODE_GAP_Y = 24
LANE_PAD_X = 80
LANE_PAD_Y = 20
HEADER_H = 44
SUMMARY_BAR_H = 32
LEGEND_H = 140
THREAT_TABLE_ROW_H = 20
THREAT_TABLE_HEADER_H = 28
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

EDGE_LABELS: dict[EdgeType, str] = {
    EdgeType.DEPENDENCY: "Dependency",
    EdgeType.CONTAINMENT: "Containment",
    EdgeType.NETWORK_FLOW: "Network Flow",
    EdgeType.IAM_BINDING: "IAM Binding",
    EdgeType.DATA_FLOW: "Data Flow",
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#ef4444",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#3b82f6",
    "info": "#94a3b8",
}

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Attack path visualization constants
ATTACK_PATH_SECTION_TITLE_H = 28
ATTACK_PATH_ROW_H = 56
ATTACK_PATH_NODE_W = 120
ATTACK_PATH_NODE_H = 28
ATTACK_PATH_ARROW_W = 60
ATTACK_PATH_PAD = 16
ATTACK_PATH_MAX_PATHS = 5
ATTACK_PATH_CIRCLE_R = 9

# Entry/target zones for attack path computation
_ENTRY_ZONES = {TrustZone.INTERNET, TrustZone.DMZ}
_TARGET_ZONES = {TrustZone.DATA, TrustZone.MANAGEMENT}

STRIDE_DISPLAY: dict[str, str] = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Info Disclosure",
    "denial_of_service": "Denial of Service",
    "elevation_of_privilege": "Elevation of Privilege",
}

# STRIDE element -> shape mapping
_PROCESS_CATEGORIES = {
    NodeCategory.COMPUTE,
    NodeCategory.SERVERLESS,
    NodeCategory.CONTAINER,
    NodeCategory.MONITORING,
    NodeCategory.UNKNOWN,
}
_DATA_STORE_CATEGORIES = {NodeCategory.STORAGE, NodeCategory.DATABASE}
_DATA_FLOW_CATEGORIES = {
    NodeCategory.NETWORK,
    NodeCategory.CDN,
    NodeCategory.DNS,
    NodeCategory.MESSAGING,
}
_ENTITY_CATEGORIES = {NodeCategory.IAM}

FONT_FAMILY = '"Inter", "Segoe UI", system-ui, sans-serif'


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if it exceeds max_len."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


class DiagramRenderer:
    """Renders a threat model data flow diagram as SVG."""

    def __init__(self, report: ThreatReport, graph: InfraGraph) -> None:
        self.report = report
        self.graph = graph
        # Layout state -- populated by _compute_layout
        self._node_positions: dict[str, tuple[float, float]] = {}
        self._zone_lanes: list[tuple[TrustZone, float, float, list[Any]]] = []
        self._canvas_w = 0.0
        self._canvas_h = 0.0
        # Attack path state -- populated by _compute_attack_paths
        self._attack_paths: list[tuple[int, str, list[str]]] = []  # (num, severity, node_ids)
        self._edge_attack_path_map: dict[tuple[str, str], list[int]] = {}
        self._attack_paths_y = 0.0

    def render(self) -> str:
        self._compute_layout()
        parts: list[str] = []
        parts.append(self._svg_open())
        parts.append(self._svg_defs())
        parts.append(self._svg_header())
        parts.append(self._svg_summary_bar())
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
        parts.append(self._svg_attack_paths())
        parts.append(self._svg_threat_table())
        parts.append(self._svg_legend())
        parts.append("</svg>")
        return "\n".join(parts)

    # -- Layout ---------------------------------------------------------------

    def _compute_layout(self) -> None:
        zones_map = self.graph.nodes_by_zone()
        y_cursor = HEADER_H + SUMMARY_BAR_H + CANVAS_PAD
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

        # Compute attack paths before sizing
        self._compute_attack_paths()
        self._build_edge_attack_path_map()

        # Attack path section height
        attack_path_h = 0.0
        if self._attack_paths:
            attack_path_h = (
                ATTACK_PATH_SECTION_TITLE_H
                + len(self._attack_paths) * ATTACK_PATH_ROW_H
                + ATTACK_PATH_PAD * 2
            )

        # Compute attack path section width requirement
        attack_path_w = 0.0
        for _, _, path_nodes in self._attack_paths:
            n = len(path_nodes)
            pw = ATTACK_PATH_PAD * 2 + n * ATTACK_PATH_NODE_W + (n - 1) * ATTACK_PATH_ARROW_W
            attack_path_w = max(attack_path_w, pw)

        # Threat table height
        n_threats = len(self.report.threats)
        threat_table_h = 0.0
        if n_threats > 0:
            threat_table_h = (
                THREAT_TABLE_HEADER_H
                + n_threats * THREAT_TABLE_ROW_H
                + 40  # section title + padding
            )

        # Ensure canvas is wide enough for legend, attack paths, and expanded table
        min_legend_w = 900
        self._canvas_w = max(
            max_lane_w + CANVAS_PAD * 2, 400, min_legend_w, attack_path_w + CANVAS_PAD * 2
        )
        self._attack_paths_y = y_cursor
        y_cursor += attack_path_h
        self._threat_table_y = y_cursor
        y_cursor += threat_table_h
        self._legend_y = y_cursor
        self._canvas_h = y_cursor + LEGEND_H + CANVAS_PAD

    def _threats_for_node(self, node_id: str) -> list[Threat]:
        return [t for t in self.report.threats if t.resource_address == node_id]

    def _sorted_threats(self) -> list[Threat]:
        """Return all threats sorted by severity (critical first)."""
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(self.report.threats, key=lambda t: rank.get(t.severity.value, 99))

    # -- Attack path computation -----------------------------------------------

    def _compute_attack_paths(self) -> None:
        """Find exploitable routes from entry points to critical targets."""
        nodes = self.graph.nodes
        if not nodes:
            return

        # Identify entry and target nodes that have threats
        threat_nodes = {t.resource_address for t in self.report.threats}
        entries = [
            nid for nid, n in nodes.items() if n.trust_zone in _ENTRY_ZONES and nid in threat_nodes
        ]
        targets = [
            nid for nid, n in nodes.items() if n.trust_zone in _TARGET_ZONES and nid in threat_nodes
        ]

        if not entries or not targets:
            return

        # Use undirected view for pathfinding (attacks can traverse edges either way)
        undirected = self.graph._graph.to_undirected()

        raw_paths: list[tuple[str, list[str]]] = []
        seen: set[tuple[str, ...]] = set()
        severity_rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}

        for entry in entries:
            for target in targets:
                if entry == target:
                    continue
                try:
                    path = nx.shortest_path(undirected, entry, target)
                except nx.NetworkXNoPath:
                    continue

                path_key = tuple(path)
                if path_key in seen:
                    continue
                seen.add(path_key)

                # Only keep paths where >= 2 nodes have threats
                threatened_in_path = [nid for nid in path if nid in threat_nodes]
                if len(threatened_in_path) < 2:
                    continue

                # Determine worst severity across threats on path nodes
                worst_sev = "info"
                for nid in path:
                    for t in self._threats_for_node(nid):
                        if severity_rank.get(t.severity.value, 99) < severity_rank.get(
                            worst_sev, 99
                        ):
                            worst_sev = t.severity.value

                raw_paths.append((worst_sev, list(path)))

        # Sort by worst severity (critical first), limit
        raw_paths.sort(key=lambda p: severity_rank.get(p[0], 99))
        self._attack_paths = [
            (i + 1, sev, path) for i, (sev, path) in enumerate(raw_paths[:ATTACK_PATH_MAX_PATHS])
        ]

    def _build_edge_attack_path_map(self) -> None:
        """Map (source, target) edge pairs to attack path numbers."""
        self._edge_attack_path_map = {}
        for path_num, _, path_nodes in self._attack_paths:
            for i in range(len(path_nodes) - 1):
                a, b = path_nodes[i], path_nodes[i + 1]
                # Check both directions since undirected pathfinding may reverse edges
                for key in [(a, b), (b, a)]:
                    self._edge_attack_path_map.setdefault(key, []).append(path_num)

    def _format_mitre_techniques(self, threat: Threat) -> str:
        """Format MITRE ATT&CK technique IDs with names."""
        if not threat.mitre_techniques:
            return "-"
        parts: list[str] = []
        for tid in threat.mitre_techniques:
            tech = TECHNIQUE_DB.get(tid)
            if tech:
                parts.append(f"{tid}: {tech['name']}")
            else:
                parts.append(tid)
        return ", ".join(parts)

    # -- SVG building blocks --------------------------------------------------

    def _svg_open(self) -> str:
        w = self._canvas_w
        h = self._canvas_h
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {w:.0f} {h:.0f}" '
            f'width="{w:.0f}" height="{h:.0f}" '
            f"font-family={_quote(FONT_FAMILY)}>"
        )

    def _svg_defs(self) -> str:
        return (
            "<defs>"
            + self._svg_style()
            + '<filter id="shadow" x="-4%" y="-4%" width="108%" height="116%">'
            '<feDropShadow dx="0" dy="1" stdDeviation="2" flood-opacity="0.08"/>'
            "</filter>"
            '<filter id="glow" x="-10%" y="-10%" width="120%" height="120%">'
            '<feGaussianBlur stdDeviation="2" result="blur"/>'
            '<feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>'
            "</filter>" + self._svg_arrow_markers() + "</defs>"
        )

    def _svg_style(self) -> str:
        return (
            "<style>"
            ".node { cursor: pointer; }"
            ".node:hover rect, .node:hover ellipse, "
            ".node:hover polygon { stroke-width: 2.5; stroke: #475569; }"
            ".edge { cursor: pointer; }"
            ".edge:hover { stroke-width: 3 !important; opacity: 0.9; }"
            ".threat-row:hover rect { opacity: 0.8; }"
            ".tooltip { display: none; }"
            ".node:hover .tooltip, .edge:hover .tooltip { display: block; }"
            ".attack-path-marker { pointer-events: none; }"
            "</style>"
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
        markers.append(
            '<marker id="arrow-boundary" viewBox="0 0 10 7" refX="10" refY="3.5" '
            'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
            '<polygon points="0 0, 10 3.5, 0 7" fill="#ef4444"/>'
            "</marker>"
        )
        markers.append(
            '<marker id="arrow-attack-path" viewBox="0 0 10 7" refX="10" refY="3.5" '
            'markerWidth="8" markerHeight="6" orient="auto-start-reverse">'
            '<polygon points="0 0, 10 3.5, 0 7" fill="#dc2626"/>'
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

    def _svg_summary_bar(self) -> str:
        w = self._canvas_w
        y = HEADER_H
        parts: list[str] = [
            '<g class="summary-bar">',
            f'<rect x="0" y="{y}" width="{w:.0f}" height="{SUMMARY_BAR_H}" fill="#f1f5f9"/>',
            f'<line x1="0" y1="{y + SUMMARY_BAR_H}" x2="{w:.0f}" '
            f'y2="{y + SUMMARY_BAR_H}" stroke="#e2e8f0" stroke-width="1"/>',
        ]

        # Count threats by severity
        counts: dict[str, int] = {}
        stride_cats: set[str] = set()
        for t in self.report.threats:
            counts[t.severity.value] = counts.get(t.severity.value, 0) + 1
            stride_cats.add(t.stride_category)

        cx = 16.0
        cy = y + SUMMARY_BAR_H / 2 + 4
        for sev in SEVERITY_ORDER:
            count = counts.get(sev, 0)
            if count == 0:
                continue
            color = SEVERITY_COLORS.get(sev, "#94a3b8")
            label = f"{count} {sev.capitalize()}"
            pill_w = len(label) * 6.5 + 16
            # Pill background
            parts.append(
                f'<rect x="{cx:.0f}" y="{cy - 10:.0f}" width="{pill_w:.0f}" '
                f'height="18" rx="9" fill="{color}" opacity="0.15"/>'
            )
            # Pill dot
            parts.append(f'<circle cx="{cx + 10:.0f}" cy="{cy - 1:.0f}" r="3" fill="{color}"/>')
            # Pill text
            parts.append(
                f'<text x="{cx + 17:.0f}" y="{cy + 3:.0f}" fill="{color}" '
                f'font-size="10" font-weight="600">{_esc(label)}</text>'
            )
            cx += pill_w + 8

        # Total summary
        total = len(self.report.threats)
        n_stride = len(stride_cats)
        if total > 0:
            summary = f"Total: {total} threats across {n_stride} STRIDE categories"
            parts.append(
                f'<text x="{w - 16:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
                f'font-size="9" text-anchor="end">{_esc(summary)}</text>'
            )

        parts.append("</g>")
        return "\n".join(parts)

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
        if cat in _DATA_STORE_CATEGORIES:
            shape = self._svg_node_datastore(x, y, NODE_W, NODE_H)
        elif cat in _DATA_FLOW_CATEGORIES:
            shape = self._svg_node_dataflow(x, y, NODE_W, NODE_H)
        elif cat in _ENTITY_CATEGORIES:
            shape = self._svg_node_entity(x, y, NODE_W, NODE_H)
        else:
            shape = self._svg_node_process(x, y, NODE_W, NODE_H)

        # Resource type (first part of ID before the dot, or resource_type)
        res_type = node.resource_type if node.resource_type else node.id.split(".")[0]
        res_type_display = _truncate(res_type, 22)

        # Short name: last segment after dot
        short_name = node.name if "." not in node.id else node.id.rsplit(".", 1)[-1]

        parts = [
            f'<g class="node" data-id="{_esc(node.id)}" filter="url(#shadow)">',
            shape,
            # Resource type label (top, 8px gray)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + 14:.0f}" fill="#94a3b8" '
            f'font-size="8" text-anchor="middle">{_esc(res_type_display)}</text>',
            # Resource short name (center, 11px bold)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + NODE_H / 2 + 5:.0f}" '
            f'fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">'
            f"{_esc(short_name)}</text>",
        ]

        # Tooltip via <title>
        tooltip = self._node_tooltip(node, threats)
        parts.append(f"<title>{_esc(tooltip)}</title>")

        if threats:
            worst = max(threats, key=lambda t: t.severity.rank)
            badge = self._svg_threat_badge(
                x + NODE_W - 10,
                y - 4,
                len(threats),
                worst.severity.value,
            )
            parts.append(badge)

        parts.append("</g>")
        return "\n".join(parts)

    def _node_tooltip(self, node: Any, threats: list[Threat]) -> str:
        """Build native browser tooltip text for a node."""
        zone_label = ZONE_LABELS.get(node.trust_zone, node.trust_zone.value.upper())
        lines = [
            node.id,
            f"Zone: {zone_label} | Category: {node.category.value}",
        ]
        if threats:
            sorted_threats = sorted(threats, key=lambda t: -t.severity.rank)
            lines.append("")
            lines.append(f"{len(threats)} threats:")
            for t in sorted_threats:
                sev = t.severity.value.upper()
                stride = STRIDE_DISPLAY.get(t.stride_category, t.stride_category)
                lines.append(f"  {sev} - {t.title} ({stride})")
        return "\n".join(lines)

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
        return f'<polygon points="{points}" fill="#ffffff" stroke="#cbd5e1" stroke-width="1.5"/>'

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

        # Build tooltip
        tooltip = self._edge_tooltip(edge)

        parts: list[str] = [
            '<g class="edge-group">',
            f'<path d="{path_d}" fill="none" stroke="{color}" '
            f'stroke-width="{width}"{dash_attr} '
            f'marker-end="{marker}"{filt} '
            f'class="edge" data-type="{edge.edge_type.value}" '
            f'data-boundary="{str(is_boundary).lower()}"/>',
            f"<title>{_esc(tooltip)}</title>",
        ]

        # Edge label for boundary crossings
        if is_boundary:
            label = self._edge_label_text(edge)
            if label:
                mx = (x1 + x2) / 2
                my = (y1 + y2) / 2
                parts.append(self._svg_edge_label(mx, my, label))

        # Attack path overlay markers
        path_nums = self._edge_attack_path_map.get((edge.source, edge.target), [])
        if not path_nums:
            path_nums = self._edge_attack_path_map.get((edge.target, edge.source), [])
        if path_nums:
            mx = (x1 + x2) / 2
            my = (y1 + y2) / 2
            for j, pnum in enumerate(path_nums):
                offset_x = j * (ATTACK_PATH_CIRCLE_R * 2 + 2)
                parts.append(
                    f'<g class="attack-path-marker">'
                    f'<circle cx="{mx + offset_x:.0f}" cy="{my + 12:.0f}" '
                    f'r="{ATTACK_PATH_CIRCLE_R}" fill="#dc2626"/>'
                    f'<text x="{mx + offset_x:.0f}" y="{my + 16:.0f}" fill="#ffffff" '
                    f'font-size="9" font-weight="700" text-anchor="middle">{pnum}</text>'
                    f"</g>"
                )

        parts.append("</g>")
        return "\n".join(parts)

    def _edge_tooltip(self, edge: InfraEdge) -> str:
        """Build tooltip text for an edge."""
        if edge.crosses_trust_boundary:
            src_zone = edge.metadata.get("source_zone", "?")
            tgt_zone = edge.metadata.get("target_zone", "?")
            return (
                f"Trust boundary crossing: {src_zone} -> {tgt_zone}\n"
                f"Data should be encrypted, authenticated, and validated"
            )
        label = EDGE_LABELS.get(edge.edge_type, edge.edge_type.value)
        return f"{label}: {edge.source} -> {edge.target}"

    def _edge_label_text(self, edge: InfraEdge) -> str:
        """Return zone transition label for boundary-crossing edges."""
        src_zone = edge.metadata.get("source_zone", "")
        tgt_zone = edge.metadata.get("target_zone", "")
        if src_zone and tgt_zone:
            return f"{src_zone.upper()} -> {tgt_zone.upper()}"
        return ""

    def _svg_edge_label(self, x: float, y: float, text: str) -> str:
        """Render a small label at the midpoint of a boundary-crossing edge."""
        text_w = len(text) * 5.5 + 8
        return (
            f'<rect x="{x - text_w / 2:.0f}" y="{y - 7:.0f}" '
            f'width="{text_w:.0f}" height="14" rx="3" fill="#ffffff" '
            f'stroke="#ef4444" stroke-width="0.5" opacity="0.95"/>'
            f'<text x="{x:.0f}" y="{y + 3:.0f}" fill="#ef4444" '
            f'font-size="8" font-weight="500" text-anchor="middle" '
            f'class="edge-label">{_esc(text)}</text>'
        )

    def _svg_attack_paths(self) -> str:
        """Render attack path chains between diagram and threat table."""
        if not self._attack_paths:
            return ""

        y = self._attack_paths_y
        parts: list[str] = ['<g class="attack-paths">']

        # Section title
        parts.append(
            f'<text x="16" y="{y + 18:.0f}" fill="#1e293b" '
            f'font-size="12" font-weight="600">Attack Paths</text>'
        )
        y += ATTACK_PATH_SECTION_TITLE_H

        for path_num, worst_sev, path_nodes in self._attack_paths:
            sev_color = SEVERITY_COLORS.get(worst_sev, "#94a3b8")
            sev_label = worst_sev.capitalize()

            # Path header line
            parts.append(
                f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{y + 14:.0f}" fill="{sev_color}" '
                f'font-size="10" font-weight="600">'
                f"Attack Path {path_num} ({_esc(sev_label)})</text>"
            )
            y += 18

            # Draw chain of nodes with arrows
            cx = float(ATTACK_PATH_PAD)
            node_cy = y + ATTACK_PATH_NODE_H / 2

            for i, nid in enumerate(path_nodes):
                short_name = nid.rsplit(".", 1)[-1] if "." in nid else nid
                short_name = _truncate(short_name, 14)

                # Node box
                parts.append(
                    f'<rect x="{cx:.0f}" y="{y:.0f}" '
                    f'width="{ATTACK_PATH_NODE_W}" height="{ATTACK_PATH_NODE_H}" '
                    f'rx="4" fill="#ffffff" stroke="{sev_color}" stroke-width="1.5"/>'
                )
                # Node label
                parts.append(
                    f'<text x="{cx + ATTACK_PATH_NODE_W / 2:.0f}" '
                    f'y="{node_cy + 4:.0f}" fill="#1e293b" '
                    f'font-size="9" font-weight="600" text-anchor="middle">'
                    f"{_esc(short_name)}</text>"
                )

                # Annotation below: worst threat title for this node
                node_threats = self._threats_for_node(nid)
                if node_threats:
                    worst_t = max(node_threats, key=lambda t: t.severity.rank)
                    ann = _truncate(worst_t.title, 18)
                    parts.append(
                        f'<text x="{cx + ATTACK_PATH_NODE_W / 2:.0f}" '
                        f'y="{y + ATTACK_PATH_NODE_H + 12:.0f}" fill="#64748b" '
                        f'font-size="7" text-anchor="middle">{_esc(ann)}</text>'
                    )

                cx += ATTACK_PATH_NODE_W

                # Arrow to next node
                if i < len(path_nodes) - 1:
                    # Find edge type between this pair
                    edge_label = self._find_edge_type_label(nid, path_nodes[i + 1])
                    arrow_y = node_cy
                    parts.append(
                        f'<line x1="{cx:.0f}" y1="{arrow_y:.0f}" '
                        f'x2="{cx + ATTACK_PATH_ARROW_W - 8:.0f}" y2="{arrow_y:.0f}" '
                        f'stroke="{sev_color}" stroke-width="1.5" '
                        f'marker-end="url(#arrow-attack-path)"/>'
                    )
                    if edge_label:
                        parts.append(
                            f'<text x="{cx + ATTACK_PATH_ARROW_W / 2:.0f}" '
                            f'y="{arrow_y - 5:.0f}" fill="#94a3b8" '
                            f'font-size="7" text-anchor="middle">{_esc(edge_label)}</text>'
                        )
                    cx += ATTACK_PATH_ARROW_W

            y += ATTACK_PATH_ROW_H - 18  # remaining row height

        parts.append("</g>")
        return "\n".join(parts)

    def _find_edge_type_label(self, source: str, target: str) -> str:
        """Find the edge type label between two nodes (either direction)."""
        for edge in self.graph.edges:
            if (edge.source == source and edge.target == target) or (
                edge.source == target and edge.target == source
            ):
                return EDGE_LABELS.get(edge.edge_type, edge.edge_type.value)
        return ""

    def _svg_threat_table(self) -> str:
        """Render a full threat listing table below the diagram."""
        threats = self._sorted_threats()
        if not threats:
            return ""

        y = self._threat_table_y
        w = self._canvas_w
        parts: list[str] = ['<g class="threat-table">']

        # Section title
        parts.append(
            f'<text x="16" y="{y + 18:.0f}" fill="#1e293b" '
            f'font-size="12" font-weight="600">Threat Findings</text>'
        )
        y += 28

        # Column widths (proportional to canvas)
        col_sev_w = 56
        col_res_w = min(150, w * 0.15)
        col_threat_w = min(160, w * 0.17)
        col_desc_w = min(170, w * 0.18)
        col_attack_w = min(160, w * 0.17)
        col_stride_w = min(110, w * 0.12)
        col_source_w = 50

        # Header row
        parts.append(
            f'<rect x="16" y="{y:.0f}" width="{w - 32:.0f}" '
            f'height="{THREAT_TABLE_HEADER_H}" rx="4" fill="#1e293b"/>'
        )
        hx = 24.0
        hy = y + THREAT_TABLE_HEADER_H / 2 + 4
        headers = [
            ("Severity", col_sev_w),
            ("Resource", col_res_w),
            ("Threat", col_threat_w),
            ("Description", col_desc_w),
            ("ATT&amp;CK Technique", col_attack_w),
            ("STRIDE Category", col_stride_w),
            ("Source", col_source_w),
        ]
        for label, col_w in headers:
            parts.append(
                f'<text x="{hx:.0f}" y="{hy:.0f}" fill="#ffffff" '
                f'font-size="9" font-weight="600">{label}</text>'
            )
            hx += col_w

        y += THREAT_TABLE_HEADER_H

        # Data rows
        for i, threat in enumerate(threats):
            row_fill = "#ffffff" if i % 2 == 0 else "#f8fafc"
            parts.append(
                f'<g class="threat-row">'
                f'<rect x="16" y="{y:.0f}" width="{w - 32:.0f}" '
                f'height="{THREAT_TABLE_ROW_H}" fill="{row_fill}"/>'
            )

            rx = 24.0
            ry = y + THREAT_TABLE_ROW_H / 2 + 3.5

            # Severity dot + label
            sev = threat.severity.value
            sev_color = SEVERITY_COLORS.get(sev, "#94a3b8")
            sev_label = sev.upper()[:4]
            parts.append(f'<circle cx="{rx + 4:.0f}" cy="{ry - 2:.0f}" r="3" fill="{sev_color}"/>')
            parts.append(
                f'<text x="{rx + 12:.0f}" y="{ry:.0f}" fill="{sev_color}" '
                f'font-size="9" font-weight="600">{_esc(sev_label)}</text>'
            )
            rx += col_sev_w

            # Resource
            res_display = _truncate(threat.resource_address, 22)
            parts.append(
                f'<text x="{rx:.0f}" y="{ry:.0f}" fill="#475569" '
                f'font-size="9">{_esc(res_display)}</text>'
            )
            rx += col_res_w

            # Threat title
            title_display = _truncate(threat.title, 28)
            parts.append(
                f'<text x="{rx:.0f}" y="{ry:.0f}" fill="#1e293b" '
                f'font-size="9">{_esc(title_display)}</text>'
            )
            rx += col_threat_w

            # Description (truncated, full in tooltip)
            desc_display = _truncate(threat.description, 60)
            parts.append(
                f'<text x="{rx:.0f}" y="{ry:.0f}" fill="#64748b" '
                f'font-size="8" class="threat-desc">{_esc(desc_display)}</text>'
            )
            rx += col_desc_w

            # ATT&CK Technique
            mitre_display = _truncate(self._format_mitre_techniques(threat), 28)
            parts.append(
                f'<text x="{rx:.0f}" y="{ry:.0f}" fill="#7c3aed" '
                f'font-size="8" class="threat-mitre">{_esc(mitre_display)}</text>'
            )
            rx += col_attack_w

            # STRIDE category
            stride = STRIDE_DISPLAY.get(threat.stride_category, threat.stride_category)
            parts.append(
                f'<text x="{rx:.0f}" y="{ry:.0f}" fill="#64748b" '
                f'font-size="9">{_esc(stride)}</text>'
            )
            rx += col_stride_w

            # Source
            parts.append(
                f'<text x="{rx:.0f}" y="{ry:.0f}" fill="#94a3b8" '
                f'font-size="9">{_esc(threat.source.value)}</text>'
            )

            # Row tooltip — includes mitigation
            tooltip_lines = [f"{threat.title}: {threat.description}"]
            if threat.mitigation:
                tooltip_lines.append(f"Mitigation: {threat.mitigation}")
            parts.append(f"<title>{_esc(chr(10).join(tooltip_lines))}</title>")
            parts.append("</g>")
            y += THREAT_TABLE_ROW_H

        parts.append("</g>")
        return "\n".join(parts)

    def _svg_legend(self) -> str:
        """Render a 3-column legend with mini SVG shapes, line samples, and severity badges."""
        y = self._legend_y
        w = self._canvas_w
        parts: list[str] = [
            '<g class="legend">',
            f'<rect x="0" y="{y:.0f}" width="{w:.0f}" height="{LEGEND_H}" fill="#f8fafc"/>',
            f'<line x1="0" y1="{y:.0f}" x2="{w:.0f}" y2="{y:.0f}" '
            f'stroke="#e2e8f0" stroke-width="1"/>',
        ]

        col1_x = 24.0
        col2_x = col1_x + 220
        col3_x = col2_x + 220

        # -- Column 1: Node Shapes --
        cy = y + 20
        parts.append(
            f'<text x="{col1_x:.0f}" y="{cy:.0f}" fill="#1e293b" '
            f'font-size="10" font-weight="600">Node Shapes</text>'
        )
        cy += 18

        # Process (rounded rect)
        parts.append(
            f'<rect x="{col1_x:.0f}" y="{cy - 7:.0f}" width="18" height="12" '
            f'rx="3" fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{col1_x + 24:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
            f'font-size="9">Process (compute, serverless, container)</text>'
        )
        cy += 20

        # Data Store (cylinder)
        cx_cyl = col1_x + 9
        parts.append(
            f'<rect x="{col1_x:.0f}" y="{cy - 4:.0f}" width="18" height="8" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        parts.append(
            f'<ellipse cx="{cx_cyl:.0f}" cy="{cy - 4:.0f}" rx="9" ry="3" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        parts.append(
            f'<ellipse cx="{cx_cyl:.0f}" cy="{cy + 4:.0f}" rx="9" ry="3" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{col1_x + 24:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
            f'font-size="9">Data Store (storage, database)</text>'
        )
        cy += 20

        # Data Flow (diamond)
        dx = col1_x + 9
        dy = cy
        parts.append(
            f'<polygon points="{dx},{dy - 6} {dx + 9},{dy} {dx},{dy + 6} {dx - 9},{dy}" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        parts.append(
            f'<text x="{col1_x + 24:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
            f'font-size="9">Data Flow (network, cdn, messaging)</text>'
        )
        cy += 20

        # External Entity (double rect)
        parts.append(
            f'<rect x="{col1_x:.0f}" y="{cy - 7:.0f}" width="18" height="12" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        parts.append(
            f'<rect x="{col1_x + 2:.0f}" y="{cy - 5:.0f}" width="14" height="8" '
            f'fill="none" stroke="#cbd5e1" stroke-width="0.8"/>'
        )
        parts.append(
            f'<text x="{col1_x + 24:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
            f'font-size="9">External Entity (IAM)</text>'
        )

        # -- Column 2: Edge Types --
        cy = y + 20
        parts.append(
            f'<text x="{col2_x:.0f}" y="{cy:.0f}" fill="#1e293b" '
            f'font-size="10" font-weight="600">Edge Types</text>'
        )
        cy += 18

        edge_legend = [
            (EdgeType.DEPENDENCY, "Dependency"),
            (EdgeType.CONTAINMENT, "Containment"),
            (EdgeType.NETWORK_FLOW, "Network Flow"),
            (EdgeType.IAM_BINDING, "IAM Binding"),
            (EdgeType.DATA_FLOW, "Data Flow"),
        ]
        for etype, label in edge_legend:
            color, width, dash = EDGE_STYLES[etype]
            dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
            parts.append(
                f'<line x1="{col2_x:.0f}" y1="{cy:.0f}" '
                f'x2="{col2_x + 30:.0f}" y2="{cy:.0f}" '
                f'stroke="{color}" stroke-width="{width}"{dash_attr}/>'
            )
            # Arrow head
            parts.append(
                f'<polygon points="{col2_x + 30:.0f},{cy - 3} '
                f'{col2_x + 36:.0f},{cy} {col2_x + 30:.0f},{cy + 3}" fill="{color}"/>'
            )
            parts.append(
                f'<text x="{col2_x + 42:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
                f'font-size="9">{_esc(label)}</text>'
            )
            cy += 16

        # Boundary crossing (red glow)
        parts.append(
            f'<line x1="{col2_x:.0f}" y1="{cy:.0f}" '
            f'x2="{col2_x + 30:.0f}" y2="{cy:.0f}" '
            f'stroke="#ef4444" stroke-width="2" filter="url(#glow)"/>'
        )
        parts.append(
            f'<polygon points="{col2_x + 30:.0f},{cy - 3} '
            f'{col2_x + 36:.0f},{cy} {col2_x + 30:.0f},{cy + 3}" fill="#ef4444"/>'
        )
        parts.append(
            f'<text x="{col2_x + 42:.0f}" y="{cy + 3:.0f}" fill="#ef4444" '
            f'font-size="9" font-weight="600">Trust Boundary Crossing</text>'
        )

        # -- Column 3: Severity Badges --
        cy = y + 20
        parts.append(
            f'<text x="{col3_x:.0f}" y="{cy:.0f}" fill="#1e293b" '
            f'font-size="10" font-weight="600">Severity Badges</text>'
        )
        cy += 18

        for sev in ["critical", "high", "medium", "low"]:
            color = SEVERITY_COLORS[sev]
            parts.append(f'<circle cx="{col3_x + 6:.0f}" cy="{cy:.0f}" r="5" fill="{color}"/>')
            parts.append(
                f'<text x="{col3_x + 16:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
                f'font-size="9">{sev.capitalize()}</text>'
            )
            cy += 16

        # Explanation
        parts.append(
            f'<text x="{col3_x:.0f}" y="{cy + 6:.0f}" fill="#94a3b8" '
            f'font-size="8">Badge number = threat count on resource</text>'
        )

        # Footer
        parts.append(
            f'<text x="{w - 16:.0f}" y="{y + LEGEND_H - 8:.0f}" fill="#cbd5e1" '
            f'font-size="9" text-anchor="end">Generated by ThreatCode</text>'
        )

        parts.append("</g>")
        return "\n".join(parts)

    # -- Geometry helpers -----------------------------------------------------

    def _bezier(self, x1: float, y1: float, x2: float, y2: float) -> str:
        dy = abs(y2 - y1)
        if dy < 10:
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
