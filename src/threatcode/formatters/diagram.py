"""SVG threat model diagram renderer - data flow diagrams with trust zone swim lanes.

The diagram draws what the report and the graph say and computes nothing of its own about attack
routes: attack paths come from ``report.attack_paths`` and are drawn hop by hop in the direction
of their edges.
Containment (a VPC around its subnets, a subnet around its instances, a Dockerfile stage around
its instructions) is drawn as labelled nested frames, not as arrows from every child to its
parent.
"""

from __future__ import annotations

import hashlib
import logging
import math
import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from html import escape
from typing import TYPE_CHECKING

from threatcode.engine.mitre import TECHNIQUE_DB
from threatcode.formatters.diagram_routing import (
    Grid,
    GridNode,
    Point,
    Rect,
    Shape,
    SpatialIndex,
    place_on_route,
    point_at_half_length,
    polyline_to_path,
    route_edges,
    route_segments,
)
from threatcode.ir.edges import EdgeType
from threatcode.ir.nodes import NodeCategory, TrustZone
from threatcode.models.report import threat_severity

if TYPE_CHECKING:
    from threatcode.ir.edges import InfraEdge
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.nodes import InfraNode
    from threatcode.models.attack_path import AttackHop, AttackPath
    from threatcode.models.report import ThreatReport
    from threatcode.models.threat import Threat

logger = logging.getLogger(__name__)

# Layout constants
NODE_W = 160
NODE_H = 54
NODE_GAP_X = 36
NODE_GAP_Y = 40
LANE_PAD_X = 80
LANE_PAD_Y = 40
HEADER_H = 44
SUMMARY_BAR_H = 32
LEGEND_H = 140
THREAT_TABLE_ROW_H = 20
THREAT_TABLE_HEADER_H = 28
MIN_LANE_H = 90
MAX_NODES_PER_ROW = 5
CANVAS_PAD = 20

# Findings table: the most rows drawn (the rest become one overflow row) and the most lines
# one cell wraps onto before its last line is cut with an ellipsis (the row tooltip has it all)
DEFAULT_MAX_ROWS = 200
TABLE_MAX_CELL_LINES = 3
TABLE_TEXT_TOP = 13.5
TABLE_ROW_BOTTOM_PAD = 6.5

# Above this many nodes the diagram collapses nodes of one zone and type into a summary node
DEFAULT_LOD_THRESHOLD = 150
NOTICE_H = 26
# A Dockerfile stage with more instructions than this is drawn as one node
DOCKER_COLLAPSE_MIN = 6
DOCKER_STAGE_TYPE = "dockerfile_stage"

# Nested containment frames: padding per nesting level, label strip height and how many levels
# deep a node is framed (the innermost ones when the chain is longer)
FRAME_PAD = 8
FRAME_LABEL_H = 14
MAX_FRAME_DEPTH = 3
FRAME_STROKES = {1: "#64748b", 2: "#94a3b8", 3: "#b6c2d2"}

# Node text baselines (offsets from the node top), shared by every shape so names
# line up across a row; clear of cylinder caps and inside the diamond outline
NODE_TYPE_BASELINE = 21
NODE_NAME_BASELINE = 37
NODE_TYPE_MAX_CHARS = 22
DIAMOND_TYPE_MAX_CHARS = 20
NODE_NAME_MAX_CHARS = 24

# Routing clearances: keep horizontal runs off node edges and threat badges
CHANNEL_CLEAR_BELOW = 8
CHANNEL_CLEAR_ABOVE = 14
GAP_CLEAR = 6

# Boundary label geometry (font-size 9, semibold, uppercase)
EDGE_LABEL_FONT = 9
EDGE_LABEL_CHAR_W = 5.9
# Glyphs much narrower or wider than an average uppercase letter at that size
EDGE_LABEL_GLYPH_W = {" ": 2.6, "I": 2.6, "→": 9.0}
EDGE_LABEL_PAD_X = 8
EDGE_LABEL_H = 16
OVERLAY_CLEARANCE = 5

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

# Short names for the edge types on an attack path, where a hop has 84 pixels to say it
_HOP_EDGE_LABELS: dict[str, str] = {
    "network_flow": "network",
    "data_flow": "data",
    "iam_binding": "iam",
    "dependency": "depends",
    "containment": "contains",
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
ATTACK_PATH_ROW_H = 92
ATTACK_PATH_NODE_W = 120
ATTACK_PATH_NODE_H = 28
ATTACK_PATH_ARROW_W = 84
ATTACK_PATH_PAD = 16
ATTACK_PATH_MAX_PATHS = 5
ATTACK_PATH_CIRCLE_R = 9
ATTACK_PATH_NOTE_H = 36
# Smallest font the attack path blocks use: captions and edge labels stay readable
ATTACK_PATH_FONT = 9
ATTACK_PATH_LINE_H = 11
ATTACK_PATH_CAPTION_LINES = 2

NO_ATTACK_PATHS_NOTE = "No attack paths found"
NO_ATTACK_PATHS_DETAIL = (
    "Paths follow modelled traffic and IAM reachability from an internet entry point "
    "to a data or secret store."
)

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
    NodeCategory.API,
    NodeCategory.UNKNOWN,
}
_DATA_STORE_CATEGORIES = {
    NodeCategory.STORAGE,
    NodeCategory.DATABASE,
    NodeCategory.SECRET,
}
_DATA_FLOW_CATEGORIES = {
    NodeCategory.NETWORK,
    NodeCategory.CDN,
    NodeCategory.DNS,
    NodeCategory.MESSAGING,
}
_ENTITY_CATEGORIES = {NodeCategory.IAM}

FONT_FAMILY = 'Inter, system-ui, "Segoe UI", Helvetica, Arial, sans-serif'

# Average glyph width as a fraction of font size, slightly above Inter's real
# average so wrapped text stays inside its column across fallback fonts.
_AVG_CHAR_WIDTH_EM = 0.6
_COLUMN_GAP_PX = 8
# Where a token with no space may be broken: after these characters
_BREAK_AFTER = ".-_/[]:,;"


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if it exceeds max_len."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 3] + "..."


def _chars_per_line(width_px: float, font_size: float) -> int:
    return max(int((width_px - _COLUMN_GAP_PX) / (font_size * _AVG_CHAR_WIDTH_EM)), 4)


def _split_token(token: str, limit: int) -> list[str]:
    """Break a token longer than ``limit`` at a separator when one is near, else mid-word."""
    pieces: list[str] = []
    while len(token) > limit:
        cut = max((token.rfind(ch, 0, limit) for ch in _BREAK_AFTER), default=-1) + 1
        if cut < limit // 2:
            cut = limit
        pieces.append(token[:cut])
        token = token[cut:]
    pieces.append(token)
    return pieces


def _wrap(text: str, width_px: float, font_size: float, max_lines: int) -> list[str]:
    """Wrap text into lines that fit ``width_px``; only an overflowing last line is cut.

    Words wrap at spaces, a token with no spaces (an address, a technique id) is broken after a
    separator, so the start of a title and its identifying tail both stay visible.
    More than ``max_lines`` lines end in an ellipsis on the last one.
    """
    limit = _chars_per_line(width_px, font_size)
    lines: list[str] = []
    current = ""
    for word in text.split():
        for i, piece in enumerate(_split_token(word, limit)):
            glued = i > 0
            if current and len(current) + (0 if glued else 1) + len(piece) <= limit:
                current += piece if glued else " " + piece
            else:
                if current:
                    lines.append(current)
                current = piece
    if current:
        lines.append(current)
    if not lines:
        return [""]
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        last = lines[-1]
        if len(last) + 3 > limit:
            last = last[: limit - 3]
        lines[-1] = last.rstrip() + "..."
    return lines


def _line_h(font_size: float) -> int:
    return round(font_size * 1.25)


def _text_block(x: float, y: float, lines: list[str], line_h: float, attrs: str) -> str:
    """A <text> element for one line, or one <tspan> per line when the text wrapped."""
    if len(lines) <= 1:
        content = _esc(lines[0]) if lines else ""
        return f'<text x="{x:.0f}" y="{y:.1f}" {attrs}>{content}</text>'
    spans = "".join(
        f'<tspan x="{x:.0f}" dy="{0 if i == 0 else line_h:g}">{_esc(line)}</tspan>'
        for i, line in enumerate(lines)
    )
    return f'<text x="{x:.0f}" y="{y:.1f}" {attrs}>{spans}</text>'


def _doc_prefix(source: str) -> str:
    """Prefix of every id in one document: 'tc' and a hash of the input file name.

    Two diagrams embedded in one HTML page would otherwise both define ``#shadow`` and ``#glow``
    and the second would silently use the first one's.
    """
    return "tc" + hashlib.sha1(source.encode(), usedforsecurity=False).hexdigest()[:8]


_ID_UNSAFE = re.compile(r"[^A-Za-z0-9_-]+")


def _element_id(prefix: str, kind: str, raw: str) -> str:
    """A valid, unique XML id for an element built from a resource address."""
    slug = _ID_UNSAFE.sub("_", raw).strip("_")[:40]
    digest = hashlib.sha1(raw.encode(), usedforsecurity=False).hexdigest()[:6]
    return f"{prefix}-{kind}-{slug}-{digest}" if slug else f"{prefix}-{kind}-{digest}"


def _format_timestamp(raw: str) -> str:
    """Minute-resolution UTC time of an ISO 8601 timestamp, or '' when there is none."""
    if not raw:
        return ""
    try:
        moment = datetime.fromisoformat(raw)
    except ValueError:
        return raw[:16].replace("T", " ")
    if moment.tzinfo is not None:
        moment = moment.astimezone(timezone.utc)
    return moment.strftime("%Y-%m-%d %H:%M UTC")


# -- Display model ---------------------------------------------------------------


@dataclass
class _DNode:
    """A node as drawn: one resource, a collapsed Dockerfile stage or a zone/type summary."""

    id: str
    resource_type: str
    name: str
    category: NodeCategory
    zone: TrustZone
    threats: list[Threat] = field(default_factory=list)
    tooltip: str = ""
    # Replaces the resource type line when set (a collapsed stage says how many instructions)
    caption: str = ""


@dataclass
class _DEdge:
    """A connector as drawn."""

    source: str
    target: str
    edge_type: EdgeType
    crosses: bool
    label: str
    tooltip: str


@dataclass
class _FrameInfo:
    """A container drawn as a frame around its members."""

    container: str
    label: str
    threats: list[Threat]
    tooltip: str


@dataclass
class _Frame:
    """One drawn frame: a container's members in one lane (or one row of it)."""

    container: str
    rect: Rect
    height: int
    badge: bool


@dataclass
class _TableRow:
    threat: Threat
    cells: list[list[str]]
    height: float


def _worst(threats: list[Threat]) -> Threat | None:
    """The most severe threat; the first one on a tie."""
    best: Threat | None = None
    for t in threats:
        if best is None or threat_severity(t).rank > threat_severity(best).rank:
            best = t
    return best


class DiagramRenderer:
    """Renders a threat model data flow diagram as SVG."""

    def __init__(
        self,
        report: ThreatReport,
        graph: InfraGraph,
        *,
        max_rows: int | None = DEFAULT_MAX_ROWS,
        expand_docker: bool = False,
        lod_threshold: int | None = DEFAULT_LOD_THRESHOLD,
    ) -> None:
        self.report = report
        self.graph = graph
        self.max_rows = max_rows
        self.expand_docker = expand_docker
        self.lod_threshold = lod_threshold
        self._prefix = _doc_prefix(report.input_file)
        self._threats_by_address: dict[str, list[Threat]] = defaultdict(list)
        self._threats_by_id: dict[str, Threat] = {}
        for threat in report.threats:
            self._threats_by_address[threat.resource_address].append(threat)
            self._threats_by_id.setdefault(threat.id, threat)
        # Display model -- populated by _build_view
        self._dnodes: dict[str, _DNode] = {}
        self._dedges: list[_DEdge] = []
        self._repr: dict[str, str | None] = {}
        # A Dockerfile stage drawn as a frame -> its first instruction, where stage edges land
        self._stage_anchor: dict[str, str] = {}
        self._chain: dict[str, tuple[str, ...]] = {}
        self._frame_info: dict[str, _FrameInfo] = {}
        self._notice = ""
        # Layout state -- populated by _compute_layout
        self._node_positions: dict[str, tuple[float, float]] = {}
        self._zone_lanes: list[tuple[TrustZone, float, float, list[_DNode]]] = []
        self._row_depth: dict[int, int] = {}
        self._gap_x = NODE_GAP_X
        self._frames: list[_Frame] = []
        self._canvas_w = 0.0
        self._canvas_h = 0.0
        self._notice_y = 0.0
        self._threat_table_y = 0.0
        self._legend_y = 0.0
        # Attack path state -- the paths drawn, numbered from 1, and where their edges are
        self._attack_paths: list[tuple[int, AttackPath]] = []
        self._edge_attack_path_map: dict[tuple[str, str], list[int]] = {}
        self._attack_paths_y = 0.0
        self._attack_paths_h = 0.0
        # Findings table state
        self._table_rows: list[_TableRow] = []
        self._table_overflow = 0
        self._table_cols: list[float] = []
        # Routing state -- populated by _compute_routes
        self._node_cells: dict[str, tuple[int, int]] = {}  # node_id -> (col, global row)
        self._grid: Grid | None = None
        self._routes: dict[tuple[str, str], list[Point]] = {}
        self._edge_labels: dict[tuple[str, str], tuple[Rect, str, str]] = {}
        self._edge_markers: dict[tuple[str, str], tuple[Rect, list[int]]] = {}

    def render(self) -> str:
        self._build_view()
        self._compute_layout()
        parts: list[str] = []
        parts.append(self._svg_open())
        parts.append(self._svg_accessible_text())
        parts.append(self._svg_defs())
        # Opaque canvas so the diagram stays readable in dark-themed viewers
        parts.append(
            f'<rect x="0" y="0" width="{self._canvas_w:.0f}" '
            f'height="{self._canvas_h:.0f}" fill="#ffffff"/>'
        )
        parts.append(self._svg_header())
        parts.append(self._svg_summary_bar())
        parts.append(self._svg_notice())
        for zone, y, h, nodes in self._zone_lanes:
            parts.append(self._svg_zone_lane(zone, y, h, nodes))
        parts.append(self._svg_frames())
        glowing: set[tuple[str, str]] = set()
        for edge in self._dedges:
            svg = self._svg_edge(edge, glowing)
            if svg:
                parts.append(svg)
        for node_id, (x, y) in self._node_positions.items():
            parts.append(self._svg_node(self._dnodes[node_id], x, y))
        # Labels and markers sit above nodes so no box can cover them
        parts.append(self._svg_edge_overlays())
        parts.append(self._svg_attack_paths())
        parts.append(self._svg_threat_table())
        parts.append(self._svg_legend())
        parts.append("</svg>")
        return "\n".join(part for part in parts if part)

    # -- Display model --------------------------------------------------------

    def _build_view(self) -> None:
        """Decide what is drawn: frames for containers, collapsed stages, summary nodes."""
        nodes = self.graph.nodes
        edges = self.graph.edges
        collapsed = self._collapsed_docker_members(nodes, edges)
        parent_of = self._containment_parents(nodes, edges, collapsed)
        containers = set(parent_of.values())
        visible = [nid for nid in nodes if nid not in collapsed]
        framed = [nid for nid in visible if nid not in containers]
        use_lod = self.lod_threshold is not None and len(framed) > self.lod_threshold
        if use_lod:
            self._build_summary_view(nodes, edges, collapsed, visible)
            return

        self._repr = {nid: (None if nid in containers else nid) for nid in nodes}
        for member, stage in collapsed.items():
            self._repr[member] = stage
        members_of: dict[str, list[str]] = defaultdict(list)
        for member, stage in collapsed.items():
            members_of[stage].append(member)
        for nid in framed:
            node = nodes[nid]
            threats = list(self._threats_by_address.get(nid, ()))
            caption = ""
            tooltip_extra: list[str] = []
            if nid in members_of:
                folded = members_of[nid]
                for member in folded:
                    threats.extend(self._threats_by_address.get(member, ()))
                caption = f"stage: {len(folded)} instructions"
                tooltip_extra = self._collapsed_tooltip(folded)
            self._dnodes[nid] = _DNode(
                id=nid,
                resource_type=node.resource_type or nid.split(".")[0],
                name=_short_name(node),
                category=node.category,
                zone=node.trust_zone,
                threats=threats,
                tooltip=self._node_tooltip(node, threats, tooltip_extra),
                caption=caption,
            )
        for child, container in parent_of.items():
            if nodes[container].resource_type == DOCKER_STAGE_TYPE:
                self._stage_anchor.setdefault(container, child)
        self._build_edges(edges)

        # Frames: every container of a node's chain, outermost first
        for nid in framed:
            chain: list[str] = []
            seen = {nid}
            current = parent_of.get(nid)
            while current is not None and current not in seen:
                chain.append(current)
                seen.add(current)
                current = parent_of.get(current)
            chain.reverse()
            if chain:
                self._chain[nid] = tuple(chain[-MAX_FRAME_DEPTH:])
        for cid in sorted({c for chain in self._chain.values() for c in chain}):
            node = nodes[cid]
            threats = list(self._threats_by_address.get(cid, ()))
            self._frame_info[cid] = _FrameInfo(
                container=cid,
                label=cid,
                threats=threats,
                tooltip=self._node_tooltip(node, threats, []),
            )

    def _collapsed_docker_members(
        self, nodes: dict[str, InfraNode], edges: list[InfraEdge]
    ) -> dict[str, str]:
        """Instruction nodes folded into their stage: {instruction id: stage id}.

        A stage with more than DOCKER_COLLAPSE_MIN instructions is one node; its instructions'
        findings move to the stage tooltip and badge.
        """
        if self.expand_docker:
            return {}
        members: dict[str, list[str]] = defaultdict(list)
        for edge in edges:
            if edge.edge_type is not EdgeType.CONTAINMENT:
                continue
            source = nodes.get(edge.source)
            target = nodes.get(edge.target)
            if (
                source is not None
                and target is not None
                and target.resource_type == DOCKER_STAGE_TYPE
                and source.resource_type != DOCKER_STAGE_TYPE
            ):
                members[edge.target].append(edge.source)
        collapsed: dict[str, str] = {}
        for stage, ids in members.items():
            unique = list(dict.fromkeys(ids))
            if len(unique) > DOCKER_COLLAPSE_MIN:
                for member in unique:
                    collapsed.setdefault(member, stage)
        return collapsed

    def _containment_parents(
        self,
        nodes: dict[str, InfraNode],
        edges: list[InfraEdge],
        collapsed: dict[str, str],
    ) -> dict[str, str]:
        """Child -> container for every containment edge into a network, namespace or stage."""
        parent_of: dict[str, str] = {}
        for edge in edges:
            if edge.edge_type is not EdgeType.CONTAINMENT or edge.source == edge.target:
                continue
            child = nodes.get(edge.source)
            container = nodes.get(edge.target)
            if child is None or container is None or edge.source in collapsed:
                continue
            if not (container.is_container or container.resource_type == DOCKER_STAGE_TYPE):
                continue
            parent_of.setdefault(edge.source, edge.target)
        # A containment cycle in hostile input would loop; cut the link that closes it
        for start in list(parent_of):
            seen = {start}
            current = start
            while current in parent_of:
                parent = parent_of[current]
                if parent in seen:
                    del parent_of[current]
                    break
                seen.add(parent)
                current = parent
        return parent_of

    def _collapsed_tooltip(self, members: list[str]) -> list[str]:
        lines = ["", f"{len(members)} instructions folded into this stage"]
        for member in members:
            for threat in self._threats_by_address.get(member, ()):
                sev = threat_severity(threat).value.upper()
                lines.append(f"  {sev} - {threat.title} [{member}]")
        return lines

    def _build_edges(self, edges: list[InfraEdge]) -> None:
        """Map graph edges onto the drawn nodes: no containment, no self loops from merging."""
        index: dict[tuple[str, str, EdgeType], int] = {}
        for edge in edges:
            if edge.edge_type is EdgeType.CONTAINMENT:
                continue
            source = self._repr.get(edge.source)
            target = self._repr.get(edge.target)
            if source is None and target is None:
                continue
            if source is None or target is None:
                # An edge between two stages (COPY --from, FROM <stage>) lands on the first
                # instruction of a stage drawn as a frame
                if not self._joins_stages(edge):
                    continue
                source = source or self._stage_anchor.get(edge.source)
                target = target or self._stage_anchor.get(edge.target)
                if source is None or target is None:
                    continue
            if source == target and edge.source != edge.target:
                continue
            key = (source, target, edge.edge_type)
            if key in index:
                existing = self._dedges[index[key]]
                if edge.crosses_trust_boundary and not existing.crosses:
                    existing.crosses = True
                    existing.label = self._edge_label_text(edge)
                    existing.tooltip = self._edge_tooltip(edge)
                continue
            index[key] = len(self._dedges)
            self._dedges.append(
                _DEdge(
                    source=source,
                    target=target,
                    edge_type=edge.edge_type,
                    crosses=edge.crosses_trust_boundary,
                    label=self._edge_label_text(edge) if edge.crosses_trust_boundary else "",
                    tooltip=self._edge_tooltip(edge),
                )
            )

    def _joins_stages(self, edge: InfraEdge) -> bool:
        nodes = self.graph.nodes
        a = nodes.get(edge.source)
        b = nodes.get(edge.target)
        return (
            a is not None
            and b is not None
            and a.resource_type == DOCKER_STAGE_TYPE
            and b.resource_type == DOCKER_STAGE_TYPE
        )

    def _build_summary_view(
        self,
        nodes: dict[str, InfraNode],
        edges: list[InfraEdge],
        collapsed: dict[str, str],
        visible: list[str],
    ) -> None:
        """Level of detail for a large input: one node per zone and resource type."""
        groups: dict[tuple[TrustZone, str], list[str]] = {}
        for nid in visible:
            node = nodes[nid]
            groups.setdefault((node.trust_zone, node.resource_type or "unknown"), []).append(nid)
        self._repr = {}
        for (zone, rtype), ids in groups.items():
            gid = f"group.{zone.value}.{rtype}"
            threats: list[Threat] = []
            for nid in ids:
                self._repr[nid] = gid
                threats.extend(self._threats_by_address.get(nid, ()))
            first = nodes[ids[0]]
            shown = ids[:12]
            lines = [
                f"{len(ids)} x {rtype}",
                f"Zone: {ZONE_LABELS.get(zone, zone.value.upper())}"
                f" | Category: {first.category.value}",
                "",
                *shown,
            ]
            if len(ids) > len(shown):
                lines.append(f"... and {len(ids) - len(shown)} more")
            if threats:
                lines.extend(self._threat_lines(threats))
            self._dnodes[gid] = _DNode(
                id=gid,
                resource_type=rtype,
                name=f"{len(ids)} resources" if len(ids) > 1 else _short_name(first),
                category=first.category,
                zone=zone,
                threats=threats,
                tooltip="\n".join(lines),
            )
        for member, stage in collapsed.items():
            folded_into = self._repr.get(stage)
            if folded_into is not None:
                self._repr[member] = folded_into
                self._dnodes[folded_into].threats.extend(self._threats_by_address.get(member, ()))
        self._build_edges(edges)
        total = len(visible)
        self._notice = (
            f"Large input: {total} resources collapsed into {len(self._dnodes)} groups "
            "by zone and type. Scan a smaller scope or use the JSON or SARIF report for detail."
        )
        logger.warning(
            "Diagram collapsed %d resources into %d groups by zone and type "
            "(more than %s resources)",
            total,
            len(self._dnodes),
            self.lod_threshold,
        )

    # -- Layout ---------------------------------------------------------------

    def _ordered_lane(self, nodes: list[_DNode]) -> list[_DNode]:
        """Nodes of one lane with the members of each container side by side."""
        return sorted(nodes, key=lambda n: self._chain.get(n.id, ()))

    def _compute_layout(self) -> None:
        zones_map: dict[TrustZone, list[_DNode]] = defaultdict(list)
        for dnode in self._dnodes.values():
            zones_map[dnode.zone].append(dnode)

        max_depth = max((len(c) for c in self._chain.values()), default=0)
        self._gap_x = max(NODE_GAP_X, 2 * FRAME_PAD * max_depth + 12)
        notice_h = NOTICE_H if self._notice else 0
        self._notice_y = HEADER_H + SUMMARY_BAR_H + 4
        y_cursor: float = HEADER_H + SUMMARY_BAR_H + CANVAS_PAD + notice_h
        max_lane_w = 0.0
        row_base = 0
        lane_cells: dict[str, tuple[int, int]] = {}

        for zone in ZONE_ORDER:
            lane_nodes = self._ordered_lane(zones_map.get(zone, []))
            if not lane_nodes:
                continue
            # Rows: a new one when the outermost container changes, so a frame has its own band
            col = 0
            row = 0
            previous_top: str | None = None
            for i, dnode in enumerate(lane_nodes):
                chain = self._chain.get(dnode.id, ())
                top = chain[0] if chain else None
                if i > 0 and (col >= MAX_NODES_PER_ROW or (col > 0 and top != previous_top)):
                    row += 1
                    col = 0
                lane_cells[dnode.id] = (col, row)
                previous_top = top
                col += 1
            rows = row + 1
            cols = max(c for c, _ in (lane_cells[n.id] for n in lane_nodes)) + 1

            depth = [0] * rows
            for dnode in lane_nodes:
                r = lane_cells[dnode.id][1]
                depth[r] = max(depth[r], len(self._chain.get(dnode.id, ())))
            row_y: list[float] = []
            y = y_cursor + LANE_PAD_Y + (FRAME_PAD + FRAME_LABEL_H) * depth[0]
            for r in range(rows):
                if r > 0:
                    gap = (
                        NODE_GAP_Y
                        + FRAME_PAD * depth[r - 1]
                        + (FRAME_PAD + FRAME_LABEL_H) * depth[r]
                    )
                    y = row_y[-1] + NODE_H + gap
                row_y.append(y)
            lane_bottom = row_y[-1] + NODE_H + LANE_PAD_Y + FRAME_PAD * depth[-1]
            lane_h = max(MIN_LANE_H, lane_bottom - y_cursor)
            lane_w = LANE_PAD_X + cols * (NODE_W + self._gap_x) + self._gap_x

            for dnode in lane_nodes:
                c, r = lane_cells[dnode.id]
                nx = LANE_PAD_X + self._gap_x + c * (NODE_W + self._gap_x)
                self._node_positions[dnode.id] = (nx, row_y[r])
                self._node_cells[dnode.id] = (c, row_base + r)
            for r in range(rows):
                self._row_depth[row_base + r] = depth[r]

            self._zone_lanes.append((zone, y_cursor, lane_h, lane_nodes))
            y_cursor += lane_h
            row_base += rows
            max_lane_w = max(max_lane_w, lane_w)

        # Handle empty graph
        if not self._zone_lanes:
            max_lane_w = 400

        self._compute_frames(lane_cells)

        # Attack paths come from the report; number them and find their edges
        self._attack_paths = [
            (i + 1, path) for i, path in enumerate(self.report.attack_paths[:ATTACK_PATH_MAX_PATHS])
        ]
        self._build_edge_attack_path_map()

        # Attack path section height
        attack_path_h = 0.0
        if self._attack_paths:
            attack_path_h = (
                ATTACK_PATH_SECTION_TITLE_H
                + len(self._attack_paths) * ATTACK_PATH_ROW_H
                + ATTACK_PATH_PAD * 2
            )
            if len(self.report.attack_paths) > len(self._attack_paths):
                attack_path_h += ATTACK_PATH_NOTE_H / 2
        elif self._dnodes:
            attack_path_h = ATTACK_PATH_SECTION_TITLE_H + ATTACK_PATH_NOTE_H + ATTACK_PATH_PAD
        self._attack_paths_h = attack_path_h

        # Compute attack path section width requirement
        attack_path_w = 0.0
        for _, path in self._attack_paths:
            n = max(len(path.hops), 1)
            pw = ATTACK_PATH_PAD * 2 + n * ATTACK_PATH_NODE_W + (n - 1) * ATTACK_PATH_ARROW_W
            attack_path_w = max(attack_path_w, pw)

        # Ensure canvas is wide enough for legend, attack paths, and expanded table
        min_legend_w = 900
        self._canvas_w = max(
            max_lane_w + CANVAS_PAD * 2, 400, min_legend_w, attack_path_w + CANVAS_PAD * 2
        )

        self._prepare_table()
        threat_table_h = 0.0
        if self.report.threats:
            threat_table_h = (
                THREAT_TABLE_HEADER_H
                + sum(row.height for row in self._table_rows)
                + (THREAT_TABLE_ROW_H if self._table_overflow else 0)
                + 40  # section title + padding
            )

        self._attack_paths_y = y_cursor
        y_cursor += attack_path_h
        self._threat_table_y = y_cursor
        y_cursor += threat_table_h
        self._legend_y = y_cursor
        self._canvas_h = y_cursor + LEGEND_H + CANVAS_PAD

        self._compute_routes()
        self._place_edge_overlays()

    def _compute_frames(self, cells: dict[str, tuple[int, int]]) -> None:
        """Place a frame around each container's members in each lane."""
        first_drawn: set[str] = set()
        for _, _, _, lane_nodes in self._zone_lanes:
            containers: list[str] = []
            for dnode in lane_nodes:
                for c in self._chain.get(dnode.id, ()):
                    if c not in containers:
                        containers.append(c)
            for container in containers:
                members = [n for n in lane_nodes if container in self._chain.get(n.id, ())]
                for segment in self._frame_segments(container, members, lane_nodes, cells):
                    x0 = y0 = math.inf
                    x1 = y1 = -math.inf
                    height = 1
                    for dnode in segment:
                        x, y = self._node_positions[dnode.id]
                        chain = self._chain[dnode.id]
                        h = len(chain) - chain.index(container)
                        height = max(height, h)
                        x0, y0 = min(x0, x), min(y0, y)
                        x1, y1 = max(x1, x + NODE_W), max(y1, y + NODE_H)
                    rect = Rect(
                        x0 - FRAME_PAD * height,
                        y0 - (FRAME_PAD + FRAME_LABEL_H) * height,
                        x1 - x0 + 2 * FRAME_PAD * height,
                        y1 - y0 + (2 * FRAME_PAD + FRAME_LABEL_H) * height,
                    )
                    badge = container not in first_drawn
                    first_drawn.add(container)
                    self._frames.append(_Frame(container, rect, height, badge))
        # Outer frames first so inner ones draw over them
        self._frames.sort(key=lambda f: -f.height)

    @staticmethod
    def _frame_segments(
        container: str,
        members: list[_DNode],
        lane_nodes: list[_DNode],
        cells: dict[str, tuple[int, int]],
    ) -> list[list[_DNode]]:
        """One group of members when their block holds no stranger, else one group per row."""
        cols = [cells[n.id][0] for n in members]
        rows = [cells[n.id][1] for n in members]
        member_ids = {n.id for n in members}
        c0, c1, r0, r1 = min(cols), max(cols), min(rows), max(rows)
        for other in lane_nodes:
            if other.id in member_ids:
                continue
            col, row = cells[other.id]
            if c0 <= col <= c1 and r0 <= row <= r1:
                by_row: dict[int, list[_DNode]] = defaultdict(list)
                for n in members:
                    by_row[cells[n.id][1]].append(n)
                return [by_row[r] for r in sorted(by_row)]
        return [members]

    # -- Findings table layout ------------------------------------------------

    def _prepare_table(self) -> None:
        """Wrap every cell of the findings table and measure its rows."""
        w = self._canvas_w
        col_sev_w = 66
        col_stride_w = 132  # fits "Elevation of Privilege"
        col_source_w = 50
        # Free-text columns share what is left of the table width.
        flexible = max(w - 40 - col_sev_w - col_stride_w - col_source_w, 320)
        col_res_w = flexible * 0.22
        col_threat_w = flexible * 0.26
        col_desc_w = flexible * 0.28
        col_attack_w = flexible * 0.24
        self._table_cols = [
            col_sev_w,
            col_res_w,
            col_threat_w,
            col_desc_w,
            col_attack_w,
            col_stride_w,
            col_source_w,
        ]
        threats = self._sorted_threats()
        limit = len(threats) if self.max_rows is None else max(self.max_rows, 0)
        shown = threats[:limit]
        self._table_overflow = len(threats) - len(shown)
        self._table_rows = []
        for threat in shown:
            stride = STRIDE_DISPLAY.get(threat.stride_category, threat.stride_category)
            cells = [
                [threat_severity(threat).value.upper()],
                _wrap(threat.resource_address, col_res_w, 9, TABLE_MAX_CELL_LINES),
                _wrap(threat.title, col_threat_w, 9, TABLE_MAX_CELL_LINES),
                _wrap(threat.description.strip(), col_desc_w, 8, TABLE_MAX_CELL_LINES),
                _wrap(self._format_mitre_techniques(threat), col_attack_w, 8, TABLE_MAX_CELL_LINES),
                _wrap(stride, col_stride_w, 9, 2),
                [threat.source.value],
            ]
            fonts = [9, 9, 9, 8, 8, 9, 9]
            body = max((len(c) - 1) * _line_h(f) for c, f in zip(cells, fonts, strict=True))
            height = max(float(THREAT_TABLE_ROW_H), TABLE_TEXT_TOP + body + TABLE_ROW_BOTTOM_PAD)
            self._table_rows.append(_TableRow(threat, cells, height))

    # -- Edge routing ---------------------------------------------------------

    def _compute_routes(self) -> None:
        """Route every node pair through the gaps between grid rows and columns."""
        if not self._zone_lanes:
            return

        lane_end: dict[int, float] = {}
        row_tops: dict[int, float] = {}
        for node_id, (_, row) in self._node_cells.items():
            row_tops[row] = self._node_positions[node_id][1]
        for _, lane_y, lane_h, nodes in self._zone_lanes:
            for node in nodes:
                lane_end[self._node_cells[node.id][1]] = lane_y + lane_h

        n_rows = max(row_tops) + 1
        channels: list[tuple[float, float]] = []
        keep_out: dict[int, tuple[float, float]] = {}
        half_label = EDGE_LABEL_H / 2 + OVERLAY_CLEARANCE + 1
        for row in range(n_rows):
            lo = row_tops[row] + NODE_H + CHANNEL_CLEAR_BELOW + FRAME_PAD * self._row_depth[row]
            if row + 1 < n_rows:
                hi = (
                    row_tops[row + 1]
                    - CHANNEL_CLEAR_ABOVE
                    - (FRAME_PAD + FRAME_LABEL_H) * self._row_depth[row + 1]
                )
                border = lane_end[row]
                if border < row_tops[row + 1]:
                    # Keep runs (and the labels centered on them) off the lane border
                    keep_out[row] = (border - half_label, border + half_label)
            else:
                hi = lane_end[row] - CHANNEL_CLEAR_BELOW
            channels.append((lo, hi))

        n_cols = max(col for col, _ in self._node_cells.values()) + 1
        gaps: list[tuple[float, float]] = []
        for gap in range(n_cols + 1):
            right = LANE_PAD_X + self._gap_x + gap * (NODE_W + self._gap_x)
            gaps.append((right - self._gap_x + GAP_CLEAR, right - GAP_CLEAR))

        grid_nodes: dict[str, GridNode] = {}
        for node_id, (col, row) in self._node_cells.items():
            x, y = self._node_positions[node_id]
            grid_nodes[node_id] = GridNode(
                id=node_id,
                col=col,
                row=row,
                rect=Rect(x, y, NODE_W, NODE_H),
                shape=_shape_for(self._dnodes[node_id].category),
            )

        self._grid = Grid(nodes=grid_nodes, channels=channels, gaps=gaps, keep_out=keep_out)
        pairs = [(e.source, e.target) for e in self._dedges]
        self._routes = route_edges(self._grid, pairs)

    def _overlay_obstacles(self) -> SpatialIndex:
        """Areas edge labels and markers must stay clear of: nodes, badges, titles, frame labels."""
        obstacles = SpatialIndex()
        for node_id, (x, y) in self._node_positions.items():
            obstacles.add_rect(Rect(x, y, NODE_W, NODE_H).expand(OVERLAY_CLEARANCE))
            if self._dnodes[node_id].threats:
                obstacles.add_rect(_badge_rect(x, y).expand(OVERLAY_CLEARANCE))
        for zone, lane_y, _, _ in self._zone_lanes:
            label = ZONE_LABELS.get(zone, zone.value.upper())
            obstacles.add_rect(Rect(8, lane_y + 12, len(label) * 7.5 + 8, 18))
        for frame in self._frames:
            strip_w = min(frame.rect.w, len(self._frame_label(frame)) * 5.6 + 16)
            obstacles.add_rect(Rect(frame.rect.x, frame.rect.y, strip_w, FRAME_LABEL_H + 2))
        return obstacles

    def _place_edge_overlays(self) -> None:
        """Pick collision-free spots for boundary labels and attack path markers."""
        if not self._routes:
            return
        lanes_top = self._zone_lanes[0][1]
        last_lane = self._zone_lanes[-1]
        lanes_bottom = last_lane[1] + last_lane[2]
        bounds = Rect(4, lanes_top + 2, self._canvas_w - 8, lanes_bottom - lanes_top - 4)
        obstacles = self._overlay_obstacles()

        labels: dict[tuple[str, str], tuple[str, str]] = {}
        markers: dict[tuple[str, str], list[int]] = {}
        for edge in self._dedges:
            key = (edge.source, edge.target)
            if key not in self._routes:
                continue
            if edge.crosses and key not in labels and edge.label:
                labels[key] = (edge.label, edge.tooltip)
            path_nums = self._edge_attack_path_map.get(key)
            if path_nums and key not in markers:
                markers[key] = path_nums

        # Lane borders and every route are indexed once; a label skips its own route by tag
        avoid = SpatialIndex()
        for _, lane_y, _, _ in self._zone_lanes[1:]:
            avoid.add_segment((0.0, lane_y), (self._canvas_w, lane_y), "lane")
        for key, points in self._routes.items():
            avoid.add_route(points, key)

        # Longest routes first: they have the most room, short ones get what is left
        lengths = {
            key: -sum(math.dist(a, b) for a, b in route_segments(self._routes[key]))
            for key in (*labels, *markers)
        }

        for key in sorted(labels, key=lambda k: (lengths[k], k)):
            text, tooltip = labels[key]
            size = (_label_text_width(text) + EDGE_LABEL_PAD_X * 2, EDGE_LABEL_H)
            points = self._routes[key]
            rect = place_on_route(points, size, obstacles, bounds, avoid, skip_tag=key)
            if rect is None:
                # Nothing is free; fall back to the midpoint, still drawn above nodes
                mx, my = point_at_half_length(points)
                rect = Rect(mx - size[0] / 2, my - size[1] / 2, size[0], size[1])
            self._edge_labels[key] = (rect, text, tooltip)
            obstacles.add_rect(rect.expand(OVERLAY_CLEARANCE))

        for key, path_nums in markers.items():
            d = ATTACK_PATH_CIRCLE_R * 2
            size = (len(path_nums) * (d + 2) - 2, d)
            rect = place_on_route(self._routes[key], size, obstacles, bounds, avoid, skip_tag=key)
            if rect is None:
                mx, my = point_at_half_length(self._routes[key])
                rect = Rect(mx - size[0] / 2, my - size[1] / 2, size[0], size[1])
            self._edge_markers[key] = (rect, path_nums)
            obstacles.add_rect(rect.expand(OVERLAY_CLEARANCE))

    def _sorted_threats(self) -> list[Threat]:
        """Return all threats sorted by severity (critical first)."""
        rank = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return sorted(self.report.threats, key=lambda t: rank.get(threat_severity(t).value, 99))

    # -- Attack paths ---------------------------------------------------------

    def _build_edge_attack_path_map(self) -> None:
        """Map each drawn (source, target) connector to the numbers of the paths that use it.

        A hop leads from one node to the next, so only the connector that points the same way is
        marked: a path never lights up an edge that runs the other direction.
        """
        self._edge_attack_path_map = {}
        for path_num, path in self._attack_paths:
            for here, there in zip(path.hops, path.hops[1:], strict=False):
                a = self._repr.get(here.node_id)
                b = self._repr.get(there.node_id)
                if a is None or b is None or a == b:
                    continue
                nums = self._edge_attack_path_map.setdefault((a, b), [])
                if path_num not in nums:
                    nums.append(path_num)

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

    def _id(self, name: str) -> str:
        """An id of this document: the per-document prefix and a name."""
        return f"{self._prefix}-{name}"

    def _url(self, name: str) -> str:
        return f"url(#{self._id(name)})"

    def _svg_open(self) -> str:
        w = self._canvas_w
        h = self._canvas_h
        return (
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'viewBox="0 0 {w:.0f} {h:.0f}" '
            f'width="{w:.0f}" height="{h:.0f}" '
            f'role="img" aria-labelledby="{self._id("title")} {self._id("desc")}" '
            f"font-family={_quote(FONT_FAMILY)}>"
        )

    def _svg_accessible_text(self) -> str:
        """Document title and description for assistive technology."""
        source = self.report.input_file.replace("\\", "/").rsplit("/", 1)[-1]
        title = "ThreatCode threat model" + (f" of {source}" if source else "")
        counts: dict[str, int] = {}
        for t in self.report.threats:
            sev = threat_severity(t).value
            counts[sev] = counts.get(sev, 0) + 1
        n_res = self.report.scanned_resources or self.graph.node_count
        by_sev = ", ".join(f"{counts[s]} {s}" for s in SEVERITY_ORDER if counts.get(s))
        desc = (
            f"Data flow diagram of {n_res} resources in {len(self._zone_lanes)} trust zones "
            f"with {len(self.report.threats)} threats"
            + (f" ({by_sev})" if by_sev else "")
            + f" and {len(self.report.attack_paths)} attack paths."
        )
        return (
            f'<title id="{self._id("title")}">{_esc(title)}</title>'
            f'<desc id="{self._id("desc")}">{_esc(desc)}</desc>'
        )

    def _svg_defs(self) -> str:
        # The glow region is in user space: straight edges have a zero-height (or
        # zero-width) bounding box, and a bbox-relative region would clip them away.
        return (
            "<defs>"
            + self._svg_style()
            + f'<filter id="{self._id("shadow")}" x="-4%" y="-4%" width="108%" height="116%">'
            '<feDropShadow dx="0" dy="1" stdDeviation="2" flood-opacity="0.08"/>'
            "</filter>"
            f'<filter id="{self._id("glow")}" filterUnits="userSpaceOnUse" x="0" y="0" '
            f'width="{self._canvas_w:.0f}" height="{self._canvas_h:.0f}">'
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

    def _marker(self, name: str, color: str) -> str:
        # Fixed-size heads: in stroke units a 2px boundary edge would draw a head twice as large
        return (
            f'<marker id="{self._id(name)}" viewBox="0 0 10 7" refX="10" refY="3.5" '
            f'markerUnits="userSpaceOnUse" markerWidth="9" markerHeight="7" '
            f'orient="auto-start-reverse">'
            f'<polygon points="0 0, 10 3.5, 0 7" fill="{color}"/>'
            f"</marker>"
        )

    def _svg_arrow_markers(self) -> str:
        markers: list[str] = []
        for etype, (color, _, _) in EDGE_STYLES.items():
            if etype is EdgeType.CONTAINMENT:
                continue  # containment is a frame, never an arrow
            markers.append(self._marker(f"arrow-{etype.value}", color))
        markers.append(self._marker("arrow-boundary", "#ef4444"))
        for sev in SEVERITY_ORDER:
            markers.append(self._marker(f"arrow-path-{sev}", SEVERITY_COLORS[sev]))
        return "".join(markers)

    def _svg_header(self) -> str:
        w = self._canvas_w
        n_res = self.report.scanned_resources or self.graph.node_count
        n_threats = len(self.report.threats)
        title = "ThreatCode Threat Model"
        meta = f"{n_res} resources · {n_threats} threats"
        ts = _format_timestamp(self.report.timestamp)
        if ts:
            meta += f" · {ts}"
        return (
            f'<rect x="0" y="0" width="{w:.0f}" height="{HEADER_H}" fill="#1e293b" rx="0"/>'
            f'<text x="16" y="{HEADER_H // 2 + 5}" fill="#ffffff" '
            f'font-size="14" font-weight="600">{_esc(title)}</text>'
            f'<text x="{w - 16}" y="{HEADER_H // 2 + 5}" fill="#94a3b8" '
            f'font-size="11" text-anchor="end">{_esc(meta)}</text>'
        )

    def _svg_notice(self) -> str:
        """The level-of-detail banner under the summary bar."""
        if not self._notice:
            return ""
        w = self._canvas_w
        y = self._notice_y
        return (
            f'<g class="lod-notice"><rect x="16" y="{y:.0f}" width="{w - 32:.0f}" '
            f'height="{NOTICE_H - 6}" rx="4" fill="#fef9c3" stroke="#eab308" stroke-width="1"/>'
            f'<text x="26" y="{y + 13:.0f}" fill="#713f12" font-size="10">'
            f"{_esc(self._notice)}</text></g>"
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
            sev = threat_severity(t).value
            counts[sev] = counts.get(sev, 0) + 1
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

    def _svg_zone_lane(self, zone: TrustZone, y: float, h: float, nodes: list[_DNode]) -> str:
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

    # -- Frames ---------------------------------------------------------------

    def _frame_label(self, frame: _Frame) -> str:
        return self._frame_info[frame.container].label

    def _svg_frames(self) -> str:
        """Containers as labelled rounded frames around their members."""
        if not self._frames:
            return ""
        parts: list[str] = ['<g class="frames">']
        for number, frame in enumerate(self._frames):
            info = self._frame_info[frame.container]
            rect = frame.rect
            stroke = FRAME_STROKES.get(frame.height, "#94a3b8")
            max_chars = max(int((rect.w - 36) / 5.6), 6)
            label = _truncate(info.label, max_chars)
            parts.append(
                f'<g class="frame" '
                f'id="{_element_id(self._prefix, "frame", f"{number}:{info.container}")}" '
                f'data-id="{_esc(info.container)}">'
                f"<title>{_esc(info.tooltip)}</title>"
                f'<rect x="{rect.x:.1f}" y="{rect.y:.1f}" width="{rect.w:.1f}" '
                f'height="{rect.h:.1f}" rx="10" ry="10" fill="#ffffff" fill-opacity="0.55" '
                f'stroke="{stroke}" stroke-width="1.2"/>'
                f'<text x="{rect.x + 8:.1f}" y="{rect.y + FRAME_LABEL_H - 3:.1f}" '
                f'fill="#475569" font-size="9" font-weight="600">{_esc(label)}</text>'
            )
            if frame.badge and info.threats:
                worst = _worst(info.threats)
                assert worst is not None
                parts.append(
                    self._svg_threat_badge(
                        rect.right - 12,
                        rect.y + 2,
                        len(info.threats),
                        threat_severity(worst).value,
                    )
                )
            parts.append("</g>")
        parts.append("</g>")
        return "\n".join(parts)

    # -- Nodes ----------------------------------------------------------------

    def _svg_node(self, node: _DNode, x: float, y: float) -> str:
        threats = node.threats
        cat = node.category
        if cat in _DATA_STORE_CATEGORIES:
            shape = self._svg_node_datastore(x, y, NODE_W, NODE_H)
        elif cat in _DATA_FLOW_CATEGORIES:
            shape = self._svg_node_dataflow(x, y, NODE_W, NODE_H)
        elif cat in _ENTITY_CATEGORIES:
            shape = self._svg_node_entity(x, y, NODE_W, NODE_H)
        else:
            shape = self._svg_node_process(x, y, NODE_W, NODE_H)

        max_chars = DIAMOND_TYPE_MAX_CHARS if cat in _DATA_FLOW_CATEGORIES else NODE_TYPE_MAX_CHARS
        res_type_display = _truncate(node.caption or node.resource_type, max_chars)

        parts = [
            f'<g class="node" id="{_element_id(self._prefix, "node", node.id)}" '
            f'data-id="{_esc(node.id)}" filter="{self._url("shadow")}">',
            shape,
            # Resource type label (top, 8px gray)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + NODE_TYPE_BASELINE:.0f}" fill="#94a3b8" '
            f'font-size="8" text-anchor="middle">{_esc(res_type_display)}</text>',
            # Resource short name (center, 11px bold)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + NODE_NAME_BASELINE:.0f}" '
            f'fill="#1e293b" font-size="11" font-weight="600" text-anchor="middle">'
            f"{_esc(_truncate(node.name, NODE_NAME_MAX_CHARS))}</text>",
            # Tooltip via <title>
            f"<title>{_esc(node.tooltip)}</title>",
        ]

        worst = _worst(threats)
        if worst is not None:
            parts.append(
                self._svg_threat_badge(
                    x + NODE_W - 10,
                    y - 4,
                    len(threats),
                    threat_severity(worst).value,
                )
            )

        parts.append("</g>")
        return "\n".join(parts)

    def _threat_lines(self, threats: list[Threat]) -> list[str]:
        sorted_threats = sorted(threats, key=lambda t: -threat_severity(t).rank)
        lines = ["", f"{len(threats)} threats:"]
        for t in sorted_threats:
            sev = threat_severity(t).value.upper()
            stride = STRIDE_DISPLAY.get(t.stride_category, t.stride_category)
            lines.append(f"  {sev} - {t.title} ({stride})")
        return lines

    def _node_tooltip(self, node: InfraNode, threats: list[Threat], extra: list[str]) -> str:
        """Build native browser tooltip text for a node."""
        zone_label = ZONE_LABELS.get(node.trust_zone, node.trust_zone.value.upper())
        lines = [
            node.id,
            f"Zone: {zone_label} | Category: {node.category.value}",
        ]
        lines.extend(extra)
        if threats:
            lines.extend(self._threat_lines(threats))
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

    # -- Edges ----------------------------------------------------------------

    def _svg_edge(self, edge: _DEdge, glowing: set[tuple[str, str]]) -> str:
        key = (edge.source, edge.target)
        points = self._routes.get(key)
        if not points:
            return ""

        path_d = polyline_to_path(points)

        if edge.crosses:
            color = "#ef4444"
            width = "2"
            dash = ""
            marker = self._url("arrow-boundary")
            # Parallel edges share a route; glow once so stacked glows do not darken
            filt = "" if key in glowing else f' filter="{self._url("glow")}"'
            glowing.add(key)
        else:
            color, width, dash = EDGE_STYLES.get(edge.edge_type, ("#94a3b8", "1", ""))
            marker = self._url(f"arrow-{edge.edge_type.value}")
            filt = ""

        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""

        parts: list[str] = [
            '<g class="edge-group">',
            f'<path d="{path_d}" fill="none" stroke="{color}" '
            f'stroke-width="{width}"{dash_attr} stroke-linejoin="round" '
            f'marker-end="{marker}"{filt} '
            f'class="edge" data-type="{edge.edge_type.value}" '
            f'data-boundary="{str(edge.crosses).lower()}"/>',
            f"<title>{_esc(edge.tooltip)}</title>",
            "</g>",
        ]
        return "\n".join(parts)

    def _edge_tooltip(self, edge: InfraEdge) -> str:
        """Build tooltip text for an edge."""
        if edge.crosses_trust_boundary:
            src_zone, tgt_zone = _edge_zones(edge)
            return (
                f"Trust boundary crossing: {src_zone} → {tgt_zone}\n"
                f"Data should be encrypted, authenticated, and validated"
            )
        label = EDGE_LABELS.get(edge.edge_type, edge.edge_type.value)
        relation = f" ({edge.relation})" if edge.relation else ""
        return f"{label}{relation}: {edge.source} → {edge.target}"

    def _edge_label_text(self, edge: InfraEdge) -> str:
        """Return zone transition label for boundary-crossing edges."""
        src_zone, tgt_zone = _edge_zones(edge)
        if src_zone and tgt_zone:
            return f"{src_zone.upper()} → {tgt_zone.upper()}"
        return ""

    def _svg_edge_overlays(self) -> str:
        """Render boundary labels and attack path markers in a layer above the nodes."""
        if not self._edge_labels and not self._edge_markers:
            return ""
        parts: list[str] = ['<g class="edge-overlays">']
        for rect, text, tooltip in self._edge_labels.values():
            parts.append(self._svg_edge_label(rect, text, tooltip))
        colors = {num: _path_color(path) for num, path in self._attack_paths}
        for rect, path_nums in self._edge_markers.values():
            cy = rect.cy
            for j, pnum in enumerate(path_nums):
                cx = rect.x + ATTACK_PATH_CIRCLE_R + j * (ATTACK_PATH_CIRCLE_R * 2 + 2)
                parts.append(
                    f'<g class="attack-path-marker">'
                    f'<circle cx="{cx:.1f}" cy="{cy:.1f}" '
                    f'r="{ATTACK_PATH_CIRCLE_R}" fill="{colors.get(pnum, "#dc2626")}" '
                    f'stroke="#ffffff" stroke-width="1.5"/>'
                    f'<text x="{cx:.1f}" y="{cy + 3.2:.1f}" fill="#ffffff" '
                    f'font-size="9" font-weight="700" text-anchor="middle">{pnum}</text>'
                    f"</g>"
                )
        parts.append("</g>")
        return "\n".join(parts)

    def _svg_edge_label(self, rect: Rect, text: str, tooltip: str) -> str:
        """Render a boundary-crossing label on an opaque pill so it reads over edges."""
        return (
            f'<g class="edge-label-group">'
            f"<title>{_esc(tooltip)}</title>"
            f'<rect class="edge-label-bg" x="{rect.x:.1f}" y="{rect.y:.1f}" '
            f'width="{rect.w:.1f}" height="{rect.h:.1f}" rx="3" fill="#ffffff" '
            f'stroke="#fca5a5" stroke-width="1"/>'
            f'<text x="{rect.cx:.1f}" y="{rect.cy + 3.2:.1f}" fill="#dc2626" '
            f'font-size="{EDGE_LABEL_FONT}" font-weight="600" text-anchor="middle" '
            f'class="edge-label">{_esc(text)}</text>'
            f"</g>"
        )

    # -- Attack path section --------------------------------------------------

    def _svg_attack_paths(self) -> str:
        """Render the attack paths of the report between the diagram and the threat table."""
        if not self._attack_paths and not self._dnodes:
            return ""

        y = self._attack_paths_y
        parts: list[str] = ['<g class="attack-paths">']
        total = len(self.report.attack_paths)
        title = "Attack Paths"
        if total > len(self._attack_paths):
            title += f" ({len(self._attack_paths)} of {total} shown)"
        parts.append(
            f'<text x="16" y="{y + 18:.0f}" fill="#1e293b" '
            f'font-size="12" font-weight="600">{_esc(title)}</text>'
        )
        y += ATTACK_PATH_SECTION_TITLE_H

        if not self._attack_paths:
            parts.append(
                f'<g class="attack-paths-empty">'
                f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{y + 12:.0f}" fill="#475569" '
                f'font-size="11" font-weight="600">{_esc(NO_ATTACK_PATHS_NOTE)}</text>'
                f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{y + 27:.0f}" fill="#64748b" '
                f'font-size="10">{_esc(NO_ATTACK_PATHS_DETAIL)}</text>'
                f"</g>"
            )
            parts.append("</g>")
            return "\n".join(parts)

        for path_num, path in self._attack_paths:
            parts.append(self._svg_attack_path(path_num, path, y))
            y += ATTACK_PATH_ROW_H

        if total > len(self._attack_paths):
            more = total - len(self._attack_paths)
            parts.append(
                f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{y + 10:.0f}" fill="#64748b" '
                f'font-size="10">{more} more attack paths not shown; '
                f"see the JSON or SARIF report</text>"
            )
        parts.append("</g>")
        return "\n".join(parts)

    def _svg_attack_path(self, path_num: int, path: AttackPath, top: float) -> str:
        sev_color = _path_color(path)
        sev = path.severity.value
        node_w = ATTACK_PATH_NODE_W
        font = ATTACK_PATH_FONT
        group_id = _element_id(self._prefix, "path", path.id or str(path_num))
        parts: list[str] = [f'<g class="attack-path" id="{group_id}" data-severity="{sev}">']

        header = f"Attack Path {path_num} ({sev.capitalize()})"
        if path.score:
            header += f" - score {path.score:g}"
        parts.append(
            f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{top + 14:.0f}" fill="{sev_color}" '
            f'font-size="10" font-weight="600">{_esc(header)}</text>'
        )
        if path.rationale:
            header_w = len(header) * 10 * 0.6 + 20
            room = max(self._canvas_w - ATTACK_PATH_PAD - header_w - 24, 80)
            rationale = _wrap(path.rationale, room, 9, 1)[0]
            parts.append(
                f'<text x="{ATTACK_PATH_PAD + 4 + header_w:.0f}" y="{top + 14:.0f}" '
                f'fill="#64748b" font-size="9">{_esc(rationale)}</text>'
            )

        box_y = top + 22
        node_cy = box_y + ATTACK_PATH_NODE_H / 2
        cx = float(ATTACK_PATH_PAD)
        for i, hop in enumerate(path.hops):
            short_name = hop.node_id.rsplit(".", 1)[-1] if "." in hop.node_id else hop.node_id
            name_lines = _wrap(short_name, node_w, font, 2)
            parts.append(
                f'<rect x="{cx:.0f}" y="{box_y:.0f}" '
                f'width="{node_w}" height="{ATTACK_PATH_NODE_H}" '
                f'rx="4" fill="#ffffff" stroke="{sev_color}" stroke-width="1.5"/>'
            )
            name_y = node_cy + 3 - (len(name_lines) - 1) * ATTACK_PATH_LINE_H / 2
            parts.append(
                _text_block(
                    cx + node_w / 2,
                    name_y,
                    name_lines,
                    ATTACK_PATH_LINE_H,
                    f'fill="#1e293b" font-size="{font}" font-weight="600" text-anchor="middle"',
                )
            )

            caption = self._hop_caption(hop)
            if caption:
                lines = _wrap(caption, node_w + 24, font, ATTACK_PATH_CAPTION_LINES)
                parts.append(
                    _text_block(
                        cx + node_w / 2,
                        box_y + ATTACK_PATH_NODE_H + 13,
                        lines,
                        ATTACK_PATH_LINE_H,
                        f'fill="#475569" font-size="{font}" text-anchor="middle"',
                    )
                )

            cx += node_w
            if i < len(path.hops) - 1:
                label = _hop_edge_label(hop)
                parts.append(
                    f'<line x1="{cx:.0f}" y1="{node_cy:.0f}" '
                    f'x2="{cx + ATTACK_PATH_ARROW_W:.0f}" y2="{node_cy:.0f}" '
                    f'stroke="{sev_color}" stroke-width="1.5" '
                    f'marker-end="{self._url(f"arrow-path-{sev}")}"/>'
                )
                if label:
                    shown = _truncate(label, _chars_per_line(ATTACK_PATH_ARROW_W + 8, font))
                    parts.append(
                        f'<text x="{cx + ATTACK_PATH_ARROW_W / 2:.0f}" '
                        f'y="{node_cy - 5:.0f}" fill="#64748b" '
                        f'font-size="{font}" text-anchor="middle">{_esc(shown)}</text>'
                    )
                cx += ATTACK_PATH_ARROW_W

        parts.append("</g>")
        return "\n".join(parts)

    def _hop_caption(self, hop: AttackHop) -> str:
        """The title of the worst finding that enables this hop, else the worst on the node."""
        enabling = [self._threats_by_id[t] for t in hop.enabled_by if t in self._threats_by_id]
        worst = _worst(enabling) or _worst(self._threats_by_address.get(hop.node_id, []))
        return worst.title if worst is not None else ""

    # -- Findings table -------------------------------------------------------

    def _svg_threat_table(self) -> str:
        """Render a full threat listing table below the diagram."""
        if not self._table_rows and not self._table_overflow:
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

        cols = self._table_cols

        # Header row
        parts.append(
            f'<rect x="16" y="{y:.0f}" width="{w - 32:.0f}" '
            f'height="{THREAT_TABLE_HEADER_H}" rx="4" fill="#1e293b"/>'
        )
        hx = 24.0
        hy = y + THREAT_TABLE_HEADER_H / 2 + 4
        headers = [
            "Severity",
            "Resource",
            "Threat",
            "Description",
            "ATT&amp;CK Technique",
            "STRIDE Category",
            "Source",
        ]
        for label, col_w in zip(headers, cols, strict=True):
            parts.append(
                f'<text x="{hx:.0f}" y="{hy:.0f}" fill="#ffffff" '
                f'font-size="9" font-weight="600">{label}</text>'
            )
            hx += col_w

        y += THREAT_TABLE_HEADER_H

        styles = [
            ("", 9),
            ("#475569", 9),
            ("#1e293b", 9),
            ("#64748b", 8),
            ("#7c3aed", 8),
            ("#64748b", 9),
            ("#94a3b8", 9),
        ]
        classes = ["", "", "", ' class="threat-desc"', ' class="threat-mitre"', "", ""]

        # Data rows
        for i, row in enumerate(self._table_rows):
            threat = row.threat
            row_fill = "#ffffff" if i % 2 == 0 else "#f8fafc"
            parts.append(
                f'<g class="threat-row">'
                f'<rect x="16" y="{y:.0f}" width="{w - 32:.0f}" '
                f'height="{row.height:.1f}" fill="{row_fill}"/>'
            )

            rx = 24.0
            ry = y + TABLE_TEXT_TOP
            for c, (cell, (color, font)) in enumerate(zip(row.cells, styles, strict=True)):
                if c == 0:
                    # Severity dot + label
                    sev = threat_severity(threat).value
                    sev_color = SEVERITY_COLORS.get(sev, "#94a3b8")
                    parts.append(
                        f'<circle cx="{rx + 4:.0f}" cy="{ry - 2:.0f}" r="3" fill="{sev_color}"/>'
                    )
                    parts.append(
                        f'<text x="{rx + 12:.0f}" y="{ry:.0f}" fill="{sev_color}" '
                        f'font-size="9" font-weight="600">{_esc(cell[0])}</text>'
                    )
                else:
                    attrs = f'fill="{color}" font-size="{font}"{classes[c]}'
                    parts.append(_text_block(rx, ry, cell, _line_h(font), attrs))
                rx += cols[c]

            # Row tooltip: the full text of the cells, plus the mitigation
            tooltip_lines = [f"{threat.title}: {threat.description}"]
            if threat.mitigation:
                tooltip_lines.append(f"Mitigation: {threat.mitigation}")
            parts.append(f"<title>{_esc(chr(10).join(tooltip_lines))}</title>")
            parts.append("</g>")
            y += row.height

        if self._table_overflow:
            parts.append(
                f'<g class="threat-overflow">'
                f'<rect x="16" y="{y:.0f}" width="{w - 32:.0f}" '
                f'height="{THREAT_TABLE_ROW_H}" fill="#fef9c3"/>'
                f'<text x="24" y="{y + TABLE_TEXT_TOP:.1f}" '
                f'fill="#713f12" font-size="9" font-weight="600">'
                f"{self._table_overflow} more threats not shown; "
                f"see JSON/SARIF report</text></g>"
            )

        parts.append("</g>")
        return "\n".join(parts)

    # -- Legend ---------------------------------------------------------------

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
            f'font-size="9">Data Store (storage, database, secret)</text>'
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
            f'stroke="#ef4444" stroke-width="2" filter="{self._url("glow")}"/>'
        )
        parts.append(
            f'<polygon points="{col2_x + 30:.0f},{cy - 3} '
            f'{col2_x + 36:.0f},{cy} {col2_x + 30:.0f},{cy + 3}" fill="#ef4444"/>'
        )
        parts.append(
            f'<text x="{col2_x + 42:.0f}" y="{cy + 3:.0f}" fill="#ef4444" '
            f'font-size="9" font-weight="600">Trust Boundary Crossing</text>'
        )
        cy += 18

        # Containment is a nested frame, not an arrow
        parts.append(
            f'<rect x="{col2_x:.0f}" y="{cy - 6:.0f}" width="30" height="12" rx="3" '
            f'fill="#ffffff" fill-opacity="0.55" stroke="{FRAME_STROKES[1]}" stroke-width="1.2"/>'
        )
        parts.append(
            f'<text x="{col2_x + 42:.0f}" y="{cy + 3:.0f}" fill="#64748b" '
            f'font-size="9">Containment (nested frame)</text>'
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


def _short_name(node: InfraNode) -> str:
    """Name shown in a node: the last segment of its address, or the node name."""
    if "." not in node.id:
        return node.name
    short = node.id.rsplit(".", 1)[-1]
    # A Dockerfile instruction is dockerfile.run.3: "run.3" says more than "3"
    if node.resource_type.startswith("dockerfile_") and short.isdigit():
        return ".".join(node.id.rsplit(".", 2)[-2:])
    return short


def _shape_for(category: NodeCategory) -> Shape:
    """Outline used for a node category, for edge port placement."""
    if category in _DATA_STORE_CATEGORIES:
        return "cylinder"
    if category in _DATA_FLOW_CATEGORIES:
        return "diamond"
    return "rect"


def _edge_zones(edge: InfraEdge) -> tuple[str, str]:
    """Source and target zone names of an edge, from its typed fields or its legacy metadata."""
    src = edge.source_zone.value if edge.source_zone else str(edge.metadata.get("source_zone", ""))
    tgt = edge.target_zone.value if edge.target_zone else str(edge.metadata.get("target_zone", ""))
    return src, tgt


def _path_color(path: AttackPath) -> str:
    return SEVERITY_COLORS.get(path.severity.value, "#94a3b8")


def _hop_edge_label(hop: AttackHop) -> str:
    """What an arrow between two hops says: the edge type, then the ports it carries."""
    if not hop.edge_type_to_next:
        return ""
    label = _HOP_EDGE_LABELS.get(hop.edge_type_to_next, hop.edge_type_to_next)
    ports = hop.via.get("ports") or hop.via.get("port")
    if ports:
        shown = ",".join(str(p) for p in ports) if isinstance(ports, list | tuple) else str(ports)
        label += f" :{shown}"
    return label


def _label_text_width(text: str) -> float:
    """Estimated rendered width of a boundary label's text."""
    return sum(EDGE_LABEL_GLYPH_W.get(ch, EDGE_LABEL_CHAR_W) for ch in text)


def _badge_rect(x: float, y: float) -> Rect:
    """Bounding box of the threat badge drawn by _svg_threat_badge for a node at (x, y)."""
    return Rect(x + NODE_W - 17, y - 11, 14, 14)


def _esc(text: str) -> str:
    """XML-escape text for safe SVG embedding."""
    return escape(str(text))


def _quote(text: str) -> str:
    """Quote an attribute value."""
    return f'"{_esc(text)}"'


def format_diagram(
    report: ThreatReport,
    graph: InfraGraph,
    *,
    max_rows: int | None = DEFAULT_MAX_ROWS,
    expand_docker: bool = False,
    lod_threshold: int | None = DEFAULT_LOD_THRESHOLD,
) -> str:
    """Format a threat report + graph as an SVG data flow diagram.

    ``max_rows`` caps the findings table (the rest become one overflow row), ``expand_docker``
    draws every Dockerfile instruction instead of one node per large stage, and
    ``lod_threshold`` is the node count above which nodes collapse by zone and type
    (None keeps every node).
    """
    return DiagramRenderer(
        report,
        graph,
        max_rows=max_rows,
        expand_docker=expand_docker,
        lod_threshold=lod_threshold,
    ).render()
