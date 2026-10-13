"""SVG threat model diagram renderer - data flow diagrams with trust zone swim lanes.

The diagram draws what the report and the graph say and computes nothing of its own about attack
routes: attack paths come from ``report.attack_paths`` and are drawn hop by hop in the direction
of their edges, numbered in the order the Markdown, terminal and SARIF reports number them.
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
from threatcode.formatters._utils import threat_source
from threatcode.formatters.diagram_labels import (
    GENERIC_EDGE_LABELS,
    Enabler,
    base_name,
    edge_label,
    edge_phrase,
    first_sentence,
    hop_enablers,
    humanize_tokens,
    node_labels,
    ordered_attack_paths,
    shorten_address,
    shorten_middle,
)
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
from threatcode.ir.edges import FLOW_EDGE_TYPES, EdgeType
from threatcode.ir.nodes import NodeCategory, TrustZone
from threatcode.models.report import threat_severity
from threatcode.models.threat import Severity

if TYPE_CHECKING:
    from threatcode.ir.edges import InfraEdge
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.nodes import InfraNode
    from threatcode.models.attack_path import AttackHop, AttackPath
    from threatcode.models.report import ThreatReport
    from threatcode.models.threat import Threat

logger = logging.getLogger(__name__)

# Layout constants
NODE_W = 176
NODE_H = 54
NODE_GAP_X = 36
NODE_GAP_Y = 40
LANE_PAD_X = 80
LANE_PAD_Y = 40
HEADER_H = 44
SUMMARY_BAR_H = 32
LEGEND_H = 140
LEGEND_COL_W = 236
LEGEND_MIN_W = 24 + 4 * LEGEND_COL_W
LEGEND_ROW_H = 18
THREAT_TABLE_ROW_H = 20
THREAT_TABLE_HEADER_H = 28
MIN_LANE_H = 90
MAX_NODES_PER_ROW = 5
MAX_COLUMNS = 8
CANVAS_PAD = 20

# Findings table: the most rows drawn (the rest become one overflow row) and the most lines
# one cell wraps onto before its last line is cut with an ellipsis (the row tooltip has it all)
DEFAULT_MAX_ROWS = 200
TABLE_MAX_CELL_LINES = 3
# The description is the first sentence of the rule's text, which is sometimes long
TABLE_DESCRIPTION_LINES = 4
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
# A label's text is about this wide per character at 9px semibold, and sits in this much padding
FRAME_LABEL_CHAR_W = 5.4
FRAME_LABEL_PAD = 5
# How many places along a frame's top edge a label is tried at
FRAME_LABEL_SLOTS = 24
FRAME_STROKES = {1: "#64748b", 2: "#94a3b8", 3: "#b6c2d2"}

# Node text baselines (offsets from the node top), shared by every shape so names
# line up across a row; clear of cylinder caps and inside the diamond outline
NODE_TYPE_BASELINE = 21
NODE_NAME_BASELINE = 37
NODE_TYPE_FONT = 9
NODE_TYPE_MAX_CHARS = 31
NODE_NAME_MAX_CHARS = 26

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
ARROW = "\u2192"
CROSSING_WIDTH = "1.6"
TRANSITION_TOOLTIP_EDGES = 10
# Zone transition labels: amber, so they stay apart from the severity colors of attack paths
BOUNDARY_STROKE = "#fcd34d"
BOUNDARY_INK = "#92400e"
# The ``P1`` badge a path number sits in
PATH_BADGE_H = 14
PATH_BADGE_PAD_X = 5
PATH_BADGE_CHAR_W = 5.6

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

# The same hues, dark enough to read on the lane they name: the lane border colors above are
# pastels meant for lines, and as 10px text on the lane fill they have a contrast of 1.3 to 1.7
ZONE_TITLE_COLORS: dict[TrustZone, str] = {
    TrustZone.INTERNET: "#b91c1c",
    TrustZone.DMZ: "#c2410c",
    TrustZone.PRIVATE: "#1d4ed8",
    TrustZone.DATA: "#15803d",
    TrustZone.MANAGEMENT: "#6d28d9",
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

# Which type of several edges between the same two nodes decides the look of the one arrow:
# what carries traffic or data, then what grants authority, then what only references
_EDGE_RANK: dict[EdgeType, int] = {
    EdgeType.CONTAINMENT: 0,
    EdgeType.DEPENDENCY: 1,
    EdgeType.IAM_BINDING: 2,
    EdgeType.DATA_FLOW: 3,
    EdgeType.NETWORK_FLOW: 4,
}

SEVERITY_COLORS: dict[str, str] = {
    "critical": "#dc2626",
    "high": "#f97316",
    "medium": "#eab308",
    "low": "#2563eb",
    "info": "#94a3b8",
}

# Severity as text on white or a pale fill: the fills above are for dots, badges and strokes
SEVERITY_TEXT_COLORS: dict[str, str] = {
    "critical": "#b91c1c",
    "high": "#c2410c",
    "medium": "#a16207",
    "low": "#1d4ed8",
    "info": "#475569",
}
# What is written on a badge of that fill: white where it reads, else the dark ink
BADGE_INK_LIGHT = "#ffffff"
BADGE_INK_DARK = "#1e293b"
SEVERITY_BADGE_INK: dict[str, str] = {
    "critical": BADGE_INK_LIGHT,
    "high": BADGE_INK_DARK,
    "medium": BADGE_INK_DARK,
    "low": BADGE_INK_LIGHT,
    "info": BADGE_INK_DARK,
}

# Greys for text: every one is at least 4.5:1 on white and on the legend and summary fills
INK = "#1e293b"
INK_MUTED = "#475569"
INK_SOFT = "#64748b"

SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"]

# Attack path visualization constants
ATTACK_PATH_SECTION_TITLE_H = 28
ATTACK_PATH_HEADER_H = 18
ATTACK_PATH_ROW_GAP = 14
ATTACK_PATH_NODE_W = 132
ATTACK_PATH_NODE_H = 28
ATTACK_PATH_ARROW_W = 90
# The hops start this far from the left edge: what is written under the first one is as wide as
# a box plus an arrow less 12 pixels, and must not run off the canvas
ATTACK_PATH_X0 = (ATTACK_PATH_ARROW_W - 12) // 2 + 6
# The most lines an address wraps onto inside its box, the most lines a rationale takes, the most
# findings listed under one hop (the rest are counted) and the lines one finding wraps onto
ATTACK_PATH_NAME_LINES = 3
ATTACK_PATH_RATIONALE_LINES = 3
ATTACK_PATH_MAX_ENABLERS = 3
ATTACK_PATH_ENABLER_LINES = 3
ATTACK_PATH_PAD = 16
ATTACK_PATH_MAX_PATHS = 5
ATTACK_PATH_CIRCLE_R = 9
ATTACK_PATH_NOTE_H = 36
# Smallest font the attack path blocks use: captions and edge labels stay readable
ATTACK_PATH_FONT = 9
ATTACK_PATH_LINE_H = 11

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

# STRIDE element -> shape mapping: a data store is a cylinder, anything else a process box
_DATA_STORE_CATEGORIES = {
    NodeCategory.STORAGE,
    NodeCategory.DATABASE,
    NodeCategory.SECRET,
}
# Network and delivery plumbing: drawn as a dashed box, never as a flow or a store
_NETWORK_CATEGORIES = {
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
_BREAK_PRIORITY = (".:", "/", "-_[]:,;")


def _chars_per_line(width_px: float, font_size: float) -> int:
    return max(int((width_px - _COLUMN_GAP_PX) / (font_size * _AVG_CHAR_WIDTH_EM)), 4)


def _split_token(token: str, limit: int) -> list[str]:
    """Break a token longer than ``limit`` at a separator when one is near, else mid-word."""
    pieces: list[str] = []
    while len(token) > limit:
        # An address breaks best where its type ends and its name starts, then at a path
        # separator, then after any other separator
        cut = 0
        for group in _BREAK_PRIORITY:
            cut = max((token.rfind(ch, 0, limit) for ch in group), default=-1) + 1
            if cut >= limit // 2:
                break
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


def _wrap_keep_end(text: str, width_px: float, font_size: float, max_lines: int) -> list[str]:
    """Like ``_wrap``, but a text too long for ``max_lines`` is cut in the middle.

    An address or a path says which resource it is at its end, so the end is what has to stay.
    """
    room = _chars_per_line(width_px, font_size) * max_lines - max_lines
    return _wrap(shorten_address(text, max(room, 8)), width_px, font_size, max_lines)


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
    """Prefix of every id in one document: 'tc' and a hash of what the diagram is of.

    Two diagrams embedded in one HTML page would otherwise both define ``#shadow`` and ``#glow``
    and the second would silently use the first one's.
    """
    return "tc" + hashlib.sha1(source.encode(), usedforsecurity=False).hexdigest()[:8]


def _document_key(report: ThreatReport, graph: InfraGraph) -> str:
    """What tells one diagram from another: the input, the resources, the findings and the paths.

    The input name alone is not enough, since every scan of the current directory is named ``.``
    and two scans of one directory (a branch and its base, before and after a fix) share a name.
    Nothing here changes between two renders of one report, the time of the scan included.
    """
    parts = [
        report.input_file,
        *sorted(graph.nodes),
        *sorted(threat.id for threat in report.threats),
        *sorted(path.id for path in report.attack_paths),
    ]
    return "\x00".join(parts)


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
    # Drawn as an external entity: the internet and identities, not something that is deployed
    entity: bool = False


@dataclass
class _DEdge:
    """A connector as drawn: every graph edge between the same two drawn nodes, as one arrow.

    ``edge_type`` is the strongest of the merged edges and decides how the arrow looks.
    ``crosses`` is true for a flow (traffic or data) between two trust zones; a reference or an
    IAM binding that merely runs between two zones is not a crossing.
    """

    source: str
    target: str
    edge_type: EdgeType
    crosses: bool = False
    # Source and target zone of a crossing, as the engine names them ("" when it is not one)
    zones: tuple[str, str] = ("", "")
    # What each merged graph edge says, one line each, for the tooltip
    lines: list[str] = field(default_factory=list)


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
    zone: TrustZone
    # What the frame is called on the diagram: the container, and for a container drawn in
    # several lanes or rows, which part this is
    label: str = ""
    # Where the label sits, once the routes are known
    label_rect: Rect | None = None


@dataclass
class _StripHop:
    """One hop of an attack path as the strip draws it."""

    address: list[str]
    # One wrapped block per finding that enables the hop, then the ATT&CK line
    captions: list[list[str]]
    tooltip: str


@dataclass
class _Strip:
    """The size of one attack path strip and what is written in it."""

    rationale: list[str]
    hops: list[_StripHop]
    box_h: float
    caption_lines: int

    @property
    def height(self) -> float:
        captions = 6 + self.caption_lines * ATTACK_PATH_LINE_H if self.caption_lines else 0
        return (
            ATTACK_PATH_HEADER_H
            + len(self.rationale) * ATTACK_PATH_LINE_H
            + 8
            + self.box_h
            + captions
            + ATTACK_PATH_ROW_GAP
        )


@dataclass
class _TableRow:
    threats: list[Threat]
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
        self._prefix = _doc_prefix(_document_key(report, graph))
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
        self._paths_by_number: dict[int, AttackPath] = {}
        self._edge_attack_path_map: dict[tuple[str, str], list[int]] = {}
        # Per connector: (path number, step in that path, steps in that path)
        self._edge_steps: dict[tuple[str, str], list[tuple[int, int, int]]] = {}
        self._attack_paths_y = 0.0
        self._attack_paths_h = 0.0
        self._strips: dict[int, _Strip] = {}
        # Findings table state
        self._table_rows: list[_TableRow] = []
        self._table_overflow = 0
        self._table_entries_total = 0
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
        for zone, y, h, _nodes in self._zone_lanes:
            parts.append(self._svg_zone_lane(zone, y, h))
        parts.append(self._svg_frames())
        glowing: set[tuple[str, str]] = set()
        # Attack path hops are drawn last, so no plain connector lies over one
        on_path = self._edge_attack_path_map
        ordered = sorted(self._dedges, key=lambda e: (e.source, e.target) in on_path)
        for edge in ordered:
            svg = self._svg_edge(edge, glowing)
            if svg:
                parts.append(svg)
        for node_id, (x, y) in self._node_positions.items():
            parts.append(self._svg_node(self._dnodes[node_id], x, y))
        # Frame labels sit above connectors and nodes, so nothing is drawn through their text
        parts.append(self._svg_frame_labels())
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
        companions = self._folded_companions(nodes, edges, collapsed)
        hidden = {**collapsed, **companions}
        parent_of = self._containment_parents(nodes, edges, hidden)
        containers = set(parent_of.values())
        visible = [nid for nid in nodes if nid not in hidden]
        framed = [nid for nid in visible if nid not in containers]
        use_lod = self.lod_threshold is not None and len(framed) > self.lod_threshold
        if use_lod:
            self._build_summary_view(nodes, edges, hidden, visible)
            return

        self._repr = {nid: (None if nid in containers else nid) for nid in nodes}
        for member, host in hidden.items():
            self._repr[member] = host
        members_of: dict[str, list[str]] = defaultdict(list)
        for member, stage in collapsed.items():
            members_of[stage].append(member)
        settings_of: dict[str, list[str]] = defaultdict(list)
        for companion, owner in companions.items():
            settings_of[owner].append(companion)
        self._draw_nodes(framed, members_of, settings_of)
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

    def _draw_nodes(
        self,
        framed: list[str],
        members_of: dict[str, list[str]],
        settings_of: dict[str, list[str]],
    ) -> None:
        """One drawn node per resource that is not a frame, with what was folded into it."""
        nodes = self.graph.nodes
        names = node_labels(
            [(nid, nodes[nid].resource_type) for nid in framed], limit=NODE_NAME_MAX_CHARS
        )
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
            if nid in settings_of:
                for companion in settings_of[nid]:
                    threats.extend(self._threats_by_address.get(companion, ()))
                tooltip_extra += self._settings_tooltip(settings_of[nid])
            self._dnodes[nid] = _DNode(
                id=nid,
                resource_type=node.resource_type or nid.split(".")[0],
                name=names[nid],
                category=node.category,
                zone=node.trust_zone,
                threats=threats,
                tooltip=self._node_tooltip(node, threats, tooltip_extra),
                caption=caption,
                entity=node.is_internet or node.category in _ENTITY_CATEGORIES,
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

    def _folded_companions(
        self,
        nodes: dict[str, InfraNode],
        edges: list[InfraEdge],
        skip: dict[str, str],
    ) -> dict[str, str]:
        """Settings resources folded into the data store they configure: {companion: owner}.

        ``aws_s3_bucket_public_access_block`` and ``aws_s3_bucket_server_side_encryption_
        configuration`` are the bucket's settings, written as resources of their own.
        Drawn as nodes they are more cylinders named like the bucket; folded in, the bucket's
        badge and tooltip carry their findings.
        A companion is a data store whose type extends the type of the data store it references.
        """
        found: dict[str, str] = {}
        for edge in edges:
            if edge.edge_type is not EdgeType.DEPENDENCY or edge.source == edge.target:
                continue
            companion = nodes.get(edge.source)
            owner = nodes.get(edge.target)
            if companion is None or owner is None or edge.source in skip:
                continue
            if (
                companion.category in _DATA_STORE_CATEGORIES
                and owner.category in _DATA_STORE_CATEGORIES
                and companion.resource_type.startswith(owner.resource_type + "_")
            ):
                found.setdefault(edge.source, edge.target)
        # A companion of a companion folds into the data store at the root
        for companion_id in list(found):
            seen = {companion_id}
            root = found[companion_id]
            while root in found and root not in seen:
                seen.add(root)
                root = found[root]
            if root in seen:  # a cycle in hostile input: leave the nodes alone
                del found[companion_id]
            else:
                found[companion_id] = root
        return found

    def _settings_tooltip(self, companions: list[str]) -> list[str]:
        lines = ["", f"Settings folded into this resource ({len(companions)}):"]
        for companion in companions:
            lines.append(f"  {companion}")
            for threat in self._threats_by_address.get(companion, ()):
                lines.append(f"    {threat_severity(threat).value.upper()} - {threat.title}")
        return lines

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
        """Map graph edges onto the drawn nodes: no containment, no self loops from merging.

        Edges between the same two drawn nodes become one arrow, whatever their types: two
        arrows on one route are drawn on top of each other and read as one anyway.
        """
        index: dict[tuple[str, str], int] = {}
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
            key = (source, target)
            crossing = edge.crosses_trust_boundary and edge.edge_type in FLOW_EDGE_TYPES
            line = self._edge_line(edge)
            if key in index:
                existing = self._dedges[index[key]]
                if _EDGE_RANK[edge.edge_type] > _EDGE_RANK[existing.edge_type]:
                    existing.edge_type = edge.edge_type
                if crossing and not existing.crosses:
                    existing.crosses = True
                    existing.zones = _edge_zones(edge)
                if line not in existing.lines:
                    existing.lines.append(line)
                continue
            index[key] = len(self._dedges)
            self._dedges.append(
                _DEdge(
                    source=source,
                    target=target,
                    edge_type=edge.edge_type,
                    crosses=crossing,
                    zones=_edge_zones(edge) if crossing else ("", ""),
                    lines=[line],
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

    def _number_attack_paths(self) -> float:
        """Number the report's attack paths, find their connectors, return the width they need."""
        # The numbers are the ones the Markdown, text and SARIF reports give the same paths
        ordered = ordered_attack_paths(self.report.attack_paths)
        self._attack_paths = list(enumerate(ordered[:ATTACK_PATH_MAX_PATHS], start=1))
        self._paths_by_number = dict(self._attack_paths)
        self._build_edge_attack_path_map()
        attack_path_w = 0.0
        for _, path in self._attack_paths:
            n = max(len(path.hops), 1)
            pw = (
                ATTACK_PATH_X0
                + ATTACK_PATH_PAD
                + n * ATTACK_PATH_NODE_W
                + (n - 1) * ATTACK_PATH_ARROW_W
            )
            attack_path_w = max(attack_path_w, pw)
        return attack_path_w

    def _size_attack_paths(self) -> None:
        """Lay out each strip at the final canvas width and total the height of the section."""
        self._strips = {num: self._layout_strip(path) for num, path in self._attack_paths}
        attack_path_h = 0.0
        if self._attack_paths:
            attack_path_h = (
                ATTACK_PATH_SECTION_TITLE_H
                + sum(strip.height for strip in self._strips.values())
                + ATTACK_PATH_PAD * 2
            )
            if len(self.report.attack_paths) > len(self._attack_paths):
                attack_path_h += ATTACK_PATH_NOTE_H / 2
        elif self._dnodes:
            attack_path_h = ATTACK_PATH_SECTION_TITLE_H + ATTACK_PATH_NOTE_H + ATTACK_PATH_PAD
        self._attack_paths_h = attack_path_h

    def _layout_strip(self, path: AttackPath) -> _Strip:
        """Wrap everything a strip says: the rationale, each address, each hop's findings."""
        font = ATTACK_PATH_FONT
        rationale: list[str] = []
        if path.rationale:
            room = self._canvas_w - 2 * ATTACK_PATH_PAD - 8
            rationale = _wrap(path.rationale, room, font, ATTACK_PATH_RATIONALE_LINES)
        enablers = hop_enablers(path, self._threats_by_id)
        hops: list[_StripHop] = []
        caption_w = ATTACK_PATH_NODE_W + ATTACK_PATH_ARROW_W - 12
        for hop, found in zip(path.hops, enablers, strict=True):
            captions: list[list[str]] = []
            for enabler in found[:ATTACK_PATH_MAX_ENABLERS]:
                captions.append(
                    _wrap(_enabler_text(enabler), caption_w, font, ATTACK_PATH_ENABLER_LINES)
                )
            if len(found) > ATTACK_PATH_MAX_ENABLERS:
                more = len(found) - ATTACK_PATH_MAX_ENABLERS
                captions.append([f"+{more} more finding{'s' if more > 1 else ''}"])
            if hop.techniques:
                captions.append(_wrap("ATT&CK " + ", ".join(hop.techniques), caption_w, font, 1))
            hops.append(
                _StripHop(
                    address=_wrap(hop.node_id, ATTACK_PATH_NODE_W, font, ATTACK_PATH_NAME_LINES),
                    captions=captions,
                    tooltip=self._hop_tooltip(hop, found),
                )
            )
        name_lines = max((len(h.address) for h in hops), default=1)
        box_h = max(float(ATTACK_PATH_NODE_H), 10 + name_lines * ATTACK_PATH_LINE_H)
        caption_lines = max((sum(len(c) for c in h.captions) for h in hops), default=0)
        return _Strip(rationale, hops, box_h, caption_lines)

    def _hop_tooltip(self, hop: AttackHop, found: list[Enabler]) -> str:
        """The whole of a hop: address, zone, what it does next, every finding, the techniques."""
        lines = [hop.node_id]
        if hop.zone:
            lines.append(f"Zone: {hop.zone}")
        phrase = edge_phrase(hop.edge_type_to_next, via=hop.via)
        if phrase:
            lines.append(f"Then: {phrase}")
        for enabler in found:
            severity = enabler.severity.value.upper() + " - " if enabler.severity else ""
            lines.append(f"Enabled by {severity}{_enabler_text(enabler)}")
        if hop.techniques:
            lines.append("ATT&CK: " + ", ".join(hop.techniques))
        return "\n".join(lines)

    def _compute_layout(self) -> None:
        zones_map: dict[TrustZone, list[_DNode]] = defaultdict(list)
        for dnode in self._dnodes.values():
            zones_map[dnode.zone].append(dnode)

        max_depth = max((len(c) for c in self._chain.values()), default=0)
        self._gap_x = max(NODE_GAP_X, 2 * FRAME_PAD * max_depth + 12)
        # The canvas is at least as wide as the legend and the longest attack path; the nodes
        # of a lane use that width instead of leaving the right of the lane empty
        attack_path_w = self._number_attack_paths()
        target_w = max(LEGEND_MIN_W, attack_path_w + CANVAS_PAD * 2)
        per_row = max(
            MAX_NODES_PER_ROW,
            min(int((target_w - LANE_PAD_X - self._gap_x) // (NODE_W + self._gap_x)), MAX_COLUMNS),
        )
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
                if i > 0 and (col >= per_row or (col > 0 and top != previous_top)):
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

        # Ensure canvas is wide enough for legend, attack paths, and expanded table
        self._canvas_w = max(max_lane_w + CANVAS_PAD * 2, 400, target_w)

        self._size_attack_paths()
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
        y_cursor += self._attack_paths_h
        self._threat_table_y = y_cursor
        y_cursor += threat_table_h
        self._legend_y = y_cursor
        self._canvas_h = y_cursor + LEGEND_H + CANVAS_PAD

        self._compute_routes()
        self._place_frame_labels()
        self._place_edge_overlays()

    def _compute_frames(self, cells: dict[str, tuple[int, int]]) -> None:
        """Place a frame around each container's members in each lane."""
        first_drawn: set[str] = set()
        for zone, _, _, lane_nodes in self._zone_lanes:
            containers: list[str] = []
            for dnode in lane_nodes:
                for c in self._chain.get(dnode.id, ()):
                    if c not in containers:
                        containers.append(c)
            for container in containers:
                members = [n for n in lane_nodes if container in self._chain.get(n.id, ())]
                for segment in self._frame_segments(members, lane_nodes, cells):
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
                    self._frames.append(_Frame(container, rect, height, badge, zone))
        self._name_frame_parts()
        # Outer frames first so inner ones draw over them
        self._frames.sort(key=lambda f: -f.height)

    def _name_frame_parts(self) -> None:
        """Label a container drawn more than once by the part of it each frame holds.

        A VPC with members in three trust zones has three frames, and three frames that all say
        ``aws_vpc.main`` read as three VPCs; they say ``aws_vpc.main (dmz)`` and so on.
        """
        parts: dict[str, list[_Frame]] = defaultdict(list)
        for frame in self._frames:
            parts[frame.container].append(frame)
        for container, frames in parts.items():
            if len(frames) == 1:
                frames[0].label = container
                continue
            for frame in frames:
                same_zone = [f for f in frames if f.zone is frame.zone]
                zone = ZONE_LABELS.get(frame.zone, frame.zone.value.upper()).lower()
                part = f", part {same_zone.index(frame) + 1}" if len(same_zone) > 1 else ""
                frame.label = f"{container} ({zone}{part})"

    @staticmethod
    def _frame_segments(
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

    def _table_entries(self) -> list[list[Threat]]:
        """The findings, worst first, with findings that share a root cause on one resource as one.

        The same grouping the terminal report uses: a pod without a seccomp profile, with no
        dropped capabilities and no resource limits is one row that says it has two more related
        findings, not three rows that read alike.
        """
        rank = {sev: i for i, sev in enumerate(SEVERITY_ORDER)}
        ordered = sorted(self.report.threats, key=lambda t: rank.get(threat_severity(t).value, 99))
        groups: dict[tuple[str, str], list[Threat]] = {}
        entries: list[list[Threat]] = []
        for threat in ordered:
            if threat.root_cause:
                key = (threat.resource_address, threat.root_cause)
                if key in groups:
                    groups[key].append(threat)
                    continue
                groups[key] = [threat]
                entries.append(groups[key])
            else:
                entries.append([threat])
        return entries

    def _prepare_table(self) -> None:
        """Wrap every cell of the findings table and measure its rows."""
        w = self._canvas_w
        col_sev_w = 66
        col_stride_w = 124  # fits "Elevation of Privilege"
        col_location_w = 118
        col_source_w = 54
        # Free-text columns share what is left of the table width.
        flexible = max(
            w - 40 - col_sev_w - col_stride_w - col_location_w - col_source_w,
            320,
        )
        col_res_w = flexible * 0.22
        col_threat_w = flexible * 0.25
        col_desc_w = flexible * 0.29
        col_attack_w = flexible * 0.24
        self._table_cols = [
            col_sev_w,
            col_res_w,
            col_threat_w,
            col_desc_w,
            col_attack_w,
            col_stride_w,
            col_location_w,
            col_source_w,
        ]
        entries = self._table_entries()
        limit = len(entries) if self.max_rows is None else max(self.max_rows, 0)
        shown = entries[:limit]
        self._table_overflow = sum(len(entry) for entry in entries[limit:])
        self._table_entries_total = len(entries)
        self._table_rows = []
        for entry in shown:
            first = entry[0]
            stride = STRIDE_DISPLAY.get(first.stride_category, first.stride_category)
            title = first.title
            if len(entry) > 1 and first.root_cause:
                cause = first.root_cause.replace("_", " ").replace("-", " ")
                title += f" (+{len(entry) - 1} related: {cause})"
            techniques = list(dict.fromkeys(t for member in entry for t in member.mitre_techniques))
            cells = [
                [max(threat_severity(member) for member in entry).value.upper()],
                _wrap_keep_end(first.resource_address, col_res_w, 9, TABLE_MAX_CELL_LINES),
                _wrap(humanize_tokens(title), col_threat_w, 9, TABLE_MAX_CELL_LINES),
                _wrap(
                    first_sentence(humanize_tokens(first.description)),
                    col_desc_w,
                    8,
                    TABLE_DESCRIPTION_LINES,
                ),
                _wrap(
                    self._format_mitre_techniques(techniques), col_attack_w, 8, TABLE_MAX_CELL_LINES
                ),
                _wrap(stride, col_stride_w, 9, 2),
                _wrap_keep_end(self._location_text(first), col_location_w, 9, 2),
                [first.source.value],
            ]
            fonts = [9, 9, 9, 8, 8, 9, 9, 9]
            body = max((len(c) - 1) * _line_h(f) for c, f in zip(cells, fonts, strict=True))
            height = max(float(THREAT_TABLE_ROW_H), TABLE_TEXT_TOP + body + TABLE_ROW_BOTTOM_PAD)
            self._table_rows.append(_TableRow(entry, cells, height))

    def _location_text(self, threat: Threat) -> str:
        """``file:line`` of a finding, or ``-`` when nothing knows where it is."""
        file, line, _end = threat_source(threat, self.graph)
        if not file:
            return "-"
        return f"{file}:{line}" if line else file

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
        for index, (zone, lane_y, _, _) in enumerate(self._zone_lanes):
            label = ZONE_LABELS.get(zone, zone.value.upper())
            obstacles.add_rect(Rect(8, lane_y + 12, len(label) * 7.5 + 8, 18))
            if index:
                # A badge or label on the line between two zones reads as belonging to both
                half = EDGE_LABEL_H / 2 + 2
                obstacles.add_rect(Rect(0, lane_y - half, self._canvas_w, 2 * half))
        for frame in self._frames:
            if frame.label_rect is not None:
                obstacles.add_rect(frame.label_rect.expand(2))
        return obstacles

    def _place_edge_overlays(self) -> None:
        """Pick collision-free spots for the attack path badges and the zone labels.

        A badge goes on every connector of an attack path.
        A zone label goes on one connector per distinct transition (``DMZ -> PRIVATE``), with the
        number of connectors that make the same crossing, so seven crossings from the DMZ into the
        private zone are one label and not seven.
        """
        if not self._routes:
            return
        lanes_top = self._zone_lanes[0][1]
        last_lane = self._zone_lanes[-1]
        lanes_bottom = last_lane[1] + last_lane[2]
        bounds = Rect(4, lanes_top + 2, self._canvas_w - 8, lanes_bottom - lanes_top - 4)
        obstacles = self._overlay_obstacles()

        transitions: dict[str, list[_DEdge]] = defaultdict(list)
        for edge in self._dedges:
            if edge.crosses and (edge.source, edge.target) in self._routes:
                text = self._zone_label_text(edge)
                if text:
                    transitions[text].append(edge)
        markers: dict[tuple[str, str], list[int]] = {
            key: nums for key, nums in self._edge_attack_path_map.items() if key in self._routes
        }

        # Lane borders and every route are indexed once; a label skips its own route by tag
        avoid = SpatialIndex()
        for _, lane_y, _, _ in self._zone_lanes[1:]:
            avoid.add_segment((0.0, lane_y), (self._canvas_w, lane_y), "lane")
        for key, points in self._routes.items():
            avoid.add_route(points, key)

        def length(key: tuple[str, str]) -> float:
            return sum(math.dist(a, b) for a, b in route_segments(self._routes[key]))

        # Badges first, longest routes first: they have the most room, short ones get what is left
        for key in sorted(markers, key=lambda k: (-length(k), k)):
            nums = markers[key]
            text = _path_badge_text(nums)
            size = (_badge_text_width(text) + 2 * PATH_BADGE_PAD_X, PATH_BADGE_H)
            rect = place_on_route(self._routes[key], size, obstacles, bounds, avoid, skip_tag=key)
            if rect is None:
                mx, my = point_at_half_length(self._routes[key])
                rect = Rect(mx - size[0] / 2, my - size[1] / 2, size[0], size[1])
            self._edge_markers[key] = (rect, nums)
            obstacles.add_rect(rect.expand(OVERLAY_CLEARANCE))

        for text in sorted(transitions):
            edges = transitions[text]
            keys = sorted(
                {(e.source, e.target) for e in edges},
                key=lambda k: (k not in markers, -length(k), k),
            )
            shown = text if len(keys) == 1 else f"{text} x{len(keys)}"
            size = (_label_text_width(shown) + EDGE_LABEL_PAD_X * 2, EDGE_LABEL_H)
            placed: tuple[tuple[str, str], Rect] | None = None
            for key in keys:
                rect = place_on_route(
                    self._routes[key], size, obstacles, bounds, avoid, skip_tag=key
                )
                if rect is not None:
                    placed = (key, rect)
                    break
            if placed is None:
                # Nothing is free; fall back to the midpoint, still drawn above nodes
                mx, my = point_at_half_length(self._routes[keys[0]])
                placed = (keys[0], Rect(mx - size[0] / 2, my - size[1] / 2, size[0], size[1]))
            key, rect = placed
            self._edge_labels[key] = (rect, shown, self._transition_tooltip(text, keys))
            obstacles.add_rect(rect.expand(OVERLAY_CLEARANCE))

    @staticmethod
    def _zone_label_text(edge: _DEdge) -> str:
        """``DMZ -> PRIVATE`` for a crossing, ``""`` when the engine named no zones."""
        src, tgt = edge.zones
        return f"{src.upper()} {ARROW} {tgt.upper()}" if src and tgt else ""

    def _transition_tooltip(self, text: str, keys: list[tuple[str, str]]) -> str:
        count = len(keys)
        lines = [
            f"Trust boundary crossing: {text.lower()}",
            f"{count} connection{'s' if count != 1 else ''} cross{'es' if count == 1 else ''} "
            "this boundary. Data should be encrypted, authenticated, and validated.",
        ]
        for source, target in keys[:TRANSITION_TOOLTIP_EDGES]:
            lines.append(f"  {source} {ARROW} {target}")
        if count > TRANSITION_TOOLTIP_EDGES:
            lines.append(f"  ... and {count - TRANSITION_TOOLTIP_EDGES} more")
        return "\n".join(lines)

    # -- Attack paths ---------------------------------------------------------

    def _build_edge_attack_path_map(self) -> None:
        """Map each drawn (source, target) connector to the numbers of the paths that use it.

        A hop leads from one node to the next, so only the connector that points the same way is
        marked: a path never lights up an edge that runs the other direction.
        A hop the graph has no connector for (between two nodes the view drew) gets its own, so
        every hop of a path is on the diagram.
        """
        self._edge_attack_path_map = {}
        self._edge_steps = {}
        drawn = {(e.source, e.target) for e in self._dedges}
        for path_num, path in self._attack_paths:
            total = len(path.hops) - 1
            hops = zip(path.hops, path.hops[1:], strict=False)
            for step, (here, there) in enumerate(hops, start=1):
                a = self._repr.get(here.node_id)
                b = self._repr.get(there.node_id)
                if (
                    a is None
                    or b is None
                    or a == b
                    or a not in self._dnodes
                    or b not in self._dnodes
                ):
                    continue
                if (a, b) not in drawn:
                    drawn.add((a, b))
                    self._dedges.append(_DEdge(a, b, _hop_edge_type(here)))
                self._say_what_a_hop_does(a, b, here)
                nums = self._edge_attack_path_map.setdefault((a, b), [])
                if path_num not in nums:
                    nums.append(path_num)
                self._edge_steps.setdefault((a, b), []).append((path_num, step, total))

    def _say_what_a_hop_does(self, source: str, target: str, hop: AttackHop) -> None:
        """Put the hop's own words (``Network Flow: tcp/8080``) on its connector's tooltip.

        The hop knows the ports and the relation of the step; a graph edge that only says its
        type (``Network Flow: traffic``) gives way to it.
        """
        edge = next(e for e in self._dedges if (e.source, e.target) == (source, target))
        line = _hop_line(hop)
        kind = line.split(":")[0]
        edge.lines = [
            existing
            for existing in edge.lines
            if not (
                existing.startswith(f"{kind}: ")
                and existing.split(": ", 1)[1] in GENERIC_EDGE_LABELS
            )
        ]
        if line not in edge.lines:
            edge.lines.append(line)

    def _format_mitre_techniques(self, technique_ids: list[str]) -> str:
        """Format MITRE ATT&CK technique IDs with names."""
        if not technique_ids:
            return "-"
        parts: list[str] = []
        for tid in technique_ids:
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
            ink = INK  # the dot carries the color; on a tinted pill colored text is under 4.5:1
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
                f'<text x="{cx + 17:.0f}" y="{cy + 3:.0f}" fill="{ink}" '
                f'font-size="10" font-weight="600">{_esc(label)}</text>'
            )
            cx += pill_w + 8

        # Total summary
        total = len(self.report.threats)
        n_stride = len(stride_cats)
        if total > 0:
            summary = f"Total: {total} threats across {n_stride} STRIDE categories"
            parts.append(
                f'<text x="{w - 16:.0f}" y="{cy + 3:.0f}" fill="{INK_MUTED}" '
                f'font-size="9" text-anchor="end">{_esc(summary)}</text>'
            )

        parts.append("</g>")
        return "\n".join(parts)

    def _svg_zone_lane(self, zone: TrustZone, y: float, h: float) -> str:
        w = self._canvas_w
        fill, border = ZONE_COLORS.get(zone, ("#f8fafc", "#cbd5e1"))
        label = ZONE_LABELS.get(zone, zone.value.upper())
        return (
            f'<g class="zone-{zone.value}">'
            f'<rect x="0" y="{y:.0f}" width="{w:.0f}" height="{h:.0f}" '
            f'fill="{fill}" stroke="{border}" stroke-width="1"/>'
            f'<text x="12" y="{y + 24:.0f}" fill="{ZONE_TITLE_COLORS.get(zone, INK_MUTED)}" '
            f'font-size="10" font-weight="600" letter-spacing="0.5">{_esc(label)}</text>'
            f"</g>"
        )

    # -- Frames ---------------------------------------------------------------

    def _shown_frame_label(self, frame: _Frame) -> str:
        """The label of a frame as drawn: cut in the middle when the frame is too narrow."""
        room = frame.rect.w - 2 * FRAME_LABEL_PAD - (22 if frame.badge else 6)
        max_chars = max(int(room / FRAME_LABEL_CHAR_W), 6)
        return shorten_middle(frame.label or frame.container, max_chars)

    def _place_frame_labels(self) -> None:
        """Put each frame's label where no connector runs through it.

        A label starts at the top left of its frame, and slides right along the frame's top
        edge to the first spot clear of every route and of the other labels.
        When the whole edge is crossed it stays at the left, on an opaque background.
        """
        index = SpatialIndex()
        for key, points in self._routes.items():
            index.add_route(points, key)
        placed = SpatialIndex()
        for frame in self._frames:
            width = len(self._shown_frame_label(frame)) * FRAME_LABEL_CHAR_W + 2 * FRAME_LABEL_PAD
            top = frame.rect.y + 1
            lo = frame.rect.x + 6
            # Keep clear of the badge at the right end of a frame that carries one
            hi = frame.rect.right - width - (22 if frame.badge else 6)
            positions = [lo]
            if hi > lo:
                step = max((hi - lo) / FRAME_LABEL_SLOTS, 4.0)
                positions += [lo + step * i for i in range(1, int((hi - lo) / step) + 1)]
            chosen = Rect(lo, top, width, FRAME_LABEL_H - 1)
            for x in positions:
                rect = Rect(x, top, width, FRAME_LABEL_H - 1)
                if self._label_is_clear(rect, index, placed):
                    chosen = rect
                    break
            frame.label_rect = chosen
            placed.add_rect(chosen)

    @staticmethod
    def _label_is_clear(rect: Rect, routes: SpatialIndex, placed: SpatialIndex) -> bool:
        if any(rect.intersects(other) for other in placed.rects_near(rect)):
            return False
        padded = rect.expand(1)
        return not any(padded.intersects_segment(a, b) for a, b, _ in routes.segments_near(padded))

    def _svg_frames(self) -> str:
        """Containers as rounded frames around their members (the labels are drawn later)."""
        if not self._frames:
            return ""
        parts: list[str] = ['<g class="frames">']
        for number, frame in enumerate(self._frames):
            info = self._frame_info[frame.container]
            rect = frame.rect
            stroke = FRAME_STROKES.get(frame.height, "#94a3b8")
            parts.append(
                f'<g class="frame" '
                f'id="{_element_id(self._prefix, "frame", f"{number}:{info.container}")}" '
                f'data-id="{_esc(info.container)}">'
                f"<title>{_esc(info.tooltip)}</title>"
                f'<rect x="{rect.x:.1f}" y="{rect.y:.1f}" width="{rect.w:.1f}" '
                f'height="{rect.h:.1f}" rx="10" ry="10" fill="#ffffff" fill-opacity="0.55" '
                f'stroke="{stroke}" stroke-width="1.2"/>'
            )
            worst = _worst(info.threats)
            if frame.badge and worst is not None:
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

    def _svg_frame_labels(self) -> str:
        """Frame labels above the connectors, each on a backing that hides a line under it."""
        if not self._frames:
            return ""
        parts: list[str] = ['<g class="frame-labels">']
        for frame in self._frames:
            rect = frame.label_rect
            if rect is None:
                continue
            label = self._shown_frame_label(frame)
            parts.append(
                f'<g class="frame-label" data-id="{_esc(frame.container)}">'
                f'<rect x="{rect.x:.1f}" y="{rect.y:.1f}" width="{rect.w:.1f}" '
                f'height="{rect.h:.1f}" rx="3" fill="#ffffff" fill-opacity="0.85"/>'
                f'<text x="{rect.x + FRAME_LABEL_PAD:.1f}" y="{rect.y + FRAME_LABEL_H - 4:.1f}" '
                f'fill="{INK_MUTED}" font-size="9" font-weight="600">{_esc(label)}</text>'
                f"</g>"
            )
        parts.append("</g>")
        return "\n".join(parts)

    # -- Nodes ----------------------------------------------------------------

    def _svg_node(self, node: _DNode, x: float, y: float) -> str:
        threats = node.threats
        cat = node.category
        if node.entity:
            shape = self._svg_node_entity(x, y, NODE_W, NODE_H)
        elif cat in _DATA_STORE_CATEGORIES:
            shape = self._svg_node_datastore(x, y, NODE_W, NODE_H)
        elif cat in _NETWORK_CATEGORIES:
            shape = self._svg_node_network(x, y, NODE_W, NODE_H)
        else:
            shape = self._svg_node_process(x, y, NODE_W, NODE_H)

        res_type_display = shorten_middle(node.caption or node.resource_type, NODE_TYPE_MAX_CHARS)

        parts = [
            f'<g class="node" id="{_element_id(self._prefix, "node", node.id)}" '
            f'data-id="{_esc(node.id)}" filter="{self._url("shadow")}">',
            shape,
            # Resource type label (top, 9px grey)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + NODE_TYPE_BASELINE:.0f}" fill="{INK_SOFT}" '
            f'font-size="{NODE_TYPE_FONT}" text-anchor="middle">{_esc(res_type_display)}</text>',
            # Resource short name (center, 11px bold)
            f'<text x="{x + NODE_W / 2:.0f}" y="{y + NODE_NAME_BASELINE:.0f}" '
            f'fill="{INK}" font-size="11" font-weight="600" text-anchor="middle">'
            f"{_esc(shorten_middle(node.name, NODE_NAME_MAX_CHARS))}</text>",
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

    def _svg_node_network(self, x: float, y: float, w: float, h: float) -> str:
        """A network or delivery component: a box with a dashed outline, so it reads as plumbing."""
        return (
            f'<rect x="{x:.0f}" y="{y:.0f}" width="{w}" height="{h}" rx="6" ry="6" '
            f'fill="#ffffff" stroke="#94a3b8" stroke-width="1.5" stroke-dasharray="5,3"/>'
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
        ink = SEVERITY_BADGE_INK.get(severity, BADGE_INK_DARK)
        return (
            f'<circle cx="{x:.0f}" cy="{y:.0f}" r="7" fill="{color}"/>'
            f'<text x="{x:.0f}" y="{y + 3.5:.0f}" fill="{ink}" '
            f'font-size="9" font-weight="600" text-anchor="middle">{count}</text>'
        )

    # -- Edges ----------------------------------------------------------------

    def _svg_edge(self, edge: _DEdge, glowing: set[tuple[str, str]]) -> str:
        """One connector.

        An attack path hop is drawn thick in the severity color of the worst path over it and
        glows.
        Everything else keeps the look of its type, so a crossing flow differs from a plain one
        only by its zone label, and a reference that happens to span two zones is not a crossing.
        """
        key = (edge.source, edge.target)
        points = self._routes.get(key)
        if not points:
            return ""

        path_d = polyline_to_path(points)
        path_nums = self._edge_attack_path_map.get(key)
        classes = "edge"
        extra = ""
        if path_nums:
            severity = self._worst_path_severity(path_nums)
            color = SEVERITY_COLORS[severity]
            width = "2.6"
            dash = ""
            marker = self._url(f"arrow-path-{severity}")
            # Paths that share a hop draw it once, so glows do not stack and darken
            filt = "" if key in glowing else f' filter="{self._url("glow")}"'
            glowing.add(key)
            classes = "edge attack-path-edge"
            extra = f' data-path="{" ".join(str(n) for n in path_nums)}"'
        else:
            color, width, dash = EDGE_STYLES.get(edge.edge_type, ("#94a3b8", "1", ""))
            if edge.crosses:
                width = CROSSING_WIDTH
            marker = self._url(f"arrow-{edge.edge_type.value}")
            filt = ""

        dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
        parts: list[str] = [
            '<g class="edge-group">',
            f'<path d="{path_d}" fill="none" stroke="{color}" '
            f'stroke-width="{width}"{dash_attr} stroke-linejoin="round" '
            f'marker-end="{marker}"{filt} '
            f'class="{classes}" data-type="{edge.edge_type.value}" '
            f'data-boundary="{str(edge.crosses).lower()}"{extra}/>',
            f"<title>{_esc(self._edge_tooltip(edge))}</title>",
            "</g>",
        ]
        return "\n".join(parts)

    def _worst_path_severity(self, path_nums: list[int]) -> str:
        by_number = self._paths_by_number
        return max(
            (by_number[n].severity for n in path_nums if n in by_number),
            key=lambda sev: sev.rank,
            default=Severity.MEDIUM,
        ).value

    def _edge_line(self, edge: InfraEdge) -> str:
        """What one graph edge says, in words: ``Network flow: tcp/8080``."""
        kind = EDGE_LABELS.get(edge.edge_type, edge.edge_type.value)
        label = edge_label(edge.edge_type.value, edge.relation, edge.attributes)
        return f"{kind}: {label}" if label else kind

    def _edge_tooltip(self, edge: _DEdge) -> str:
        """Both ends, what connects them, the crossing and the attack paths over it."""
        key = (edge.source, edge.target)
        lines = [f"{edge.source} {ARROW} {edge.target}", *edge.lines]
        if edge.crosses:
            src, tgt = edge.zones
            lines.append(
                f"Crosses a trust boundary: {src} {ARROW} {tgt}. "
                "Data should be encrypted, authenticated, and validated."
            )
        by_number = self._paths_by_number
        for path_num, step, total in self._edge_steps.get(key, ()):
            path = by_number.get(path_num)
            severity = f" ({path.severity.value})" if path else ""
            lines.append(f"Attack path {path_num}{severity}, step {step} of {total}")
        return "\n".join(lines)

    def _svg_edge_overlays(self) -> str:
        """Render zone labels and attack path badges in a layer above the nodes."""
        if not self._edge_labels and not self._edge_markers:
            return ""
        parts: list[str] = ['<g class="edge-overlays">']
        for rect, text, tooltip in self._edge_labels.values():
            parts.append(self._svg_edge_label(rect, text, tooltip))
        for key, (rect, path_nums) in self._edge_markers.items():
            parts.append(self._svg_path_badge(rect, path_nums, key))
        parts.append("</g>")
        return "\n".join(parts)

    def _svg_path_badge(
        self,
        rect: Rect,
        path_nums: list[int],
        key: tuple[str, str],
    ) -> str:
        """An outlined square badge ``P1``: a path number, unlike the round severity badges."""
        worst = self._worst_path_severity(path_nums)
        stroke = SEVERITY_COLORS[worst]
        ink = SEVERITY_TEXT_COLORS[worst]
        text = _path_badge_text(path_nums)
        numbers = ", ".join(str(n) for n in path_nums)
        steps = self._edge_steps.get(key, [])
        detail = "; ".join(f"path {n}, step {k} of {t}" for n, k, t in steps)
        return (
            f'<g class="attack-path-marker">'
            f"<title>Attack path {numbers} ({detail})</title>"
            f'<rect x="{rect.x:.1f}" y="{rect.y:.1f}" width="{rect.w:.1f}" height="{rect.h:.1f}" '
            f'rx="3" fill="#ffffff" stroke="{stroke}" stroke-width="1.5"/>'
            f'<text x="{rect.cx:.1f}" y="{rect.cy + 3.2:.1f}" fill="{ink}" '
            f'font-size="9" font-weight="700" text-anchor="middle">{text}</text>'
            f"</g>"
        )

    def _svg_edge_label(self, rect: Rect, text: str, tooltip: str) -> str:
        """Render a zone transition label on an opaque pill so it reads over edges."""
        return (
            f'<g class="edge-label-group">'
            f"<title>{_esc(tooltip)}</title>"
            f'<rect class="edge-label-bg" x="{rect.x:.1f}" y="{rect.y:.1f}" '
            f'width="{rect.w:.1f}" height="{rect.h:.1f}" rx="3" fill="#ffffff" '
            f'stroke="{BOUNDARY_STROKE}" stroke-width="1"/>'
            f'<text x="{rect.cx:.1f}" y="{rect.cy + 3.2:.1f}" fill="{BOUNDARY_INK}" '
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
            y += self._strips[path_num].height

        if total > len(self._attack_paths):
            more = total - len(self._attack_paths)
            parts.append(
                f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{y + 10:.0f}" fill="{INK_SOFT}" '
                f'font-size="10">{more} more attack paths not shown; '
                f"see the JSON or SARIF report</text>"
            )
        parts.append("</g>")
        return "\n".join(parts)

    def _svg_attack_path(self, path_num: int, path: AttackPath, top: float) -> str:
        """One strip: the header, the rationale in full, the hops and what enables each."""
        strip = self._strips[path_num]
        sev_color = _path_color(path)
        sev = path.severity.value
        node_w = ATTACK_PATH_NODE_W
        font = ATTACK_PATH_FONT
        group_id = _element_id(self._prefix, "path", path.id or str(path_num))
        parts: list[str] = [f'<g class="attack-path" id="{group_id}" data-severity="{sev}">']

        header = f"Attack Path {path_num} ({sev.capitalize()})"
        if path.score:
            header += f" - score {path.score:g}"
        if path.target_kind:
            header += f" - target: {path.target_kind}"
        parts.append(
            f'<text x="{ATTACK_PATH_PAD + 4:.0f}" y="{top + 12:.0f}" '
            f'fill="{SEVERITY_TEXT_COLORS.get(sev, INK_MUTED)}" '
            f'font-size="10" font-weight="600">{_esc(header)}</text>'
        )
        y = top + ATTACK_PATH_HEADER_H
        if strip.rationale:
            parts.append(
                _text_block(
                    ATTACK_PATH_PAD + 4,
                    y + 8,
                    strip.rationale,
                    ATTACK_PATH_LINE_H,
                    f'fill="{INK_SOFT}" font-size="{font}" text-anchor="start"',
                )
            )
            y += len(strip.rationale) * ATTACK_PATH_LINE_H
        box_y = y + 8
        node_cy = box_y + strip.box_h / 2
        cx = float(ATTACK_PATH_X0)
        for i, (hop, drawn) in enumerate(zip(path.hops, strip.hops, strict=True)):
            parts.append(
                f'<g class="attack-path-hop"><title>{_esc(drawn.tooltip)}</title>'
                f'<rect x="{cx:.0f}" y="{box_y:.0f}" '
                f'width="{node_w}" height="{strip.box_h:g}" '
                f'rx="4" fill="#ffffff" stroke="{sev_color}" stroke-width="1.5"/>'
            )
            name_y = node_cy + 3 - (len(drawn.address) - 1) * ATTACK_PATH_LINE_H / 2
            parts.append(
                _text_block(
                    cx + node_w / 2,
                    name_y,
                    drawn.address,
                    ATTACK_PATH_LINE_H,
                    f'fill="{INK}" font-size="{font}" font-weight="600" text-anchor="middle"',
                )
            )
            line_y = box_y + strip.box_h + 13
            for block in drawn.captions:
                parts.append(
                    _text_block(
                        cx + node_w / 2,
                        line_y,
                        block,
                        ATTACK_PATH_LINE_H,
                        f'fill="{INK_MUTED}" font-size="{font}" text-anchor="middle"',
                    )
                )
                line_y += len(block) * ATTACK_PATH_LINE_H
            parts.append("</g>")

            cx += node_w
            if i < len(path.hops) - 1:
                label = edge_label(hop.edge_type_to_next, via=hop.via)
                parts.append(
                    f'<line x1="{cx:.0f}" y1="{node_cy:.0f}" '
                    f'x2="{cx + ATTACK_PATH_ARROW_W:.0f}" y2="{node_cy:.0f}" '
                    f'stroke="{sev_color}" stroke-width="1.5" '
                    f'marker-end="{self._url(f"arrow-path-{sev}")}"/>'
                )
                if label:
                    shown = shorten_middle(label, _chars_per_line(ATTACK_PATH_ARROW_W + 6, font))
                    parts.append(
                        f'<text x="{cx + ATTACK_PATH_ARROW_W / 2:.0f}" '
                        f'y="{node_cy - 5:.0f}" fill="{INK_SOFT}" '
                        f'font-size="{font}" text-anchor="middle">{_esc(shown)}</text>'
                    )
                cx += ATTACK_PATH_ARROW_W

        parts.append("</g>")
        return "\n".join(parts)

    # -- Findings table -------------------------------------------------------

    def _svg_threat_table(self) -> str:
        """Render a full threat listing table below the diagram."""
        if not self._table_rows and not self._table_overflow:
            return ""

        y = self._threat_table_y
        w = self._canvas_w
        parts: list[str] = ['<g class="threat-table">']

        # Section title
        total = len(self.report.threats)
        title = f"Threat Findings ({total})"
        if self._table_entries_total < total:
            title += f", {self._table_entries_total} rows after grouping by root cause"
        parts.append(
            f'<text x="16" y="{y + 18:.0f}" fill="{INK}" '
            f'font-size="12" font-weight="600">{_esc(title)}</text>'
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
            "Location",
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
            (INK_MUTED, 9),
            (INK, 9),
            (INK_SOFT, 8),
            ("#6d28d9", 8),
            (INK_SOFT, 9),
            (INK_SOFT, 9),
            (INK_SOFT, 9),
        ]
        classes = ["", "", "", ' class="threat-desc"', ' class="threat-mitre"', "", "", ""]

        # Data rows
        for i, row in enumerate(self._table_rows):
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
                    sev = cell[0].lower()
                    sev_color = SEVERITY_COLORS.get(sev, "#94a3b8")
                    sev_ink = SEVERITY_TEXT_COLORS.get(sev, INK_MUTED)
                    parts.append(
                        f'<circle cx="{rx + 4:.0f}" cy="{ry - 2:.0f}" r="3" fill="{sev_color}"/>'
                    )
                    parts.append(
                        f'<text x="{rx + 12:.0f}" y="{ry:.0f}" fill="{sev_ink}" '
                        f'font-size="9" font-weight="600">{_esc(cell[0])}</text>'
                    )
                else:
                    attrs = f'fill="{color}" font-size="{font}"{classes[c]}'
                    parts.append(_text_block(rx, ry, cell, _line_h(font), attrs))
                rx += cols[c]

            # Row tooltip: the full text of the cells, plus the mitigation
            tooltip_lines: list[str] = []
            for threat in row.threats:
                tooltip_lines.append(f"{threat.title}: {humanize_tokens(threat.description)}")
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
        """Render a four column legend: node shapes, edge types, attack paths and badges.

        Every sample is drawn the way the diagram draws it, so the legend can be read against
        the picture.
        """
        y = self._legend_y
        w = self._canvas_w
        parts: list[str] = [
            '<g class="legend">',
            f'<rect x="0" y="{y:.0f}" width="{w:.0f}" height="{LEGEND_H}" fill="#f8fafc"/>',
            f'<line x1="0" y1="{y:.0f}" x2="{w:.0f}" y2="{y:.0f}" '
            f'stroke="#e2e8f0" stroke-width="1"/>',
        ]
        columns = [24.0 + i * LEGEND_COL_W for i in range(4)]

        def title(x: float, text: str) -> None:
            parts.append(
                f'<text x="{x:.0f}" y="{y + 20:.0f}" fill="{INK}" '
                f'font-size="10" font-weight="600">{_esc(text)}</text>'
            )

        def label(x: float, row: int, text: str, ink: str = INK_SOFT, weight: str = "") -> None:
            parts.append(
                f'<text x="{x + 42:.0f}" y="{y + 41 + row * LEGEND_ROW_H:.0f}" fill="{ink}" '
                f'font-size="9"{weight}>{_esc(text)}</text>'
            )

        def row_y(row: int) -> float:
            return y + 38 + row * LEGEND_ROW_H

        # -- Node shapes --
        x = columns[0]
        title(x, "Node Shapes")
        cy = row_y(0)
        parts.append(
            f'<rect x="{x:.0f}" y="{cy - 1:.0f}" width="30" height="12" rx="3" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        label(x, 0, "Process (compute, serverless, container)")
        cy = row_y(1)
        parts.append(
            f'<rect x="{x:.0f}" y="{cy + 2:.0f}" width="30" height="8" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
            f'<ellipse cx="{x + 15:.0f}" cy="{cy + 2:.0f}" rx="15" ry="3" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
            f'<ellipse cx="{x + 15:.0f}" cy="{cy + 10:.0f}" rx="15" ry="3" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
        )
        label(x, 1, "Data store (storage, database, secret)")
        cy = row_y(2)
        parts.append(
            f'<rect x="{x:.0f}" y="{cy - 1:.0f}" width="30" height="12" rx="3" '
            f'fill="#ffffff" stroke="#94a3b8" stroke-width="1" stroke-dasharray="4,2"/>'
        )
        label(x, 2, "Network (network, cdn, dns, messaging)")
        cy = row_y(3)
        parts.append(
            f'<rect x="{x:.0f}" y="{cy - 1:.0f}" width="30" height="12" '
            f'fill="#ffffff" stroke="#cbd5e1" stroke-width="1"/>'
            f'<rect x="{x + 2:.0f}" y="{cy + 1:.0f}" width="26" height="8" '
            f'fill="none" stroke="#cbd5e1" stroke-width="0.8"/>'
        )
        label(x, 3, "External entity (internet, identity)")
        cy = row_y(4)
        parts.append(
            f'<rect x="{x:.0f}" y="{cy - 1:.0f}" width="30" height="12" rx="3" '
            f'fill="#ffffff" fill-opacity="0.55" stroke="{FRAME_STROKES[1]}" stroke-width="1.2"/>'
        )
        label(x, 4, "Container (nested frame)")

        # -- Edge types --
        x = columns[1]
        title(x, "Edge Types")
        edge_legend = [
            (EdgeType.DEPENDENCY, "Dependency (references)"),
            (EdgeType.NETWORK_FLOW, "Network flow"),
            (EdgeType.IAM_BINDING, "IAM binding"),
            (EdgeType.DATA_FLOW, "Data flow"),
        ]
        for row, (etype, text) in enumerate(edge_legend):
            color, width, dash = EDGE_STYLES[etype]
            dash_attr = f' stroke-dasharray="{dash}"' if dash else ""
            cy = row_y(row) + 5
            parts.append(
                f'<line x1="{x:.0f}" y1="{cy:.0f}" x2="{x + 30:.0f}" y2="{cy:.0f}" '
                f'stroke="{color}" stroke-width="{width}"{dash_attr}/>'
                f'<polygon points="{x + 30:.0f},{cy - 3:.0f} {x + 36:.0f},{cy:.0f} '
                f'{x + 30:.0f},{cy + 3:.0f}" fill="{color}"/>'
            )
            label(x, row, text)

        # -- Attack paths --
        x = columns[2]
        title(x, "Attack Paths")
        cy = row_y(0) + 5
        red = SEVERITY_COLORS["critical"]
        parts.append(
            f'<line x1="{x:.0f}" y1="{cy:.0f}" x2="{x + 30:.0f}" y2="{cy:.0f}" '
            f'stroke="{red}" stroke-width="2.6" filter="{self._url("glow")}"/>'
            f'<polygon points="{x + 30:.0f},{cy - 3.5:.0f} {x + 37:.0f},{cy:.0f} '
            f'{x + 30:.0f},{cy + 3.5:.0f}" fill="{red}"/>'
        )
        label(x, 0, "Attack path hop (color = severity)")
        cy = row_y(1)
        parts.append(
            f'<rect x="{x + 6:.0f}" y="{cy - 1:.0f}" width="22" height="{PATH_BADGE_H}" rx="3" '
            f'fill="#ffffff" stroke="{red}" stroke-width="1.5"/>'
            f'<text x="{x + 17:.0f}" y="{cy + 9.2:.0f}" fill="{SEVERITY_TEXT_COLORS["critical"]}" '
            f'font-size="9" font-weight="700" text-anchor="middle">P1</text>'
        )
        label(x, 1, "Attack path number (listed below)")
        cy = row_y(2)
        parts.append(
            f'<rect x="{x + 1:.0f}" y="{cy - 1:.0f}" width="32" height="{EDGE_LABEL_H - 2}" rx="3" '
            f'fill="#ffffff" stroke="{BOUNDARY_STROKE}" stroke-width="1"/>'
            f'<text x="{x + 17:.0f}" y="{cy + 9.4:.0f}" fill="{BOUNDARY_INK}" '
            f'font-size="8" font-weight="600" text-anchor="middle">A {ARROW} B</text>'
        )
        label(x, 2, "Trust boundary crossing (flow)")

        # -- Severity badges --
        x = columns[3]
        title(x, "Severity Badges")
        for row, sev in enumerate(["critical", "high", "medium", "low"]):
            cy = row_y(row) + 5
            parts.append(
                f'<circle cx="{x + 8:.0f}" cy="{cy:.0f}" r="6" fill="{SEVERITY_COLORS[sev]}"/>'
            )
            parts.append(
                f'<text x="{x + 24:.0f}" y="{cy + 3:.0f}" fill="{INK_SOFT}" '
                f'font-size="9">{sev.capitalize()}</text>'
            )
        parts.append(
            f'<text x="{x:.0f}" y="{row_y(4) + 8:.0f}" fill="{INK_SOFT}" '
            f'font-size="9">Badge number = threat count</text>'
        )

        # Footer
        parts.append(
            f'<text x="{w - 16:.0f}" y="{y + LEGEND_H - 8:.0f}" fill="{INK_SOFT}" '
            f'font-size="9" text-anchor="end">Generated by ThreatCode</text>'
        )
        parts.append("</g>")
        return "\n".join(parts)


def _short_name(node: InfraNode) -> str:
    """Name shown in a node: the last segment of its address, or the node name."""
    if "." not in node.id and "::" not in node.id:
        return node.name
    return base_name(node.id, node.resource_type)


def _shape_for(category: NodeCategory) -> Shape:
    """Outline used for a node category, for edge port placement."""
    if category in _DATA_STORE_CATEGORIES:
        return "cylinder"
    return "rect"


def _edge_zones(edge: InfraEdge) -> tuple[str, str]:
    """Source and target zone names of an edge, from its typed fields or its legacy metadata."""
    src = edge.source_zone.value if edge.source_zone else str(edge.metadata.get("source_zone", ""))
    tgt = edge.target_zone.value if edge.target_zone else str(edge.metadata.get("target_zone", ""))
    return src, tgt


def _path_color(path: AttackPath) -> str:
    return SEVERITY_COLORS.get(path.severity.value, "#94a3b8")


def _enabler_text(enabler: Enabler) -> str:
    """A finding in a strip: its rule id and its title, without saying the id twice.

    A scanner finding's title already starts with its id (``CVE-2022-37434: zlib: ...``).
    """
    if not enabler.known or not enabler.title:
        return enabler.label
    bare = enabler.label.rsplit(":", 1)[-1]
    if enabler.title.startswith(bare):
        return enabler.title
    return f"{enabler.label}: {enabler.title}"


def _path_badge_text(path_nums: list[int]) -> str:
    """``P1``, ``P1 P3`` or ``P1-P4``: consecutive path numbers are written as a range."""
    nums = sorted(path_nums)
    runs: list[list[int]] = []
    for num in nums:
        if runs and num == runs[-1][-1] + 1:
            runs[-1].append(num)
        else:
            runs.append([num])
    return " ".join(
        f"P{run[0]}"
        if len(run) == 1
        else f"P{run[0]}-P{run[-1]}"
        if len(run) > 2
        else f"P{run[0]} P{run[1]}"
        for run in runs
    )


def _badge_text_width(text: str) -> float:
    return len(text) * PATH_BADGE_CHAR_W


def _hop_edge_type(hop: AttackHop) -> EdgeType:
    """The edge type a hop names; a hop without a known one is drawn as a reference."""
    try:
        return EdgeType(hop.edge_type_to_next or "")
    except ValueError:
        return EdgeType.DEPENDENCY


def _hop_line(here: AttackHop) -> str:
    """What the path says about the step out of ``here``."""
    kind = EDGE_LABELS.get(_hop_edge_type(here), "Dependency")
    label = edge_label(here.edge_type_to_next, via=here.via)
    return f"{kind}: {label}" if label else kind


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
