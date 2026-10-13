"""Mermaid flowcharts: the graph by trust zone with the attack paths highlighted.

``format_mermaid`` is the ``mermaid`` output format and draws every resource an attacker can act
through, with the attack path hops as thick red arrows.
``attack_path_flowchart`` draws just the hops of the attack paths and is embedded in the Markdown
report, where GitHub renders it.
The two differ on purpose: the embed is the picture of the paths alone, without the other
resources and the alternative instances, so it stays small enough to read in a pull request
comment.

The charts run top to bottom, which keeps them narrow: five trust zones side by side are more
than 3000 pixels wide, and stacked they fit a comment.
Edge labels are plain words (``HTTPS 443``, ``assumes``), never the engine's tokens.

Resource addresses come from the scanned input, so they are untrusted.
Mermaid has a rich syntax (links, click handlers, HTML in labels, directives), and a label that
closes its quotes could add any of it.
So node ids are generated (``n1``, ``n2``, ...), every label sits in double quotes, and the
characters that carry meaning inside a label are written as Mermaid entity codes (``#quot;``).
Labels are one line and capped in length.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from threatcode.formatters._utils import collapse_whitespace, truncate
from threatcode.formatters.diagram_labels import edge_label, shorten_address
from threatcode.ir.catalog.types import TrustZone
from threatcode.ir.edges import REACHABILITY, EdgeType

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.analysis import AnalysisResult
    from threatcode.models.attack_path import AttackPath
    from threatcode.models.report import ThreatReport

__all__ = ["attack_path_flowchart", "format_mermaid", "mermaid_label"]

LABEL_LIMIT = 60
# Resource labels get more room: Mermaid wraps a node's text at about 200 pixels, so a long
# address runs over a few lines instead of widening the chart
NODE_LABEL_LIMIT = 72
# Nodes and edges drawn by the whole-graph format; GitHub stops rendering past 500 edges.
MAX_NODES = 150
MAX_EDGES = 300
DIRECTION = "TB"
# Labels of edges between the same two resources, joined into one, and how many are kept
_MAX_JOINED_LABELS = 3

# Written as entity codes inside a quoted label. ``#`` is in the set, so it is encoded exactly once.
_ENTITY_CODES = {
    "#": "#35;",
    '"': "#quot;",
    "<": "#lt;",
    ">": "#gt;",
    "&": "#amp;",
    "`": "#96;",
    "[": "#91;",
    "]": "#93;",
    "{": "#123;",
    "}": "#125;",
    "|": "#124;",
    "\\": "#92;",
    ";": "#59;",
    "%": "#37;",
}
_NEEDS_ENTITY = re.compile("[" + re.escape("".join(_ENTITY_CODES)) + "]")

_ZONE_ORDER = tuple(zone.value for zone in TrustZone)
_UNKNOWN_ZONE = "unknown"
_INSTANCE = re.compile(r"^(?P<base>.+)\[(?P<index>\d+)\]$")

_STYLES = (
    "  classDef entry stroke:#d1242f,stroke-width:3px",
    "  classDef target stroke:#8250df,stroke-width:3px",
    "  classDef onpath stroke:#d1242f,stroke-width:2px",
    "  classDef alt stroke:#d1242f,stroke-width:2px,stroke-dasharray:4 3",
)
_PATH_LINK = "stroke:#d1242f,stroke-width:3px"
_ALT_LINK = "stroke:#d1242f,stroke-width:2px,stroke-dasharray:5 3"
_COMMENT_CHARS = re.compile(r"[^A-Za-z0-9 .,:()'-]")


def mermaid_label(text: str, limit: int = LABEL_LIMIT) -> str:
    """``text`` made safe inside a double-quoted Mermaid label.

    The text becomes one line of at most ``limit`` characters, and every character that has a
    meaning inside a label is replaced by its entity code.
    The result never contains a quote, an angle bracket, a backtick, a bracket or a newline.
    """
    flat = truncate(collapse_whitespace(text), limit)
    return _NEEDS_ENTITY.sub(lambda m: _ENTITY_CODES[m.group(0)], flat)


def _zone_key(zone: str) -> str:
    return zone if zone in _ZONE_ORDER else _UNKNOWN_ZONE


def _collapse_constant_segments(keys: Sequence[str]) -> dict[str, str]:
    """Each address with the path segments every address shares replaced by ``...``.

    A scan of a template repository names its resources ``python3.10/step-func/{{x}}/template.yaml
    ::Fn``, and ``{{x}}`` is the same in all of them.
    A segment (counted from the end, so paths of different depth line up) that is the same in
    every path-like address says nothing about which resource this is, so it goes.
    """
    pathlike = [k for k in keys if "/" in k]
    if len(set(pathlike)) < 2:
        return {k: k for k in keys}
    split = {k: k.split("/") for k in pathlike}
    depth = min(len(parts) for parts in split.values())
    constant = {j for j in range(2, depth + 1) if len({parts[-j] for parts in split.values()}) == 1}
    out = {k: k for k in keys}
    for key, parts in split.items():
        kept: list[str] = []
        for j, segment in enumerate(reversed(parts), start=1):
            if j in constant and j != len(parts):
                if not kept or kept[-1] != "...":
                    kept.append("...")
            else:
                kept.append(segment)
        out[key] = "/".join(reversed(kept))
    return out


def _display_labels(raw: dict[str, str]) -> dict[str, str]:
    """The text of each node: addresses shortened from the middle, so the resource name stays.

    Labels that still read the same get more room before they are cut again.
    """
    collapsed = _collapse_constant_segments(list(raw.values()))
    labels = {key: shorten_address(collapsed[text], NODE_LABEL_LIMIT) for key, text in raw.items()}
    for room in (NODE_LABEL_LIMIT + 24, NODE_LABEL_LIMIT + 48):
        seen: dict[str, int] = {}
        for label in labels.values():
            seen[label] = seen.get(label, 0) + 1
        clash = {label for label, count in seen.items() if count > 1}
        if not clash:
            break
        for key, label in labels.items():
            if label in clash:
                labels[key] = shorten_address(collapsed[raw[key]], room)
    return {key: mermaid_label(label, limit=NODE_LABEL_LIMIT + 48) for key, label in labels.items()}


@dataclass
class _Edge:
    source: str
    target: str
    labels: list[str]
    # "path" (a hop of an attack path), "alt" (a route through another instance), "iam"
    # (dotted) or "plain"
    kind: str
    both_ways: bool = False
    order: int = 0


@dataclass
class _Chart:
    """Collects nodes by zone and edges, hands out generated ids, renders the chart."""

    _ids: dict[str, str] = field(default_factory=dict)
    _raw: dict[str, str] = field(default_factory=dict)
    _zones: dict[str, str] = field(default_factory=dict)
    _edges: dict[tuple[str, str], _Edge] = field(default_factory=dict)
    _classes: dict[str, set[str]] = field(default_factory=dict)

    def node(self, key: str, zone: str, label: str | None = None) -> str:
        if key not in self._ids:
            self._ids[key] = f"n{len(self._ids) + 1}"
            self._raw[key] = label if label is not None else key
            self._zones[key] = _zone_key(zone)
        return self._ids[key]

    def has_node(self, key: str) -> bool:
        return key in self._ids

    def mark(self, key: str, css: str) -> None:
        self._classes.setdefault(css, set()).add(self._ids[key])

    def has_class(self, key: str, css: str) -> bool:
        return self._ids[key] in self._classes.get(css, ())

    def edge(self, source: str, target: str, label: str, *, kind: str) -> bool:
        """Add an edge; returns False when the edge, with that label, is already drawn.

        Edges between the same two resources share one arrow and their labels are joined, so
        two labels never sit on top of each other; an arrow that runs both ways is one arrow
        with a head at each end.
        """
        forward = self._edges.get((source, target))
        backward = self._edges.get((target, source))
        existing = forward or backward
        if existing is not None and (existing.kind == "path") == (kind == "path"):
            if label in existing.labels:
                return False
            existing.labels.append(label)
            if forward is None:
                existing.both_ways = True
            if kind == "alt":
                existing.kind = "alt"
            return True
        if forward is not None:
            return False
        self._edges[(source, target)] = _Edge(
            source, target, [label] if label else [], kind, order=len(self._edges)
        )
        return True

    @property
    def node_count(self) -> int:
        return len(self._ids)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def render(self, header: Sequence[str] = ()) -> str:
        lines = [f"flowchart {DIRECTION}", *header]
        if not self._ids:
            lines.append('  n1["nothing to draw"]')
            return "\n".join(lines) + "\n"
        labels = _display_labels(self._raw)
        by_zone: dict[str, list[str]] = {}
        for key, zone in self._zones.items():
            by_zone.setdefault(zone, []).append(key)
        zone_names = [z for z in (*_ZONE_ORDER, _UNKNOWN_ZONE) if z in by_zone]
        for index, zone in enumerate(zone_names, start=1):
            lines.append(f'  subgraph z{index}["{mermaid_label(zone)}"]')
            for key in by_zone[zone]:
                lines.append(f'    {self._ids[key]}["{labels[key]}"]')
            lines.append("  end")
        links: dict[str, list[int]] = {"path": [], "alt": []}
        for index, edge in enumerate(sorted(self._edges.values(), key=lambda e: e.order)):
            arrow = _arrow(edge)
            joined = ", ".join(edge.labels[:_MAX_JOINED_LABELS])
            if len(edge.labels) > _MAX_JOINED_LABELS:
                joined += ", ..."
            text = f'|"{mermaid_label(joined)}"|' if joined else ""
            lines.append(f"  {self._ids[edge.source]} {arrow}{text} {self._ids[edge.target]}")
            if edge.kind in links:
                links[edge.kind].append(index)
        for kind, style in (("path", _PATH_LINK), ("alt", _ALT_LINK)):
            if links[kind]:
                lines.append(f"  linkStyle {','.join(str(i) for i in links[kind])} {style}")
        if self._classes:
            lines.extend(_STYLES)
            for css in ("entry", "target", "onpath", "alt"):
                members = sorted(self._classes.get(css, ()), key=lambda i: int(i[1:]))
                if members:
                    lines.append(f"  class {','.join(members)} {css}")
        return "\n".join(lines) + "\n"


def _arrow(edge: _Edge) -> str:
    if edge.kind == "path":
        return "==>"
    dotted = edge.kind in ("iam", "alt")
    if edge.both_ways:
        return "<-.->" if dotted else "<-->"
    return "-.->" if dotted else "-->"


def _comment(text: str) -> str:
    """A ``%%`` comment line; comments carry fixed wording, never input text."""
    return f"  %% {_COMMENT_CHARS.sub('', text)}"


def _add_paths(chart: _Chart, paths: Iterable[AttackPath]) -> None:
    for path in paths:
        hops = path.hops
        for index, hop in enumerate(hops):
            chart.node(hop.node_id, hop.zone)
            if index == 0:
                chart.mark(hop.node_id, "entry")
            elif index == len(hops) - 1:
                chart.mark(hop.node_id, "target")
            else:
                chart.mark(hop.node_id, "onpath")
        for here, there in zip(hops, hops[1:], strict=False):
            chart.edge(
                here.node_id,
                there.node_id,
                edge_label(here.edge_type_to_next, via=here.via),
                kind="path",
            )


def attack_path_flowchart(paths: Sequence[AttackPath], *, limit: int = 5) -> str:
    """A flowchart of the hops of the first ``limit`` attack paths, trust zones as subgraphs.

    Only the hops are drawn: the resources and routes around them are in the ``mermaid`` format.
    Returns the Mermaid source without a code fence, or ``""`` when there is nothing to draw.
    """
    shown = [p for p in paths[:limit] if len(p.hops) >= 2]
    if not shown:
        return ""
    chart = _Chart()
    _add_paths(chart, shown)
    return chart.render(
        [_comment("Attack path hops only. threatcode scan -f mermaid draws the whole graph.")]
    )


def format_mermaid(analysis: AnalysisResult | ThreatReport, graph: InfraGraph | None = None) -> str:
    """Render the graph as a Mermaid flowchart: trust zones as subgraphs, attack paths in red.

    Only resources an attacker can act through are drawn (those with a network flow, data flow
    or IAM binding) plus every resource on an attack path, at most ``MAX_NODES`` and ``MAX_EDGES``.
    The hops of the attack paths are thick red arrows.
    Another instance of a counted resource that a path runs through (``app[1]`` next to
    ``app[0]``) is drawn with a dashed red outline, because the path holds for it too.
    Without a graph the chart shows the attack paths alone.
    """
    from threatcode.models.analysis import AnalysisResult

    if isinstance(analysis, AnalysisResult):
        report, graph = analysis.report, analysis.graph
    else:
        report = analysis
    chart = _Chart()
    paths = list(report.attack_paths)
    path_edges = {
        (a.node_id, b.node_id) for p in paths for a, b in zip(p.hops, p.hops[1:], strict=False)
    }
    _add_paths(chart, paths)
    omitted_nodes = omitted_edges = 0
    if graph is not None:
        omitted_nodes, omitted_edges = _add_graph(chart, graph, path_edges, paths)
    header = []
    if omitted_nodes or omitted_edges:
        header.append(
            _comment(f"{omitted_nodes} nodes and {omitted_edges} edges not drawn (size cap)")
        )
    return chart.render(header)


def _alternative_instances(graph: InfraGraph, paths: Sequence[AttackPath]) -> set[str]:
    """Other instances of the counted resources the paths run through: ``app[1]`` for ``app[0]``."""
    on_path = {hop.node_id for path in paths for hop in path.hops}
    bases = {m.group("base") for node_id in on_path if (m := _INSTANCE.match(node_id))}
    found: set[str] = set()
    for node_id in graph.nodes:
        match = _INSTANCE.match(node_id)
        if match and match.group("base") in bases and node_id not in on_path:
            found.add(node_id)
    return found


def _add_graph(
    chart: _Chart,
    graph: InfraGraph,
    path_edges: set[tuple[str, str]],
    paths: Sequence[AttackPath] = (),
) -> tuple[int, int]:
    alternatives = _alternative_instances(graph, paths)
    flow_edges = [e for e in graph.edges if e.edge_type in REACHABILITY]
    touched = {e.source for e in flow_edges} | {e.target for e in flow_edges}
    candidates = sorted(
        node_id
        for node_id, node in graph.nodes.items()
        if node.mode != "data" and (node_id in touched or chart.has_node(node_id))
    )
    if not candidates:
        candidates = sorted(
            node_id
            for node_id, node in graph.nodes.items()
            if node.mode != "data" and not node.is_container
        )
    omitted_nodes = 0
    for node_id in candidates:
        node = graph.nodes[node_id]
        if chart.has_node(node_id):
            continue
        if chart.node_count >= MAX_NODES:
            omitted_nodes += 1
            continue
        chart.node(node_id, node.trust_zone.value)
        if node_id in alternatives:
            chart.mark(node_id, "alt")
    omitted_edges = 0
    for edge in sorted(flow_edges, key=lambda e: (e.source, e.target, e.edge_type.value)):
        if not (chart.has_node(edge.source) and chart.has_node(edge.target)):
            continue
        if (edge.source, edge.target) in path_edges:
            # Already drawn thick as a hop of an attack path
            continue
        if chart.edge_count >= MAX_EDGES:
            omitted_edges += 1
            continue
        if _is_alternative_route(chart, alternatives, edge.source, edge.target):
            kind = "alt"
        else:
            kind = "iam" if edge.edge_type is EdgeType.IAM_BINDING else "plain"
        chart.edge(
            edge.source,
            edge.target,
            edge_label(edge.edge_type.value, edge.relation, edge.attributes),
            kind=kind,
        )
    return omitted_nodes, omitted_edges


def _is_alternative_route(chart: _Chart, alternatives: set[str], source: str, target: str) -> bool:
    """Whether an edge joins another instance to the attack path (or to another instance)."""
    ends = (source, target)
    if not any(end in alternatives for end in ends):
        return False
    return all(
        end in alternatives
        or any(chart.has_class(end, css) for css in ("entry", "target", "onpath"))
        for end in ends
    )
