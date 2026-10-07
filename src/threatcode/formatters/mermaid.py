"""Mermaid flowcharts: the graph by trust zone with the attack paths highlighted.

``format_mermaid`` is the ``mermaid`` output format.
``attack_path_flowchart`` draws just the attack paths and is embedded in the Markdown report, where
GitHub renders it.

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
from typing import TYPE_CHECKING

from threatcode.formatters._utils import collapse_whitespace, truncate
from threatcode.ir.catalog.types import TrustZone
from threatcode.ir.edges import REACHABILITY, EdgeType

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.analysis import AnalysisResult
    from threatcode.models.attack_path import AttackPath
    from threatcode.models.report import ThreatReport

__all__ = ["attack_path_flowchart", "format_mermaid", "mermaid_label"]

LABEL_LIMIT = 60
# Nodes and edges drawn by the whole-graph format; GitHub stops rendering past 500 edges.
MAX_NODES = 150
MAX_EDGES = 300

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

_STYLES = (
    "  classDef entry stroke:#d1242f,stroke-width:3px",
    "  classDef target stroke:#8250df,stroke-width:3px",
    "  classDef onpath stroke:#d1242f,stroke-width:2px",
)


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


class _Chart:
    """Collects nodes by zone and edges, hands out generated ids, renders the chart."""

    def __init__(self) -> None:
        self._ids: dict[str, str] = {}
        self._labels: dict[str, str] = {}
        self._zones: dict[str, str] = {}
        self._edges: list[tuple[str, str, str, bool, bool]] = []
        self._edge_keys: set[tuple[str, str, str]] = set()
        self._classes: dict[str, set[str]] = {}

    def node(self, key: str, zone: str, label: str | None = None) -> str:
        if key not in self._ids:
            self._ids[key] = f"n{len(self._ids) + 1}"
            self._labels[key] = mermaid_label(label if label is not None else key)
            self._zones[key] = _zone_key(zone)
        return self._ids[key]

    def has_node(self, key: str) -> bool:
        return key in self._ids

    def mark(self, key: str, css: str) -> None:
        self._classes.setdefault(css, set()).add(self._ids[key])

    def edge(self, source: str, target: str, label: str, *, dotted: bool, highlight: bool) -> bool:
        key = (source, target, label)
        if key in self._edge_keys:
            return False
        self._edge_keys.add(key)
        self._edges.append((self._ids[source], self._ids[target], label, dotted, highlight))
        return True

    @property
    def node_count(self) -> int:
        return len(self._ids)

    @property
    def edge_count(self) -> int:
        return len(self._edges)

    def render(self, header: Sequence[str] = ()) -> str:
        lines = ["flowchart LR", *header]
        if not self._ids:
            lines.append('  n1["nothing to draw"]')
            return "\n".join(lines) + "\n"
        by_zone: dict[str, list[str]] = {}
        for key, zone in self._zones.items():
            by_zone.setdefault(zone, []).append(key)
        zone_names = [z for z in (*_ZONE_ORDER, _UNKNOWN_ZONE) if z in by_zone]
        for index, zone in enumerate(zone_names, start=1):
            lines.append(f'  subgraph z{index}["{mermaid_label(zone)}"]')
            for key in by_zone[zone]:
                lines.append(f'    {self._ids[key]}["{self._labels[key]}"]')
            lines.append("  end")
        highlighted: list[int] = []
        for index, (source, target, label, dotted, highlight) in enumerate(self._edges):
            arrow = "-.->" if dotted else ("==>" if highlight else "-->")
            text = f'|"{mermaid_label(label)}"|' if label else ""
            lines.append(f"  {source} {arrow}{text} {target}")
            if highlight:
                highlighted.append(index)
        if highlighted:
            joined = ",".join(str(i) for i in highlighted)
            lines.append(f"  linkStyle {joined} stroke:#d1242f,stroke-width:3px")
        if self._classes:
            lines.extend(_STYLES)
            for css in ("entry", "target", "onpath"):
                members = sorted(self._classes.get(css, ()), key=lambda i: int(i[1:]))
                if members:
                    lines.append(f"  class {','.join(members)} {css}")
        return "\n".join(lines) + "\n"


def _edge_label(edge_type: str | None, via: dict[str, object]) -> str:
    parts = [edge_type or ""]
    ports = via.get("ports", via.get("port"))
    if isinstance(ports, (list, tuple)):
        parts.append(",".join(str(p) for p in ports))
    elif isinstance(ports, (str, int)) and not isinstance(ports, bool):
        parts.append(str(ports))
    return " ".join(p for p in parts if p)


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
                _edge_label(here.edge_type_to_next, here.via),
                dotted=False,
                highlight=True,
            )


def attack_path_flowchart(paths: Sequence[AttackPath], *, limit: int = 5) -> str:
    """A flowchart of the first ``limit`` attack paths, trust zones as subgraphs.

    Returns the Mermaid source without a code fence, or ``""`` when there is nothing to draw.
    """
    shown = [p for p in paths[:limit] if len(p.hops) >= 2]
    if not shown:
        return ""
    chart = _Chart()
    _add_paths(chart, shown)
    return chart.render()


def format_mermaid(analysis: AnalysisResult | ThreatReport, graph: InfraGraph | None = None) -> str:
    """Render the graph as a Mermaid flowchart: trust zones as subgraphs, attack paths in red.

    Only resources an attacker can act through are drawn (those with a network flow, data flow
    or IAM binding) plus every resource on an attack path, at most ``MAX_NODES`` and ``MAX_EDGES``.
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
        omitted_nodes, omitted_edges = _add_graph(chart, graph, path_edges)
    header = []
    if omitted_nodes or omitted_edges:
        header.append(f"  %% {omitted_nodes} nodes and {omitted_edges} edges not drawn (size cap)")
    return chart.render(header)


def _add_graph(
    chart: _Chart, graph: InfraGraph, path_edges: set[tuple[str, str]]
) -> tuple[int, int]:
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
        label = edge.edge_type.value + (f" {edge.relation}" if edge.relation else "")
        chart.edge(
            edge.source,
            edge.target,
            label,
            dotted=edge.edge_type is EdgeType.IAM_BINDING,
            highlight=False,
        )
    return omitted_nodes, omitted_edges
