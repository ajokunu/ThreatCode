"""Graph-level assertions with failure messages that show what the graph does contain.

A bare ``assert edge in graph.edges`` fails with a wall of dataclass reprs.
These helpers fail with the edges around the nodes in question, a suggestion when a
node id is misspelled, and, for paths, the set of nodes that were reachable.

The helpers read the graph only through its public ``nodes`` and ``edges``
properties and tolerate fields that later work packages add (``relation``,
``attributes``, ``exposure``), so one test file survives the parser and graph
contract changes of the rework.

Edge matching rules:

* ``type`` is an ``EdgeType`` or its string value (``"containment"``).
* ``relation`` is read from ``edge.relation`` when it exists, else from the edge metadata.
* Extra keyword arguments are compared with the edge ``attributes`` first,
  then the metadata, then plain edge fields such as ``crosses_boundary``.
"""

from __future__ import annotations

import difflib
from collections import deque
from collections.abc import Iterable
from typing import Any

from threatcode.ir.edges import InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode

_MISSING = object()
# How many edges a failure message prints before it elides the rest
_MAX_LISTED = 12


def _type_value(value: Any) -> str:
    return str(getattr(value, "value", value))


def _edge_type(edge: InfraEdge) -> str:
    return _type_value(edge.edge_type)


def edge_relation(edge: InfraEdge) -> Any:
    """The edge relation, whether it is a typed field or a metadata entry."""
    relation = getattr(edge, "relation", None)
    if relation:
        return relation
    return edge.metadata.get("relation")


def edge_attribute(edge: InfraEdge, key: str) -> Any:
    """Look an attribute up in ``attributes``, then metadata, then edge fields."""
    attributes = getattr(edge, "attributes", None)
    if isinstance(attributes, dict) and key in attributes:
        return attributes[key]
    if key in edge.metadata:
        return edge.metadata[key]
    return getattr(edge, key, _MISSING)


def describe_edge(edge: InfraEdge) -> str:
    """One line per edge: ``src -[type/relation]-> dst`` plus the boundary flag."""
    relation = edge_relation(edge)
    label = _edge_type(edge) + (f"/{relation}" if relation else "")
    crossing = " crosses-boundary" if edge.crosses_trust_boundary else ""
    return f"{edge.source} -[{label}]-> {edge.target}{crossing}"


def _listing(edges: Iterable[InfraEdge]) -> str:
    lines = [describe_edge(e) for e in edges]
    if not lines:
        return "    (none)"
    shown = lines[:_MAX_LISTED]
    if len(lines) > _MAX_LISTED:
        shown.append(f"... and {len(lines) - _MAX_LISTED} more")
    return "\n".join(f"    {line}" for line in shown)


def _edges_touching(graph: InfraGraph, *node_ids: str) -> list[InfraEdge]:
    wanted = set(node_ids)
    return [e for e in graph.edges if e.source in wanted or e.target in wanted]


def _suggest(graph: InfraGraph, node_id: str) -> str:
    near = difflib.get_close_matches(node_id, list(graph.nodes), n=3, cutoff=0.5)
    return f" Did you mean: {', '.join(near)}?" if near else ""


def _require_node(graph: InfraGraph, node_id: str) -> InfraNode:
    node = graph.nodes.get(node_id)
    if node is None:
        sample = ", ".join(sorted(graph.nodes)[:_MAX_LISTED])
        raise AssertionError(
            f"node {node_id!r} is not in the graph ({graph.node_count} nodes)."
            f"{_suggest(graph, node_id)}\n  nodes: {sample}"
        )
    return node


def _matches(
    edge: InfraEdge,
    type: Any,
    relation: str | None,
    attributes: dict[str, Any],
) -> bool:
    if type is not None and _edge_type(edge) != _type_value(type):
        return False
    if relation is not None and edge_relation(edge) != relation:
        return False
    return all(edge_attribute(edge, key) == want for key, want in attributes.items())


def find_edges(
    graph: InfraGraph,
    src: str,
    dst: str,
    type: Any = None,
    relation: str | None = None,
    **attributes: Any,
) -> list[InfraEdge]:
    """Every edge from ``src`` to ``dst`` that matches the filters."""
    return [
        e
        for e in graph.edges
        if e.source == src and e.target == dst and _matches(e, type, relation, attributes)
    ]


def assert_edge(
    graph: InfraGraph,
    src: str,
    dst: str,
    type: Any = None,
    relation: str | None = None,
    **attributes: Any,
) -> InfraEdge:
    """Assert a directed edge ``src -> dst`` exists, optionally of a type or relation."""
    _require_node(graph, src)
    _require_node(graph, dst)
    matches = find_edges(graph, src, dst, type=type, relation=relation, **attributes)
    if matches:
        return matches[0]
    wanted = [f"type={_type_value(type)}" if type is not None else None]
    wanted.append(f"relation={relation}" if relation is not None else None)
    wanted.extend(f"{k}={v!r}" for k, v in attributes.items())
    spec = ", ".join(w for w in wanted if w) or "any type"
    reverse = find_edges(graph, dst, src, type=type, relation=relation, **attributes)
    hint = f"\n  (the reverse edge {describe_edge(reverse[0])} exists)" if reverse else ""
    raise AssertionError(
        f"no edge {src} -> {dst} matching {spec}.\n"
        f"  edges touching either node:\n{_listing(_edges_touching(graph, src, dst))}{hint}"
    )


def assert_no_edge(
    graph: InfraGraph,
    src: str,
    dst: str,
    type: Any = None,
    relation: str | None = None,
    **attributes: Any,
) -> None:
    """Assert no directed edge ``src -> dst`` matches the filters."""
    matches = find_edges(graph, src, dst, type=type, relation=relation, **attributes)
    if matches:
        raise AssertionError(
            f"unexpected edge {describe_edge(matches[0])} "
            f"(metadata {matches[0].metadata}).\n"
            f"  edges touching either node:\n{_listing(_edges_touching(graph, src, dst))}"
        )


def assert_zone(graph: InfraGraph, node_id: str, zone: Any) -> None:
    """Assert a node sits in a trust zone (a ``TrustZone`` or its string value)."""
    node = _require_node(graph, node_id)
    actual = _type_value(node.trust_zone)
    if actual != _type_value(zone):
        raise AssertionError(
            f"node {node_id} ({node.resource_type}) is in zone {actual!r}, "
            f"expected {_type_value(zone)!r}.\n"
            f"  edges touching it:\n{_listing(_edges_touching(graph, node_id))}"
        )


def assert_exposure(graph: InfraGraph, node_id: str, exposure: str) -> None:
    """Assert a node's exposure: ``internet``, ``internal`` or ``unknown``.

    A node without the field reports the contract default, ``unknown``.
    """
    node = _require_node(graph, node_id)
    actual = _type_value(getattr(node, "exposure", "unknown"))
    if actual != exposure:
        raise AssertionError(
            f"node {node_id} ({node.resource_type}) has exposure {actual!r}, "
            f"expected {exposure!r}.\n"
            f"  zone: {_type_value(node.trust_zone)}\n"
            f"  edges touching it:\n{_listing(_edges_touching(graph, node_id))}"
        )


def _reachable(
    graph: InfraGraph, src: str, edge_types: Iterable[Any] | None
) -> tuple[dict[str, str | None], list[InfraEdge]]:
    """Breadth-first search along directed edges; returns the parent map and edges used."""
    allowed = {_type_value(t) for t in edge_types} if edge_types is not None else None
    outgoing: dict[str, list[InfraEdge]] = {}
    for edge in graph.edges:
        if allowed is None or _edge_type(edge) in allowed:
            outgoing.setdefault(edge.source, []).append(edge)
    parent: dict[str, str | None] = {src: None}
    queue: deque[str] = deque([src])
    used: list[InfraEdge] = []
    while queue:
        current = queue.popleft()
        for edge in outgoing.get(current, []):
            if edge.target not in parent:
                parent[edge.target] = current
                used.append(edge)
                queue.append(edge.target)
    return parent, used


def find_path(
    graph: InfraGraph, src: str, dst: str, edge_types: Iterable[Any] | None = None
) -> list[str] | None:
    """The shortest directed path of node ids from ``src`` to ``dst``, or ``None``."""
    parent, _used = _reachable(graph, src, edge_types)
    if dst not in parent:
        return None
    path = [dst]
    while parent[path[-1]] is not None:
        step = parent[path[-1]]
        assert step is not None
        path.append(step)
    return list(reversed(path))


def assert_path(
    graph: InfraGraph, src: str, dst: str, edge_types: Iterable[Any] | None = None
) -> list[str]:
    """Assert a directed path exists from ``src`` to ``dst`` over the given edge types."""
    _require_node(graph, src)
    _require_node(graph, dst)
    path = find_path(graph, src, dst, edge_types)
    if path is not None:
        return path
    parent, used = _reachable(graph, src, edge_types)
    types = ", ".join(sorted(_type_value(t) for t in edge_types)) if edge_types else "any"
    reached = sorted(parent)
    raise AssertionError(
        f"no directed path {src} -> {dst} over edge types [{types}].\n"
        f"  {len(reached)} node(s) reachable from {src}: {', '.join(reached[:_MAX_LISTED])}\n"
        f"  edges followed from {src}:\n{_listing(used)}\n"
        f"  edges touching {dst}:\n{_listing(_edges_touching(graph, dst))}"
    )


def assert_no_path(
    graph: InfraGraph, src: str, dst: str, edge_types: Iterable[Any] | None = None
) -> None:
    """Assert there is no directed path from ``src`` to ``dst`` over the given edge types."""
    _require_node(graph, src)
    _require_node(graph, dst)
    path = find_path(graph, src, dst, edge_types)
    if path is not None:
        hops = " -> ".join(path)
        raise AssertionError(f"unexpected directed path {hops}")


def assert_nodes(graph: InfraGraph, expected: Iterable[str], exact: bool = False) -> None:
    """Assert node ids are present; with ``exact`` the graph holds no other node."""
    expected_set = set(expected)
    actual = set(graph.nodes)
    missing = sorted(expected_set - actual)
    extra = sorted(actual - expected_set) if exact else []
    if missing or extra:
        parts = []
        if missing:
            hints = {m: _suggest(graph, m).strip() for m in missing}
            parts.append("missing: " + ", ".join(f"{m} {h}".strip() for m, h in hints.items()))
        if extra:
            parts.append("unexpected: " + ", ".join(extra))
        raise AssertionError("node set differs.\n  " + "\n  ".join(parts))
