"""Trust boundary crossing detection and analysis."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from threatcode.ir.edges import InfraEdge
from threatcode.ir.graph import InfraGraph

# Risk levels for zone transitions (source_zone, target_zone) -> risk_score
BOUNDARY_RISK: dict[tuple[str, str], int] = {
    ("internet", "data"): 10,
    ("internet", "management"): 10,
    ("internet", "private"): 8,
    ("dmz", "data"): 7,
    ("dmz", "management"): 7,
    ("dmz", "private"): 5,
    ("private", "data"): 3,
    ("private", "management"): 4,
}


@dataclass
class BoundaryCrossing:
    edge: InfraEdge
    source_zone: str
    target_zone: str
    risk_score: int
    description: str


def detect_boundary_crossings(graph: InfraGraph) -> list[BoundaryCrossing]:
    """Identify all trust boundary crossings in the graph."""
    crossings: list[BoundaryCrossing] = []

    for edge in graph.get_boundary_crossing_edges():
        src_zone = edge.metadata.get("source_zone", "unknown")
        tgt_zone = edge.metadata.get("target_zone", "unknown")

        # Look up risk in both directions
        risk = BOUNDARY_RISK.get(
            (src_zone, tgt_zone),
            BOUNDARY_RISK.get((tgt_zone, src_zone), 2),
        )

        src_node = graph.get_node(edge.source)
        tgt_node = graph.get_node(edge.target)
        src_name = src_node.id if src_node else edge.source
        tgt_name = tgt_node.id if tgt_node else edge.target

        crossings.append(
            BoundaryCrossing(
                edge=edge,
                source_zone=src_zone,
                target_zone=tgt_zone,
                risk_score=risk,
                description=(
                    f"{src_name} ({src_zone}) -> {tgt_name} ({tgt_zone}): "
                    f"data crosses from {src_zone} to {tgt_zone} trust zone"
                ),
            )
        )

    return sorted(crossings, key=lambda c: -c.risk_score)


def get_zone_summary(graph: InfraGraph) -> dict[str, Any]:
    """Summarize trust zones and their resources."""
    zones = graph.nodes_by_zone()
    return {
        zone.value: {
            "count": len(nodes),
            "resources": [n.id for n in nodes],
        }
        for zone, nodes in zones.items()
    }
