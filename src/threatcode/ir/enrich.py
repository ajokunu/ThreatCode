"""The step that adds context to a graph once its nodes and edges exist.

`InfraGraph.from_parsed` and `InfraGraph.from_units` call `enrich` last, with
the finished graph and a `ReferenceIndex` over all of its nodes.
It is where analysis that needs the whole graph (such as filling in
`InfraNode.exposure`) belongs, so that the graph builder itself stays a pure
translation of what the parsers reported.

Today it does nothing.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.references import ReferenceIndex


def enrich(graph: InfraGraph, index: ReferenceIndex) -> None:
    """Add context to the nodes of a built graph. Does nothing yet."""
