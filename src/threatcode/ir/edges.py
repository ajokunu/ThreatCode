"""Infrastructure graph edge types."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class EdgeType(str, Enum):
    DEPENDENCY = "dependency"
    CONTAINMENT = "containment"
    NETWORK_FLOW = "network_flow"
    IAM_BINDING = "iam_binding"
    DATA_FLOW = "data_flow"


@dataclass
class InfraEdge:
    source: str
    target: str
    edge_type: EdgeType
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def crosses_trust_boundary(self) -> bool:
        """Check if this edge crosses a trust boundary (set by graph builder)."""
        return self.metadata.get("crosses_trust_boundary", False)
