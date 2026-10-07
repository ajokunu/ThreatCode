"""Infrastructure graph edge types.

What each edge type means:

- `containment`: the source is placed in the target (instance in subnet,
  subnet in VPC).
- `dependency`: the source references the target.
  `relation` says how, for example `security_group`, `encrypts_with` or
  `references`.
  A security group attachment is a dependency with relation `security_group`: it is wiring, not
  traffic.
- `network_flow`: the source can send traffic to the target.
- `iam_binding`: the source assumes or uses the target's permissions.
  `relation` says how: `assumes` (a resource runs as a role), `instance_profile`, `attaches` (a
  policy attachment names its policy), `has_policy` (a role holds a policy), `can_assume` (a
  principal role may assume the target role), `resource_policy` (a policy document governs the
  resource) and `permission` (a role is allowed actions on the resource; the edge attributes
  carry `actions`, `access` and `wildcard`).
- `data_flow`: a flow of data the input declares (design inputs).

`STRUCTURAL` edges say how things are wired together.
`REACHABILITY` edges say what an attacker who controls the source can reach.
Attack paths follow reachability edges only, so a VPC that merely contains two
unrelated subnets never joins them.
`FLOW` edges are the ones that carry traffic: a trust boundary is a risk only where something
flows across it, so boundary threats come from these and from nothing else.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from threatcode.ir.catalog.types import TrustZone


class EdgeType(str, Enum):
    DEPENDENCY = "dependency"
    CONTAINMENT = "containment"
    NETWORK_FLOW = "network_flow"
    IAM_BINDING = "iam_binding"
    DATA_FLOW = "data_flow"


STRUCTURAL: frozenset[EdgeType] = frozenset({EdgeType.CONTAINMENT, EdgeType.DEPENDENCY})
REACHABILITY: frozenset[EdgeType] = frozenset(
    {EdgeType.NETWORK_FLOW, EdgeType.DATA_FLOW, EdgeType.IAM_BINDING}
)
FLOW_EDGE_TYPES: frozenset[EdgeType] = frozenset({EdgeType.NETWORK_FLOW, EdgeType.DATA_FLOW})

# The keys of `metadata` that only the graph builder writes, for compatibility
# with code that reads the crossing from the metadata. The typed fields of
# InfraEdge are the source of truth; a parser cannot set these
COMPUTED_METADATA_KEYS: frozenset[str] = frozenset(
    {
        "crosses_trust_boundary",
        "source_zone",
        "target_zone",
        "source_boundary",
        "target_boundary",
    }
)


@dataclass
class InfraEdge:
    source: str
    target: str
    edge_type: EdgeType
    # Parser-supplied attributes plus, for a crossing edge, the computed keys in
    # COMPUTED_METADATA_KEYS. Kept for compatibility; prefer the typed fields
    metadata: dict[str, Any] = field(default_factory=dict)
    # Computed by the graph builder from the nodes' zones and boundaries
    crosses_boundary: bool = False
    source_zone: TrustZone | None = None
    target_zone: TrustZone | None = None
    source_boundary: str = ""
    target_boundary: str = ""
    # How a dependency or binding relates the two nodes ("" when unspecified)
    relation: str = ""
    # True when the input states the edge, False when the builder inferred it
    declared: bool = False
    # What the parser said about the edge (protocol, ports, authenticated, ...),
    # kept apart from the computed fields so it cannot forge a crossing
    attributes: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        # An edge built by hand with the legacy metadata keys (a test, a plugin)
        # gets the matching typed fields. The graph builder never passes these
        # keys in `metadata`, so parser attributes cannot reach this path
        if self.crosses_boundary or not self.metadata.get("crosses_trust_boundary"):
            return
        self.crosses_boundary = True
        self.source_zone = self.source_zone or _zone(self.metadata.get("source_zone"))
        self.target_zone = self.target_zone or _zone(self.metadata.get("target_zone"))
        self.source_boundary = self.source_boundary or str(self.metadata.get("source_boundary", ""))
        self.target_boundary = self.target_boundary or str(self.metadata.get("target_boundary", ""))

    @property
    def crosses_trust_boundary(self) -> bool:
        """Whether this edge crosses a trust boundary (computed by the graph builder)."""
        return self.crosses_boundary


def _zone(value: Any) -> TrustZone | None:
    try:
        return TrustZone(value)
    except ValueError:
        return None
