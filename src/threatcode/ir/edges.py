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

Reachability edges
------------------

The reachability pass (`threatcode.ir.reachability`) adds directed edges in the direction traffic
or authority travels, from a synthetic `internet` node to what is exposed and on from there to
the data.
It writes these attributes on the edges it adds:

- `source`: where the edge comes from, one of `REACHABILITY_SOURCES`.
- `sources`: every source that contributed, when several did.
- `via`: ids of the nodes that enable the edge (the security group whose rule admits the traffic,
  the listener, the role binding).
- `protocol`, `ports`: what the traffic is (`tcp`, `["8080"]` or `["8000-8100"]`); `protocols` when
  several merged edges disagree.
- `world_open`: the edge carries traffic from anywhere on the internet.
- `definite`: false when the edge rests on a guess (an unknown value, a wildcard).
  An edge without the attribute is definite.

An edge that two facts both justify (a security group rule and a load balancer target) is one
edge whose attributes merge: ports and `via` are unions, `world_open` is true if either is,
`definite` is false if either is.
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

# The values of the `source` attribute of a reachability edge
SG_RULE = "sg_rule"
LB_LISTENER = "lb_listener"
ROUTE = "route"
CDN_ORIGIN = "cdn_origin"
API_INTEGRATION = "api_integration"
K8S_SERVICE = "k8s_service"
INGRESS = "ingress"
IAM = "iam"
AGENT = "agent"
# A managed endpoint anyone can call: a public bucket, a CloudFront distribution, a Lambda URL
PUBLIC_ENDPOINT = "public_endpoint"
# A Kubernetes workload reading a Secret, and a ServiceAccount holding a Role's permissions
WORKLOAD = "workload"
RBAC = "rbac"
REACHABILITY_SOURCES: frozenset[str] = frozenset(
    {
        SG_RULE,
        LB_LISTENER,
        ROUTE,
        CDN_ORIGIN,
        API_INTEGRATION,
        K8S_SERVICE,
        INGRESS,
        IAM,
        AGENT,
        PUBLIC_ENDPOINT,
        WORKLOAD,
        RBAC,
    }
)

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

    @property
    def source_kind(self) -> str:
        """Where a reachability edge comes from; an IAM binding without one is `iam`."""
        kind = self.attributes.get("source")
        if isinstance(kind, str) and kind:
            return kind
        return IAM if self.edge_type is EdgeType.IAM_BINDING else ""

    @property
    def world_open(self) -> bool:
        """Whether the edge carries traffic from anywhere on the internet."""
        return self.attributes.get("world_open") is True

    @property
    def definite(self) -> bool:
        """Whether the edge rests on facts the input states, not on a guess.

        An edge is not definite when the reachability pass marked it so (an unknown value, a
        server of unknown capability) and when it is an IAM permission that a wildcard or a
        condition qualifies.
        """
        if self.attributes.get("definite") is False:
            return False
        if self.relation == "permission":
            return not (self.attributes.get("wildcard") or self.attributes.get("conditional"))
        return True

    @property
    def ports(self) -> list[str]:
        """The ports of the edge as strings, in order (`["443"]`, `["8000-8100"]`)."""
        return port_list(self.attributes.get("ports"))

    @property
    def protocols(self) -> list[str]:
        """The protocols of the edge, lower case (`["tcp"]`)."""
        found: list[str] = []
        listed = self.attributes.get("protocols")
        if not isinstance(listed, (list, tuple)):
            listed = [self.attributes.get("protocol")]
        for value in listed:
            if isinstance(value, str) and value.strip():
                name = value.strip().lower()
                if name not in found:
                    found.append(name)
        return found


def port_list(value: Any) -> list[str]:
    """Normalise a `ports` attribute to a list of strings; unusable items are dropped."""
    items = value if isinstance(value, (list, tuple, set, frozenset)) else [value]
    found: list[str] = []
    for item in items:
        if item is None or isinstance(item, bool):
            continue
        text = str(item).strip()
        if text and text not in found:
            found.append(text)
    return found


def port_sort_key(port: str) -> tuple[int, int, str]:
    """Order ports numerically, a range by its first port, anything else last."""
    head = port.split("-", 1)[0]
    if head.isdigit():
        return (0, int(head), port)
    return (1, 0, port)


def _zone(value: Any) -> TrustZone | None:
    try:
        return TrustZone(value)
    except ValueError:
        return None
