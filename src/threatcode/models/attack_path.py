"""Attack path data structures.

An attack path is an ordered chain of resources an attacker can follow from an
entry point (normally the internet) to a target that matters (a data store, a
secret store, an admin identity). Each hop records the edge that leads to the
next resource, the findings that make the hop possible and the ATT&CK
techniques used on it.
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Any

from threatcode.models.threat import Severity

_PATH_ID_SEPARATOR = "->"


def attack_path_id(node_ids: Iterable[str]) -> str:
    """Stable identifier of a path: 12 hex characters of sha256 over its node sequence.

    The node ids are joined with ``->`` in hop order, so two paths over the same
    nodes in the same order always share an id and any other route differs.
    """
    joined = _PATH_ID_SEPARATOR.join(node_ids)
    return hashlib.sha256(joined.encode()).hexdigest()[:12]


@dataclass
class AttackHop:
    """One resource on an attack path."""

    node_id: str
    resource_type: str = ""
    zone: str = ""
    # Type of the edge from this hop to the next one; None on the last hop.
    edge_type_to_next: str | None = None
    # Details of that edge, such as ports, protocol and relation.
    via: dict[str, Any] = field(default_factory=dict)
    # Ids of the threats that enable this hop.
    enabled_by: list[str] = field(default_factory=list)
    techniques: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "node_id": self.node_id,
            "resource_type": self.resource_type,
            "zone": self.zone,
            "edge_type_to_next": self.edge_type_to_next,
            "via": dict(self.via),
            "enabled_by": list(self.enabled_by),
            "techniques": list(self.techniques),
        }


@dataclass
class AttackPath:
    id: str
    entry: str
    target: str
    hops: list[AttackHop] = field(default_factory=list)
    severity: Severity = Severity.MEDIUM
    score: float = 0.0
    rationale: str = ""
    techniques: list[str] = field(default_factory=list)
    tactics: list[str] = field(default_factory=list)
    # How many other routes through further instances of the same counted resource (`app[1]`
    # next to `app[0]`) this path stands for; they are not listed, because they differ only by
    # the instance number
    alternatives: int = 0
    # What makes the target worth reaching: "data store", "secret store", "administrator
    # identity", "cluster-admin grant" or "private data". Empty for a path built by hand.
    target_kind: str = ""

    @property
    def node_ids(self) -> list[str]:
        return [hop.node_id for hop in self.hops]

    def to_dict(self) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "entry": self.entry,
            "target": self.target,
            "hops": [hop.to_dict() for hop in self.hops],
            "severity": self.severity.value,
            "score": self.score,
            "rationale": self.rationale,
            "techniques": list(self.techniques),
            "tactics": list(self.tactics),
        }
        # Emitted only when it differs from its default, so a path that stands for no other
        # route renders as it always did
        if self.alternatives:
            data["alternatives"] = self.alternatives
        if self.target_kind:
            data["target_kind"] = self.target_kind
        return data
