"""Infrastructure graph node types.

The category and trust zone of each resource type are catalogued per provider
family in `threatcode.ir.catalog`; this module keeps the node type and
re-exports the catalog's public names so existing imports keep working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from threatcode.ir.catalog import (
    CATEGORY_MAP,
    TRUST_ZONE_MAP,
    _rebuild_category_prefixes,
    _rebuild_trust_zone_prefixes,
    categorize_resource,
    infer_trust_zone,
    register_category,
    register_trust_zone,
)
from threatcode.ir.catalog.types import NodeCategory, TrustZone

if TYPE_CHECKING:
    from threatcode.parsers.base import Evidence, Mode

__all__ = [
    "CATEGORY_MAP",
    "CONTAINER_TYPES",
    "TRUST_ZONE_MAP",
    "Exposure",
    "InfraNode",
    "NodeCategory",
    "TrustZone",
    "_rebuild_category_prefixes",
    "_rebuild_trust_zone_prefixes",
    "categorize_resource",
    "infer_trust_zone",
    "register_category",
    "register_trust_zone",
]

# Whether a node can be reached from the internet: "internal" is a finding of
# the exposure analysis, "unknown" means it has not been (or cannot be) decided
Exposure = Literal["internet", "internal", "unknown"]

# Resource types that hold other resources (networks and namespaces). A path
# does not end at a container, and a trust crossing into one is its members'
CONTAINER_TYPES: frozenset[str] = frozenset(
    {
        "aws_vpc",
        "aws_subnet",
        "azurerm_virtual_network",
        "azurerm_subnet",
        "google_compute_network",
        "google_compute_subnetwork",
        "kubernetes_namespace",
    }
)


@dataclass
class InfraNode:
    id: str
    resource_type: str
    name: str
    category: NodeCategory
    trust_zone: TrustZone
    properties: dict[str, Any] = field(default_factory=dict)
    provider: str = ""
    module: str = ""
    boundary: str = ""  # declared boundary id; see ParsedResource.boundary
    evidence: Evidence = "config"  # see ParsedResource.evidence
    source_file: str = ""  # the file the resource comes from, "" when unknown
    start_line: int | None = None  # 1-based, inclusive; None when unknown
    end_line: int | None = None
    mode: Mode = "managed"  # "data" for a looked-up data source
    exposure: Exposure = "unknown"

    @property
    def stride_element(self) -> str:
        return self.category.stride_element

    @property
    def is_container(self) -> bool:
        """Whether this node is a network or namespace that holds other nodes."""
        return self.resource_type in CONTAINER_TYPES
