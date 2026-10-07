"""Infrastructure graph node types.

The category and trust zone of each resource type are catalogued per provider
family in `threatcode.ir.catalog`; this module keeps the node type and
re-exports the catalog's public names so existing imports keep working.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Literal

from threatcode.ir.catalog import (
    CATEGORY_DEFAULT_ZONE,
    CATEGORY_MAP,
    DATA_CATEGORIES,
    TRUST_ZONE_MAP,
    TriState,
    _rebuild_category_prefixes,
    _rebuild_trust_zone_prefixes,
    categorize_resource,
    infer_trust_zone,
    register_category,
    register_trust_zone,
    tri_state,
)
from threatcode.ir.catalog.types import NodeCategory, TrustZone

if TYPE_CHECKING:
    from threatcode.parsers.base import Evidence, Mode

__all__ = [
    "CATEGORY_DEFAULT_ZONE",
    "CATEGORY_MAP",
    "CONTAINER_TYPES",
    "DATA_CATEGORIES",
    "INTERNET_ID",
    "INTERNET_TYPE",
    "TRUST_ZONE_MAP",
    "Exposure",
    "InfraNode",
    "NodeCategory",
    "TriState",
    "TrustZone",
    "_rebuild_category_prefixes",
    "_rebuild_trust_zone_prefixes",
    "categorize_resource",
    "infer_trust_zone",
    "register_category",
    "register_trust_zone",
    "tri_state",
]

# Whether a node can be reached from the internet: "internal" is a finding of
# the exposure analysis, "unknown" means it has not been (or cannot be) decided
Exposure = Literal["internet", "internal", "unknown"]

# The synthetic node the reachability pass adds for the internet, only when an edge needs it.
# It is a context node, not something the input deploys, so it carries mode "data": the engine
# runs no rules on it and does not count it in `scanned_resources`
INTERNET_ID = "internet"
INTERNET_TYPE = "internet"

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


# Resource types that only configure traffic: they hold rules, routes and permissions, and send
# and receive nothing themselves, so a flow can never start or end at one
NON_TRAFFIC_PREFIXES: tuple[str, ...] = (
    "aws_security_group",
    "aws_default_security_group",
    "aws_network_acl",
    "aws_default_network_acl",
    "aws_route_table",
    "aws_route",
    "aws_main_route_table_association",
    "azurerm_network_security_group",
    "azurerm_network_security_rule",
    "azurerm_route",
    "google_compute_firewall",
    "google_compute_route",
    "kubernetes_network_policy",
)
# Companion resources that attach a rule, a policy or a setting to another resource
NON_TRAFFIC_SUFFIXES: tuple[str, ...] = (
    "_policy",
    "_association",
    "_attachment",
    "_rule",
    "_acl",
    "_subnet_group",
    "_parameter_group",
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
    def is_internet(self) -> bool:
        """Whether this is the synthetic node that stands for the internet."""
        return self.resource_type == INTERNET_TYPE

    @property
    def is_container(self) -> bool:
        """Whether this node is a network or namespace that holds other nodes."""
        return self.resource_type in CONTAINER_TYPES

    @property
    def can_exchange_traffic(self) -> bool:
        """Whether this node can send or receive traffic.

        False for a container (a network or namespace), for identities and permissions (every
        IAM category node), and for resources that only configure traffic: security groups, network
        ACLs, route tables, firewall rules, network policies and the companions that attach a
        rule, policy or setting to another resource.
        A trust boundary is crossed by a flow between two nodes that pass this test.
        """
        if self.is_container or self.category is NodeCategory.IAM:
            return False
        if self.resource_type.startswith(NON_TRAFFIC_PREFIXES):
            return False
        return not self.resource_type.endswith(NON_TRAFFIC_SUFFIXES)
