"""Cloud-agnostic infrastructure graph built on NetworkX."""

from __future__ import annotations

import logging
from typing import Any

import networkx as nx

from threatcode.exceptions import ThreatCodeError
from threatcode.ir.edges import EdgeType, InfraEdge
from threatcode.ir.nodes import (
    InfraNode,
    TrustZone,
    categorize_resource,
    infer_trust_zone,
)
from threatcode.parsers.base import ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)

# Security: cap graph size to prevent resource exhaustion
MAX_NODES = 10_000
MAX_EDGES = 50_000

# Containment hint registry: (property_name, target_resource_type)
# When a resource has property_name set, look for nodes of target_resource_type.
_CONTAINMENT_HINTS: list[tuple[str, str]] = [
    ("vpc_id", "aws_vpc"),
    ("vnet_id", "azurerm_virtual_network"),
    ("network_id", "google_compute_network"),
]


def register_containment_hint(property_name: str, target_type: str) -> None:
    """Register a custom containment hint for edge inference.

    When a resource has `property_name` in its properties, an edge is inferred
    to nodes matching `target_type`.
    """
    _CONTAINMENT_HINTS.append((property_name, target_type))


class InfraGraph:
    """Directed graph representing infrastructure topology."""

    def __init__(self) -> None:
        self._graph: nx.DiGraph[str] = nx.DiGraph()
        self._nodes: dict[str, InfraNode] = {}
        self._edges: list[InfraEdge] = []
        self._edge_keys: set[tuple[str, str, str]] = set()  # (source, target, type) dedup
        self._type_index: dict[str, list[str]] = {}

    @classmethod
    def from_parsed(cls, parsed: ParsedOutput) -> InfraGraph:
        """Build graph from parsed IaC output."""
        graph = cls()
        for resource in parsed.resources:
            graph._add_resource(resource)
        graph._infer_edges(parsed.resources)
        graph._mark_trust_boundary_crossings()
        return graph

    @property
    def nodes(self) -> dict[str, InfraNode]:
        return dict(self._nodes)

    @property
    def edges(self) -> list[InfraEdge]:
        return list(self._edges)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    def get_node(self, node_id: str) -> InfraNode | None:
        return self._nodes.get(node_id)

    def get_neighbors(self, node_id: str) -> list[InfraNode]:
        if node_id not in self._graph:
            return []
        return [self._nodes[n] for n in self._graph.neighbors(node_id) if n in self._nodes]

    def get_edges_for_node(self, node_id: str) -> list[InfraEdge]:
        return [e for e in self._edges if e.source == node_id or e.target == node_id]

    def get_boundary_crossing_edges(self) -> list[InfraEdge]:
        return [e for e in self._edges if e.crosses_trust_boundary]

    def nodes_by_zone(self) -> dict[TrustZone, list[InfraNode]]:
        zones: dict[TrustZone, list[InfraNode]] = {}
        for node in self._nodes.values():
            zones.setdefault(node.trust_zone, []).append(node)
        return zones

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {nid: _node_to_dict(n) for nid, n in self._nodes.items()},
            "edges": [
                {
                    "source": e.source,
                    "target": e.target,
                    "type": e.edge_type.value,
                    "crosses_trust_boundary": e.crosses_trust_boundary,
                }
                for e in self._edges
            ],
        }

    def _add_resource(self, resource: ParsedResource) -> None:
        if len(self._nodes) >= MAX_NODES:
            raise ThreatCodeError(
                f"Infrastructure graph exceeds {MAX_NODES} node limit. "
                "Split your IaC into smaller modules or increase MAX_NODES."
            )

        category = categorize_resource(resource.resource_type)
        trust_zone = infer_trust_zone(resource.resource_type, resource.properties)
        if resource.address in self._nodes:
            logger.warning(
                "Duplicate resource address '%s' — overwriting previous node",
                resource.address,
            )
            # Remove old entry from type index to avoid stale references
            old_type = self._nodes[resource.address].resource_type
            old_list = self._type_index.get(old_type, [])
            if resource.address in old_list:
                old_list.remove(resource.address)
        node = InfraNode(
            id=resource.address,
            resource_type=resource.resource_type,
            name=resource.name,
            category=category,
            trust_zone=trust_zone,
            properties=resource.properties,
            provider=resource.provider,
            module=resource.module,
        )
        self._nodes[resource.address] = node
        self._graph.add_node(resource.address)
        # Maintain type index for O(1) lookups during edge inference
        self._type_index.setdefault(resource.resource_type, []).append(resource.address)

    def _infer_edges(self, resources: list[ParsedResource]) -> None:
        for resource in resources:
            # Explicit dependencies
            for dep in resource.dependencies:
                if dep in self._nodes:
                    self._add_edge(resource.address, dep, EdgeType.DEPENDENCY)

            # Containment: subnet → VPC, instance → subnet, etc.
            self._infer_containment(resource)

            # IAM bindings
            self._infer_iam_edges(resource)

    def _infer_containment(self, resource: ParsedResource) -> None:
        props = resource.properties

        # Registry-driven containment hints
        for prop_name, target_type in _CONTAINMENT_HINTS:
            value = props.get(prop_name)
            if value and isinstance(value, str):
                for nid in self._type_index.get(target_type, []):
                    if nid != resource.address:
                        self._add_edge(resource.address, nid, EdgeType.CONTAINMENT)
                        break

        # Subnet containment — match only if we have a reference
        subnet_id = props.get("subnet_id")
        subnet_ids = props.get("subnet_ids") or props.get("subnets") or []
        if subnet_id:
            # Merge single subnet_id into the list rather than clobbering it
            if isinstance(subnet_ids, list):
                subnet_ids = [subnet_id, *subnet_ids]
            else:
                subnet_ids = [subnet_id]
        if isinstance(subnet_ids, list) and subnet_ids:
            # Build set of referenced subnet IDs for matching
            ref_ids = set(str(s) for s in subnet_ids if s)
            for rtype, nids in self._type_index.items():
                if rtype.endswith("subnet"):
                    for nid in nids:
                        node = self._nodes.get(nid)
                        if node and nid != resource.address:
                            # Match by address or name against referenced IDs
                            if nid in ref_ids or (node.name and node.name in ref_ids):
                                self._add_edge(resource.address, nid, EdgeType.CONTAINMENT)

        # Security group attachment — match only if we have a reference
        sg_ids = props.get("security_groups") or props.get("vpc_security_group_ids") or []
        if isinstance(sg_ids, list) and sg_ids:
            ref_ids = set(str(s) for s in sg_ids if s)
            for rtype, nids in self._type_index.items():
                if "security_group" in rtype:
                    for nid in nids:
                        node = self._nodes.get(nid)
                        if node and nid != resource.address:
                            if nid in ref_ids or (node.name and node.name in ref_ids):
                                self._add_edge(resource.address, nid, EdgeType.NETWORK_FLOW)

    def _infer_iam_edges(self, resource: ParsedResource) -> None:
        rtype = resource.resource_type
        props = resource.properties

        # Role attachment
        if rtype == "aws_iam_role_policy_attachment":
            role = props.get("role", "")
            if role:
                self._match_iam_role(resource.address, role)

        # Instance profile → role
        if rtype == "aws_iam_instance_profile":
            role = props.get("role", "")
            if role:
                self._match_iam_role(resource.address, role)

    def _match_iam_role(self, source_address: str, role_ref: str) -> None:
        """Match an IAM role reference, trying address-based match first."""
        # Try address-based match first (e.g., aws_iam_role.my_role)
        address_candidate = f"aws_iam_role.{role_ref}"
        if address_candidate in self._nodes:
            self._add_edge(source_address, address_candidate, EdgeType.IAM_BINDING)
            return

        # Fall back to name-based match
        for nid in self._type_index.get("aws_iam_role", []):
            node = self._nodes[nid]
            if node.name == role_ref:
                self._add_edge(source_address, nid, EdgeType.IAM_BINDING)
                return

    def _add_edge(self, source: str, target: str, edge_type: EdgeType) -> None:
        # Deduplicate edges
        key = (source, target, edge_type.value)
        if key in self._edge_keys:
            return

        if len(self._edges) >= MAX_EDGES:
            logger.warning(
                "Edge limit reached (%d) — skipping edge %s -> %s",
                MAX_EDGES,
                source,
                target,
            )
            return

        # Only commit the dedup key after confirming the edge will be added
        self._edge_keys.add(key)
        edge = InfraEdge(source=source, target=target, edge_type=edge_type)
        self._edges.append(edge)
        self._graph.add_edge(source, target, type=edge_type.value)

    def _mark_trust_boundary_crossings(self) -> None:
        for edge in self._edges:
            src_node = self._nodes.get(edge.source)
            tgt_node = self._nodes.get(edge.target)
            if src_node and tgt_node and src_node.trust_zone != tgt_node.trust_zone:
                edge.metadata["crosses_trust_boundary"] = True
                edge.metadata["source_zone"] = src_node.trust_zone.value
                edge.metadata["target_zone"] = tgt_node.trust_zone.value


def _node_to_dict(node: InfraNode) -> dict[str, Any]:
    return {
        "resource_type": node.resource_type,
        "name": node.name,
        "category": node.category.value,
        "trust_zone": node.trust_zone.value,
        "stride_element": node.stride_element,
        "provider": node.provider,
    }
