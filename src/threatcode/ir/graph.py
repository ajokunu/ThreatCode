"""Cloud-agnostic infrastructure graph built on NetworkX."""

from __future__ import annotations

from typing import Any

import networkx as nx

from threatcode.ir.edges import EdgeType, InfraEdge
from threatcode.ir.nodes import (
    InfraNode,
    TrustZone,
    categorize_resource,
    infer_trust_zone,
)
from threatcode.parsers.base import ParsedOutput, ParsedResource


class InfraGraph:
    """Directed graph representing infrastructure topology."""

    def __init__(self) -> None:
        self._graph: nx.DiGraph = nx.DiGraph()
        self._nodes: dict[str, InfraNode] = {}
        self._edges: list[InfraEdge] = []

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
        category = categorize_resource(resource.resource_type)
        trust_zone = infer_trust_zone(resource.resource_type, resource.properties)
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
        # VPC containment
        vpc_id = props.get("vpc_id")
        if vpc_id and isinstance(vpc_id, str):
            for nid, node in self._nodes.items():
                if node.resource_type == "aws_vpc" and nid != resource.address:
                    self._add_edge(resource.address, nid, EdgeType.CONTAINMENT)
                    break

        # Subnet containment
        subnet_id = props.get("subnet_id")
        subnet_ids = props.get("subnet_ids") or props.get("subnets") or []
        if subnet_id:
            subnet_ids = [subnet_id]
        if isinstance(subnet_ids, list):
            for nid, node in self._nodes.items():
                if node.resource_type.endswith("subnet") and nid != resource.address:
                    self._add_edge(resource.address, nid, EdgeType.CONTAINMENT)

        # Security group attachment
        sg_ids = props.get("security_groups") or props.get("vpc_security_group_ids") or []
        if isinstance(sg_ids, list):
            for nid, node in self._nodes.items():
                if "security_group" in node.resource_type and nid != resource.address:
                    self._add_edge(resource.address, nid, EdgeType.NETWORK_FLOW)

    def _infer_iam_edges(self, resource: ParsedResource) -> None:
        rtype = resource.resource_type
        props = resource.properties

        # Role attachment
        if rtype == "aws_iam_role_policy_attachment":
            role = props.get("role", "")
            for nid, node in self._nodes.items():
                if node.resource_type == "aws_iam_role" and node.name == role:
                    self._add_edge(resource.address, nid, EdgeType.IAM_BINDING)
                    break

        # Instance profile → role
        if rtype == "aws_iam_instance_profile":
            role = props.get("role", "")
            for nid, node in self._nodes.items():
                if node.resource_type == "aws_iam_role" and node.name == role:
                    self._add_edge(resource.address, nid, EdgeType.IAM_BINDING)
                    break

    def _add_edge(self, source: str, target: str, edge_type: EdgeType) -> None:
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
