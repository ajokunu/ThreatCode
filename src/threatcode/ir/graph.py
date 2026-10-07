"""Cloud-agnostic infrastructure graph built on NetworkX."""

from __future__ import annotations

import difflib
import logging
import os
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any

import networkx as nx

from threatcode.diagnostics import Diagnostic, Level
from threatcode.exceptions import ConfigError, ThreatCodeError
from threatcode.ir.addressing import split_location
from threatcode.ir.edges import COMPUTED_METADATA_KEYS, EdgeType, InfraEdge
from threatcode.ir.enrich import enrich
from threatcode.ir.nodes import (
    InfraNode,
    TrustZone,
    categorize_resource,
    infer_trust_zone,
)
from threatcode.ir.references import (
    ReferenceIndex,
    TypeMatcher,
    type_contains,
    type_endswith,
    type_is,
)
from threatcode.parsers.base import ParsedEdge, ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)

# Security: cap graph size to prevent resource exhaustion. These are the defaults;
# InfraGraph(max_nodes=..., max_edges=...) and the environment variables below
# override them
MAX_NODES = 10_000
MAX_EDGES = 50_000
MAX_NODES_ENV = "THREATCODE_MAX_NODES"
MAX_EDGES_ENV = "THREATCODE_MAX_EDGES"

# Containment hint registry: (property_name, target_resource_type)
# When a resource has property_name set, look for nodes of target_resource_type.
_BUILTIN_CONTAINMENT_HINTS: tuple[tuple[str, str], ...] = (
    ("vpc_id", "aws_vpc"),
    ("vnet_id", "azurerm_virtual_network"),
    ("network_id", "google_compute_network"),
)
_custom_containment_hints: list[tuple[str, str]] = []


def register_containment_hint(property_name: str, target_type: str) -> None:
    """Register a custom containment hint for edge inference.

    When a resource has `property_name` in its properties, an edge is inferred
    to nodes matching `target_type`.
    """
    _custom_containment_hints.append((property_name, target_type))


def _all_containment_hints() -> list[tuple[str, str]]:
    return list(_BUILTIN_CONTAINMENT_HINTS) + _custom_containment_hints


@dataclass(frozen=True)
class AttachmentRule:
    """How a reference found in a resource attribute becomes an edge."""

    attributes: tuple[str, ...]
    # Which node types the reference may name; None accepts any node
    target: TypeMatcher | None
    edge_type: EdgeType
    relation: str


# A reference in one of these attributes becomes an edge of this type, and only
# to a node of the required type, so a vpc_id can never bind to a non-VPC node.
# Attribute paths use "." for nesting and "[]" for each list level.
ATTACHMENT_RULES: tuple[AttachmentRule, ...] = (
    AttachmentRule(("vpc_id",), type_is("aws_vpc"), EdgeType.CONTAINMENT, ""),
    AttachmentRule(
        (
            "subnet_id",
            "subnet_ids",
            "subnets",
            "vpc_config[].subnet_ids",
            "network_interface[].subnet_id",
        ),
        type_endswith("subnet"),
        EdgeType.CONTAINMENT,
        "",
    ),
    AttachmentRule(
        (
            "security_groups",
            "vpc_security_group_ids",
            "security_group_ids",
            "vpc_config[].security_group_ids",
        ),
        type_contains("security_group"),
        EdgeType.DEPENDENCY,
        "security_group",
    ),
    AttachmentRule(
        ("role", "role_arn", "execution_role_arn", "task_role_arn"),
        type_is("aws_iam_role"),
        EdgeType.IAM_BINDING,
        "assumes",
    ),
    AttachmentRule(
        ("iam_instance_profile",),
        type_is("aws_iam_instance_profile"),
        EdgeType.IAM_BINDING,
        "instance_profile",
    ),
    AttachmentRule(
        ("kms_key_id", "kms_master_key_id", "kms_key_arn"),
        None,
        EdgeType.DEPENDENCY,
        "encrypts_with",
    ),
)
# Any other attribute that holds a reference
_REFERENCES_RULE = AttachmentRule((), None, EdgeType.DEPENDENCY, "references")
_RULE_BY_ATTRIBUTE: dict[str, AttachmentRule] = {
    attribute: rule for rule in ATTACHMENT_RULES for attribute in rule.attributes
}
# A relation a more specific reference may replace on an existing edge
_GENERIC_RELATIONS = ("", "references")


def _limit(explicit: int | None, env_name: str, default: int, label: str) -> int:
    """Resolve a size limit: the argument, else the environment, else the default."""
    if explicit is not None:
        if explicit < 1:
            raise ThreatCodeError(f"{label} must be at least 1, got {explicit}")
        return explicit
    raw = os.environ.get(env_name, "").strip()
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value < 1:
        raise ConfigError(f"{env_name} must be a positive integer, got '{raw}'")
    return value


@dataclass
class _Unit:
    """One parse output while the graph is built: its resources and lookups."""

    parsed: ParsedOutput
    label: str
    entries: list[tuple[ParsedResource, InfraNode]] = field(default_factory=list)
    # The address a reference is written against -> its node
    by_key: dict[str, InfraNode] = field(default_factory=dict)
    # node id -> the address it is written as inside this unit (differs from the id
    # when the graph qualified or suffixed the id)
    local_key_of: dict[str, str] = field(default_factory=dict)
    # resource type -> node ids of this unit, in input order
    type_index: dict[str, list[str]] = field(default_factory=dict)
    index: ReferenceIndex = field(default_factory=lambda: ReferenceIndex({}))


class InfraGraph:
    """Directed graph representing infrastructure topology."""

    def __init__(
        self,
        *,
        max_nodes: int | None = None,
        max_edges: int | None = None,
        strict_edges: bool = True,
    ) -> None:
        self._graph: nx.DiGraph[str] = nx.DiGraph()
        self._nodes: dict[str, InfraNode] = {}
        self._edges: list[InfraEdge] = []
        self._edge_index: dict[tuple[str, str, str], InfraEdge] = {}  # (source, target, type)
        self.max_nodes = _limit(max_nodes, MAX_NODES_ENV, MAX_NODES, "max_nodes")
        self.max_edges = _limit(max_edges, MAX_EDGES_ENV, MAX_EDGES, "max_edges")
        # False turns a declared edge to an unknown node from an error into a warning
        self.strict_edges = strict_edges
        # What the build skipped, approximated or renamed; see threatcode.diagnostics
        self.diagnostics: list[Diagnostic] = []
        self._duplicate_of: dict[str, str] = {}
        self._edges_skipped = 0
        self._adjacency_size = -1
        self._out: dict[str, list[InfraEdge]] = {}
        self._in: dict[str, list[InfraEdge]] = {}

    @classmethod
    def from_parsed(
        cls,
        parsed: ParsedOutput,
        *,
        max_nodes: int | None = None,
        max_edges: int | None = None,
        strict_edges: bool = True,
    ) -> InfraGraph:
        """Build graph from parsed IaC output."""
        return cls.from_units(
            [parsed], max_nodes=max_nodes, max_edges=max_edges, strict_edges=strict_edges
        )

    @classmethod
    def from_units(
        cls,
        units: Sequence[ParsedOutput],
        *,
        max_nodes: int | None = None,
        max_edges: int | None = None,
        strict_edges: bool = True,
    ) -> InfraGraph:
        """Build one graph from several parse outputs, such as a repository's files.

        An address that only one unit uses keeps its id.
        An address that several units use is qualified as
        `<unit source path>::<address>` in every one of them, in input order, so
        the ids do not depend on which unit came first.
        References, dependencies and declared edges resolve inside their own
        unit; a unit's diagnostics are carried into `graph.diagnostics`.
        """
        graph = cls(max_nodes=max_nodes, max_edges=max_edges, strict_edges=strict_edges)
        graph._build(list(units))
        return graph

    def _build(self, parsed_units: list[ParsedOutput]) -> None:
        for parsed in parsed_units:
            self.diagnostics.extend(parsed.diagnostics)
        collisions = _colliding_addresses(parsed_units)
        units: list[_Unit] = []
        for position, parsed in enumerate(parsed_units, start=1):
            unit = _Unit(parsed, label=parsed.source_path or f"unit{position}")
            for resource in parsed.resources:
                self._add_resource(resource, unit, qualify=resource.address in collisions)
            unit.index = ReferenceIndex(unit.by_key)
            units.append(unit)
        for address, positions in sorted(collisions.items()):
            owners = ", ".join(units[p].label for p in positions)
            self._diagnose(
                "info",
                "graph.duplicate_address",
                f"Address '{address}' is used by {len(positions)} inputs ({owners}); "
                "each is qualified with its input path",
            )
        for unit in units:
            self._infer_edges(unit)
        self._add_declared_edges(units)
        self._mark_trust_boundary_crossings()
        self._flush_edge_cap()
        enrich(self, ReferenceIndex(self._nodes))

    @property
    def nodes(self) -> dict[str, InfraNode]:
        return dict(self._nodes)

    @property
    def edges(self) -> list[InfraEdge]:
        return list(self._edges)

    @property
    def node_count(self) -> int:
        return len(self._nodes)

    @property
    def duplicate_of(self) -> dict[str, str]:
        """For each node renamed because its address was taken, the id it duplicates."""
        return dict(self._duplicate_of)

    @property
    def duplicate_count(self) -> int:
        return len(self._duplicate_of)

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

    def edges_from(self, node_id: str) -> list[InfraEdge]:
        """The edges that leave a node, in the order they were added."""
        self._ensure_adjacency()
        return list(self._out.get(node_id, ()))

    def edges_to(self, node_id: str) -> list[InfraEdge]:
        """The edges that enter a node, in the order they were added."""
        self._ensure_adjacency()
        return list(self._in.get(node_id, ()))

    def successors(self, node_id: str, edge_types: Iterable[EdgeType] | None = None) -> list[str]:
        """The ids of the nodes a node has an edge to, optionally of some edge types only."""
        wanted = None if edge_types is None else frozenset(edge_types)
        found: dict[str, None] = {}
        for edge in self.edges_from(node_id):
            if wanted is None or edge.edge_type in wanted:
                found.setdefault(edge.target)
        return list(found)

    def predecessors(self, node_id: str, edge_types: Iterable[EdgeType] | None = None) -> list[str]:
        """The ids of the nodes that have an edge to a node, optionally of some edge types only."""
        wanted = None if edge_types is None else frozenset(edge_types)
        found: dict[str, None] = {}
        for edge in self.edges_to(node_id):
            if wanted is None or edge.edge_type in wanted:
                found.setdefault(edge.source)
        return list(found)

    def _ensure_adjacency(self) -> None:
        # Edges are only ever appended, so a changed length means a stale index
        if self._adjacency_size == len(self._edges):
            return
        self._out, self._in = {}, {}
        for edge in self._edges:
            self._out.setdefault(edge.source, []).append(edge)
            self._in.setdefault(edge.target, []).append(edge)
        self._adjacency_size = len(self._edges)

    def nodes_by_zone(self) -> dict[TrustZone, list[InfraNode]]:
        zones: dict[TrustZone, list[InfraNode]] = {}
        for node in self._nodes.values():
            zones.setdefault(node.trust_zone, []).append(node)
        return zones

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": {nid: _node_to_dict(n) for nid, n in self._nodes.items()},
            "edges": [_edge_to_dict(e) for e in self._edges],
        }

    def _diagnose(
        self, level: Level, code: str, message: str, file: str = "", line: int | None = None
    ) -> None:
        self.diagnostics.append(Diagnostic(level, code, message, file, line))

    def _add_resource(
        self, resource: ParsedResource, unit: _Unit | None = None, qualify: bool = False
    ) -> InfraNode:
        if len(self._nodes) >= self.max_nodes:
            raise ThreatCodeError(
                f"Infrastructure graph exceeds {self.max_nodes} node limit. "
                f"Split your IaC into smaller modules, or raise the limit with the "
                f"{MAX_NODES_ENV} environment variable."
            )

        if resource.evidence not in ("config", "design"):
            raise ThreatCodeError(
                f"Resource {resource.address} has unknown evidence '{resource.evidence}'. "
                "Valid: config, design"
            )
        if resource.mode not in ("managed", "data"):
            raise ThreatCodeError(
                f"Resource {resource.address} has unknown mode '{resource.mode}'. "
                "Valid: managed, data"
            )
        category = categorize_resource(resource.resource_type)
        trust_zone = _declared_or_inferred_zone(resource)
        source_file, legacy_line = split_location(resource.source_location)
        start_line = resource.start_line if resource.start_line is not None else legacy_line

        base_id = f"{unit.label}::{resource.address}" if unit and qualify else resource.address
        node_id = base_id
        local_key = resource.address
        if node_id in self._nodes:
            # Keep both: overwriting would silently drop the earlier resource and
            # every finding on it. Later ones get #2, #3 in input order
            number = 2
            while f"{base_id}#{number}" in self._nodes:
                number += 1
            node_id = f"{base_id}#{number}"
            self._duplicate_of[node_id] = base_id
            self._diagnose(
                "warning",
                "graph.duplicate_address",
                f"Duplicate resource address '{base_id}': the later resource is kept as "
                f"'{node_id}'",
                source_file,
                start_line,
            )
        if unit is not None and local_key in unit.by_key:
            number = 2
            while f"{resource.address}#{number}" in unit.by_key:
                number += 1
            local_key = f"{resource.address}#{number}"

        node = InfraNode(
            id=node_id,
            resource_type=resource.resource_type,
            name=resource.name,
            category=category,
            trust_zone=trust_zone,
            properties=resource.properties,
            provider=resource.provider,
            module=resource.module,
            boundary=resource.boundary,
            evidence=resource.evidence,
            source_file=source_file,
            start_line=start_line,
            end_line=resource.end_line,
            mode=resource.mode,
        )
        self._nodes[node_id] = node
        self._graph.add_node(node_id)
        if unit is not None:
            unit.by_key[local_key] = node
            unit.local_key_of[node_id] = local_key
            unit.type_index.setdefault(resource.resource_type, []).append(node_id)
            unit.entries.append((resource, node))
        return node

    def _infer_edges(self, unit: _Unit) -> None:
        for resource, node in unit.entries:
            # Explicit dependencies, resolved through the reference index
            for dep in resource.dependencies:
                for target in unit.index.resolve(dep, resource.module):
                    if target != node.id:
                        self._add_edge(node.id, target, EdgeType.DEPENDENCY)

            # References the parser found, as typed edges
            self._add_reference_edges(unit, resource, node)

            # Containment: subnet → VPC, instance → subnet, etc.
            self._infer_containment(unit, resource, node)

            # IAM bindings
            self._infer_iam_edges(unit, resource, node)

    def _add_reference_edges(self, unit: _Unit, resource: ParsedResource, node: InfraNode) -> None:
        for attribute, raws in resource.references.items():
            rule = _RULE_BY_ATTRIBUTE.get(attribute, _REFERENCES_RULE)
            for raw in [raws] if isinstance(raws, str) else raws:
                resolution = unit.index.resolve_detailed(
                    raw, resource.module, required_type=rule.target
                )
                if resolution.ambiguous:
                    self._diagnose(
                        "warning",
                        "graph.ambiguous_reference",
                        f"Reference '{raw}' in {node.id} ({attribute}) matches several nodes "
                        f"({', '.join(resolution.ambiguous)}); no edge was added",
                        node.source_file,
                        node.start_line,
                    )
                if not resolution.ids:
                    logger.debug(
                        "Unresolved reference %r in %s (%s): no edge", raw, node.id, attribute
                    )
                    continue
                for target in resolution.ids:
                    if target != node.id:
                        self._add_edge(node.id, target, rule.edge_type, relation=rule.relation)

    def _add_declared_edges(self, units: list[_Unit]) -> None:
        """Add edges the input states explicitly, such as data flows in a design.

        A declared edge to a node that does not exist is an error, reported for
        every such edge at once: dropping it would silently delete the flow and
        every threat that hangs off it. An edge the parser only inferred is skipped.
        """
        dangling: list[tuple[str, str, str, str]] = []
        for unit in units:
            for edge in unit.parsed.edges:
                edge_type = _edge_type(edge)
                source = unit.by_key.get(edge.source) or self._nodes.get(edge.source)
                target = unit.by_key.get(edge.target) or self._nodes.get(edge.target)
                if source is None or target is None:
                    missing = [
                        (role, address)
                        for role, address, found in (
                            ("source", edge.source, source),
                            ("target", edge.target, target),
                        )
                        if found is None
                    ]
                    if edge.declared:
                        dangling.extend(
                            (edge.source, edge.target, role, address) for role, address in missing
                        )
                    else:
                        logger.debug(
                            "Skipping inferred edge %s -> %s: unknown node %s",
                            edge.source,
                            edge.target,
                            ", ".join(address for _, address in missing),
                        )
                    continue
                relation = edge.metadata.get("relation", "")
                self._add_edge(
                    source.id,
                    target.id,
                    edge_type,
                    metadata=edge.metadata,
                    relation=relation if isinstance(relation, str) else "",
                    declared=edge.declared,
                )
        if dangling:
            self._report_dangling(dangling)

    def _report_dangling(self, dangling: list[tuple[str, str, str, str]]) -> None:
        known = sorted(self._nodes)
        lines: list[str] = []
        for source, target, role, address in dangling:
            hint = difflib.get_close_matches(address, known, n=3, cutoff=0.6)
            suffix = f" (closest known: {', '.join(hint)})" if hint else ""
            lines.append(f"{source} -> {target}: unknown {role} '{address}'{suffix}")
        if self.strict_edges:
            raise ThreatCodeError(
                f"{len(lines)} declared edge endpoint(s) name nodes that do not exist:\n  "
                + "\n  ".join(lines)
                + "\nFix the node ids, or build the graph with strict_edges=False to "
                "report them as warnings instead."
            )
        for line in lines:
            self._diagnose(
                "warning", "graph.dangling_declared_edge", f"Declared edge skipped: {line}"
            )

    def _infer_containment(self, unit: _Unit, resource: ParsedResource, node: InfraNode) -> None:
        props = resource.properties
        # An attribute the parser resolved references for has its edges already;
        # guessing from the literal value again could only add wrong ones
        resolved = resource.references

        def literal(name: str) -> Any:
            return None if name in resolved else props.get(name)

        # Registry-driven containment hints
        for prop_name, target_type in _all_containment_hints():
            value = literal(prop_name)
            if value and isinstance(value, str):
                for nid in unit.type_index.get(target_type, []):
                    if nid != node.id:
                        self._add_edge(node.id, nid, EdgeType.CONTAINMENT)
                        break

        # Subnet containment — match only if we have a reference
        subnet_id = literal("subnet_id")
        subnet_ids = literal("subnet_ids") or literal("subnets") or []
        if subnet_id:
            # Merge single subnet_id into the list rather than clobbering it
            if isinstance(subnet_ids, list):
                subnet_ids = [subnet_id, *subnet_ids]
            else:
                subnet_ids = [subnet_id]
        if isinstance(subnet_ids, list) and subnet_ids:
            # Build set of referenced subnet IDs for matching
            ref_ids = set(str(s) for s in subnet_ids if s)
            for rtype, nids in unit.type_index.items():
                if rtype.endswith("subnet"):
                    for nid in nids:
                        other = self._nodes.get(nid)
                        if other and nid != node.id:
                            # Match by address or name against referenced IDs
                            if _is_referenced(unit, other, ref_ids):
                                self._add_edge(node.id, nid, EdgeType.CONTAINMENT)

        # Security group attachment — match only if we have a reference
        sg_ids = literal("security_groups") or literal("vpc_security_group_ids") or []
        if isinstance(sg_ids, list) and sg_ids:
            ref_ids = set(str(s) for s in sg_ids if s)
            for rtype, nids in unit.type_index.items():
                if "security_group" in rtype:
                    for nid in nids:
                        other = self._nodes.get(nid)
                        if other and nid != node.id:
                            if _is_referenced(unit, other, ref_ids):
                                self._add_edge(node.id, nid, EdgeType.NETWORK_FLOW)

    def _infer_iam_edges(self, unit: _Unit, resource: ParsedResource, node: InfraNode) -> None:
        rtype = resource.resource_type
        if "role" in resource.references:
            return

        # Role attachment and instance profile → role
        if rtype in ("aws_iam_role_policy_attachment", "aws_iam_instance_profile"):
            role = resource.properties.get("role", "")
            if role:
                self._match_iam_role(unit, node.id, role)

    def _match_iam_role(self, unit: _Unit, source_id: str, role_ref: str) -> None:
        """Match an IAM role reference, trying address-based match first."""
        # Try address-based match first (e.g., aws_iam_role.my_role)
        by_address = unit.by_key.get(f"aws_iam_role.{role_ref}")
        if by_address is not None:
            self._add_edge(source_id, by_address.id, EdgeType.IAM_BINDING)
            return

        # Fall back to name-based match
        for nid in unit.type_index.get("aws_iam_role", []):
            if self._nodes[nid].name == role_ref:
                self._add_edge(source_id, nid, EdgeType.IAM_BINDING)
                return

    def _add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        metadata: dict[str, Any] | None = None,
        *,
        relation: str = "",
        declared: bool = False,
    ) -> None:
        # Deduplicate edges; a repeated edge only contributes what it adds
        key = (source, target, edge_type.value)
        existing = self._edge_index.get(key)
        if existing is not None:
            if metadata:
                existing.attributes.update(metadata)
                existing.metadata.update(_without_computed(metadata))
            existing.declared = existing.declared or declared
            if relation and existing.relation in _GENERIC_RELATIONS:
                existing.relation = relation
                existing.metadata["relation"] = relation
            return

        if len(self._edges) >= self.max_edges:
            self._edges_skipped += 1
            return

        attributes = dict(metadata or {})
        visible = _without_computed(attributes)
        if relation:
            visible["relation"] = relation
        edge = InfraEdge(
            source=source,
            target=target,
            edge_type=edge_type,
            metadata=visible,
            relation=relation,
            declared=declared,
            attributes=attributes,
        )
        # Only index the edge after confirming it will be added
        self._edge_index[key] = edge
        self._edges.append(edge)
        self._graph.add_edge(source, target, type=edge_type.value)

    def _flush_edge_cap(self) -> None:
        """Report, once, how many edges the edge limit made the build skip."""
        if not self._edges_skipped:
            return
        message = (
            f"Edge limit reached ({self.max_edges}): skipped {self._edges_skipped} further "
            f"edge(s). Raise the limit with the {MAX_EDGES_ENV} environment variable."
        )
        logger.warning(message)
        self._diagnose("warning", "graph.edge_cap", message)
        self._edges_skipped = 0

    def _mark_trust_boundary_crossings(self) -> None:
        for edge in self._edges:
            src_node = self._nodes.get(edge.source)
            tgt_node = self._nodes.get(edge.target)
            if not (src_node and tgt_node):
                continue
            edge.source_zone = src_node.trust_zone
            edge.target_zone = tgt_node.trust_zone
            edge.source_boundary = src_node.boundary
            edge.target_boundary = tgt_node.boundary
            zones_differ = src_node.trust_zone != tgt_node.trust_zone
            # Declared boundaries are finer than zone classes: two private
            # subnets in a design are separate boundaries in the same zone
            boundaries_differ = bool(
                src_node.boundary and tgt_node.boundary and src_node.boundary != tgt_node.boundary
            )
            edge.crosses_boundary = zones_differ or boundaries_differ
            # The crossing is computed here and only here. A parser's attributes
            # never decide it: _add_edge keeps keys of these names out of metadata
            if edge.crosses_boundary:
                edge.metadata["crosses_trust_boundary"] = True
                edge.metadata["source_zone"] = src_node.trust_zone.value
                edge.metadata["target_zone"] = tgt_node.trust_zone.value
                if boundaries_differ:
                    edge.metadata["source_boundary"] = src_node.boundary
                    edge.metadata["target_boundary"] = tgt_node.boundary


def _colliding_addresses(units: list[ParsedOutput]) -> dict[str, list[int]]:
    """Addresses that more than one unit declares, with the positions of those units."""
    users: dict[str, set[int]] = {}
    for position, parsed in enumerate(units):
        for resource in parsed.resources:
            users.setdefault(resource.address, set()).add(position)
    return {a: sorted(p) for a, p in users.items() if len(p) > 1}


def _is_referenced(unit: _Unit, node: InfraNode, ref_ids: set[str]) -> bool:
    """Whether a literal value names `node` by address or by name."""
    return (
        node.id in ref_ids
        or unit.local_key_of.get(node.id, node.id) in ref_ids
        or bool(node.name and node.name in ref_ids)
    )


def _without_computed(attributes: dict[str, Any]) -> dict[str, Any]:
    return {k: v for k, v in attributes.items() if k not in COMPUTED_METADATA_KEYS}


def _edge_type(edge: ParsedEdge) -> EdgeType:
    try:
        return EdgeType(edge.edge_type)
    except ValueError as e:
        raise ThreatCodeError(
            f"Edge {edge.source} -> {edge.target} has unknown type '{edge.edge_type}'. "
            f"Valid: {', '.join(t.value for t in EdgeType)}"
        ) from e


def _node_to_dict(node: InfraNode) -> dict[str, Any]:
    data: dict[str, Any] = {
        "resource_type": node.resource_type,
        "name": node.name,
        "category": node.category.value,
        "trust_zone": node.trust_zone.value,
        "stride_element": node.stride_element,
        "provider": node.provider,
        "boundary": node.boundary,
        "evidence": node.evidence,
    }
    # Optional attributes appear only when they differ from their default, so a
    # graph that never sets them renders exactly as before. source_file is left
    # out on purpose: this dict feeds the LLM payload, and paths belong to the
    # redactor's sensitive keys, which do not name it
    if node.mode != "managed":
        data["mode"] = node.mode
    if node.exposure != "unknown":
        data["exposure"] = node.exposure
    return data


def _edge_to_dict(edge: InfraEdge) -> dict[str, Any]:
    data: dict[str, Any] = {
        "source": edge.source,
        "target": edge.target,
        "type": edge.edge_type.value,
        "crosses_trust_boundary": edge.crosses_trust_boundary,
    }
    if edge.relation:
        data["relation"] = edge.relation
    return data


def _declared_or_inferred_zone(resource: ParsedResource) -> TrustZone:
    """Use the zone the input declares, else infer it from type and properties."""
    if resource.trust_zone is None:
        return infer_trust_zone(resource.resource_type, resource.properties)
    try:
        return TrustZone(resource.trust_zone)
    except ValueError as e:
        raise ThreatCodeError(
            f"Resource {resource.address} declares unknown trust zone '{resource.trust_zone}'. "
            f"Valid: {', '.join(z.value for z in TrustZone)}"
        ) from e
