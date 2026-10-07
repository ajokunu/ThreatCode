"""Cloud-agnostic infrastructure graph built on NetworkX."""

from __future__ import annotations

import difflib
import logging
import os
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, Literal

import networkx as nx

from threatcode.diagnostics import Diagnostic, Level
from threatcode.exceptions import ConfigError, ThreatCodeError
from threatcode.ir import exposure, iam
from threatcode.ir.addressing import split_location
from threatcode.ir.edges import COMPUTED_METADATA_KEYS, REACHABILITY, EdgeType, InfraEdge
from threatcode.ir.enrich import enrich
from threatcode.ir.nodes import (
    InfraNode,
    NodeCategory,
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
from threatcode.values import is_unknown

logger = logging.getLogger(__name__)

# Security: cap graph size to prevent resource exhaustion. These are the defaults;
# InfraGraph(max_nodes=..., max_edges=...) and the environment variables below
# override them
MAX_NODES = 10_000
MAX_EDGES = 50_000
MAX_NODES_ENV = "THREATCODE_MAX_NODES"
MAX_EDGES_ENV = "THREATCODE_MAX_EDGES"

# Containment hints registered at run time with register_containment_hint
_custom_containment_hints: list[tuple[str, str]] = []


def register_containment_hint(property_name: str, target_type: str) -> None:
    """Register a custom containment hint for edge inference.

    A resource whose `property_name` attribute names a node of `target_type` is contained in it.
    The hint joins the attachment table: it applies to the references a parser found for that
    attribute, and to a literal value the input states (an address, an id, an ARN or a unique
    name), and it only ever binds a node of `target_type`.
    """
    _custom_containment_hints.append((property_name, target_type))


@dataclass(frozen=True)
class AttachmentRule:
    """How a reference found in a resource attribute becomes an edge."""

    attributes: tuple[str, ...]
    # Which node types the reference may name; None accepts any node
    target: TypeMatcher | None
    edge_type: EdgeType
    relation: str
    # A literal value that names nothing binds the only node of the required type, when there is
    # exactly one. Only a network placement does this: with a single VPC in the input, a subnet's
    # literal `vpc_id` is that VPC. With two or more candidates nothing is bound
    bind_sole_candidate: bool = False


# A reference in one of these attributes becomes an edge of this type, and only
# to a node of the required type, so a vpc_id can never bind to a non-VPC node.
# Attribute paths use "." for nesting and "[]" for each list level.
ATTACHMENT_RULES: tuple[AttachmentRule, ...] = (
    AttachmentRule(
        ("vpc_id",), type_is("aws_vpc"), EdgeType.CONTAINMENT, "", bind_sole_candidate=True
    ),
    AttachmentRule(
        ("virtual_network_name", "virtual_network_id"),
        type_is("azurerm_virtual_network"),
        EdgeType.CONTAINMENT,
        "",
    ),
    AttachmentRule(
        ("network", "network_interface[].network"),
        type_is("google_compute_network"),
        EdgeType.CONTAINMENT,
        "",
    ),
    AttachmentRule(
        ("subnetwork", "network_interface[].subnetwork"),
        type_is("google_compute_subnetwork"),
        EdgeType.CONTAINMENT,
        "",
    ),
    AttachmentRule(
        (
            "subnet_id",
            "subnet_ids",
            "subnets",
            "vpc_config[].subnet_ids",
            "network_interface[].subnet_id",
            "network_interfaces[].subnet_id",
            "ip_configuration[].subnet_id",
            "virtual_network_subnet_id",
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
            "network_interfaces[].security_groups",
        ),
        type_contains("security_group"),
        EdgeType.DEPENDENCY,
        "security_group",
    ),
    AttachmentRule(
        (
            "role",
            "roles",
            "role_arn",
            "execution_role_arn",
            "task_role_arn",
            "node_role_arn",
            "service_role",
        ),
        type_is("aws_iam_role"),
        EdgeType.IAM_BINDING,
        "assumes",
    ),
    AttachmentRule(
        ("iam_instance_profile", "iam_instance_profile[].name", "iam_instance_profile[].arn"),
        type_is("aws_iam_instance_profile"),
        EdgeType.IAM_BINDING,
        "instance_profile",
    ),
    AttachmentRule(
        ("policy_arn",),
        type_is("aws_iam_policy"),
        EdgeType.IAM_BINDING,
        "attaches",
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
# How many dangling edges get "closest known node" suggestions in the error
_MAX_HINTED_EDGES = 20
# A relation a more specific reference may replace on an existing edge
_GENERIC_RELATIONS = ("", "references")


def _all_rules() -> list[AttachmentRule]:
    """The built-in attachment rules and one containment rule per registered hint."""
    return [
        *ATTACHMENT_RULES,
        *(
            AttachmentRule(
                (prop,), type_is(target), EdgeType.CONTAINMENT, "", bind_sole_candidate=True
            )
            for prop, target in _custom_containment_hints
        ),
    ]


def _rule_for(attribute: str) -> AttachmentRule:
    """The rule for an attribute path; a registered hint is checked after the built-ins."""
    found = _RULE_BY_ATTRIBUTE.get(attribute)
    if found is not None:
        return found
    for prop, target in _custom_containment_hints:
        if prop == attribute:
            return AttachmentRule(
                (prop,), type_is(target), EdgeType.CONTAINMENT, "", bind_sole_candidate=True
            )
    return _REFERENCES_RULE


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
        # node id -> the format of the parser that produced it ("terraform_hcl", "cloudformation",
        # "terraform_plan", ...). Enrichment and exposure read it to know where provider defaults
        # may be assumed: a plan materialises them, a template or HCL file leaves them out
        self.node_formats: dict[str, str] = {}
        # Ids of the nodes whose zone the input declared; no later pass moves them
        self.zone_declared: set[str] = set()
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
        # Passes that need the finished edges and the derived facts, in this order:
        # enrichment computes policy documents, rules and settings; IAM links roles, policies
        # and the resources they reach; exposure decides what faces the internet and the final
        # zones. The crossings are marked last because they compare the final zones
        enrich(self, ReferenceIndex(self._nodes))
        iam.link(self)
        exposure.apply(self)
        self._mark_trust_boundary_crossings()
        self._flush_edge_cap()

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

    def get_neighbors(
        self, node_id: str, direction: Literal["out", "in", "both"] = "out"
    ) -> list[InfraNode]:
        """The nodes next to a node, each once.

        `direction="out"` (the default, and the only behaviour before the argument existed) gives
        the targets of the node's edges, `"in"` the sources of the edges that enter it and
        `"both"` the targets and then the sources.
        """
        if node_id not in self._nodes:
            return []
        ids: dict[str, None] = {}
        if direction in ("out", "both"):
            ids.update(dict.fromkeys(self.successors(node_id)))
        if direction in ("in", "both"):
            ids.update(dict.fromkeys(self.predecessors(node_id)))
        return [self._nodes[n] for n in ids if n in self._nodes]

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
        # Edges are only ever appended, so the index grows by the edges added since it was built
        # (an IAM or exposure pass reads it between additions and must not rebuild it each time)
        if self._adjacency_size == len(self._edges):
            return
        if self._adjacency_size < 0 or self._adjacency_size > len(self._edges):
            self._out, self._in = {}, {}
            self._adjacency_size = 0
        for edge in self._edges[self._adjacency_size :]:
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

    def to_export_dict(self, include_properties: bool = False) -> dict[str, Any]:
        """The graph as plain data for user-facing output.

        `to_dict` feeds the redacted LLM payload and keeps its small shape.
        This one is for a person or a tool that wants to see what the engine saw:

        - `nodes`: one entry per node, sorted by id, with `id`, `type`, `name`, `category`,
          `zone`, `exposure`, `boundary`, `evidence`, `stride_element`, `module`, `mode`,
          `source_file`, `start_line` and `end_line`.
        - `edges`: one entry per edge, sorted by source, target and type, with `source`,
          `target`, `type`, `relation`, `declared`, `crosses_boundary`, `source_zone`,
          `target_zone` and the parser's `attributes`.

        Node properties are left out unless `include_properties` is true, because they come from
        the input and can hold secrets.
        The output depends only on the graph, so two runs over the same input match.
        """
        nodes = []
        for node_id in sorted(self._nodes):
            node = self._nodes[node_id]
            entry: dict[str, Any] = {
                "id": node.id,
                "type": node.resource_type,
                "name": node.name,
                "category": node.category.value,
                "zone": node.trust_zone.value,
                "exposure": node.exposure,
                "boundary": node.boundary,
                "evidence": node.evidence,
                "stride_element": node.stride_element,
                "module": node.module,
                "mode": node.mode,
                "source_file": node.source_file,
                "start_line": node.start_line,
                "end_line": node.end_line,
            }
            if include_properties:
                entry["properties"] = _plain_data(node.properties)
            nodes.append(entry)
        edges = [
            {
                "source": edge.source,
                "target": edge.target,
                "type": edge.edge_type.value,
                "relation": edge.relation,
                "declared": edge.declared,
                "crosses_boundary": edge.crosses_boundary,
                "source_zone": edge.source_zone.value if edge.source_zone else None,
                "target_zone": edge.target_zone.value if edge.target_zone else None,
                "attributes": _plain_data(edge.attributes),
            }
            for edge in sorted(
                self._edges, key=lambda e: (e.source, e.target, e.edge_type.value, e.relation)
            )
        ]
        return {"nodes": nodes, "edges": edges}

    def subgraph(self, edge_types: Iterable[EdgeType]) -> nx.MultiDiGraph[str]:
        """A graph with every node and only the edges of the given types.

        It is a `MultiDiGraph`, so two nodes joined by a dependency and a network flow keep both
        edges, keyed by edge type.
        Each edge carries `relation`, `declared` and the parser's `attributes`, and the nodes
        carry `zone` and `category`, for graph algorithms that need them.
        """
        wanted = frozenset(edge_types)
        view: nx.MultiDiGraph[str] = nx.MultiDiGraph()
        for node_id, node in self._nodes.items():
            view.add_node(node_id, zone=node.trust_zone.value, category=node.category.value)
        for edge in self._edges:
            if edge.edge_type in wanted:
                view.add_edge(
                    edge.source,
                    edge.target,
                    key=edge.edge_type.value,
                    relation=edge.relation,
                    declared=edge.declared,
                    attributes=edge.attributes,
                )
        return view

    def reachability_subgraph(self) -> nx.MultiDiGraph[str]:
        """The graph of the edges an attacker can follow: network flows, data flows and bindings.

        This is the edge set attack paths walk.
        The synthetic internet node is not part of it yet.
        """
        return self.subgraph(REACHABILITY)

    def add_edge(
        self,
        source: str,
        target: str,
        edge_type: EdgeType,
        metadata: dict[str, Any] | None = None,
        *,
        relation: str = "",
    ) -> None:
        """Add an inferred edge between two nodes of the graph.

        This is the entry point for the passes that run after the build (IAM, exposure,
        reachability).
        An edge that already exists keeps its place and only gains what the new one adds, and
        the edge limit applies.
        """
        if source not in self._nodes or target not in self._nodes:
            raise ThreatCodeError(f"Cannot add edge {source} -> {target}: unknown node")
        self._add_edge(source, target, edge_type, metadata, relation=relation)

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
                f"Split your IaC into smaller modules, or raise the limit with --max-nodes, "
                f"max_nodes in .threatcode.yml or the {MAX_NODES_ENV} environment variable."
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
        trust_zone = _declared_or_inferred_zone(resource, category)
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
            self.node_formats[node_id] = unit.parsed.format_type
            if resource.trust_zone is not None:
                self.zone_declared.add(node_id)
            unit.by_key[local_key] = node
            unit.type_index.setdefault(resource.resource_type, []).append(node_id)
            unit.entries.append((resource, node))
        return node

    def _infer_edges(self, unit: _Unit) -> None:
        """Add the edges a unit's references, dependencies and literal values state.

        An edge exists only because the input names its target: a reference the parser
        resolved, a dependency, or a literal address, id, ARN or name that matches exactly one
        node of the required type.
        Nothing is guessed from a node's position or from the first node of a type.
        """
        rules = [rule for rule in _all_rules() if rule.target is not None]
        for resource, node in unit.entries:
            # Explicit dependencies, resolved through the reference index
            for dep in resource.dependencies:
                for target in unit.index.resolve(dep, resource.module):
                    if target != node.id:
                        self._add_edge(node.id, target, EdgeType.DEPENDENCY)

            # References the parser found, as typed edges
            self._add_reference_edges(unit, resource, node)

            # Literal values of the attachment attributes the parser found no reference for
            self._add_literal_edges(unit, resource, node, rules)

    def _add_reference_edges(self, unit: _Unit, resource: ParsedResource, node: InfraNode) -> None:
        for attribute, raws in resource.references.items():
            rule = _rule_for(attribute)
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

    def _add_literal_edges(
        self, unit: _Unit, resource: ParsedResource, node: InfraNode, rules: list[AttachmentRule]
    ) -> None:
        """Resolve the literal values of attachment attributes that have no parser reference.

        This keeps hand-written inputs whose attributes hold Terraform addresses, ids, ARNs or
        names working.
        A value binds a node only through `ReferenceIndex.resolve_value`, never by position.
        A value that names nothing is an external id and adds no edge, with one exception: a
        network placement (`vpc_id`, a registered hint) binds the only node of its type when the
        input has exactly one, and the edge is marked `binding: only_candidate`.
        When several nodes of a placement's type exist and the value names none of them, the build
        says it could not choose between them instead of choosing the first.
        """
        for rule in rules:
            required = rule.target
            if required is None:
                continue
            for attribute in rule.attributes:
                if attribute in resource.references:
                    continue
                for value in _literal_values(resource.properties, attribute):
                    resolution = unit.index.resolve_value(
                        value, resource.module, required_type=required
                    )
                    for target in resolution.ids:
                        if target != node.id:
                            self._add_edge(node.id, target, rule.edge_type, relation=rule.relation)
                    if resolution.ids:
                        continue
                    if self._bind_sole_candidate(unit, node, rule, value, resolution.ambiguous):
                        continue
                    self._explain_unbound(unit, node, rule, attribute, value, resolution.ambiguous)

    def _bind_sole_candidate(
        self,
        unit: _Unit,
        node: InfraNode,
        rule: AttachmentRule,
        value: str,
        ambiguous: tuple[str, ...],
    ) -> bool:
        """Bind a literal that names nothing to the only node of the required type, if allowed."""
        if not rule.bind_sole_candidate or rule.target is None or ambiguous:
            return False
        if _ADDRESS_LIKE.match(value) or not _same_provider(node.resource_type, unit, rule.target):
            return False
        candidates = _candidates(unit, rule.target, node.id)
        if len(candidates) != 1:
            return False
        self._add_edge(
            node.id,
            candidates[0],
            rule.edge_type,
            {"binding": "only_candidate"},
            relation=rule.relation,
        )
        return True

    def _explain_unbound(
        self,
        unit: _Unit,
        node: InfraNode,
        rule: AttachmentRule,
        attribute: str,
        value: str,
        ambiguous: tuple[str, ...],
    ) -> None:
        """Report a literal placement value that matched no single node, when it was a choice.

        A value that two or more nodes carry is a real ambiguity in the input (a warning).
        A literal id that matches none of several candidates is most often a resource outside
        the input, so it is information, not a gap: the build only says it did not choose.
        """
        level: Level = "warning"
        if ambiguous:
            detail = f"matches several nodes ({', '.join(ambiguous)})"
        elif (
            rule.target is not None
            and _is_placement(rule)
            and not _ADDRESS_LIKE.match(value)
            and _same_provider(node.resource_type, unit, rule.target)
        ):
            candidates = _candidates(unit, rule.target, node.id)
            if len(candidates) < 2:
                return
            shown = ", ".join(candidates[:5]) + (", ..." if len(candidates) > 5 else "")
            detail = f"names none of {len(candidates)} candidate nodes ({shown})"
            level = "info"
        else:
            return
        self._diagnose(
            level,
            "graph.ambiguous_reference",
            f"Value '{value}' in {node.id} ({attribute}) {detail}; no edge was added",
            node.source_file,
            node.start_line,
        )

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
        for position, (source, target, role, address) in enumerate(dangling):
            # Suggestions cost a similarity score per known node, so only the
            # first few dangling edges get them; the rest are still listed
            hint = (
                difflib.get_close_matches(address, known, n=3, cutoff=0.6)
                if position < _MAX_HINTED_EDGES
                else []
            )
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
            f"edge(s). Raise the limit with --max-edges, max_edges in .threatcode.yml or the "
            f"{MAX_EDGES_ENV} environment variable."
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


def _literal_values(properties: dict[str, Any], path: str) -> list[str]:
    """The plain string values at an attribute path, following "." and "[]".

    A value that is not a string, and an `Unknown`, is not a literal and is left out.
    """
    current: list[Any] = [properties]
    for segment in path.split("."):
        key = segment[:-2] if segment.endswith("[]") else segment
        following: list[Any] = []
        for item in current:
            if isinstance(item, dict) and key in item:
                value = item[key]
                if segment.endswith("[]"):
                    following.extend(value if isinstance(value, list) else [value])
                else:
                    following.append(value)
        current = following
    found: list[str] = []
    for value in current:
        for leaf in value if isinstance(value, list) else [value]:
            if isinstance(leaf, str) and not is_unknown(leaf) and leaf.strip():
                found.append(leaf)
    return found


# A value written as a resource address: `aws_subnet.a`, `aws_subnet.a[0].id`, `module.x.y`
_ADDRESS_LIKE = re.compile(r"^(module\.|[a-z][a-z0-9]*_[a-z0-9_]+(\[[^\]]*\])?\.)[A-Za-z_]")


def _is_placement(rule: AttachmentRule) -> bool:
    """Whether a rule places a node in a network or attaches a security group to it."""
    return rule.edge_type is EdgeType.CONTAINMENT or rule.relation == "security_group"


def _same_provider(resource_type: str, unit: _Unit, required_type: TypeMatcher) -> bool:
    """Whether the resource and some candidate belong to one provider (`aws_`, `azurerm_`, ...)."""
    provider = resource_type.split("_", 1)[0]
    return any(
        candidate.split("_", 1)[0] == provider and required_type(candidate)
        for candidate in unit.type_index
    )


def _candidates(unit: _Unit, required_type: TypeMatcher, exclude: str) -> list[str]:
    """The ids of the unit's nodes whose type the rule accepts, in input order."""
    return [
        node_id
        for resource_type, node_ids in unit.type_index.items()
        if required_type(resource_type)
        for node_id in node_ids
        if node_id != exclude
    ]


def _plain_data(value: Any, depth: int = 0) -> Any:
    """A JSON-safe copy of parser data: mappings, lists and scalars; anything else as text."""
    if depth > 12:
        return str(value)
    if isinstance(value, dict):
        return {str(k): _plain_data(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [_plain_data(v, depth + 1) for v in items]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)


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


def _declared_or_inferred_zone(resource: ParsedResource, category: NodeCategory) -> TrustZone:
    """Use the zone the input declares, else infer it from type and properties."""
    if resource.trust_zone is None:
        return infer_trust_zone(
            resource.resource_type, resource.properties, category, resource.evidence
        )
    try:
        return TrustZone(resource.trust_zone)
    except ValueError as e:
        raise ThreatCodeError(
            f"Resource {resource.address} declares unknown trust zone '{resource.trust_zone}'. "
            f"Valid: {', '.join(z.value for z in TrustZone)}"
        ) from e
