"""The step that adds context to a graph once its nodes and edges exist.

`InfraGraph.from_parsed` and `InfraGraph.from_units` call `enrich` last, with the finished graph
and a `ReferenceIndex` over all of its nodes.
A single node rarely carries every fact a rule needs.
With AWS provider v4 and later a bucket's encryption lives in a sibling resource, a security
group's rules can be separate resources, and a role's permissions come from attachments and JSON
policy strings.
Enrichment computes those facts once so rules read one place.

The ``derived`` namespace
-------------------------

Enrichment writes only under ``node.properties["derived"]``, so a user's own attributes are never
overwritten, and it replaces any ``derived`` the input already carried (the namespace is reserved,
so a hostile input cannot forge a derived fact).
Rules read ``derived.<key>`` paths.
An unknown fact is an `Unknown` (`threatcode.values`), never an absent key: a companion whose
link cannot be resolved marks the keys it would have set Unknown on every candidate parent
instead of leaving the parent looking unconfigured.
The candidates are the parents of the companion's own input, because a reference never names a
resource of another input, and every such mark is reported as an ``enrich.unresolved_companion``
coverage gap, so a suppressed finding is never silent.
A fact that is a list of independent entries, to which a companion can only add (the rules of a
security group), takes one Unknown entry instead: the entries the scan does know still count,
and only a verdict that needs the whole list stays unknown.
The one exception is ``DEFAULTS``, which fills an absent attribute in place (see below).

Modules
-------

Every module of the package `threatcode.ir.enrichment` is imported in sorted name order, and a
module may export any of these names:

``COMPANIONS``
    `CompanionSpec` entries: resources that configure another resource and are folded into it.
``DERIVERS``
    `Deriver` entries: facts computed from one node alone, such as a parsed policy document or
    the legacy inline form of a setting a companion now carries.
``RELATIONS``
    `RelationSpec` entries: facts a node inherits from the node an attribute points at, such as
    the policies of the role a function runs as.
``DEFAULTS``
    ``{resource_type: {attribute_path: default}}``, applied in place, see below.
``PRODUCED``
    ``{resource_type: {"derived.<fact>", ...}}``: every derived fact the module can write, by
    resource type (an entry ending in '*' is a prefix).
    Nothing here reads it at run time: the provenance gate
    (tests/test_engine/test_rule_property_provenance.py) fails a rule that reads a fact no module
    declares, and fails when a module writes a fact it did not declare.
    `produced`, `produced_by_companions`, `produced_by_relations` and `merge_produced` build it.

The work runs in phases across all modules (defaults, companions, derivers, relations), each in
sorted module order, so a relation can rely on what every companion and deriver produced no matter
which module defined it.
Iteration order is by node id, so the output depends only on the input.
Provider rule packages add their own modules (for example ``aws_network.py``) and never edit the
core ones.

Merging
-------

Several sources can contribute to one derived key (a bucket's ``Enabled`` versioning companion and
its legacy inline block).
Contributions merge by value type: booleans mean "any source says yes" (a known ``True`` beats an
`Unknown`, an `Unknown` beats ``False``), lists concatenate without repeats, mappings merge key by
key, a scalar keeps the first non-None value (companions run before derivers, so a companion wins
over a legacy inline setting), and an `Unknown` beats anything else.

Defaults
--------

Terraform HCL and CloudFormation omit provider defaults that a plan materialises, so a rule that
tests ``enable_key_rotation equals false`` would never fire on them.
``DEFAULTS`` fills such an attribute in place on config-evidence nodes from those formats, only
when the attribute is absent (and, for ``block.attribute`` paths, only when the block exists), and
lists the filled paths in ``derived.defaults_applied``.
It never touches plan JSON or design evidence.
The format of a node is read from ``graph.node_formats`` (node id to parser ``format_type``); a
graph that does not provide it gets no defaults, because filling a plan would be wrong and the
format cannot be guessed from the node.
"""

from __future__ import annotations

import copy
import importlib
import pkgutil
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from types import MappingProxyType, ModuleType
from typing import TYPE_CHECKING, Any

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.ir.references import ReferenceIndex, Resolution, TypeMatcher
from threatcode.values import Unknown, is_unknown

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.ir.nodes import InfraNode

register_code(
    "enrich.unresolved_companion",
    "A resource that configures another could not be linked, so some findings are not reported",
)

DERIVED = "derived"
"""The reserved property namespace enrichment writes to."""

DEFAULTS_APPLIED = "defaults_applied"

# Formats whose parsers omit provider defaults; plan JSON materialises them
DEFAULT_FORMATS: frozenset[str] = frozenset({"terraform_hcl", "cloudformation"})

# Resource types are matched exactly, or by prefix when the entry ends with '*'
_SEPARATOR = "::"
_REFERENCE_ROOTS = ("var.", "local.", "module.", "data.", "each.", "count.", "self.", "path.")
# A CloudFormation `Ref` (`Name`) or `Fn::GetAtt` (`Name.Attribute`) target: logical ids are
# alphanumeric
_CFN_LOGICAL_REFERENCE = re.compile(r"^[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*$")
_RESOURCE_LIKE = re.compile(r"^[a-z][a-z0-9]*_[a-z0-9_]+(\[[^\]]*\])?\.[A-Za-z_]")
# Properties a literal link value is compared with on a candidate parent
LITERAL_KEYS: tuple[str, ...] = (
    "id",
    "name",
    "bucket",
    "arn",
    "dataset_id",
    "function_name",
    "secret_id",
    "role_name",
)


def type_matcher(entry: str) -> TypeMatcher:
    """Exact match, or prefix match for an entry that ends with '*'."""
    if entry.endswith("*"):
        prefix = entry[:-1]
        return lambda candidate: candidate.startswith(prefix)
    return lambda candidate: candidate == entry


def types_matcher(entries: Iterable[str]) -> TypeMatcher:
    matchers = [type_matcher(e) for e in entries]
    return lambda candidate: any(m(candidate) for m in matchers)


# ---------------------------------------------------------------------------
# Specs
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class CompanionSpec:
    """A resource that configures another resource.

    ``parent_type`` may end with '*'.
    ``link_attrs`` name the companion attributes that point at the parent (the first one present
    is used, a list value links several parents).
    ``derive(companion, parent, ctx)`` returns the derived facts this companion contributes to
    the parent.
    ``absent`` is what the parent's keys hold when no companion links to it; its keys are also the
    keys marked Unknown when the companion's link cannot be resolved, unless ``touches`` narrows
    them for one companion.
    ``additive`` says the keys are lists to which a companion can only add entries, never take
    one away or replace the others (the ingress rules of a security group): an unresolved
    companion then adds one Unknown entry instead of making the whole list Unknown, so an entry
    the scan does know still decides a rule that fires on it.
    """

    parent_type: str
    companion_type: str
    link_attrs: tuple[str, ...]
    derive: Callable[[InfraNode, InfraNode, EnrichContext], Mapping[str, Any]]
    absent: Mapping[str, Any] = field(default_factory=dict)
    touches: Callable[[InfraNode], Iterable[str]] | None = None
    # False for a companion that does not configure this parent (a flow log of a subnet)
    applies: Callable[[InfraNode], bool] | None = None
    additive: bool = False


@dataclass(frozen=True)
class Deriver:
    """Facts computed from one node alone, for every node whose type matches."""

    resource_types: tuple[str, ...]
    derive: Callable[[InfraNode, EnrichContext], Mapping[str, Any]]


@dataclass(frozen=True)
class RelationSpec:
    """Facts a node inherits from the node an attribute points at.

    ``link_attrs`` on a source of ``source_types`` name a ``target_type`` node, optionally one
    hop further: when ``hop_attrs`` is set the target's own ``hop_attrs`` name a ``hop_type`` node
    and that node is the one ``derive`` receives (an instance names a profile, the profile names a
    role).
    ``derive(targets, ctx)`` gets every resolved node.
    A source that has none of the link attributes names nothing, unless ``required`` says the
    attribute is mandatory, in which case its absence means a computed value and is Unknown.
    ``absent`` is written when the link attributes are present but name nothing (a null), and its
    keys are marked Unknown when the link cannot be resolved; a source with none of the link
    attributes gets no derived keys at all, unless the spec is ``required``.
    """

    source_types: tuple[str, ...]
    link_attrs: tuple[str, ...]
    target_type: str
    derive: Callable[[Sequence[InfraNode], EnrichContext], Mapping[str, Any]]
    absent: Mapping[str, Any] = field(default_factory=dict)
    hop_attrs: tuple[str, ...] = ()
    hop_type: str = ""
    # True when the link attribute is mandatory on the source, so an absent one means the value
    # is computed (plan JSON omits it) and the result is Unknown instead of "no link"
    required: bool = False


@dataclass(frozen=True)
class LinkResult:
    """What a link attribute resolved to."""

    resolved: tuple[InfraNode, ...] = ()
    # True when some value could not be resolved, so any candidate might be the target
    unresolved: bool = False
    # The reference text of the first unresolved value, for the Unknown marker
    reference: str = ""
    # False when the node has none of the link attributes at all
    present: bool = True
    # True when some value names something that is not a candidate (an external role ARN, a
    # resource of another type): it links to nothing here, but it is not "nothing"
    orphan: bool = False


# ---------------------------------------------------------------------------
# Values
# ---------------------------------------------------------------------------


def as_list(value: Any) -> list[Any]:
    """A value as a list: a list stays, None is empty, anything else is one item."""
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return list(value)
    return [value]


def blocks(value: Any) -> list[dict[str, Any]]:
    """The mapping items of a nested block, which HCL and plan JSON give as a list."""
    return [item for item in as_list(value) if isinstance(item, dict)]


def block(properties: Mapping[str, Any], name: str) -> dict[str, Any]:
    """The first block named ``name``, or an empty mapping."""
    found = blocks(properties.get(name))
    return found[0] if found else {}


def tri_bool(value: Any) -> bool | Unknown | None:
    """A bool, the strings 'true'/'false', an Unknown as itself, anything else None."""
    if is_unknown(value):
        return value
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in ("true", "false"):
            return lowered == "true"
    return None


def text(value: Any) -> str | Unknown | None:
    """A non-empty string, an Unknown as itself, anything else None."""
    if is_unknown(value):
        return value
    if isinstance(value, str) and value:
        return value
    return None


def merge_value(old: Any, new: Any) -> Any:
    """Combine two contributions to one derived key; see the module docstring."""
    old_unknown, new_unknown = is_unknown(old), is_unknown(new)
    if old_unknown or new_unknown:
        if old is True or new is True:
            return True
        return old if old_unknown else new
    if old is None:
        return copy.deepcopy(new)
    if new is None:
        return old
    if isinstance(old, bool) and isinstance(new, bool):
        return old or new
    if isinstance(old, list) and isinstance(new, list):
        seen = {repr(item) for item in old}
        merged = list(old)
        for item in new:
            marker = repr(item)
            if marker not in seen:
                seen.add(marker)
                merged.append(copy.deepcopy(item))
        return merged
    if isinstance(old, dict) and isinstance(new, dict):
        combined = dict(old)
        for key, value in new.items():
            combined[key] = merge_value(combined.get(key), value)
        return combined
    return old


# ---------------------------------------------------------------------------
# Context
# ---------------------------------------------------------------------------


def _unit_prefix(node_id: str) -> str:
    """The unit label the graph put in front of a colliding address, or ''."""
    head, separator, _ = node_id.partition(_SEPARATOR)
    return head if separator else ""


class EnrichContext:
    """The graph, the enrichable nodes and reference resolution scoped to a node's input."""

    def __init__(self, graph: InfraGraph, index: ReferenceIndex) -> None:
        self.graph = graph
        self._index = index
        self.nodes: list[InfraNode] = [
            node
            for _node_id, node in sorted(graph.nodes.items())
            if node.evidence == "config" and node.mode == "managed"
        ]
        self._by_type: dict[str, list[InfraNode]] = {}
        for node in self.nodes:
            self._by_type.setdefault(node.resource_type, []).append(node)
        self._scoped: dict[str, ReferenceIndex] = {}
        self._by_prefix: dict[str, dict[str, InfraNode]] = {}
        self._unit_indexes: dict[str, ReferenceIndex] = {}
        self._unit_members: dict[str, dict[str, InfraNode]] | None = None
        # Candidate lists and literal indexes are built once per (unit, type set) and reused,
        # so a companion's literal link is an O(1) lookup instead of a scan of every parent.
        self._groups: dict[str, dict[str, list[InfraNode]]] = {}
        self._peer_cache: dict[tuple[str | None, tuple[str, ...]], tuple[InfraNode, ...]] = {}
        self._same_input_cache: dict[tuple[str, tuple[str, ...]], tuple[InfraNode, ...]] = {}
        self._literal_cache: dict[
            tuple[str, tuple[str, ...], tuple[str, ...]], dict[str, list[InfraNode]]
        ] = {}
        self._expression_cache: dict[
            tuple[str, tuple[str, ...], tuple[str, ...]], dict[tuple[str, str], list[InfraNode]]
        ] = {}
        for node in self.nodes:
            prefix = _unit_prefix(node.id)
            if prefix:
                self._by_prefix.setdefault(prefix, {})[node.id[len(prefix) + 2 :]] = node

    def unit_of(self, node: InfraNode) -> str | None:
        """The label of the input `node` came from, None when the graph does not record it."""
        units = getattr(self.graph, "node_units", None)
        if isinstance(units, Mapping):
            found = units.get(node.id)
            return found if isinstance(found, str) else None
        return None

    def same_input(self, first: InfraNode, second: InfraNode) -> bool:
        """Whether two nodes come from one input; true when the graph cannot tell."""
        a, b = self.unit_of(first), self.unit_of(second)
        return a is None or b is None or a == b

    def _members_of(self, unit: str) -> dict[str, InfraNode]:
        """Every node of one input keyed the way that input writes its addresses."""
        if self._unit_members is None:
            members: dict[str, dict[str, InfraNode]] = {}
            units = getattr(self.graph, "node_units", {})
            for node_id, node in self.graph.nodes.items():
                label = units.get(node_id)
                if label is None:
                    continue
                marker = f"{label}{_SEPARATOR}"
                key = node_id[len(marker) :] if node_id.startswith(marker) else node_id
                members.setdefault(label, {})[key] = node
            self._unit_members = members
        return self._unit_members.get(unit, {})

    def index_for(self, node: InfraNode) -> ReferenceIndex:
        """A reference index over the input of `node`, keyed the way that input writes references.

        A reference never names a resource of another input: a CloudFormation `Ref` is a logical
        id of its own template, and a Terraform expression names its own module.
        Two inputs can hold the same address (the graph then qualifies both), and one holding a
        unique logical id must not satisfy a `Ref` in another that means a parameter.
        A graph that does not record the input of its nodes falls back to the shared index, and
        to one index per qualifying label for the nodes the graph qualified.
        """
        unit = self.unit_of(node)
        if unit is not None:
            if unit not in self._unit_indexes:
                self._unit_indexes[unit] = ReferenceIndex(self._members_of(unit))
            return self._unit_indexes[unit]
        prefix = _unit_prefix(node.id)
        if not prefix:
            return self._index
        if prefix not in self._scoped:
            self._scoped[prefix] = ReferenceIndex(self._by_prefix[prefix])
        return self._scoped[prefix]

    def resolve(self, node: InfraNode, raw: Any, matcher: TypeMatcher) -> Resolution:
        return self.index_for(node).resolve_detailed(raw, node.module, required_type=matcher)

    def _matching_types(self, matcher: TypeMatcher) -> tuple[str, ...]:
        return tuple(t for t in self._by_type if matcher(t))

    def _group(self, prefix: str, resource_type: str) -> list[InfraNode]:
        """Enrichable nodes of one type that belong to the unit labelled `prefix`."""
        if prefix not in self._groups:
            by_type: dict[str, list[InfraNode]] = {}
            for node in self.nodes:
                if _unit_prefix(node.id) == prefix:
                    by_type.setdefault(node.resource_type, []).append(node)
            self._groups[prefix] = by_type
        return self._groups[prefix].get(resource_type, [])

    def peers(
        self, node: InfraNode, matcher: TypeMatcher, *, any_input: bool = False
    ) -> Sequence[InfraNode]:
        """Enrichable nodes of the same input as `node` whose type matches.

        With ``any_input`` the nodes of every input.
        A graph that records the input of each node (``graph.node_units``) gives the exact
        answer.
        One that does not can only go by the label prefix the graph puts on colliding addresses,
        which says nothing about the unqualified nodes of an input, so a scope that cannot be
        told apart there is every unqualified node.
        The result is cached per input and set of matching types, and must not be modified.
        """
        if any_input:
            return self._peers_of(None, matcher)
        unit = self.unit_of(node)
        if unit is not None:
            return self._same_input_peers(unit, matcher)
        return self._peers_of(_unit_prefix(node.id), matcher)

    def _same_input_peers(self, unit: str, matcher: TypeMatcher) -> tuple[InfraNode, ...]:
        types = self._matching_types(matcher)
        key = (unit, types)
        found = self._same_input_cache.get(key)
        if found is None:
            found = tuple(n for t in types for n in self._by_type[t] if self.unit_of(n) == unit)
            self._same_input_cache[key] = found
        return found

    def _peers_of(self, prefix: str | None, matcher: TypeMatcher) -> tuple[InfraNode, ...]:
        types = self._matching_types(matcher)
        key = (prefix, types)
        found = self._peer_cache.get(key)
        if found is None:
            if prefix is None:
                found = tuple(n for t in types for n in self._by_type[t])
            else:
                found = tuple(n for t in types for n in self._group(prefix, t))
            self._peer_cache[key] = found
        return found

    def _literal_index(
        self, prefix: str, resource_type: str, keys: tuple[str, ...]
    ) -> dict[str, list[InfraNode]]:
        """For one unit and type: literal value of any of `keys` -> the nodes carrying it."""
        cache_key = (prefix, (resource_type,), keys)
        index = self._literal_cache.get(cache_key)
        if index is None:
            index = {}
            for candidate in self._group(prefix, resource_type):
                seen: set[str] = set()
                for key in keys:
                    value = candidate.properties.get(key)
                    if isinstance(value, str) and not is_unknown(value) and value not in seen:
                        seen.add(value)
                        index.setdefault(value, []).append(candidate)
            self._literal_cache[cache_key] = index
        return index

    def literal_hits(
        self, node: InfraNode, literal: str, matcher: TypeMatcher, keys: Sequence[str]
    ) -> list[InfraNode]:
        """Peers of `node` whose id, name or ARN (any of `keys`) equals `literal`."""
        prefix = _unit_prefix(node.id)
        key_tuple = tuple(keys)
        hits: list[InfraNode] = []
        for resource_type in self._matching_types(matcher):
            hits.extend(self._literal_index(prefix, resource_type, key_tuple).get(literal, ()))
        return hits

    def expression_hits(
        self, node: InfraNode, reference: str, matcher: TypeMatcher, keys: Sequence[str]
    ) -> list[InfraNode]:
        """Peers of `node` that state their name with the very expression `reference` is.

        A bucket named ``!Sub "${AppName}-data"`` and a policy that points at the bucket named
        ``!Sub "${AppName}-data"`` name one bucket, though the scan cannot compute the name:
        the same expression in one input and one module has one value, and bucket names are
        unique.
        Two nodes of different modules are not matched, because a module's variables can hold a
        different value in each call.
        """
        unit = self.unit_of(node)
        if unit is None:
            return []
        key_tuple = tuple(keys)
        hits: list[InfraNode] = []
        for resource_type in self._matching_types(matcher):
            cache_key = (unit, (resource_type,), key_tuple)
            index = self._expression_cache.get(cache_key)
            if index is None:
                index = {}
                for candidate in self._same_input_peers(unit, type_matcher(resource_type)):
                    for key in key_tuple:
                        value = candidate.properties.get(key)
                        if is_unknown(value) and value.reference:
                            entry = index.setdefault((candidate.module, value.reference), [])
                            if candidate not in entry:
                                entry.append(candidate)
                self._expression_cache[cache_key] = index
            hits.extend(index.get((node.module, reference), ()))
        return hits

    def contribute(self, node: InfraNode, values: Mapping[str, Any]) -> None:
        derived = node.properties.get(DERIVED)
        if not isinstance(derived, dict):
            derived = {}
            node.properties[DERIVED] = derived
        for key, value in values.items():
            derived[key] = merge_value(derived.get(key), value)

    def derived(self, node: InfraNode) -> dict[str, Any]:
        found = node.properties.get(DERIVED)
        return found if isinstance(found, dict) else {}

    def resolve_link(
        self,
        node: InfraNode,
        link_attrs: Sequence[str],
        matcher: TypeMatcher,
        *,
        literal_keys: Sequence[str] = LITERAL_KEYS,
    ) -> LinkResult:
        """Find the nodes of the matching type that `node` points at through `link_attrs`.

        Each value is tried as a reference (an HCL expression, a CloudFormation intrinsic or the
        reference an Unknown carries), then as a literal id, name or ARN of exactly one candidate.
        A literal that names no candidate is an orphan and resolves to nothing without being
        unresolved; everything that might name a candidate but cannot be decided is unresolved.
        An absent link attribute is unresolved too: plan JSON omits values that are only known
        after apply.
        """
        values: list[Any] = []
        present = False
        for attr in link_attrs:
            if attr in node.properties:
                present = True
                values.extend(as_list(node.properties[attr]))
        if not present:
            return LinkResult(unresolved=True, present=False)
        resolved: dict[str, InfraNode] = {}
        unresolved = False
        orphan = False
        reference = ""
        for value in values:
            found, status, ref = self._resolve_value(node, value, matcher, literal_keys)
            for target in found:
                resolved.setdefault(target.id, target)
            if status == "unresolved" and not unresolved:
                unresolved, reference = True, ref
            elif status == "orphan":
                orphan = True
        targets = tuple(resolved[k] for k in sorted(resolved))
        return LinkResult(targets, unresolved, reference, orphan=orphan)

    def _resolve_value(
        self,
        node: InfraNode,
        value: Any,
        matcher: TypeMatcher,
        literal_keys: Sequence[str],
    ) -> tuple[list[InfraNode], str, str]:
        """Return (nodes, status, reference) with status 'ok', 'orphan', 'unresolved' or 'none'."""
        if is_unknown(value):
            if not value.reference:
                return [], "unresolved", ""
            # The reference an Unknown carries is a reference by construction, so even a bare
            # word (a CloudFormation `Ref` to a logical id) goes through the index of its input
            return self._resolve_reference(node, value.reference, matcher, literal_keys)
        if not isinstance(value, (str, dict)):
            return [], "none", ""
        label = value if isinstance(value, str) else ""
        # A plain word is a literal name or id. Sent through the index it would be matched to a
        # node's label, which is a guess: a bucket named "logs" is not the resource labelled logs
        plain = isinstance(value, str) and "." not in value and "${" not in value
        if not plain:
            decided = self._through_index(node, value, label, matcher)
            if decided is not None:
                return decided
        if isinstance(value, str) and "${" not in value:
            hits = self.literal_hits(node, value, matcher, literal_keys)
            if len(hits) == 1:
                return hits, "ok", label
            if len(hits) > 1:
                return [], "unresolved", label
            if not _looks_like_reference(value):
                return [], "orphan", label
        return [], "unresolved", label

    def _through_index(
        self, node: InfraNode, raw: Any, label: str, matcher: TypeMatcher
    ) -> tuple[list[InfraNode], str, str] | None:
        """The verdict of the reference index of the node's input, None when it has none."""
        resolution = self.resolve(node, raw, matcher)
        if resolution.ids:
            return [self.graph.nodes[i] for i in resolution.ids], "ok", label
        if resolution.ambiguous:
            return [], "unresolved", label
        if resolution.rejected:
            return [], "orphan", label
        return None

    def _resolve_reference(
        self, node: InfraNode, reference: str, matcher: TypeMatcher, literal_keys: Sequence[str]
    ) -> tuple[list[InfraNode], str, str]:
        """Resolve the reference an Unknown carries: the index, then the template, then a name."""
        decided = self._through_index(node, reference, reference, matcher)
        if decided is not None:
            return decided
        if self._names_outside_template(node, reference):
            return [], "orphan", reference
        hits = self.expression_hits(node, reference, matcher, literal_keys)
        if len(hits) == 1:
            return hits, "ok", reference
        return [], "unresolved", reference

    def _names_outside_template(self, node: InfraNode, reference: str) -> bool:
        """Whether an unresolved CloudFormation reference names something outside its template.

        A `Ref` or `Fn::GetAtt` target is a logical id of the template itself, and one that is
        not a resource of it is a parameter, whose value comes from outside; `Fn::ImportValue`
        names an export of another stack by definition.
        Neither can be the parent of a companion of the same template, so they are not candidates
        for it and nothing is left unknown on their account.
        """
        formats = getattr(self.graph, "node_formats", None)
        if not isinstance(formats, Mapping) or formats.get(node.id) != "cloudformation":
            return False
        return bool(_CFN_LOGICAL_REFERENCE.match(reference)) or reference.startswith(
            "Fn::ImportValue"
        )


def _excluding(matcher: TypeMatcher, excluded: str) -> TypeMatcher:
    return lambda candidate: candidate != excluded and matcher(candidate)


def _looks_like_reference(value: str) -> bool:
    return value.startswith(_REFERENCE_ROOTS) or bool(_RESOURCE_LIKE.match(value))


# ---------------------------------------------------------------------------
# What a module produces
# ---------------------------------------------------------------------------

Produced = Mapping[str, frozenset[str]]


def produced(types: Iterable[str], *facts: str) -> dict[str, frozenset[str]]:
    """A ``PRODUCED`` table: each of ``types`` carries ``derived.<fact>`` for every fact."""
    names = frozenset(f"{DERIVED}.{fact}" for fact in facts)
    return dict.fromkeys(types, names)


def produced_by_companions(specs: Iterable[CompanionSpec]) -> dict[str, frozenset[str]]:
    """The facts the companion specs give their parents: the keys of each ``absent``."""
    table: dict[str, frozenset[str]] = {}
    for spec in specs:
        facts = frozenset(f"{DERIVED}.{key}" for key in spec.absent)
        table[spec.parent_type] = table.get(spec.parent_type, frozenset()) | facts
    return table


def produced_by_relations(specs: Iterable[RelationSpec]) -> dict[str, frozenset[str]]:
    """The facts the relation specs give their sources: the keys of each ``absent``."""
    table: dict[str, frozenset[str]] = {}
    for spec in specs:
        facts = frozenset(f"{DERIVED}.{key}" for key in spec.absent)
        for source_type in spec.source_types:
            table[source_type] = table.get(source_type, frozenset()) | facts
    return table


def merge_produced(*tables: Mapping[str, Iterable[str]]) -> Produced:
    """Union ``PRODUCED`` tables: a type named in several gets the union of its facts."""
    merged: dict[str, frozenset[str]] = {}
    for table in tables:
        for resource_type, names in table.items():
            merged[resource_type] = merged.get(resource_type, frozenset()) | frozenset(names)
    return MappingProxyType(merged)


# Written by the defaults phase below, on whichever type has a ``DEFAULTS`` table
PRODUCED: Produced = MappingProxyType({"*": frozenset({f"{DERIVED}.{DEFAULTS_APPLIED}"})})


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------


def apply_defaults(node: InfraNode, table: Mapping[str, Mapping[str, Any]]) -> list[str]:
    """Fill the absent attributes `table` lists for the node's type; return the paths filled.

    ``a.b`` fills ``b`` in every block ``a`` that exists and lacks it, and nothing when ``a`` is
    missing.
    A present value, including an Unknown, is never replaced.
    The caller decides whether the node's format may be defaulted at all.
    """
    defaults = table.get(node.resource_type)
    if not defaults:
        return []
    filled: list[str] = []
    for path in sorted(defaults):
        segments = path.split(".")
        parents: list[dict[str, Any]] = [node.properties]
        for segment in segments[:-1]:
            parents = [b for p in parents for b in blocks(p.get(segment))]
        changed = False
        for parent in parents:
            if segments[-1] not in parent:
                parent[segments[-1]] = copy.deepcopy(defaults[path])
                changed = True
        if changed:
            filled.append(path)
    return filled


def _node_format(graph: InfraGraph, node: InfraNode) -> str | None:
    formats = getattr(graph, "node_formats", None)
    if isinstance(formats, Mapping):
        found = formats.get(node.id)
        return found if isinstance(found, str) else None
    return None


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------


def enrichment_modules() -> list[ModuleType]:
    """Every module of `threatcode.ir.enrichment`, in sorted name order."""
    package = importlib.import_module("threatcode.ir.enrichment")
    names = sorted(
        m.name for m in pkgutil.iter_modules(package.__path__) if not m.name.startswith("_")
    )
    return [importlib.import_module(f"{package.__name__}.{name}") for name in names]


def enrich(graph: InfraGraph, index: ReferenceIndex) -> None:
    """Add context to the nodes of a built graph; see the module docstring."""
    ctx = EnrichContext(graph, index)
    for node in graph.nodes.values():
        node.properties.pop(DERIVED, None)
    modules = enrichment_modules()
    _run_defaults(ctx, modules)
    _run_companions(ctx, modules)
    _run_derivers(ctx, modules)
    _run_relations(ctx, modules)


def _run_defaults(ctx: EnrichContext, modules: Sequence[ModuleType]) -> None:
    for module in modules:
        table: Mapping[str, Mapping[str, Any]] = getattr(module, "DEFAULTS", {})
        if not table:
            continue
        for node in ctx.nodes:
            if _node_format(ctx.graph, node) not in DEFAULT_FORMATS:
                continue
            filled = apply_defaults(node, table)
            if filled:
                ctx.contribute(node, {DEFAULTS_APPLIED: filled})


def _run_companions(ctx: EnrichContext, modules: Sequence[ModuleType]) -> None:
    specs: list[CompanionSpec] = []
    for module in modules:
        specs.extend(getattr(module, "COMPANIONS", ()))
    for spec in specs:
        parent_matcher = type_matcher(spec.parent_type)
        parents = [n for n in ctx.nodes if parent_matcher(n.resource_type)]
        for parent in parents:
            if parent.resource_type != spec.companion_type and spec.absent:
                ctx.contribute(parent, spec.absent)
    for spec in specs:
        parent_matcher = type_matcher(spec.parent_type)
        parent_only = _excluding(parent_matcher, spec.companion_type)
        for companion in ctx.nodes:
            if companion.resource_type != spec.companion_type:
                continue
            if spec.applies is not None and not spec.applies(companion):
                continue
            link = ctx.resolve_link(companion, spec.link_attrs, parent_only)
            for parent in link.resolved:
                ctx.contribute(parent, spec.derive(companion, parent, ctx))
            if link.unresolved:
                _mark_unresolved(ctx, spec, companion, link)


def _mark_unresolved(
    ctx: EnrichContext, spec: CompanionSpec, companion: InfraNode, link: LinkResult
) -> None:
    """Record that a companion whose parent cannot be found might configure any candidate.

    The candidates are the matching parents of the companion's own input.
    A list that a companion can only add to takes one Unknown entry, and any other fact becomes
    Unknown, which a rule treats as neither passed nor failed.
    The mark is reported as a coverage gap, once per companion, so a finding that this
    suppresses is visible in every output and `--strict` counts it.
    """
    keys = tuple(spec.touches(companion)) if spec.touches else tuple(spec.absent)
    parent_only = _excluding(type_matcher(spec.parent_type), spec.companion_type)
    candidates = ctx.peers(companion, parent_only)
    if not keys or not candidates:
        return
    unknown = Unknown(link.reference)
    marker = {key: [unknown] if spec.additive else unknown for key in keys}
    for candidate in candidates:
        ctx.contribute(candidate, marker)
    through = f"through '{link.reference}'" if link.reference else "through an expression"
    parent_types = _and_list({c.resource_type for c in candidates})
    if len(candidates) == 1:
        scope = f"the {parent_types} resource"
    else:
        scope = f"any of the {len(candidates)} {parent_types} resources"
    effect = (
        f"it might add entries to {_and_list(keys)} that this scan cannot see"
        if spec.additive
        else f"findings that rest on {_and_list(keys)} being unset are not reported for them"
    )
    ctx.graph.diagnostics.append(
        Diagnostic(
            "warning",
            "enrich.unresolved_companion",
            f"{companion.resource_type} '{companion.id}' points at its target {through}, which "
            f"this scan cannot resolve, so it might configure {scope} of this input; {effect}",
            companion.source_file,
            companion.start_line,
        )
    )


def _and_list(items: Iterable[str]) -> str:
    return ", ".join(sorted(items))


def _run_derivers(ctx: EnrichContext, modules: Sequence[ModuleType]) -> None:
    for module in modules:
        for deriver in getattr(module, "DERIVERS", ()):
            matcher = types_matcher(deriver.resource_types)
            for node in ctx.nodes:
                if matcher(node.resource_type):
                    values = deriver.derive(node, ctx)
                    if values:
                        ctx.contribute(node, values)


def _run_relations(ctx: EnrichContext, modules: Sequence[ModuleType]) -> None:
    for module in modules:
        for spec in getattr(module, "RELATIONS", ()):
            _apply_relation(ctx, spec)


def _apply_relation(ctx: EnrichContext, spec: RelationSpec) -> None:
    source_matcher = types_matcher(spec.source_types)
    for source in ctx.nodes:
        if not source_matcher(source.resource_type):
            continue
        link = ctx.resolve_link(source, spec.link_attrs, type_matcher(spec.target_type))
        targets: list[InfraNode] = list(link.resolved)
        # A source that does not carry the link at all names nothing (no role, no profile)
        # An orphan is a role (or profile) outside the graph, whose policies are not known
        unresolved = (link.unresolved and (link.present or spec.required)) or link.orphan
        reference = link.reference
        if spec.hop_attrs:
            hopped: dict[str, InfraNode] = {}
            for middle in targets:
                second = ctx.resolve_link(middle, spec.hop_attrs, type_matcher(spec.hop_type))
                for found in second.resolved:
                    hopped.setdefault(found.id, found)
                if (second.unresolved and second.present or second.orphan) and not unresolved:
                    unresolved, reference = True, second.reference
            targets = [hopped[k] for k in sorted(hopped)]
        values: dict[str, Any] = {}
        if targets:
            values = dict(spec.derive(targets, ctx))
        elif not unresolved and link.present:
            values = dict(spec.absent)
        if unresolved:
            for key in spec.absent:
                values[key] = merge_value(values.get(key), Unknown(reference))
        if values:
            ctx.contribute(source, values)
