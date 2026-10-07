"""Resolving the references a parser found to the graph nodes they name.

A parser records what a resource refers to as raw reference strings
(`ParsedResource.references`, `ParsedResource.dependencies`).
`ReferenceIndex.resolve` turns one of them into the ids of the nodes it names.

Resolution only ever finds nodes that exist, and it never guesses:

- An exact id wins (`aws_vpc.main`, or `aws_instance.app[1]` when that node exists).
- A trailing attribute is removed by the longest prefix that is a known id, so
  `aws_vpc.main.id` finds `aws_vpc.main`.
- Indexes are stripped when no node has the exact index, so `aws_instance.app`
  and `aws_instance.app[0].id` resolve to every instance of a counted resource.
- An unqualified reference resolves inside the referring module first
  (`module.net.aws_vpc.main` for `aws_vpc.main` written in `module.net`), then
  as written.
- An HCL string such as `"${aws_subnet.a.id}-${aws_vpc.main.id}"` yields every
  reference inside its `${...}` parts.
- `var.`, `local.`, `each.`, `count.`, `self.`, `path.` and `terraform.` roots
  name no node, and neither does anything that matches no node.
- A bare name matches `node.name` only when the caller says which type of node
  it needs and exactly one node of that type has the name.
  Several candidates are reported as ambiguous, with no match.

CloudFormation intrinsics are accepted as well: `{"Ref": X}`,
`{"Fn::GetAtt": [X, attr]}`, `{"Fn::Sub": "...${X}..."}` and `{"Fn::Join": ...}`.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from threatcode.ir.addressing import base_address, components

if TYPE_CHECKING:
    from threatcode.ir.nodes import InfraNode

TypeMatcher = Callable[[str], bool]

# Roots of expressions that name something other than a resource
UNRESOLVABLE_ROOTS: frozenset[str] = frozenset(
    {"var", "local", "each", "count", "self", "path", "terraform"}
)

_MAX_DEPTH = 20
_IDENT = r"[A-Za-z_][A-Za-z0-9_\-]*"
_INDEX = r"\[[^\]]*\]"
_TOKEN = re.compile(rf"(?<![\w.\]\-]){_IDENT}(?:{_INDEX})*(?:\.{_IDENT}(?:{_INDEX})*)*")
_BARE = re.compile(rf"^{_IDENT}$")
_INTERPOLATION = re.compile(r"\$\{([^}]*)\}")
_SUB_PLACEHOLDER = re.compile(r"\$\{([^}!]+)\}")


def type_is(resource_type: str) -> TypeMatcher:
    """Match exactly one resource type."""
    return lambda candidate: candidate == resource_type


def type_endswith(suffix: str) -> TypeMatcher:
    """Match every resource type that ends with `suffix`."""
    return lambda candidate: candidate.endswith(suffix)


def type_contains(part: str) -> TypeMatcher:
    """Match every resource type that contains `part`."""
    return lambda candidate: part in candidate


@dataclass(frozen=True)
class Resolution:
    """What a raw reference resolved to."""

    ids: tuple[str, ...] = ()
    # Node ids a bare name matched when more than one node of the type has it
    ambiguous: tuple[str, ...] = ()
    # Node ids the reference named whose type is not the required one
    rejected: tuple[str, ...] = ()


class ReferenceIndex:
    """Looks up the nodes a reference names.

    `nodes` maps the address a reference is written against to its node.
    Resolution returns `node.id`, which is the same string unless the graph
    renamed the node (a duplicate or a colliding address from another unit).
    """

    def __init__(self, nodes: Mapping[str, InfraNode]) -> None:
        self._id_by_key: dict[str, str] = {}
        self._ids_by_base: dict[str, list[str]] = {}
        self._nodes_by_name: dict[str, list[InfraNode]] = {}
        self._type_by_id: dict[str, str] = {}
        for key, node in nodes.items():
            self._id_by_key[key] = node.id
            self._type_by_id[node.id] = node.resource_type
            self._ids_by_base.setdefault(base_address(key), []).append(node.id)
            if node.name:
                self._nodes_by_name.setdefault(node.name, []).append(node)

    def resolve(
        self,
        raw: Any,
        from_module: str = "",
        *,
        required_type: TypeMatcher | None = None,
    ) -> list[str]:
        """Return the ids of the nodes `raw` names, in a stable order."""
        return list(self.resolve_detailed(raw, from_module, required_type=required_type).ids)

    def resolve_detailed(
        self,
        raw: Any,
        from_module: str = "",
        *,
        required_type: TypeMatcher | None = None,
    ) -> Resolution:
        """Like `resolve`, and also report ambiguous and wrong-typed matches."""
        scope = base_address(from_module)
        ids: dict[str, None] = {}
        ambiguous: dict[str, None] = {}
        rejected: dict[str, None] = {}
        for candidate, bare in _candidates(raw):
            found, maybe = self._resolve_candidate(candidate, bare, scope, required_type)
            for node_id in found:
                ids.setdefault(node_id)
            for node_id in maybe:
                ambiguous.setdefault(node_id)
        if required_type is not None:
            kept: dict[str, None] = {}
            for node_id in ids:
                if required_type(self._type_by_id[node_id]):
                    kept.setdefault(node_id)
                else:
                    rejected.setdefault(node_id)
            ids = kept
        return Resolution(tuple(ids), tuple(ambiguous), tuple(rejected))

    def _resolve_candidate(
        self, candidate: str, bare: bool, scope: str, required_type: TypeMatcher | None
    ) -> tuple[list[str], list[str]]:
        parts = components(candidate)
        if base_address(parts[0]) in UNRESOLVABLE_ROOTS:
            return [], []
        keys = [f"{scope}.{candidate}", candidate] if scope else [candidate]
        for key in keys:
            found = self._match(components(key))
            if found:
                return sorted(found), []
        if bare and required_type is not None:
            return self._match_name(candidate, scope, required_type)
        return [], []

    def _match(self, parts: list[str]) -> list[str]:
        """Match the longest prefix of `parts` that names known nodes."""
        for count in range(len(parts), 0, -1):
            prefix = ".".join(parts[:count])
            node_id = self._id_by_key.get(prefix)
            if node_id is not None:
                return [node_id]
            fan_out = self._ids_by_base.get(base_address(prefix))
            if fan_out:
                return list(fan_out)
        return []

    def _match_name(
        self, name: str, scope: str, required_type: TypeMatcher
    ) -> tuple[list[str], list[str]]:
        """Match a bare name to a node, only when exactly one node of the type has it."""
        named = [n for n in self._nodes_by_name.get(name, []) if required_type(n.resource_type)]
        local = [n for n in named if base_address(n.module) == scope]
        for pool in (local, named):
            if len(pool) == 1:
                return [pool[0].id], []
            if len(pool) > 1:
                return [], sorted(n.id for n in pool)
        return [], []


def _candidates(raw: Any, depth: int = 0) -> list[tuple[str, bool]]:
    """Extract (reference, is_bare_name) candidates from a raw reference value."""
    if depth > _MAX_DEPTH:
        return []
    if isinstance(raw, str):
        return _string_candidates(raw)
    if isinstance(raw, (list, tuple)):
        return [c for item in raw for c in _candidates(item, depth + 1)]
    if isinstance(raw, dict):
        return _intrinsic_candidates(raw, depth)
    return []


def _string_candidates(text: str) -> list[tuple[str, bool]]:
    text = text.strip()
    if not text:
        return []
    if "${" in text:
        found: list[tuple[str, bool]] = []
        for expression in _INTERPOLATION.findall(text):
            # A lone identifier inside ${} is a function or local name, not a node
            found.extend(
                (token, False)
                for token in _TOKEN.findall(expression)
                if "." in token or "[" in token
            )
        return found
    if _BARE.match(text):
        return [(text, True)]
    return [(token, False) for token in _TOKEN.findall(text) if "." in token or "[" in token]


def _intrinsic_candidates(value: dict[Any, Any], depth: int) -> list[tuple[str, bool]]:
    if "Ref" in value:
        ref = value["Ref"]
        return [(ref.strip(), True)] if isinstance(ref, str) and _is_logical_id(ref) else []
    if "Fn::GetAtt" in value:
        target = value["Fn::GetAtt"]
        if isinstance(target, (list, tuple)) and target:
            target = target[0]
        elif isinstance(target, str):
            target = target.split(".", 1)[0]
        return [(target, True)] if isinstance(target, str) and _is_logical_id(target) else []
    if "Fn::Sub" in value:
        template = value["Fn::Sub"]
        if isinstance(template, (list, tuple)) and template:
            template = template[0]
        if not isinstance(template, str):
            return []
        names = (placeholder.split(".", 1)[0] for placeholder in _SUB_PLACEHOLDER.findall(template))
        return [(name, True) for name in names if _is_logical_id(name)]
    return [c for item in value.values() for c in _candidates(item, depth + 1)]


def _is_logical_id(text: str) -> bool:
    # CloudFormation pseudo parameters such as AWS::Region are not resources
    return bool(text) and "::" not in text and text.isalnum()
