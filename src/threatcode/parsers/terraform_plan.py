"""Terraform plan JSON parser (primary input format).

``terraform show -json PLANFILE`` holds three views of the same infrastructure, and the parser
reads each for what it is good at:

- ``planned_values`` lists every resource instance the plan leaves behind, with the values
  that are known now.
  A counted or ``for_each`` resource has one entry per instance (``aws_instance.app[0]``),
  and a module call has one ``child_modules`` entry per instance (``module.net[1]``).
- ``resource_changes[].change.after_unknown`` marks, with booleans that mirror the attribute
  shape, the values that only exist after apply.
  A planned value is left out for those, so a rule that reads the plain value would see
  "not configured" where the truth is "configured, not known yet".
  The parser puts an ``Unknown`` at each of those paths instead.
- ``configuration`` holds the expressions as written, with the references they contain.
  It is the source of truth for relationships: it says that a subnet's ``vpc_id`` comes from
  ``aws_vpc.main``, which a planned value cannot say when the id is unknown.
  It has one entry per resource, not per instance, and its references are relative to the
  module they are written in.

A reference is turned into planned addresses in four steps.
A reference to a module input (``var.vpc_id``) is replaced by the expression the parent module
call passes for it, and a reference to a module output (``module.net.subnet_id``) by the
expression inside the child module that produces it, until a resource is reached.
A reference written inside a module is qualified with the module instance the resource sits in,
so ``module.subnets[1]`` and ``module.subnets[0]`` stay apart.
The attribute suffix is dropped by matching the longest prefix that is a planned address.
A reference without an index to a resource with several instances names every instance.
A reference that matches no planned address is dropped, and nothing is ever bound by name alone.

Security: recursion depth is capped to prevent stack overflow from deeply nested Terraform
modules or unknown-value trees in malicious plan files, and every reference is resolved at most
once per module instance, so a plan cannot make resolution exponential.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.exceptions import ParseError
from threatcode.ir.addressing import base_address, components
from threatcode.parsers._json_lines import json_line_index
from threatcode.parsers._text import decode_input
from threatcode.parsers.base import BaseParser, Mode, ParsedOutput, ParsedResource
from threatcode.values import Unknown

logger = logging.getLogger(__name__)

# Max nesting depth for Terraform module recursion
MAX_MODULE_DEPTH = 50

# Max depth walked in an after_unknown tree or an expression tree
_MAX_TREE_DEPTH = 64

# A reference has a type, a name and at most MAX_MODULE_DEPTH module calls of two parts each,
# plus room for an attribute path; anything longer names nothing
_MAX_REFERENCE_PARTS = 2 * MAX_MODULE_DEPTH + 8

# Max resolved references over a whole plan. A reference to a counted resource without an index
# names every instance, so a hostile plan could otherwise ask for a list per resource that is
# as long as the plan. The graph cannot hold that many edges anyway (MAX_EDGES)
MAX_REFERENCE_ENTRIES = 500_000

register_code(
    "plan.reference_limit",
    "A Terraform plan has more resolved references than the limit, so later ones were dropped",
)

# Reference roots that name something other than a resource
_DROPPED_ROOTS = frozenset({"local", "each", "count", "self", "path", "terraform"})

# Stands for "no value here" while merging, because None is a value a plan can hold
_MISSING: Any = object()


class _PlannedUnknown(Unknown):
    """An Unknown that a plan places, and that is falsy.

    Properties are read by truthiness in places that predate ``Unknown``: the zone heuristic
    treats a set ``associate_public_ip_address`` as a public address, and containment inference
    treats a non-empty ``vpc_id`` as a literal id to look for.
    A value that is not known yet must never count as "set", so it is falsy.
    ``is_unknown`` still recognizes it, which is what the rule matcher uses.
    """

    def __bool__(self) -> bool:
        return False

    def __reduce__(self) -> tuple[type[_PlannedUnknown], tuple[str]]:
        # The inherited reduce rebuilds a plain, truthy Unknown
        return (_PlannedUnknown, (self.reference,))


@dataclass
class _Counter:
    """Counts what a parse produced: unknown values, and resolved references against the limit."""

    unknown: int = 0
    references: int = 0
    unresolved_resources: int = 0


@dataclass(frozen=True)
class _Leaf:
    """One attribute expression found in a resource's configuration."""

    path: str
    references: tuple[str, ...]
    has_constant: bool


@dataclass(frozen=True)
class _Planned:
    """One resource instance of planned_values."""

    address: str
    resource: dict[str, Any]
    pointer: str


def _dicts(value: Any) -> list[dict[str, Any]]:
    """The dictionaries of a list; anything else, or anything in it that is not one, is skipped."""
    if not isinstance(value, list):
        return []
    return [item for item in value if isinstance(item, dict)]


def _unique(items: Iterable[str]) -> list[str]:
    """Drop repeats, keeping the order each item was first seen in."""
    return list(dict.fromkeys(items))


def _join(prefix: str, name: str) -> str:
    return f"{prefix}.{name}" if prefix else name


def _module_instance(address: str) -> str:
    """The module instance path an address sits in, indexes kept, or '' at the root.

    `module.net[1].module.sub["a"].aws_vpc.main` gives `module.net[1].module.sub["a"]`.
    """
    parts = components(address)
    count = 0
    while count + 1 < len(parts) and parts[count] == "module":
        count += 2
    return ".".join(parts[:count])


def _parent_instance(instance: str) -> str:
    """The module instance that contains a module instance."""
    return ".".join(components(instance)[:-2])


def _index_matches(pattern: list[str], candidate: list[str]) -> bool:
    """Whether an address matches a reference that may leave some indexes out.

    A component of the reference that has an index must match exactly, and one without
    stands for every instance, so `aws_instance.app` matches `aws_instance.app[1]` and
    `aws_instance.app[1]` does not match `aws_instance.app[0]`.
    """
    if len(pattern) != len(candidate):
        return False
    return all(
        want == have if "[" in want else base_address(have) == want
        for want, have in zip(pattern, candidate, strict=True)
    )


# ---------------------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------------------


def _is_leaf(expression: dict[str, Any]) -> bool:
    """An attribute expression is `{references: [...]}`, `{constant_value: ...}` or both."""
    return isinstance(expression.get("references"), list) or (
        "constant_value" in expression and set(expression) <= {"constant_value", "references"}
    )


def _leaf_references(expression: dict[str, Any]) -> tuple[str, ...]:
    refs = expression.get("references")
    if not isinstance(refs, list):
        return ()
    return tuple(_unique(ref for ref in refs if isinstance(ref, str) and ref))


def _walk_expressions(expressions: Any) -> list[_Leaf]:
    """Every attribute expression of a resource with the path it is written at.

    A path uses "." for nesting and "[]" for each list level, so the `security_groups` of an
    `ingress` block is `ingress[].security_groups`.
    """
    leaves: list[_Leaf] = []
    if isinstance(expressions, dict):
        for key, value in expressions.items():
            _walk_expression(value, str(key), leaves, 0)
    return leaves


def _walk_expression(expression: Any, path: str, out: list[_Leaf], depth: int) -> None:
    if depth > _MAX_TREE_DEPTH:
        return
    if isinstance(expression, dict):
        if _is_leaf(expression):
            out.append(_Leaf(path, _leaf_references(expression), "constant_value" in expression))
            return
        for key, value in expression.items():
            _walk_expression(value, _join(path, str(key)), out, depth + 1)
    elif isinstance(expression, list):
        for item in expression:
            _walk_expression(item, f"{path}[]", out, depth + 1)


def _flat_references(expression: Any) -> list[str]:
    """Every reference inside an expression, in order, without repeats."""
    found: list[str] = []
    for leaf in _walk_expressions({"_": expression}):
        found.extend(leaf.references)
    return _unique(found)


# ---------------------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------------------


def _local_address(resource: dict[str, Any]) -> str | None:
    """`type.name`, or `data.type.name` for a data source, relative to its module."""
    rtype, name = resource.get("type"), resource.get("name")
    if not isinstance(rtype, str) or not isinstance(name, str) or not rtype or not name:
        return None
    prefix = "data." if resource.get("mode") == "data" else ""
    return f"{prefix}{rtype}.{name}"


class _Config:
    """The `configuration` block, indexed by module name path.

    Keys carry module names without instance indexes: `module.net.aws_subnet.a` for a resource
    and `module.net` for a module call.
    """

    def __init__(self, data: dict[str, Any]) -> None:
        self.resources: dict[str, dict[str, Any]] = {}
        self.calls: dict[str, dict[str, Any]] = {}
        configuration = data.get("configuration")
        if isinstance(configuration, dict):
            self._walk(configuration.get("root_module"), "", 0)

    def _walk(self, module: Any, prefix: str, depth: int) -> None:
        if not isinstance(module, dict):
            return
        if depth > MAX_MODULE_DEPTH:
            logger.warning("Config module nesting depth %d exceeds limit - skipping", depth)
            return
        for resource in _dicts(module.get("resources")):
            local = _local_address(resource)
            if local is not None:
                self.resources.setdefault(_join(prefix, local), resource)
        calls = module.get("module_calls")
        if not isinstance(calls, dict):
            return
        for name, call in calls.items():
            if not isinstance(call, dict):
                continue
            key = _join(prefix, f"module.{name}")
            self.calls.setdefault(key, call)
            self._walk(call.get("module"), key, depth + 1)

    def input_expression(self, module: str, name: str) -> Any:
        """The expression a module call passes for a variable, or None."""
        call = self.calls.get(base_address(module))
        expressions = call.get("expressions") if call else None
        return expressions.get(name) if isinstance(expressions, dict) else None

    def output_expression(self, module: str, name: str) -> Any:
        """The expression inside a module that produces an output, or None."""
        call = self.calls.get(base_address(module))
        child = call.get("module") if call else None
        outputs = child.get("outputs") if isinstance(child, dict) else None
        output = outputs.get(name) if isinstance(outputs, dict) else None
        return output.get("expression") if isinstance(output, dict) else None


# ---------------------------------------------------------------------------------------
# Reference resolution
# ---------------------------------------------------------------------------------------


class _Resolver:
    """Turns a reference written in a module into the planned addresses it names."""

    def __init__(self, addresses: list[str], config: _Config) -> None:
        self._config = config
        self._addresses = set(addresses)
        self._by_base: dict[str, list[tuple[str, list[str]]]] = {}
        self._modules_by_base: dict[str, list[tuple[str, list[str]]]] = {}
        seen_modules: set[str] = set()
        for address in addresses:
            self._by_base.setdefault(base_address(address), []).append(
                (address, components(address))
            )
            parts = components(_module_instance(address))
            # The instance and each ancestor, so a module that only holds other modules counts
            for end in range(2, len(parts) + 1, 2):
                instance = ".".join(parts[:end])
                if instance not in seen_modules:
                    seen_modules.add(instance)
                    self._modules_by_base.setdefault(base_address(instance), []).append(
                        (instance, components(instance))
                    )
        self._memo: dict[tuple[str, str], tuple[str, ...]] = {}
        self._active: set[tuple[str, str]] = set()

    def resolve(self, raw: str, instance: str, depth: int = 0) -> tuple[str, ...]:
        """The planned addresses `raw` names when written in the module instance `instance`."""
        key = (raw, instance)
        cached = self._memo.get(key)
        if cached is not None:
            return cached
        # A reference that leads back to itself, or a chain deeper than any module nesting,
        # names nothing
        if key in self._active or depth > MAX_MODULE_DEPTH:
            return ()
        self._active.add(key)
        try:
            result = tuple(_unique(self._resolve(raw, instance, depth)))
        finally:
            self._active.discard(key)
        self._memo[key] = result
        return result

    def _resolve(self, raw: str, instance: str, depth: int) -> list[str]:
        parts = components(raw)
        if len(parts) > _MAX_REFERENCE_PARTS:
            return []
        root = parts[0]
        if root == "var":
            return self._through_input(parts, instance, depth)
        if root in _DROPPED_ROOTS:
            return []
        if root == "module":
            return self._through_output(parts, instance, depth)
        return self._match([*components(instance), *parts] if instance else parts)

    def _through_input(self, parts: list[str], instance: str, depth: int) -> list[str]:
        """`var.x` inside a module is whatever the parent module call passes for `x`."""
        if not instance or len(parts) < 2:
            return []
        expression = self._config.input_expression(instance, base_address(parts[1]))
        if expression is None:
            return []
        parent = _parent_instance(instance)
        found: list[str] = []
        for reference in _flat_references(expression):
            found.extend(self.resolve(reference, parent, depth + 1))
        return found

    def _through_output(self, parts: list[str], instance: str, depth: int) -> list[str]:
        """`module.net.x` is whatever the expression behind the output `x` of `net` names."""
        count = 0
        while count + 1 < len(parts) and parts[count] == "module":
            count += 2
        rest = parts[count:]
        if not rest:
            # The module as a whole: it names no single resource
            return []
        scope = [*components(instance), *parts[:count]] if instance else parts[:count]
        module = ".".join(scope)
        expression = self._config.output_expression(module, base_address(rest[0]))
        if expression is None:
            # Not an output. A hand-built plan may write a module-qualified resource address
            return self._match([*scope, *rest])
        found: list[str] = []
        references = _flat_references(expression)
        for child in self._module_instances(scope):
            for reference in references:
                found.extend(self.resolve(reference, child, depth + 1))
        return found

    def _module_instances(self, pattern: list[str]) -> list[str]:
        """The planned module instances a module reference names, all of them without an index."""
        candidates = self._modules_by_base.get(base_address(".".join(pattern)), [])
        return [name for name, parts in candidates if _index_matches(pattern, parts)]

    def _match(self, parts: list[str]) -> list[str]:
        """The planned addresses named by the longest prefix of `parts` that names any."""
        for count in range(len(parts), 1, -1):
            prefix = parts[:count]
            joined = ".".join(prefix)
            if joined in self._addresses:
                # Fully indexed, or not counted: exactly one address, found without a scan
                return [joined]
            candidates = self._by_base.get(base_address(joined))
            if not candidates:
                continue
            hits = [addr for addr, comps in candidates if _index_matches(prefix, comps)]
            if hits:
                return hits
        return []


# ---------------------------------------------------------------------------------------
# Unknown values
# ---------------------------------------------------------------------------------------


def _reference_for(path: str, by_path: dict[str, str]) -> str:
    """The reference written for an attribute, or for the closest enclosing one."""
    probe = path
    while probe:
        found = by_path.get(probe)
        if found:
            return found
        if probe.endswith("[]"):
            probe = probe[:-2]
        else:
            probe = probe[: probe.rfind(".")] if "." in probe else ""
    return ""


def _filler(tree: Any) -> Any:
    """What stands in for a list item that was skipped to keep the later items aligned."""
    if isinstance(tree, dict):
        return {}
    if isinstance(tree, list):
        return []
    return None


def _apply_after_unknown(
    current: Any,
    tree: Any,
    path: str,
    references: dict[str, str],
    counter: _Counter,
    depth: int = 0,
) -> Any:
    """Return `current` with an Unknown at each path `tree` marks and `current` has no value for.

    `tree` mirrors the attribute shape with true at each unknown leaf.
    A planned null counts as no value, because Terraform writes null in place of an unknown
    list item.
    Nothing is changed in `current`: the parts that change are copied, the rest is shared.
    The result is `current` itself when nothing changed.
    """
    if depth > _MAX_TREE_DEPTH:
        return current
    if tree is True:
        if current is _MISSING or current is None:
            counter.unknown += 1
            return _PlannedUnknown(_reference_for(path, references))
        return current
    if isinstance(tree, dict) and tree:
        return _apply_unknown_to_mapping(current, tree, path, references, counter, depth)
    if isinstance(tree, list) and tree:
        return _apply_unknown_to_list(current, tree, path, references, counter, depth)
    return current


def _apply_unknown_to_mapping(
    current: Any,
    tree: dict[str, Any],
    path: str,
    references: dict[str, str],
    counter: _Counter,
    depth: int,
) -> Any:
    base: dict[str, Any]
    if current is _MISSING or current is None:
        base = {}
    elif isinstance(current, dict):
        base = current
    else:
        return current
    changed: dict[str, Any] | None = None
    for key, sub in tree.items():
        child = base.get(key, _MISSING)
        updated = _apply_after_unknown(
            child, sub, _join(path, str(key)), references, counter, depth + 1
        )
        if updated is not child:
            if changed is None:
                changed = dict(base)
            changed[key] = updated
    return current if changed is None else changed


def _apply_unknown_to_list(
    current: Any,
    tree: list[Any],
    path: str,
    references: dict[str, str],
    counter: _Counter,
    depth: int,
) -> Any:
    items: list[Any]
    if current is _MISSING or current is None:
        items = []
    elif isinstance(current, list):
        items = current
    else:
        return current
    grown: list[Any] | None = None
    for index, sub in enumerate(tree):
        child = items[index] if index < len(items) else _MISSING
        updated = _apply_after_unknown(child, sub, f"{path}[]", references, counter, depth + 1)
        if updated is child:
            continue
        if grown is None:
            grown = list(items)
        while len(grown) < index:
            grown.append(_filler(tree[len(grown)]))
        if index < len(grown):
            grown[index] = updated
        else:
            grown.append(updated)
    return current if grown is None else grown


def _apply_config_unknown(current: Any, expression: Any, counter: _Counter, depth: int = 0) -> Any:
    """Return `current` with an Unknown for each attribute that is written as a reference.

    An attribute whose expression holds references and no constant, and that the plan has no
    value for, is configured but not known.
    Only attributes of blocks the plan has are filled: a block is never invented, because a
    dynamic block that produces nothing is written in the configuration all the same.
    """
    if depth > _MAX_TREE_DEPTH:
        return current
    if isinstance(expression, dict):
        if _is_leaf(expression):
            references = _leaf_references(expression)
            if current is _MISSING and references and "constant_value" not in expression:
                counter.unknown += 1
                return _PlannedUnknown(references[0])
            return current
        if not isinstance(current, dict):
            return current
        changed: dict[str, Any] | None = None
        for key, sub in expression.items():
            child = current.get(key, _MISSING)
            updated = _apply_config_unknown(child, sub, counter, depth + 1)
            if updated is not child:
                if changed is None:
                    changed = dict(current)
                changed[key] = updated
        return current if changed is None else changed
    if isinstance(expression, list):
        if not isinstance(current, list):
            return current
        grown: list[Any] | None = None
        for index, sub in enumerate(expression[: len(current)]):
            updated = _apply_config_unknown(current[index], sub, counter, depth + 1)
            if updated is not current[index]:
                if grown is None:
                    grown = list(current)
                grown[index] = updated
        return current if grown is None else grown
    return current


# ---------------------------------------------------------------------------------------
# The parser
# ---------------------------------------------------------------------------------------


# Every property the parser synthesizes, by resource type, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py).
# None: each property of a resource is an attribute of the plan under the provider's own name.
PRODUCED: Mapping[str, frozenset[str]] = MappingProxyType({})


class TerraformPlanParser(BaseParser):
    """Parse output of `terraform show -json <planfile>`."""

    def parse(self, data: Any, source_path: str = "", text: str | None = None) -> ParsedOutput:
        """Parse a loaded plan.

        `text` is the file the plan was loaded from; without it the file at `source_path` is
        read again, to give each resource the line it starts on.
        A plan that comes from anywhere else simply has no lines.
        """
        if not isinstance(data, dict):
            raise ParseError("Terraform plan JSON must be an object")

        planned = self._collect_planned(data)
        config = _Config(data)
        resolver = _Resolver([p.address for p in planned], config)
        changes = self._index_changes(data)
        lines = _load_line_index(source_path, text)
        counter = _Counter()

        resources = [
            self._build_resource(p, config, resolver, changes, lines, source_path, counter)
            for p in planned
        ]

        diagnostics: list[Diagnostic] = []
        data_sources = sum(1 for r in resources if r.mode == "data")
        if data_sources:
            diagnostics.append(
                Diagnostic(
                    "info",
                    "plan.data_source",
                    f"{data_sources} data source(s) added as context nodes; rules do not "
                    "evaluate them and they are not counted as scanned resources",
                    source_path,
                )
            )
        if counter.unknown:
            diagnostics.append(
                Diagnostic(
                    "info",
                    "plan.unknown_values",
                    f"{counter.unknown} value(s) are unknown until apply; a rule treats them as "
                    "not known, never as not configured",
                    source_path,
                )
            )
        if counter.unresolved_resources:
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "plan.reference_limit",
                    f"The plan holds more than {MAX_REFERENCE_ENTRIES} resolved references; the "
                    f"relationships of {counter.unresolved_resources} resource(s) are missing "
                    "from the graph",
                    source_path,
                )
            )
        if not any(r.mode == "managed" for r in resources):
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "parse.zero_resources",
                    "The plan holds no managed resources to model"
                    + (
                        f" ({data_sources} data source(s) only)"
                        if data_sources
                        else ": planned_values lists no resources"
                    ),
                    source_path,
                )
            )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="terraform_plan",
            metadata={
                "format_version": data.get("format_version", ""),
                "terraform_version": data.get("terraform_version", ""),
            },
            diagnostics=diagnostics,
        )

    # -- planned_values ---------------------------------------------------------------

    def _collect_planned(self, data: dict[str, Any]) -> list[_Planned]:
        """Every resource instance of planned_values, the root module first."""
        planned_values = data.get("planned_values")
        found: list[_Planned] = []
        if isinstance(planned_values, dict):
            self._walk_module(
                planned_values.get("root_module"), "/planned_values/root_module", found, 0
            )
        return found

    def _walk_module(self, module: Any, pointer: str, out: list[_Planned], depth: int) -> None:
        if not isinstance(module, dict):
            return
        if depth > MAX_MODULE_DEPTH:
            logger.warning(
                "Module nesting depth %d exceeds limit %d - skipping", depth, MAX_MODULE_DEPTH
            )
            return
        resources = module.get("resources")
        if isinstance(resources, list):
            for position, res in enumerate(resources):
                if isinstance(res, dict):
                    address = self._address_of(res, module)
                    if address:
                        out.append(_Planned(address, res, f"{pointer}/resources/{position}"))
        children = module.get("child_modules")
        if isinstance(children, list):
            for position, child in enumerate(children):
                self._walk_module(child, f"{pointer}/child_modules/{position}", out, depth + 1)

    @staticmethod
    def _address_of(res: dict[str, Any], module: dict[str, Any]) -> str:
        address = res.get("address")
        if isinstance(address, str) and address:
            return address
        local = _local_address(res)
        if local is None:
            return ""
        parent = module.get("address")
        return _join(parent if isinstance(parent, str) else "", local)

    @staticmethod
    def _index_changes(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
        """The `change` of each resource instance, by planned address."""
        changes: dict[str, dict[str, Any]] = {}
        for entry in _dicts(data.get("resource_changes")):
            address, change = entry.get("address"), entry.get("change")
            if isinstance(address, str) and isinstance(change, dict) and not entry.get("deposed"):
                changes.setdefault(address, change)
        return changes

    # -- one resource -----------------------------------------------------------------

    def _build_resource(
        self,
        planned: _Planned,
        config: _Config,
        resolver: _Resolver,
        changes: dict[str, dict[str, Any]],
        lines: dict[str, int],
        source_path: str,
        counter: _Counter,
    ) -> ParsedResource:
        res = planned.resource
        address = planned.address
        instance = _module_instance(address)
        configured = config.resources.get(base_address(address)) or {}
        expressions = configured.get("expressions")
        leaves = _walk_expressions(expressions)

        # Past the limit a reference resolves to nothing, but the path is still recorded
        resolving = counter.references < MAX_REFERENCE_ENTRIES
        if not resolving:
            counter.unresolved_resources += 1

        references: dict[str, list[str]] = {}
        for leaf in leaves:
            if not leaf.references:
                continue
            # A path is recorded even when none of its references resolves: the graph then
            # knows the attribute is a reference and never guesses from its literal value
            bucket = references.setdefault(leaf.path, [])
            if resolving:
                for reference in leaf.references:
                    bucket.extend(a for a in resolver.resolve(reference, instance) if a != address)
            references[leaf.path] = _unique(bucket)

        depends_on = [d for d in (configured.get("depends_on") or []) if isinstance(d, str) and d]
        dependencies = _unique(
            a
            for raw in depends_on
            if resolving
            for a in resolver.resolve(raw, instance)
            if a != address
        )
        dependencies = _unique([*dependencies, *(a for refs in references.values() for a in refs)])
        counter.references += len(dependencies) + sum(len(refs) for refs in references.values())

        properties = self._properties(res, changes.get(address), expressions, leaves, counter)

        mode: Mode = "data" if self._is_data(res, address) else "managed"
        pointer_line = lines.get(planned.pointer)
        return ParsedResource(
            resource_type=str(res.get("type") or ""),
            address=address,
            name=str(res.get("name") or ""),
            provider=str(res.get("provider_name") or ""),
            properties=properties,
            dependencies=dependencies,
            # References are emitted as planned addresses from the root, so the graph must not
            # also try them inside the module: a root resource passed in through a variable
            # would bind to a same-named resource of the module. The module is in meta
            module="",
            source_location=source_path,
            references=references,
            start_line=pointer_line,
            mode=mode,
            meta=self._meta(res, configured, depends_on, instance, changes.get(address)),
        )

    @staticmethod
    def _is_data(res: dict[str, Any], address: str) -> bool:
        if res.get("mode") == "data":
            return True
        if res.get("mode") is not None:
            return False
        parts = components(address)
        count = len(components(_module_instance(address)))
        return count < len(parts) and parts[count] == "data"

    @staticmethod
    def _properties(
        res: dict[str, Any],
        change: dict[str, Any] | None,
        expressions: Any,
        leaves: list[_Leaf],
        counter: _Counter,
    ) -> dict[str, Any]:
        values = res.get("values")
        properties: Any = dict(values) if isinstance(values, dict) else {}
        unknown_tree = change.get("after_unknown") if change else None
        if unknown_tree:
            first_reference: dict[str, str] = {}
            for leaf in leaves:
                if leaf.references:
                    first_reference.setdefault(leaf.path, leaf.references[0])
            properties = _apply_after_unknown(
                properties, unknown_tree, "", first_reference, counter
            )
        if isinstance(expressions, dict) and expressions:
            properties = _apply_config_unknown(properties, expressions, counter)
        result: dict[str, Any] = properties
        return result

    @staticmethod
    def _meta(
        res: dict[str, Any],
        configured: dict[str, Any],
        depends_on: list[str],
        instance: str,
        change: dict[str, Any] | None,
    ) -> dict[str, Any]:
        meta: dict[str, Any] = {}
        index = res.get("index")
        if isinstance(index, (int, str)) and not isinstance(index, bool):
            meta["index"] = index
        if "count_expression" in configured:
            meta["count"] = True
        if "for_each_expression" in configured:
            meta["for_each"] = True
        if depends_on:
            meta["depends_on"] = depends_on
        if instance:
            meta["module"] = instance
        actions = change.get("actions") if change else None
        if isinstance(actions, list) and all(isinstance(a, str) for a in actions):
            meta["change_actions"] = list(actions)
        return meta


def _load_line_index(source_path: str, text: str | None) -> dict[str, int]:
    """Line of each JSON value of the plan file, or nothing when the file is not at hand."""
    if text is None:
        if not source_path:
            return {}
        path = Path(source_path)
        try:
            if not path.is_file():
                return {}
            text = decode_input(path)
        except (OSError, ParseError):
            return {}
    index = json_line_index(text)
    # Text of another document would give wrong lines, so it is only used if it is a plan
    return index if "/planned_values" in index else {}
