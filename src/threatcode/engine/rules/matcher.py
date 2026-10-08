"""Safe declarative condition evaluator for rule matching.

Conditions are plain data (dicts and lists), never code: there is no ``eval()`` anywhere.

Every check yields one of three values, :class:`Tri`: TRUE, FALSE or UNKNOWN.
UNKNOWN means the scan cannot tell, because the value is an :class:`~threatcode.values.Unknown`
(known only after apply, an unresolved reference) or because the property is missing on a
node that comes from a design, where a missing property is a question, not a fact.
Logical operators follow Kleene's three-valued logic, so UNKNOWN is never turned into a
finding by a negation.
A rule fires only when its condition is TRUE.

Security: nesting is capped at ``MAX_CONDITION_DEPTH`` and path resolution is bounded, so a
hostile rule cannot exhaust the stack.
Beyond the cap evaluation yields UNKNOWN, which stays UNKNOWN through ``not``.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass
from enum import Enum
from functools import lru_cache
from typing import TYPE_CHECKING, Any

from threatcode.ir.nodes import InfraNode, NodeCategory, TrustZone
from threatcode.values import is_unknown
from threatcode.vocab import is_world_source

if TYPE_CHECKING:
    from threatcode.engine.rules.loader import Rule

logger = logging.getLogger(__name__)

# Max nesting depth for logical operators and quantifiers (all_of, any_of, none_of, not,
# any_item, all_items, none_items); rules nested deeper are rejected at load time
MAX_CONDITION_DEPTH = 10

# Max segments in a property path; longer paths are rejected at load time
MAX_PATH_SEGMENTS = 16

LOGICAL_OPERATORS: frozenset[str] = frozenset({"all_of", "any_of", "none_of", "not"})
QUANTIFIER_OPERATORS: frozenset[str] = frozenset({"any_item", "all_items", "none_items"})
# Operators that take a property's value: {"<path>": {"<operator>": <argument>}}
PROPERTY_OPERATORS: frozenset[str] = frozenset(
    {
        "exists",
        "not_exists",
        "equals",
        "not_equals",
        "equals_ci",
        "contains",
        "not_contains",
        "matches_any",
        "greater_than",
        "less_than",
        "is_true",
        "is_empty",
        "is_world_cidr",
    }
    | QUANTIFIER_OPERATORS
)
# Keys that stand for a check on the whole property mapping instead of one property
ELEMENT_PREDICATES: frozenset[str] = frozenset({"port_overlaps"})
# The single source of truth the rule loader validates operator names against
VALID_OPERATORS: frozenset[str] = LOGICAL_OPERATORS | PROPERTY_OPERATORS | ELEMENT_PREDICATES


# ---------------------------------------------------------------------------
# Three-valued logic
# ---------------------------------------------------------------------------


class Tri(Enum):
    """TRUE, FALSE or UNKNOWN. Compare with ``is``; a Tri has no truth value."""

    TRUE = "true"
    FALSE = "false"
    UNKNOWN = "unknown"

    def __bool__(self) -> bool:
        raise TypeError("Tri has no truth value; compare with Tri.TRUE explicitly")

    @classmethod
    def of(cls, value: bool) -> Tri:
        return cls.TRUE if value else cls.FALSE


def tri_not(value: Tri) -> Tri:
    if value is Tri.TRUE:
        return Tri.FALSE
    if value is Tri.FALSE:
        return Tri.TRUE
    return Tri.UNKNOWN


def tri_and(values: Iterable[Tri]) -> Tri:
    """FALSE if any is FALSE, else UNKNOWN if any is UNKNOWN, else TRUE (empty is TRUE)."""
    result = Tri.TRUE
    for value in values:
        if value is Tri.FALSE:
            return Tri.FALSE
        if value is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result


def tri_or(values: Iterable[Tri]) -> Tri:
    """TRUE if any is TRUE, else UNKNOWN if any is UNKNOWN, else FALSE (empty is FALSE)."""
    result = Tri.FALSE
    for value in values:
        if value is Tri.TRUE:
            return Tri.TRUE
        if value is Tri.UNKNOWN:
            result = Tri.UNKNOWN
    return result


# ---------------------------------------------------------------------------
# Public entry points
# ---------------------------------------------------------------------------


def evaluate_condition_tri(condition: Mapping[str, Any], node: InfraNode, _depth: int = 0) -> Tri:
    """Evaluate a rule condition against a node, keeping UNKNOWN apart from FALSE."""
    scope = _Scope(node.properties, getattr(node, "evidence", "config") == "design")
    return _eval(condition, scope, _depth)


def evaluate_condition(condition: Mapping[str, Any], node: InfraNode, _depth: int = 0) -> bool:
    """True only when the condition is TRUE for the node; UNKNOWN is not a hit."""
    return evaluate_condition_tri(condition, node, _depth) is Tri.TRUE


def evaluate_rule(condition: Mapping[str, Any], properties: Mapping[str, Any]) -> bool:
    """Evaluate a rule condition against a flat properties dict.

    Convenience wrapper that creates a minimal InfraNode for the matcher.
    Used by tests and simple rule evaluation without full graph context.
    """
    node = InfraNode(
        id="__eval__",
        resource_type="__eval__",
        name="__eval__",
        category=NodeCategory.UNKNOWN,
        trust_zone=TrustZone.PRIVATE,
        properties=dict(properties),
    )
    return evaluate_condition(condition, node)


def match_state(rule: Rule, node: InfraNode) -> Tri:
    """Whether a rule applies to a node: TRUE, FALSE, or UNKNOWN when it cannot be told."""
    # Data sources describe existing infrastructure, not something this scan creates
    if getattr(node, "mode", "managed") == "data":
        return Tri.FALSE
    if not resource_type_matches(rule.resource_types, node.resource_type):
        return Tri.FALSE
    return evaluate_condition_tri(rule.condition, node)


def matches_rule(rule: Rule, node: InfraNode) -> bool:
    """Check if a rule matches a given node (exact type or glob, then a TRUE condition)."""
    return match_state(rule, node) is Tri.TRUE


def resource_type_matches(resource_types: Iterable[str], resource_type: str) -> bool:
    """Exact type membership; an entry ending in '*' matches by prefix."""
    for entry in resource_types:
        if entry.endswith("*"):
            if resource_type.startswith(entry[:-1]):
                return True
        elif entry == resource_type:
            return True
    return False


# ---------------------------------------------------------------------------
# Property paths
# ---------------------------------------------------------------------------


class PathError(ValueError):
    """A property path is malformed."""


@dataclass(frozen=True)
class _Atom:
    """One step of a property path."""

    text: str
    # Written with brackets and quotes or an escape: never a wildcard or an index, and
    # never joined with its neighbours into a longer dotted key
    exact: bool = False

    @property
    def wildcard(self) -> bool:
        return not self.exact and self.text == "*"

    @property
    def index(self) -> int | None:
        if not self.exact and re.fullmatch(r"[0-9]+", self.text):
            return int(self.text)
        return None


@lru_cache(maxsize=4096)
def parse_path(path: str) -> tuple[_Atom, ...]:  # noqa: C901 - one-pass scanner, a branch per character class
    """Split a property path into steps.

    ``a.b`` is two steps, ``a['b.c']`` and ``a.b\\.c`` are steps whose second key contains a
    dot, ``a.0`` and ``a[0]`` index a list, and ``a.*`` and ``a[*]`` fan out over a list or a
    mapping.
    """
    if not isinstance(path, str) or not path:
        raise PathError("path must be a non-empty string")
    atoms: list[_Atom] = []
    buf: list[str] = []
    exact = False
    after_bracket = False
    i, n = 0, len(path)

    def flush() -> None:
        nonlocal exact
        if not buf:
            raise PathError(f"empty segment in path {path!r}")
        atoms.append(_Atom("".join(buf), exact))
        buf.clear()
        exact = False

    while i < n:
        char = path[i]
        if char == "\\":
            if after_bracket:
                raise PathError(f"expected '.' or '[' after ']' in path {path!r}")
            if i + 1 >= n or path[i + 1] not in ".[]\\":
                raise PathError(f"unsupported escape in path {path!r}")
            buf.append(path[i + 1])
            exact = True
            i += 2
        elif char == ".":
            if buf:
                flush()
            elif not after_bracket:
                raise PathError(f"empty segment in path {path!r}")
            after_bracket = False
            i += 1
            if i >= n:
                raise PathError(f"path {path!r} ends with '.'")
        elif char == "[":
            if buf:
                flush()
            elif not after_bracket and i != 0:
                raise PathError(f"unexpected '[' in path {path!r}")
            i = _parse_bracket(path, i, atoms)
            after_bracket = True
        else:
            if after_bracket:
                raise PathError(f"expected '.' or '[' after ']' in path {path!r}")
            buf.append(char)
            i += 1
    if buf:
        flush()
    if not atoms:
        raise PathError(f"empty path {path!r}")
    if len(atoms) > MAX_PATH_SEGMENTS:
        raise PathError(f"path {path!r} has more than {MAX_PATH_SEGMENTS} segments")
    return tuple(atoms)


def _parse_bracket(path: str, start: int, atoms: list[_Atom]) -> int:
    """Parse ``[...]`` starting at ``start``; append its atom and return the next index."""
    n = len(path)
    j = start + 1
    if j < n and path[j] in "'\"":
        quote = path[j]
        end = path.find(quote, j + 1)
        if end == -1 or end + 1 >= n or path[end + 1] != "]":
            raise PathError(f"unterminated quoted key in path {path!r}")
        key = path[j + 1 : end]
        if not key:
            raise PathError(f"empty quoted key in path {path!r}")
        atoms.append(_Atom(key, exact=True))
        return end + 2
    end = path.find("]", j)
    if end == -1:
        raise PathError(f"unterminated '[' in path {path!r}")
    content = path[j:end].strip()
    if content != "*" and not re.fullmatch(r"[0-9]+", content):
        raise PathError(f"bracket in path {path!r} must hold an index, '*' or a quoted key")
    atoms.append(_Atom(content))
    return end + 1


class PathKind(Enum):
    VALUE = "value"  # one value
    MANY = "many"  # several values from a fan-out; ``value`` is the list of them
    MISSING = "missing"  # nothing at the path
    UNKNOWN = "unknown"  # an Unknown at or above the path; ``value`` is that Unknown


@dataclass(frozen=True)
class Resolved:
    kind: PathKind
    value: Any = None


_MISSING = Resolved(PathKind.MISSING)


def resolve_path(data: Any, path: str) -> Resolved:
    """Find the value a property path points at.

    At each mapping the longest remaining dotted key that exists literally wins, so
    ``labels.pod-security.kubernetes.io/enforce`` finds that one label.
    An integer step indexes a list.
    Any other step on a list descends into a one-element list of mappings (how Terraform
    stores a nested block), fans out over a longer list, and finds nothing in an empty one.
    ``*`` fans out over list elements or mapping values.
    None counts as nothing.
    An Unknown at or above the path makes the result UNKNOWN.
    """
    if not isinstance(path, str):
        return _MISSING
    try:
        atoms = parse_path(path)
    except PathError:
        return _MISSING  # the loader rejects malformed paths; this is the runtime backstop
    return _resolve(data, atoms, 0, {})


def _resolve(
    current: Any, atoms: tuple[_Atom, ...], i: int, memo: dict[tuple[int, int], Resolved]
) -> Resolved:
    if is_unknown(current):
        return Resolved(PathKind.UNKNOWN, current)
    if i == len(atoms):
        return _MISSING if current is None else Resolved(PathKind.VALUE, current)
    if isinstance(current, Mapping):
        key = (id(current), i)
        found = memo.get(key)
        if found is None:
            found = memo[key] = _resolve_mapping(current, atoms, i, memo)
        return found
    if isinstance(current, list | tuple):
        key = (id(current), i)
        found = memo.get(key)
        if found is None:
            found = memo[key] = _resolve_list(current, atoms, i, memo)
        return found
    return _MISSING


def _resolve_mapping(
    mapping: Mapping[str, Any],
    atoms: tuple[_Atom, ...],
    i: int,
    memo: dict[tuple[int, int], Resolved],
) -> Resolved:
    atom = atoms[i]
    if atom.wildcard:
        return _fan_out(list(mapping.values()), atoms, i + 1, memo)
    # Atoms that may be joined into one dotted key: plain ones, not bracketed or wildcards
    run = 0
    while i + run < len(atoms) and not atoms[i + run].exact and not atoms[i + run].wildcard:
        run += 1
    for length in range(max(run, 1), 0, -1):
        key = ".".join(a.text for a in atoms[i : i + length])
        if key in mapping:
            sub = _resolve(mapping[key], atoms, i + length, memo)
            if sub.kind is not PathKind.MISSING:
                return sub
    return _MISSING


def _resolve_list(
    items: list[Any] | tuple[Any, ...],
    atoms: tuple[_Atom, ...],
    i: int,
    memo: dict[tuple[int, int], Resolved],
) -> Resolved:
    atom = atoms[i]
    if atom.wildcard:
        return _fan_out(items, atoms, i + 1, memo)
    index = atom.index
    if index is not None:
        if index >= len(items):
            return _MISSING
        return _resolve(items[index], atoms, i + 1, memo)
    if not items:
        return _MISSING
    if len(items) == 1:
        return _resolve(items[0], atoms, i, memo)
    return _fan_out(items, atoms, i, memo)


def _fan_out(
    items: Iterable[Any],
    atoms: tuple[_Atom, ...],
    i: int,
    memo: dict[tuple[int, int], Resolved],
) -> Resolved:
    leaves: list[Any] = []
    for item in items:
        sub = _resolve(item, atoms, i, memo)
        if sub.kind is PathKind.VALUE or sub.kind is PathKind.UNKNOWN:
            leaves.append(sub.value)
        elif sub.kind is PathKind.MANY:
            leaves.extend(sub.value)
    return Resolved(PathKind.MANY, leaves) if leaves else _MISSING


def _leaves(resolved: Resolved) -> list[Any]:
    if resolved.kind is PathKind.VALUE:
        return [resolved.value]
    if resolved.kind is PathKind.MANY:
        return list(resolved.value)
    return []


# ---------------------------------------------------------------------------
# Evaluation
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class _Scope:
    """What a condition is evaluated against: properties, and whether they are a design's."""

    props: Mapping[str, Any]
    design: bool


_Handler = Callable[[Any, Resolved, _Scope, int], Tri]
_warned_operators: set[str] = set()


def _eval(condition: Any, scope: _Scope, depth: int) -> Tri:
    if depth > MAX_CONDITION_DEPTH:
        logger.warning("Condition nested deeper than %d levels; treating as unknown", depth)
        return Tri.UNKNOWN
    if not isinstance(condition, Mapping) or not condition:
        return Tri.UNKNOWN
    logical = [op for op in LOGICAL_OPERATORS if op in condition]
    if logical:
        if len(logical) > 1 or len(condition) > 1:
            logger.warning("Condition mixes a logical operator with other keys; unknown")
            return Tri.UNKNOWN
        return _eval_logical(logical[0], condition[logical[0]], scope, depth)
    return tri_and(_eval_property(key, check, scope, depth) for key, check in condition.items())


def _eval_logical(op: str, argument: Any, scope: _Scope, depth: int) -> Tri:
    if op == "not":
        if not isinstance(argument, Mapping):
            return Tri.UNKNOWN
        return tri_not(_eval(argument, scope, depth + 1))
    if not isinstance(argument, list | tuple) or not argument:
        return Tri.UNKNOWN
    results = (_eval(c, scope, depth + 1) for c in argument)
    if op == "all_of":
        return tri_and(results)
    if op == "any_of":
        return tri_or(results)
    return tri_not(tri_or(results))  # none_of


def _eval_property(key: Any, check: Any, scope: _Scope, depth: int) -> Tri:
    if not isinstance(key, str):
        return Tri.UNKNOWN
    if key in ELEMENT_PREDICATES:
        return _port_overlaps(check, scope)
    resolved = resolve_path(scope.props, key)
    if isinstance(check, Mapping):
        if not check:
            return Tri.UNKNOWN
        return tri_and(_apply(op, arg, resolved, scope, depth) for op, arg in check.items())
    return _apply("equals", check, resolved, scope, depth)


def _apply(op: Any, argument: Any, resolved: Resolved, scope: _Scope, depth: int) -> Tri:
    handler = _HANDLERS.get(op) if isinstance(op, str) else None
    if handler is None:
        if str(op) not in _warned_operators:
            _warned_operators.add(str(op))
            logger.warning("Unknown operator %r in rule condition; treating as unknown", op)
        return Tri.UNKNOWN
    if resolved.kind is PathKind.UNKNOWN:
        return Tri.UNKNOWN
    if resolved.kind is PathKind.MISSING and scope.design:
        return Tri.UNKNOWN
    return handler(argument, resolved, scope, depth)


# --- value helpers ---------------------------------------------------------


def _is_absent(value: Any) -> bool:
    """None, '', [] and {} are absent; False and 0 are present."""
    return value is None or (isinstance(value, str | list | tuple | Mapping) and len(value) == 0)


def _contains_unknown(value: Any, depth: int = 0) -> bool:
    if is_unknown(value):
        return True
    if depth >= 8:
        return False
    if isinstance(value, Mapping):
        return any(_contains_unknown(v, depth + 1) for v in value.values())
    if isinstance(value, list | tuple):
        return any(_contains_unknown(v, depth + 1) for v in value)
    return False


def _eq(a: Any, b: Any) -> bool:
    """Equality where True is not 1 and an Unknown equals nothing."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if is_unknown(a) or is_unknown(b):
        return False
    if isinstance(a, list | tuple) and isinstance(b, list | tuple):
        return len(a) == len(b) and all(_eq(x, y) for x, y in zip(a, b, strict=True))
    if isinstance(a, Mapping) and isinstance(b, Mapping):
        return a.keys() == b.keys() and all(_eq(a[k], b[k]) for k in a)
    return bool(a == b)


_NUMBER_RE = re.compile(r"[+-]?(\d+(\.\d*)?|\.\d+)")


def _to_number(value: Any) -> int | float | None:
    """A number, or a numeric string such as CloudFormation writes; never a boolean."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return value
    if isinstance(value, str) and _NUMBER_RE.fullmatch(value.strip()):
        text = value.strip()
        return float(text) if "." in text else int(text)
    return None


_TRUE_WORDS = frozenset({"true", "1", "yes"})


def _is_truthy(value: Any) -> bool:
    return value is True or (isinstance(value, str) and value.strip().lower() in _TRUE_WORDS)


def _is_world(value: Any) -> bool:
    if not isinstance(value, str):
        return False
    if is_world_source(value):
        return True
    try:
        return ipaddress.ip_network(value.strip(), strict=False).prefixlen == 0
    except ValueError:
        return False


# --- per-leaf predicates ---------------------------------------------------


def _p_exists(leaf: Any, _expected: Any) -> Tri:
    return Tri.of(not _is_absent(leaf))


def _p_equals(leaf: Any, expected: Any) -> Tri:
    return Tri.of(_eq(leaf, expected))


def _p_equals_ci(leaf: Any, expected: Any) -> Tri:
    if not isinstance(expected, str):
        return Tri.FALSE
    if isinstance(leaf, bool):
        return Tri.of(str(leaf).lower() == expected.casefold())
    if isinstance(leaf, str):
        return Tri.of(leaf.casefold() == expected.casefold())
    return Tri.FALSE


def _p_contains(leaf: Any, expected: Any) -> Tri:
    if isinstance(leaf, str):
        return Tri.of(isinstance(expected, str) and expected in leaf)
    if isinstance(leaf, list | tuple):
        return tri_or(Tri.UNKNOWN if is_unknown(el) else Tri.of(_eq(el, expected)) for el in leaf)
    if isinstance(leaf, Mapping):
        return Tri.of(any(_eq(k, expected) for k in leaf))
    return Tri.FALSE


def _p_matches_any(leaf: Any, expected: Any) -> Tri:
    if not isinstance(expected, list | tuple):
        return Tri.UNKNOWN
    return Tri.of(any(_eq(leaf, e) for e in expected))


def _p_greater_than(leaf: Any, expected: Any) -> Tri:
    number, bound = _to_number(leaf), _to_number(expected)
    if number is None or bound is None:
        return Tri.FALSE
    return Tri.of(number > bound)


def _p_less_than(leaf: Any, expected: Any) -> Tri:
    number, bound = _to_number(leaf), _to_number(expected)
    if number is None or bound is None:
        return Tri.FALSE
    return Tri.of(number < bound)


def _p_is_true(leaf: Any, _expected: Any) -> Tri:
    return Tri.of(_is_truthy(leaf))


def _p_is_world_cidr(leaf: Any, _expected: Any) -> Tri:
    if isinstance(leaf, list | tuple):
        return tri_or(Tri.UNKNOWN if is_unknown(el) else Tri.of(_is_world(el)) for el in leaf)
    return Tri.of(_is_world(leaf))


def _any_leaf(predicate: Callable[[Any, Any], Tri], expected: Any, resolved: Resolved) -> Tri:
    """TRUE if the predicate holds for any value; UNKNOWN if none does and one is unknown."""
    outcome = Tri.FALSE
    for leaf in _leaves(resolved):
        result = Tri.UNKNOWN if is_unknown(leaf) else predicate(leaf, expected)
        if result is Tri.FALSE and _contains_unknown(leaf):
            result = Tri.UNKNOWN
        if result is Tri.TRUE:
            return Tri.TRUE
        if result is Tri.UNKNOWN:
            outcome = Tri.UNKNOWN
    return outcome


def _value_handler(predicate: Callable[[Any, Any], Tri], *, negate: bool = False) -> _Handler:
    """Handler for an operator whose argument is a value to compare with."""

    def handler(expected: Any, resolved: Resolved, _scope: _Scope, _depth: int) -> Tri:
        result = _any_leaf(predicate, expected, resolved)
        return tri_not(result) if negate else result

    return handler


def _flag_handler(predicate: Callable[[Any, Any], Tri], *, invert: bool = False) -> _Handler:
    """Handler for an operator whose argument is true or false (``invert`` flips the flag)."""

    def handler(expected: Any, resolved: Resolved, _scope: _Scope, _depth: int) -> Tri:
        if not isinstance(expected, bool):
            return Tri.UNKNOWN
        result = _any_leaf(predicate, None, resolved)
        return result if (expected != invert) else tri_not(result)

    return handler


# --- quantifiers -----------------------------------------------------------


def _elements(resolved: Resolved) -> list[Any]:
    elements: list[Any] = []
    for leaf in _leaves(resolved):
        if isinstance(leaf, list | tuple):
            elements.extend(leaf)
        else:
            elements.append(leaf)
    return elements


def _eval_element(condition: Any, element: Any, scope: _Scope, depth: int) -> Tri:
    """Evaluate a condition against one list element as if it were a node of its own."""
    if is_unknown(element):
        return Tri.UNKNOWN
    props = element if isinstance(element, Mapping) else {"_value": element}
    return _eval(condition, _Scope(props, scope.design), depth + 1)


def _quantifier(kind: str) -> _Handler:
    def handler(expected: Any, resolved: Resolved, scope: _Scope, depth: int) -> Tri:
        if not isinstance(expected, Mapping):
            return Tri.UNKNOWN
        results = (_eval_element(expected, el, scope, depth) for el in _elements(resolved))
        if kind == "all_items":
            return tri_and(results)
        any_result = tri_or(results)
        return any_result if kind == "any_item" else tri_not(any_result)

    return handler


# --- ports -----------------------------------------------------------------

_ALL_PORTS = (0, 65535)
_ALL_PROTOCOLS = frozenset({"-1", "all", "*"})
_PORTLESS_PROTOCOLS = frozenset({"icmp", "icmpv6", "icmp6", "1", "58"})


def _port_number(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        number = value
    elif isinstance(value, str) and re.fullmatch(r"\s*[0-9]+\s*", value):
        number = int(value)
    else:
        return None
    return number if 0 <= number <= 65535 else None


def _port_range(value: Any) -> tuple[int, int]:
    """One port, a 'lo-hi' range or '*' as an inclusive range; ValueError if it is none."""
    if isinstance(value, str):
        text = value.strip()
        if text in ("*", "any", "all"):
            return _ALL_PORTS
        low, dash, high = text.partition("-")
        if dash:
            lo, hi = _port_number(low), _port_number(high)
            if lo is not None and hi is not None:
                return (min(lo, hi), max(lo, hi))
            raise ValueError(f"invalid port range {value!r}")
    number = _port_number(value)
    if number is None:
        raise ValueError(f"invalid port {value!r}")
    return (number, number)


def parse_port_ranges(wanted: Any) -> tuple[tuple[int, int], ...]:
    """Ranges for a list of ports, 'lo-hi' strings and '*'; ValueError on anything else."""
    items = wanted if isinstance(wanted, list | tuple | set | frozenset) else [wanted]
    return tuple(_port_range(item) for item in items)


def _all_protocols(protocol: Any) -> bool:
    return protocol is not None and str(protocol).strip().lower() in _ALL_PROTOCOLS


def _portless(protocol: Any) -> bool:
    return protocol is not None and str(protocol).strip().lower() in _PORTLESS_PROTOCOLS


def _spec_ranges(first: Any, last: Any) -> list[tuple[int, int]]:
    """Port ranges named by a port, a 'lo-hi' string, '*', a list of those, or a from/to pair."""
    if last is not None:
        lo, hi = _port_number(first), _port_number(last)
        if lo is not None and hi is not None:
            return [(min(lo, hi), max(lo, hi))]
        return []
    ranges: list[tuple[int, int]] = []
    for item in first if isinstance(first, list | tuple) else [first]:
        try:
            ranges.append(_port_range(item))
        except ValueError:
            continue
    return ranges


def _overlaps(ranges: Iterable[tuple[int, int]], wanted: Iterable[tuple[int, int]]) -> bool:
    wanted_list = list(wanted)
    return any(lo <= b and a <= hi for lo, hi in ranges for a, b in wanted_list)


def ports_overlap(from_port: Any, to_port: Any, protocol: Any, wanted: Any) -> bool:
    """Whether a rule's ports overlap any of the wanted ports.

    ``wanted`` is a list of ints, 'lo-hi' strings and '*'.
    The protocol ``-1``, ``all`` or ``*`` means every port; ICMP has no ports.
    Otherwise ``from_port`` and ``to_port`` are an inclusive range, or ``to_port`` is None
    and ``from_port`` is a port, a 'lo-hi' string, '*' or a list of those (Azure style).
    A value that is not a port overlaps nothing.
    """
    wanted_ranges = parse_port_ranges(wanted)
    if _all_protocols(protocol):
        return bool(wanted_ranges)
    if _portless(protocol):
        return False
    return _overlaps(_spec_ranges(from_port, to_port), wanted_ranges)


_PORT_KEYS = ("port", "port_range", "destination_port_range", "destination_port_ranges")


def _port_overlaps(expected: Any, scope: _Scope) -> Tri:
    """The ``port_overlaps`` predicate: do this element's ports overlap the wanted ones."""
    try:
        wanted = parse_port_ranges(expected)
    except ValueError:
        return Tri.UNKNOWN
    if not wanted:
        return Tri.UNKNOWN
    props = scope.props
    protocol = props.get("protocol", props.get("ip_protocol"))
    candidates: list[Any] = [props[k] for k in _PORT_KEYS if props.get(k) is not None]
    from_to = [props.get("from_port"), props.get("to_port")]
    if is_unknown(protocol) or any(is_unknown(c) or _contains_unknown(c) for c in candidates):
        return Tri.UNKNOWN
    if candidates:
        # Azure and GCP style: the ranges are authoritative; protocol "*" means any protocol
        # there, not any port
        return Tri.of(_overlaps([r for c in candidates for r in _spec_ranges(c, None)], wanted))
    if _all_protocols(protocol):
        return Tri.TRUE
    if any(is_unknown(v) for v in from_to):
        return Tri.UNKNOWN
    if from_to[0] is None and from_to[1] is None:
        return Tri.UNKNOWN if scope.design else Tri.FALSE
    if _portless(protocol):
        return Tri.FALSE
    first, last = from_to
    if last is None:
        last = first
    if first is None:
        first = last
    return Tri.of(_overlaps(_spec_ranges(first, last), wanted))


# --- operator table --------------------------------------------------------

_HANDLERS: dict[str, _Handler] = {
    "exists": _flag_handler(_p_exists),
    "not_exists": _flag_handler(_p_exists, invert=True),
    "is_empty": _flag_handler(_p_exists, invert=True),
    "equals": _value_handler(_p_equals),
    "not_equals": _value_handler(_p_equals, negate=True),
    "equals_ci": _value_handler(_p_equals_ci),
    "contains": _value_handler(_p_contains),
    "not_contains": _value_handler(_p_contains, negate=True),
    "matches_any": _value_handler(_p_matches_any),
    "greater_than": _value_handler(_p_greater_than),
    "less_than": _value_handler(_p_less_than),
    "is_true": _flag_handler(_p_is_true),
    "is_world_cidr": _flag_handler(_p_is_world_cidr),
    "any_item": _quantifier("any_item"),
    "all_items": _quantifier("all_items"),
    "none_items": _quantifier("none_items"),
}
