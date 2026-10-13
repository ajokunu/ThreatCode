"""YAML rule file loader and rule validation.

A rule file is loaded once and every part of it is checked at load time, so a typo in a
custom rule is a loud ``RuleLoadError`` naming the file, the rule and the key path instead
of a rule that quietly never fires.
Loaded rules are immutable: the condition and metadata are read-only containers, so the
cached built-in rules can be shared by every engine.
"""

from __future__ import annotations

import copy
import difflib
import logging
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from types import MappingProxyType
from typing import TYPE_CHECKING, Any, NoReturn

import yaml

from threatcode.constants import VALID_SEVERITIES, VALID_STRIDE_CATEGORIES
from threatcode.engine.mitre import TECHNIQUE_DB, is_deprecated, is_revoked, normalize_technique
from threatcode.engine.rules.matcher import (
    ELEMENT_PREDICATES,
    EXPOSURE_PROPERTY,
    LOGICAL_OPERATORS,
    MAX_CONDITION_DEPTH,
    PROPERTY_OPERATORS,
    QUANTIFIER_OPERATORS,
    VALID_OPERATORS,
    PathError,
    parse_path,
    parse_port_ranges,
    resource_type_matches,
)
from threatcode.exceptions import RuleLoadError

logger = logging.getLogger(__name__)

# Regex for valid MITRE ATT&CK technique IDs (T#### or T####.###)
_TECHNIQUE_ID_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
# Regex for valid MITRE ATT&CK tactic IDs (TA####)
_TACTIC_ID_RE = re.compile(r"^TA\d{4}$")
# The forms the reports accept for a CWE id: CWE-312 or 312
_CWE_ID_RE = re.compile(r"^(?:CWE-)?\d{1,5}$", re.IGNORECASE)

# Security limits
MAX_RULES_PER_FILE = 100
MAX_TOTAL_RULES = 1000
MAX_RULE_FILE_SIZE = 1 * 1024 * 1024  # 1 MB

CONFIDENCE_LEVELS: tuple[str, ...] = ("definitive", "heuristic", "absence")

# Named groups of resource types, written ``resource_type: "@name"`` (or as a list entry).
# The workload groups are the Kubernetes kinds that carry a pod template, plus bare pods.
RESOURCE_TYPE_GROUPS: Mapping[str, tuple[str, ...]] = MappingProxyType(
    {
        "kubernetes_pod_workloads": (
            "kubernetes_pod",
            "kubernetes_deployment",
            "kubernetes_daemon_set",
            "kubernetes_stateful_set",
            "kubernetes_replica_set",
            "kubernetes_job",
            "kubernetes_cron_job",
        ),
        # Workloads that run until stopped: the same without job and cron_job
        "kubernetes_long_running": (
            "kubernetes_pod",
            "kubernetes_deployment",
            "kubernetes_daemon_set",
            "kubernetes_stateful_set",
            "kubernetes_replica_set",
        ),
        # Workloads that manage pods: the pod group without bare pods
        "kubernetes_controllers": (
            "kubernetes_deployment",
            "kubernetes_daemon_set",
            "kubernetes_stateful_set",
            "kubernetes_replica_set",
            "kubernetes_job",
            "kubernetes_cron_job",
        ),
    }
)

_RESOURCE_TYPE_RE = re.compile(r"[A-Za-z0-9_.\-]+\*?")


# ---------------------------------------------------------------------------
# Read-only containers
# ---------------------------------------------------------------------------


def _read_only(*_args: Any, **_kwargs: Any) -> NoReturn:
    raise TypeError("rule data is read-only; copy it with dict() or copy.deepcopy() to change it")


class FrozenDict(dict[str, Any]):
    """A dict that cannot be changed.

    It is still a ``dict`` so it serializes as one; ``dict(x)``, ``copy.copy(x)`` and
    ``copy.deepcopy(x)`` give a plain mutable copy.
    """

    __setitem__ = _read_only
    __delitem__ = _read_only
    __ior__ = _read_only
    clear = _read_only
    pop = _read_only
    popitem = _read_only
    setdefault = _read_only
    update = _read_only

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(frozenset(self.items()))

    def __copy__(self) -> dict[str, Any]:
        return dict(self)

    def __deepcopy__(self, memo: dict[int, Any]) -> dict[str, Any]:
        return {copy.deepcopy(k, memo): copy.deepcopy(v, memo) for k, v in self.items()}

    def __reduce__(self) -> tuple[Any, ...]:
        return (dict, (dict(self),))


class FrozenList(list[Any]):
    """A list that cannot be changed; ``list(x)`` and ``copy.deepcopy(x)`` give a plain list."""

    __setitem__ = _read_only
    __delitem__ = _read_only
    __iadd__ = _read_only
    __imul__ = _read_only
    append = _read_only
    clear = _read_only
    extend = _read_only
    insert = _read_only
    pop = _read_only
    remove = _read_only
    reverse = _read_only
    sort = _read_only

    def __hash__(self) -> int:  # type: ignore[override]
        return hash(tuple(self))

    def __copy__(self) -> list[Any]:
        return list(self)

    def __deepcopy__(self, memo: dict[int, Any]) -> list[Any]:
        return [copy.deepcopy(v, memo) for v in self]

    def __reduce__(self) -> tuple[Any, ...]:
        return (list, (list(self),))


def _freeze(value: Any) -> Any:
    if isinstance(value, Mapping):
        return FrozenDict({k: _freeze(v) for k, v in value.items()})
    if isinstance(value, list | tuple):
        return FrozenList(_freeze(v) for v in value)
    return value


# ---------------------------------------------------------------------------
# The Rule type
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    description: str
    stride_category: str
    severity: str
    # Exact resource types; an entry ending in '*' is a prefix glob. Never empty.
    resource_types: tuple[str, ...]
    condition: dict[str, Any]
    mitigation: str = ""
    # Read-only; copy it (copy.deepcopy) before attaching it to anything that may change
    metadata: dict[str, Any] = field(default_factory=FrozenDict)
    # The rule file the rule came from: 'aws__s3' for builtin/aws/s3.yml, 'custom__<stem>'
    source_group: str = ""
    # How the condition was established: definitive (the configuration proves it),
    # heuristic (inferred from names or partial data) or absence (something is missing)
    confidence: str = "definitive"
    # What actually has to change, when several findings share one underlying cause
    root_cause: str = ""

    def __post_init__(self) -> None:
        types = (
            (self.resource_types,) if isinstance(self.resource_types, str) else self.resource_types
        )
        object.__setattr__(self, "resource_types", tuple(types))
        object.__setattr__(self, "condition", _freeze(self.condition))
        object.__setattr__(self, "metadata", _freeze(self.metadata))
        if not self.resource_types:
            raise ValueError(f"Rule {self.id} must name at least one resource type")

    @property
    def resource_type(self) -> str:
        """The first resource type (kept for callers written before rules had several)."""
        return self.resource_types[0]

    def matches_type(self, resource_type: str) -> bool:
        """Whether a node of this resource type is in scope for the rule."""
        return resource_type_matches(self.resource_types, resource_type)

    @property
    def properties_read(self) -> tuple[str, ...]:
        """The top-level properties the condition reads, in the order it names them."""
        return condition_properties(self.condition)


def condition_properties(condition: Mapping[str, Any]) -> tuple[str, ...]:
    """The top-level properties a condition reads, in the order it names them, each once.

    ``labels.app`` and ``labels['a.b']`` both read ``labels``; the logical operators are walked
    and name nothing themselves; the ``_exposure`` pseudo-property and the element predicates
    (``port_overlaps``) are not properties of the resource.
    A malformed condition yields what can be read from it, because the loader validates a
    condition before it builds a rule and this only describes one that passed.
    """
    found: dict[str, None] = {}

    def walk(node: Any, depth: int) -> None:
        if not isinstance(node, Mapping) or depth > MAX_CONDITION_DEPTH:
            return
        for key, value in node.items():
            if key in LOGICAL_OPERATORS:
                children = [value] if isinstance(value, Mapping) else list(value or ())
                for child in children:
                    walk(child, depth + 1)
            elif isinstance(key, str) and key not in ELEMENT_PREDICATES:
                if key == EXPOSURE_PROPERTY:
                    continue
                try:
                    found.setdefault(parse_path(key)[0].text)
                except PathError:
                    continue

    walk(condition, 0)
    return tuple(found)


@dataclass(frozen=True)
class RuleFile:
    """The contents of one rule file."""

    rules: tuple[Rule, ...]
    # IDs of rules that used to live in this file and were removed
    deprecated_ids: frozenset[str] = frozenset()


# ---------------------------------------------------------------------------
# YAML
# ---------------------------------------------------------------------------

if TYPE_CHECKING:
    _YamlBase = yaml.SafeLoader
else:
    _YamlBase = getattr(yaml, "CSafeLoader", yaml.SafeLoader)


class _RuleYamlLoader(_YamlBase):
    """SafeLoader (libyaml-backed when available) that rejects duplicate mapping keys.

    PyYAML keeps the last of two equal keys, which would silently drop half of a condition
    that repeats ``any_of`` or a property name.
    """

    def construct_mapping(self, node: yaml.MappingNode, deep: bool = False) -> dict[Any, Any]:
        seen: set[Any] = set()
        for key_node, _value_node in node.value:
            key = self.construct_object(key_node, deep=True)
            try:
                duplicate = key in seen
                seen.add(key)
            except TypeError:
                continue  # unhashable key: the base class reports it
            if duplicate:
                raise yaml.constructor.ConstructorError(
                    None, None, f"duplicate key {key!r}", key_node.start_mark
                )
        return super().construct_mapping(node, deep=deep)


def _load_yaml(content: str) -> Any:
    return yaml.load(content, Loader=_RuleYamlLoader)  # noqa: S506 - a SafeLoader subclass


# ---------------------------------------------------------------------------
# Condition validation
# ---------------------------------------------------------------------------

_BOOL_OPERATORS = frozenset({"exists", "not_exists", "is_true", "is_empty", "is_world_cidr"})
_SCALAR = (str, int, float, bool)


class _Context:
    """Where a condition lives, for error messages."""

    def __init__(self, rule_id: str, source: str) -> None:
        self.rule_id = rule_id
        self.source = source

    def fail(self, path: str, message: str) -> NoReturn:
        where = f" in {self.source}" if self.source else ""
        raise RuleLoadError(f"Rule {self.rule_id}{where}: {path}: {message}")


def _suggest(word: str, choices: Iterable[str], cutoff: float = 0.6) -> str:
    close = difflib.get_close_matches(word, sorted(choices), n=1, cutoff=cutoff)
    return f" (did you mean '{close[0]}'?)" if close else ""


def validate_condition(
    condition: Any, *, rule_id: str, source: str | Path = "", path: str = "condition"
) -> None:
    """Raise RuleLoadError unless ``condition`` is a well-formed rule condition.

    A condition is either a logical operator (``all_of``, ``any_of``, ``none_of``, ``not``)
    alone, or a mapping of property paths to checks, which are ANDed.
    Operator names, argument types, property paths, port lists and nesting depth are checked.
    """
    _validate_node(condition, _Context(rule_id, str(source)), path, 0)


def _validate_node(cond: Any, ctx: _Context, path: str, depth: int) -> None:
    if depth > MAX_CONDITION_DEPTH:
        ctx.fail(path, f"conditions may nest at most {MAX_CONDITION_DEPTH} levels deep")
    if not isinstance(cond, Mapping):
        ctx.fail(path, f"must be a mapping, got {type(cond).__name__}")
    if not cond:
        ctx.fail(path, "must not be empty")
    for key in cond:
        if not isinstance(key, str):
            ctx.fail(path, f"keys must be strings, got {key!r}")
    logical = [key for key in cond if key in LOGICAL_OPERATORS]
    if logical:
        if len(logical) > 1:
            ctx.fail(
                path,
                f"has more than one logical operator ({', '.join(sorted(logical))}); "
                "nest them instead",
            )
        others = sorted(set(cond) - set(logical))
        if others:
            ctx.fail(
                path,
                f"mixes the logical operator '{logical[0]}' with property keys {others}; "
                "put the properties inside the operator",
            )
        _validate_logical(logical[0], cond[logical[0]], ctx, f"{path}.{logical[0]}", depth)
        return
    for key, check in cond.items():
        _validate_property(key, check, ctx, f"{path}.{key}", depth)


def _validate_logical(op: str, argument: Any, ctx: _Context, path: str, depth: int) -> None:
    if op == "not":
        if not isinstance(argument, Mapping):
            ctx.fail(path, f"'not' takes a condition mapping, got {type(argument).__name__}")
        _validate_node(argument, ctx, path, depth + 1)
        return
    if not isinstance(argument, list | tuple) or not argument:
        ctx.fail(path, f"'{op}' takes a non-empty list of conditions")
    for index, item in enumerate(argument):
        _validate_node(item, ctx, f"{path}[{index}]", depth + 1)


def _validate_property(key: str, check: Any, ctx: _Context, path: str, depth: int) -> None:
    if key in ELEMENT_PREDICATES:
        _validate_ports(check, ctx, path)
        return
    if key in VALID_OPERATORS:
        ctx.fail(
            path,
            f"'{key}' is an operator, not a property; "
            "write the property path first, then the operator under it",
        )
    close_logical = difflib.get_close_matches(key, sorted(LOGICAL_OPERATORS), n=1, cutoff=0.8)
    if (
        close_logical
        and isinstance(check, list)
        and check
        and all(isinstance(item, Mapping) for item in check)
    ):
        ctx.fail(path, f"unknown logical operator '{key}' (did you mean '{close_logical[0]}'?)")
    try:
        parse_path(key)
    except PathError as e:
        ctx.fail(path, f"invalid property path: {e}")
    if isinstance(check, Mapping):
        if not check:
            ctx.fail(path, "has no operator; write one such as 'equals' or 'exists'")
        for op, argument in check.items():
            _validate_operator(op, argument, ctx, f"{path}.{op}", depth)
    elif check is None:
        ctx.fail(path, "null is not a comparison value; use 'not_exists: true' to test for absence")


def _fail_not_a_property_operator(op: Any, ctx: _Context, path: str) -> NoReturn:
    """Reject a key under a property that is not a property operator, with the likely cause."""
    if isinstance(op, str) and op in LOGICAL_OPERATORS:
        ctx.fail(path, f"the logical operator '{op}' goes around properties, not under one")
    if isinstance(op, str) and op in ELEMENT_PREDICATES:
        ctx.fail(path, f"'{op}' is checked on a whole mapping; use it as a key, not as an operator")
    ctx.fail(
        path,
        f"Unknown operator {op!r}{_suggest(str(op), VALID_OPERATORS)}. "
        f"Valid operators: {', '.join(sorted(VALID_OPERATORS))}",
    )


def _validate_operator(op: Any, argument: Any, ctx: _Context, path: str, depth: int) -> None:
    if not isinstance(op, str) or op not in PROPERTY_OPERATORS:
        _fail_not_a_property_operator(op, ctx, path)
    if op in QUANTIFIER_OPERATORS:
        if not isinstance(argument, Mapping):
            ctx.fail(path, f"'{op}' takes a condition mapping, got {type(argument).__name__}")
        _validate_node(argument, ctx, path, depth + 1)
        return
    _validate_value_argument(op, argument, ctx, path)


def _validate_value_argument(op: str, argument: Any, ctx: _Context, path: str) -> None:
    """Check the argument of an operator that compares a value (every one but the quantifiers)."""
    if op in _BOOL_OPERATORS:
        if not isinstance(argument, bool):
            ctx.fail(path, f"'{op}' takes true or false, got {argument!r}")
    elif op == "matches_any":
        if not isinstance(argument, list | tuple) or not argument:
            ctx.fail(path, "'matches_any' takes a non-empty list of values")
        if not all(isinstance(item, _SCALAR) for item in argument):
            ctx.fail(path, "'matches_any' values must be strings, numbers or booleans")
    elif op in ("greater_than", "less_than"):
        if isinstance(argument, bool) or not isinstance(argument, int | float):
            ctx.fail(path, f"'{op}' takes a number, got {argument!r}")
    elif op == "equals_ci":
        if not isinstance(argument, str):
            ctx.fail(path, f"'equals_ci' takes a string, got {argument!r}")
    elif op in ("contains", "not_contains"):
        if not isinstance(argument, _SCALAR):
            ctx.fail(path, f"'{op}' takes a string, number or boolean, got {argument!r}")
    elif op in ("equals", "not_equals") and argument is None:
        ctx.fail(path, f"'{op}' cannot compare with null; use 'exists' or 'not_exists'")


def _validate_ports(argument: Any, ctx: _Context, path: str) -> None:
    if not isinstance(argument, list | tuple) or not argument:
        ctx.fail(path, "'port_overlaps' takes a non-empty list of ports such as [22, '1024-2048']")
    try:
        parse_port_ranges(argument)
    except ValueError as e:
        ctx.fail(path, f"'port_overlaps' list is invalid: {e}")


# ---------------------------------------------------------------------------
# Rule files
# ---------------------------------------------------------------------------

_BUILTIN_DIR = Path(__file__).parent / "builtin"
_TOP_LEVEL_KEYS = frozenset({"rules", "deprecated_ids"})


def _source_group(path: Path) -> str:
    """Name the rule file a rule came from: 'aws__s3' for builtin/aws/s3.yml."""
    try:
        relative = path.resolve().relative_to(_BUILTIN_DIR.resolve())
    except ValueError:
        return f"custom__{path.stem}"
    return "__".join(relative.with_suffix("").parts)


def _resolve_resource_types(raw: Mapping[str, Any], rule_id: str, path: Path) -> tuple[str, ...]:
    prefix = f"Rule {rule_id} in {path}"
    has_one, has_many = "resource_type" in raw, "resource_types" in raw
    if has_one == has_many:
        raise RuleLoadError(f"{prefix}: set exactly one of resource_type or resource_types")
    if has_one:
        entries: Any = [raw["resource_type"]]
        field_name = "resource_type"
    else:
        entries = raw["resource_types"]
        field_name = "resource_types"
        if not isinstance(entries, list) or not entries:
            raise RuleLoadError(f"{prefix}: resource_types must be a non-empty list")
    resolved: list[str] = []
    for entry in entries:
        if not isinstance(entry, str) or not entry.strip():
            raise RuleLoadError(f"{prefix}: {field_name} entries must be non-empty strings")
        entry = entry.strip()
        if entry.startswith("@"):
            group = RESOURCE_TYPE_GROUPS.get(entry[1:])
            if group is None:
                known = ", ".join(f"@{name}" for name in sorted(RESOURCE_TYPE_GROUPS))
                raise RuleLoadError(
                    f"{prefix}: unknown resource type group '{entry}'. Known groups: {known}"
                )
            resolved.extend(group)
            continue
        if not _RESOURCE_TYPE_RE.fullmatch(entry) or entry == "*":
            raise RuleLoadError(
                f"{prefix}: invalid resource type '{entry}'; use an exact type or one trailing "
                "'*' after a prefix (for example 'aws_s3_bucket*'), with no other wildcard"
            )
        resolved.append(entry)
    return tuple(dict.fromkeys(resolved))


def _reference_list(metadata: Mapping[str, Any], name: str, prefix: str) -> list[Any]:
    """The values of a metadata field that names external references, one or a list."""
    value = metadata.get(name)
    if value is None:
        return []
    items = list(value) if isinstance(value, list) else [value]
    if not all(isinstance(item, str | int) and not isinstance(item, bool) for item in items):
        raise RuleLoadError(f"{prefix}: metadata.{name} must be an id or a list of ids")
    return items


def _validate_references(metadata: Mapping[str, Any], rule_id: str, prefix: str) -> None:
    """Check the ``cwe`` and ``cis`` fields reports show beside a finding (SARIF tags)."""
    for item in _reference_list(metadata, "cwe", prefix):
        if not _CWE_ID_RE.match(str(item).strip()):
            logger.warning("Rule %s: invalid CWE id '%s' - expected CWE-<number>", rule_id, item)
    for item in _reference_list(metadata, "cis", prefix):
        if not str(item).strip():
            raise RuleLoadError(f"{prefix}: metadata.cis must not hold an empty control id")


def _validate_metadata(metadata: Any, rule_id: str, path: Path) -> None:
    prefix = f"Rule {rule_id} in {path}"
    if not isinstance(metadata, Mapping):
        raise RuleLoadError(f"{prefix}: metadata must be a mapping")
    _validate_references(metadata, rule_id, prefix)
    mitre = metadata.get("mitre", {})
    if mitre in ({}, None):
        return
    if not isinstance(mitre, Mapping):
        raise RuleLoadError(f"{prefix}: metadata.mitre must be a mapping")
    for name in ("techniques", "tactics"):
        values = mitre.get(name, [])
        if not isinstance(values, list) or not all(isinstance(v, str) for v in values):
            raise RuleLoadError(f"{prefix}: metadata.mitre.{name} must be a list of strings")
    for tid in mitre.get("techniques", []):
        if not _TECHNIQUE_ID_RE.match(tid):
            logger.warning(
                "Rule %s: invalid MITRE technique ID '%s' - expected T#### or T####.###",
                rule_id,
                tid,
            )
        elif tid not in TECHNIQUE_DB:
            logger.warning(
                "Rule %s: MITRE technique ID '%s' not found in known technique database",
                rule_id,
                tid,
            )
        elif is_revoked(tid):
            logger.warning(
                "Rule %s: MITRE technique ID '%s' was revoked by ATT&CK - use '%s' instead",
                rule_id,
                tid,
                normalize_technique(tid),
            )
        elif is_deprecated(tid):
            logger.warning(
                "Rule %s: MITRE technique ID '%s' was deprecated by ATT&CK without a replacement",
                rule_id,
                tid,
            )
    for tac_id in mitre.get("tactics", []):
        if not _TACTIC_ID_RE.match(tac_id):
            logger.warning(
                "Rule %s: invalid MITRE tactic ID '%s' - expected TA####", rule_id, tac_id
            )


def _build_rule(raw: Any, path: Path, group: str) -> Rule:
    if not isinstance(raw, Mapping):
        raise RuleLoadError(f"Rule in {path} must be a mapping, got {type(raw).__name__}")
    for name in ("id", "title", "description", "stride_category", "severity", "condition"):
        if name not in raw:
            raise RuleLoadError(f"Rule in {path} missing required field: '{name}'")
    rule_id = str(raw["id"])
    if not rule_id.strip():
        raise RuleLoadError(f"Rule in {path} has an empty id")
    prefix = f"Rule {rule_id} in {path}"
    severity, stride = str(raw["severity"]), str(raw["stride_category"])
    if severity not in VALID_SEVERITIES:
        raise RuleLoadError(f"{prefix}: invalid severity '{severity}'")
    if stride not in VALID_STRIDE_CATEGORIES:
        raise RuleLoadError(f"{prefix}: invalid stride_category '{stride}'")
    resource_types = _resolve_resource_types(raw, rule_id, path)
    confidence = raw.get("confidence", "definitive")
    if confidence not in CONFIDENCE_LEVELS:
        raise RuleLoadError(
            f"{prefix}: invalid confidence {confidence!r}; "
            f"use one of {', '.join(CONFIDENCE_LEVELS)}"
        )
    root_cause = raw.get("root_cause", "")
    if not isinstance(root_cause, str):
        raise RuleLoadError(f"{prefix}: root_cause must be a string")
    metadata = raw.get("metadata") or {}
    _validate_metadata(metadata, rule_id, path)
    validate_condition(raw["condition"], rule_id=rule_id, source=path)
    return Rule(
        id=rule_id,
        title=str(raw["title"]),
        description=str(raw["description"]),
        stride_category=stride,
        severity=severity,
        resource_types=resource_types,
        condition=raw["condition"],
        mitigation=str(raw.get("mitigation", "")),
        metadata=metadata,
        source_group=group,
        confidence=confidence,
        root_cause=root_cause,
    )


def load_rule_file(path: Path) -> RuleFile:
    """Load and validate one rule file."""
    # Check file size before reading
    try:
        file_size = path.stat().st_size
    except OSError as e:
        raise RuleLoadError(f"Cannot stat rule file {path}: {e}") from e

    if file_size > MAX_RULE_FILE_SIZE:
        raise RuleLoadError(
            f"Rule file {path} is {file_size} bytes, exceeding {MAX_RULE_FILE_SIZE} byte limit"
        )

    try:
        data = _load_yaml(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as e:
        raise RuleLoadError(f"Failed to load rule file {path}: {e}") from e

    if not isinstance(data, dict) or "rules" not in data:
        raise RuleLoadError(f"Rule file {path} must contain a 'rules' key")
    unknown_keys = sorted(set(data) - _TOP_LEVEL_KEYS, key=str)
    if unknown_keys:
        logger.warning("Rule file %s has unknown top-level keys %s; ignored", path, unknown_keys)

    raw_rules = data["rules"]
    if not isinstance(raw_rules, list):
        raise RuleLoadError(f"Rule file {path}: 'rules' must be a list")

    if len(raw_rules) > MAX_RULES_PER_FILE:
        raise RuleLoadError(
            f"Rule file {path} has {len(raw_rules)} rules, exceeding limit of {MAX_RULES_PER_FILE}"
        )

    group = _source_group(path)
    rules = tuple(_build_rule(raw, path, group) for raw in raw_rules)

    deprecated = data.get("deprecated_ids", [])
    if not isinstance(deprecated, list) or not all(
        isinstance(item, str) and item.strip() for item in deprecated
    ):
        raise RuleLoadError(f"Rule file {path}: deprecated_ids must be a list of rule IDs")
    clash = sorted({rule.id for rule in rules} & set(deprecated))
    if clash:
        raise RuleLoadError(
            f"Rule file {path}: {', '.join(clash)} listed in deprecated_ids but still defined"
        )
    return RuleFile(rules=rules, deprecated_ids=frozenset(deprecated))


def load_rules_from_file(path: Path) -> list[Rule]:
    """Load rules from a single YAML file."""
    return list(load_rule_file(path).rules)


@dataclass(frozen=True)
class _BuiltinBundle:
    rules: tuple[Rule, ...]
    deprecated_ids: frozenset[str]
    files: tuple[tuple[str, int], ...]  # (file name, size in bytes)


@lru_cache(maxsize=1)
def _builtin_bundle() -> _BuiltinBundle:
    rules: list[Rule] = []
    deprecated: set[str] = set()
    files: list[tuple[str, int]] = []
    seen: set[str] = set()
    if _BUILTIN_DIR.exists():
        for path in sorted(_BUILTIN_DIR.rglob("*.yml")):
            loaded = load_rule_file(path)
            for rule in loaded.rules:
                if rule.id in seen:
                    raise RuleLoadError(
                        f"Duplicate rule ID '{rule.id}' in built-in rules. Rule IDs must be unique."
                    )
                seen.add(rule.id)
            rules.extend(loaded.rules)
            deprecated |= loaded.deprecated_ids
            files.append((path.name, path.stat().st_size))
    return _BuiltinBundle(tuple(rules), frozenset(deprecated), tuple(files))


def clear_builtin_cache() -> None:
    """Forget the loaded built-in rules (for tests that change rule files)."""
    _builtin_bundle.cache_clear()


def load_builtin_rules() -> tuple[Rule, ...]:
    """The built-in rules: loaded and validated once, then shared (they are immutable)."""
    bundle = _builtin_bundle()
    for name, size in bundle.files:
        logger.debug("Loading built-in rules: %s (%d bytes)", name, size)
    return bundle.rules


def _checked_extra_path(path: Path) -> Path:
    """Reject symlinks and non-files among the extra rule paths; return the resolved path."""
    # Security: block symlinks in extra rule paths
    if path.is_symlink():
        raise RuleLoadError(f"Extra rule path is a symlink (blocked for security): {path}")
    resolved = path.resolve()
    # Security: prevent path traversal via symlinks or .. components
    if not resolved.is_file():
        raise RuleLoadError(f"Extra rule path does not exist or is not a file: {path}")
    return resolved


def deprecated_rule_ids(extra_paths: list[Path] | None = None) -> frozenset[str]:
    """IDs that rule files list in ``deprecated_ids``: rules that were removed.

    Suppressions naming one of these should warn that the rule no longer exists.
    """
    ids = set(_builtin_bundle().deprecated_ids)
    for path in extra_paths or []:
        ids |= load_rule_file(_checked_extra_path(path)).deprecated_ids
    return frozenset(ids)


def load_all_rules(extra_paths: list[Path] | None = None) -> list[Rule]:
    """Load built-in rules plus any additional rule files."""
    rules = list(load_builtin_rules())

    # Enforce unique rule IDs (start with builtins)
    seen_ids: set[str] = set()
    for rule in rules:
        if rule.id in seen_ids:
            raise RuleLoadError(
                f"Duplicate rule ID '{rule.id}' in built-in rules. Rule IDs must be unique."
            )
        seen_ids.add(rule.id)

    for path in extra_paths or []:
        extra_rules = load_rules_from_file(_checked_extra_path(path))
        for rule in extra_rules:
            if rule.id in seen_ids:
                raise RuleLoadError(
                    f"Duplicate rule ID '{rule.id}' - already defined. Rule IDs must be unique."
                )
            seen_ids.add(rule.id)
        rules.extend(extra_rules)

    if len(rules) > MAX_TOTAL_RULES:
        raise RuleLoadError(f"Total rule count {len(rules)} exceeds limit of {MAX_TOTAL_RULES}")

    return rules
