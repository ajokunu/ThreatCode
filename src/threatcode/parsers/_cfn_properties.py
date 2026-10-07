"""Translating CloudFormation properties to the attributes the rules read.

The rules, the zone logic and the graph's attachment table are written for Terraform
attribute names and shapes (`storage_encrypted`, `server_side_encryption_configuration`,
`vpc_config[].subnet_ids`), while a template spells everything in PascalCase, nests blocks
as plain mappings and hides values behind intrinsic functions.
`translate` bridges the two for one resource:

1. Intrinsics are resolved where the template decides them.
   A `Ref` to a parameter with a `Default` is the default, an `Fn::If` over conditions that
   parameter defaults decide takes its branch, `Ref AWS::NoValue` removes the property, and
   `Fn::Join`, `Fn::Sub`, `Fn::Select`, `Fn::Split`, `Fn::FindInMap` and `Fn::Base64` are
   evaluated when every part is known.
   Anything else (a `Ref` or `Fn::GetAtt` to a resource, a parameter with no default, a
   pseudo parameter such as `AWS::Region`) becomes `values.Unknown`, so a rule never reads
   it as "not configured".
2. Keys become snake_case, with a per-type table of the names that differ from Terraform's
   (`AccessControl` is `acl`, `SecurityGroupIds` is `vpc_security_group_ids`).
   Free-form maps (`Tags`, `Environment.Variables`) keep their keys.
3. Blocks take Terraform's shape: a nested block is a list of one mapping, so a rule can
   read `vpc_config.0.endpoint_public_access`, and the reference paths use `vpc_config[].x`.
4. Policy documents become compact JSON text with sorted keys, the form `jsonencode` and a
   Terraform plan produce, so a rule that looks for `"Action":"*"` sees the same text from
   either format.
   Unresolved values inside a document are written as the `Unknown` text.
5. `'true'`, `'false'` and numeric strings become scalars, except for attributes that hold
   names, identifiers, versions and other text.

The raw properties stay under `properties["_cfn"]`.
`Translation.paths` maps an attribute path of the raw tree to where it ended up, so the
references found in the raw tree can be keyed by the attribute a rule or the graph reads.
"""

from __future__ import annotations

import datetime
import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from threatcode.parsers._cfn_refs import (
    MAX_DEPTH,
    WorkBudget,
    getatt_target,
    intrinsic_of,
    join_path,
    sub_template,
)
from threatcode.values import Unknown, is_unknown

RAW_KEY = "_cfn"

# What `Ref AWS::NoValue` evaluates to: the property is left out
_NO_VALUE: Any = object()
# What a name that is not a parameter or pseudo parameter evaluates to
_UNRESOLVED: Any = object()

_SUB_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")

# Pseudo parameters whose value does not depend on where the stack is deployed
_FIXED_PSEUDO = {"AWS::Partition": "aws", "AWS::URLSuffix": "amazonaws.com"}

# ---------------------------------------------------------------------------
# Names
# ---------------------------------------------------------------------------

# Plural and mixed-case acronyms the generic rule would split in the wrong place
_ACRONYM_FIXES: tuple[tuple[str, str], ...] = (
    ("ARNs", "Arns"),
    ("IDs", "Ids"),
    ("URLs", "Urls"),
    ("CIDRs", "Cidrs"),
    ("IPs", "Ips"),
    ("IPv6", "Ipv6"),
    ("IPv4", "Ipv4"),
)
_ACRONYM_RUN = re.compile(r"([A-Z]+)([A-Z][a-z])")
_WORD_BOUNDARY = re.compile(r"([a-z0-9])([A-Z])")


def snake_case(key: str) -> str:
    """PascalCase to snake_case: `DBInstanceClass` is `db_instance_class`."""
    for old, new in _ACRONYM_FIXES:
        if old in key:
            key = key.replace(old, new)
    key = _ACRONYM_RUN.sub(r"\1_\2", key)
    return _WORD_BOUNDARY.sub(r"\1_\2", key).lower()


# ---------------------------------------------------------------------------
# Scalars
# ---------------------------------------------------------------------------

# Attributes that hold text even when the text looks like a number or a boolean
_TEXT_KEYS = frozenset(
    {
        "name", "id", "arn", "description", "password", "version", "value", "key", "prefix",
        "path", "domain", "identifier", "image", "command", "family", "alias", "cpu", "memory",
        "user_data", "comment", "text", "secret_string", "policy", "definition", "bucket",
        "endpoint", "schedule", "pattern", "tag", "label", "labels", "port_name", "username",
        "engine", "content", "template", "role", "type", "mode", "status", "state", "region",
        "zone", "availability_zone", "cidr_block", "protocol", "ip_protocol", "target",
    }
)  # fmt: skip
_TEXT_SUFFIXES = (
    "_name", "_id", "_ids", "_arn", "_arns", "_key", "_identifier", "_prefix", "_version",
    "_password", "_description", "_pattern", "_endpoint", "_url", "_uri", "_text", "_value",
    "_type", "_zone", "_cidr", "_cidrs", "_address", "_class", "_role", "_username",
)  # fmt: skip
_INT_TEXT = re.compile(r"-?(?:0|[1-9][0-9]{0,14})")
_FLOAT_TEXT = re.compile(r"-?(?:0|[1-9][0-9]{0,14})\.[0-9]{1,6}")


def coerce_scalar(key: str, value: Any) -> Any:
    """Turn 'true', 'false' and numeric strings into scalars for attributes that are not text.

    CloudFormation writes booleans and numbers as strings; a rule that compares with
    `false` or `0` needs the real scalar.
    """
    if not isinstance(value, str) or is_unknown(value):
        return value
    if key in _TEXT_KEYS or key.endswith(_TEXT_SUFFIXES):
        return value
    lowered = value.strip().lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if _INT_TEXT.fullmatch(value):
        return int(value)
    if _FLOAT_TEXT.fullmatch(value) and repr(float(value)) == value:
        return float(value)
    return value


def canonical_json(value: Any) -> Any:
    """Compact JSON text with sorted keys, the form `jsonencode` produces.

    A string stays as it is, and so does an `Unknown`.
    Unknown values inside a document are written as the `Unknown` text, which no rule
    reads as a wildcard.
    """
    if value is None or isinstance(value, str):
        return value
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def _text(value: Any) -> str | None:
    """A scalar as the text CloudFormation would substitute, or None when it is not one."""
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int | float):
        return str(value)
    if isinstance(value, str) and not is_unknown(value):
        return value
    return None


def first_unknown(value: Any, depth: int = 0) -> Unknown | None:
    """The first `Unknown` inside a resolved value, or None."""
    if is_unknown(value):
        return value
    if depth >= 12:
        return None
    if isinstance(value, Mapping):
        children: Any = value.values()
    elif isinstance(value, list):
        children = value
    else:
        return None
    for child in children:
        found = first_unknown(child, depth + 1)
        if found is not None:
            return found
    return None


# ---------------------------------------------------------------------------
# Template context and intrinsic resolution
# ---------------------------------------------------------------------------


@dataclass
class TemplateContext:
    """The parts of a template that decide intrinsics: parameters, conditions, mappings."""

    parameters: Mapping[str, Any] = field(default_factory=dict)
    conditions: Mapping[str, Any] = field(default_factory=dict)
    mappings: Mapping[str, Any] = field(default_factory=dict)
    budget: WorkBudget = field(default_factory=WorkBudget)

    @classmethod
    def from_template(
        cls, template: Mapping[str, Any], budget: WorkBudget | None = None
    ) -> TemplateContext:
        def section(name: str) -> Mapping[str, Any]:
            value = template.get(name)
            return value if isinstance(value, Mapping) else {}

        return cls(
            parameters=section("Parameters"),
            conditions=section("Conditions"),
            mappings=section("Mappings"),
            budget=budget or WorkBudget(),
        )


_LIST_PARAMETER_TYPES = ("CommaDelimitedList", "List<", "AWS::SSM::Parameter::Value<List<")


def _parameter_default(name: str, spec: Any) -> Any:
    """The value a parameter takes when nobody overrides its default, or `_UNRESOLVED`."""
    if not isinstance(spec, Mapping) or "Default" not in spec:
        return _UNRESOLVED
    default = spec["Default"]
    declared = spec.get("Type")
    kind = declared if isinstance(declared, str) else "String"
    if kind.startswith("AWS::SSM::Parameter::Value<"):
        return _UNRESOLVED  # the default is the name of an SSM parameter, not its value
    if kind.startswith(_LIST_PARAMETER_TYPES) and isinstance(default, str):
        items: list[Any] = [part.strip() for part in default.split(",")]
        if "Number" in kind:
            items = [coerce_scalar("n", part) for part in items]
        return items
    if kind == "Number" and isinstance(default, str):
        return coerce_scalar("n", default)
    if isinstance(default, bool):
        return "true" if default else "false"
    if isinstance(default, int | float) and kind != "Number":
        return str(default)
    if isinstance(default, datetime.date):
        return default.isoformat()
    return default


class _Resolver:
    """Resolves the intrinsics of one resource's properties."""

    def __init__(self, context: TemplateContext) -> None:
        self.context = context
        self.unresolved = 0
        self._active: set[int] = set()
        self._conditions_active: set[str] = set()

    def _unknown(self, reference: str) -> Unknown:
        self.unresolved += 1
        return Unknown(reference)

    # -- trees -----------------------------------------------------------------------

    def resolve(self, value: Any, depth: int = 0) -> Any:
        """A copy of `value` with every intrinsic resolved or replaced by an Unknown."""
        self.context.budget.spend()
        if depth > MAX_DEPTH:
            return Unknown("(nested too deeply to read)")
        if isinstance(value, Mapping):
            intrinsic = intrinsic_of(value)
            if intrinsic is not None:
                return self._intrinsic(intrinsic[0], intrinsic[1], depth)
            return self._guarded(value, depth, self._mapping)
        if isinstance(value, list):
            return self._guarded(value, depth, self._list)
        if isinstance(value, datetime.date):
            return value.isoformat()
        if value is None or isinstance(value, str | int | float | bool):
            return value
        return str(value)

    def _guarded(self, value: Any, depth: int, build: Callable[[Any, int], Any]) -> Any:
        marker = id(value)
        if marker in self._active:
            return Unknown("(structure that contains itself)")  # a YAML anchor cycle
        self._active.add(marker)
        try:
            return build(value, depth)
        finally:
            self._active.discard(marker)

    def _mapping(self, value: Mapping[Any, Any], depth: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, child in value.items():
            resolved = self.resolve(child, depth + 1)
            if resolved is not _NO_VALUE:
                result[str(key)] = resolved
        return result

    def _list(self, value: list[Any], depth: int) -> list[Any]:
        items = (self.resolve(child, depth + 1) for child in value)
        return [item for item in items if item is not _NO_VALUE]

    # -- intrinsics ------------------------------------------------------------------

    def _intrinsic(self, name: str, argument: Any, depth: int) -> Any:
        handler = {
            "Ref": self._ref,
            "Fn::GetAtt": self._getatt,
            "Fn::Sub": self._sub,
            "Fn::Join": self._join,
            "Fn::Select": self._select,
            "Fn::Split": self._split,
            "Fn::FindInMap": self._find_in_map,
            "Fn::Base64": self._base64,
            "Fn::If": self._if,
            "Fn::ImportValue": self._import_value,
        }.get(name)
        if handler is not None:
            return handler(argument, depth)
        if name in ("Fn::Equals", "Fn::And", "Fn::Or", "Fn::Not"):
            decided = self.condition({name: argument})
            return self._unknown(name) if decided is None else decided
        return self._unknown(name)

    def _ref_value(self, name: str) -> Any:
        """What `Ref name` is when the template decides it, else `_UNRESOLVED`."""
        if name == "AWS::NoValue":
            return _NO_VALUE
        if name in _FIXED_PSEUDO:
            return _FIXED_PSEUDO[name]
        if name.startswith("AWS::"):
            return _UNRESOLVED
        if name in self.context.parameters:
            return _parameter_default(name, self.context.parameters[name])
        return _UNRESOLVED

    def _ref(self, argument: Any, depth: int) -> Any:
        if not isinstance(argument, str):
            return self._unknown("Ref")
        value = self._ref_value(argument)
        if value is _UNRESOLVED:
            return self._unknown(argument)
        return value

    def _getatt(self, argument: Any, depth: int) -> Any:
        if isinstance(argument, list) and all(isinstance(part, str) for part in argument):
            return self._unknown(".".join(argument))
        target = getatt_target(argument)
        return self._unknown(argument if isinstance(argument, str) else target or "Fn::GetAtt")

    def _import_value(self, argument: Any, depth: int) -> Any:
        resolved = self.resolve(argument, depth + 1)
        text = _text(resolved)
        return self._unknown(f"Fn::ImportValue {text}" if text else "Fn::ImportValue")

    def _sub(self, argument: Any, depth: int) -> Any:
        parsed = sub_template(argument)
        if parsed is None:
            return self._unknown("Fn::Sub")
        template, variables = parsed
        values = {str(key): self.resolve(value, depth + 1) for key, value in variables.items()}
        blocked = first_unknown(list(values.values()))
        missing = False

        def substitute(match: re.Match[str]) -> str:
            nonlocal missing
            name = match.group(1).strip()
            if name.startswith("!"):
                return "${" + name[1:] + "}"
            value = values[name] if name in values else _UNRESOLVED
            if value is _UNRESOLVED and "." not in name:
                value = self._ref_value(name)
            text = _text(value) if value is not _UNRESOLVED else None
            if text is None:
                missing = True
                return match.group(0)
            return text

        rendered = _SUB_PLACEHOLDER.sub(substitute, template)
        if missing:
            return blocked if blocked is not None else self._unknown(template)
        return rendered

    def _join(self, argument: Any, depth: int) -> Any:
        if not (isinstance(argument, list) and len(argument) == 2):
            return self._unknown("Fn::Join")
        delimiter = self.resolve(argument[0], depth + 1)
        items = self.resolve(argument[1], depth + 1)
        inner = first_unknown([delimiter, items])
        if inner is not None:
            return inner
        parts = [_text(item) for item in items] if isinstance(items, list) else [None]
        if not isinstance(delimiter, str) or any(part is None for part in parts):
            return self._unknown("Fn::Join")
        return delimiter.join(part for part in parts if part is not None)

    def _select(self, argument: Any, depth: int) -> Any:
        if not (isinstance(argument, list) and len(argument) == 2):
            return self._unknown("Fn::Select")
        index = self.resolve(argument[0], depth + 1)
        items = self.resolve(argument[1], depth + 1)
        inner = first_unknown([index, items])
        if inner is not None:
            return inner
        position = _text(index)
        if isinstance(items, list) and position is not None and position.lstrip("-").isdigit():
            if 0 <= int(position) < len(items):
                return items[int(position)]
        return self._unknown("Fn::Select")

    def _split(self, argument: Any, depth: int) -> Any:
        if not (isinstance(argument, list) and len(argument) == 2):
            return self._unknown("Fn::Split")
        delimiter = self.resolve(argument[0], depth + 1)
        source = self.resolve(argument[1], depth + 1)
        inner = first_unknown([delimiter, source])
        if inner is not None:
            return inner
        if isinstance(delimiter, str) and delimiter and isinstance(source, str):
            return source.split(delimiter)
        return self._unknown("Fn::Split")

    def _find_in_map(self, argument: Any, depth: int) -> Any:
        if not (isinstance(argument, list) and len(argument) == 3):
            return self._unknown("Fn::FindInMap")
        name = self.resolve(argument[0], depth + 1)
        top = self.resolve(argument[1], depth + 1)
        second = self.resolve(argument[2], depth + 1)
        inner = first_unknown([name, top, second])
        if inner is not None:
            return inner
        table = self.context.mappings.get(name) if isinstance(name, str) else None
        row = table.get(top) if isinstance(table, Mapping) and isinstance(top, str) else None
        if isinstance(row, Mapping) and isinstance(second, str) and second in row:
            return self.resolve(row[second], depth + 1)
        return self._unknown("Fn::FindInMap")

    def _base64(self, argument: Any, depth: int) -> Any:
        resolved = self.resolve(argument, depth + 1)
        inner = first_unknown(resolved)
        if inner is not None:
            return inner
        # Kept as the text it encodes, which is what a Terraform user_data attribute holds
        return resolved if isinstance(resolved, str) else self._unknown("Fn::Base64")

    def _if(self, argument: Any, depth: int) -> Any:
        if not (isinstance(argument, list) and len(argument) == 3):
            return self._unknown("Fn::If")
        decided = self.condition(argument[0])
        if decided is None:
            name = argument[0] if isinstance(argument[0], str) else "Fn::If"
            return self._unknown(f"Fn::If {name}")
        return self.resolve(argument[1] if decided else argument[2], depth + 1)

    # -- conditions ------------------------------------------------------------------

    def condition(self, expression: Any, depth: int = 0) -> bool | None:
        """Whether a condition holds under the parameter defaults; None when it cannot be told."""
        self.context.budget.spend()
        if depth > MAX_DEPTH:
            return None
        if isinstance(expression, bool):
            return expression
        if isinstance(expression, str):
            return self._named_condition(expression, depth)
        if isinstance(expression, Mapping) and len(expression) == 1 and "Condition" in expression:
            named = expression["Condition"]
            return self._named_condition(named, depth) if isinstance(named, str) else None
        intrinsic = intrinsic_of(expression)
        if intrinsic is None:
            return None
        name, argument = intrinsic
        if name == "Fn::Equals":
            return self._equals(argument)
        if not isinstance(argument, list):
            return None
        results = [self.condition(item, depth + 1) for item in argument]
        if name == "Fn::Not":
            return None if not results or results[0] is None else not results[0]
        if name == "Fn::And":
            if any(result is False for result in results):
                return False
            return None if any(result is None for result in results) else True
        if name == "Fn::Or":
            if any(result is True for result in results):
                return True
            return None if any(result is None for result in results) else False
        return None

    def _named_condition(self, name: str, depth: int) -> bool | None:
        expression = self.context.conditions.get(name)
        if expression is None or name in self._conditions_active:
            return None
        self._conditions_active.add(name)
        try:
            return self.condition(expression, depth + 1)
        finally:
            self._conditions_active.discard(name)

    def _equals(self, argument: Any) -> bool | None:
        if not (isinstance(argument, list) and len(argument) == 2):
            return None
        before = self.unresolved
        left = self.resolve(argument[0])
        right = self.resolve(argument[1])
        self.unresolved = before  # deciding a condition is not an unresolved value
        if first_unknown([left, right]) is not None:
            return None
        left_text, right_text = _text(left), _text(right)
        if left_text is None or right_text is None:
            return None
        return left_text == right_text


# ---------------------------------------------------------------------------
# Path map
# ---------------------------------------------------------------------------

_LIST = "[]"


def _tokens(path: str) -> tuple[str, ...]:
    """`A[].B` is ('A', '[]', 'B')."""
    tokens: list[str] = []
    for segment in path.split(".") if path else []:
        key = segment
        markers = 0
        while key.endswith(_LIST):
            key = key[: -len(_LIST)]
            markers += 1
        if key:
            tokens.append(key)
        tokens.extend([_LIST] * markers)
    return tuple(tokens)


def _render(tokens: list[str] | tuple[str, ...]) -> str:
    parts: list[str] = []
    for token in tokens:
        if token == _LIST and parts:
            parts[-1] += _LIST
        else:
            parts.append(token)
    return ".".join(parts)


@dataclass(frozen=True)
class _PathRule:
    target: tuple[str, ...]
    # True: everything below the raw path ends up in the one translated attribute
    collapse: bool


class PathMap:
    """Where an attribute path of the raw template properties ended up after translation.

    Paths use `.` between keys and `[]` for every list of blocks.
    Only the places where translation moves, renames or flattens something are recorded;
    every other key keeps its position and is snake_cased.
    """

    def __init__(self) -> None:
        self._rules: dict[tuple[str, ...], _PathRule] = {}

    def add(self, raw: str, translated: str, *, collapse: bool = False) -> None:
        """Record that the raw path (and, unless `collapse`, what is below it) moved."""
        self._rules[_tokens(raw)] = _PathRule(_tokens(translated), collapse)

    def map(self, raw: str) -> str:
        """The translated attribute path of a raw attribute path."""
        tokens = _tokens(raw)
        for length in range(len(tokens), 0, -1):
            rule = self._rules.get(tokens[:length])
            if rule is not None:
                rest = () if rule.collapse else tokens[length:]
                return _render([*rule.target, *self._generic(rest)])
        return _render(self._generic(tokens))

    @staticmethod
    def _generic(tokens: tuple[str, ...]) -> list[str]:
        return [token if token == _LIST else snake_case(token) for token in tokens]

    def __len__(self) -> int:
        return len(self._rules)


# ---------------------------------------------------------------------------
# Converter
# ---------------------------------------------------------------------------

# (converter, raw path, value, the mapping being filled, translated path of that mapping)
Handler = Callable[["_Converter", str, Any, dict[str, Any], str], None]
Post = Callable[["_Converter", Mapping[str, Any], dict[str, Any]], None]


@dataclass(frozen=True)
class Spec:
    """How the properties of one CloudFormation type are translated.

    Every path is a raw attribute path: `.` between keys, `[]` for each list level,
    so `LoggingConfiguration.DestinationBucketName` and `Rules[].Statement`.
    """

    # raw path -> the Terraform name of that key
    rename: Mapping[str, str] = field(default_factory=dict)
    # raw paths of mappings that become a one-item list (a Terraform block)
    blocks: frozenset[str] = frozenset()
    # raw paths whose value becomes compact JSON text (a policy document)
    text: frozenset[str] = frozenset()
    # raw paths whose value is kept as written (a map of user-chosen keys)
    free: frozenset[str] = frozenset()
    # raw paths of mappings whose keys move up into the parent
    hoist: frozenset[str] = frozenset()
    # raw paths whose scalar value becomes a one-item list
    listify: frozenset[str] = frozenset()
    # raw paths whose ENABLED and DISABLED become booleans
    flags: frozenset[str] = frozenset()
    # raw path -> a function that writes the translated attribute(s) itself
    custom: Mapping[str, Handler] = field(default_factory=dict)
    # runs after the keys are converted, with the resolved raw properties
    post: Post | None = None
    # False keeps the keys as written (a Custom:: resource's properties are user-defined)
    snake_keys: bool = True


class _Converter:
    """Applies a Spec to a resolved property tree and records the path map."""

    def __init__(self, spec: Spec, budget: WorkBudget) -> None:
        self.spec = spec
        self.budget = budget
        self.paths = PathMap()

    def key(self, raw_key: str) -> str:
        return snake_case(raw_key) if self.spec.snake_keys else raw_key

    def convert_mapping(
        self, mapping: Mapping[str, Any], raw: str, tf: str, out: dict[str, Any], depth: int = 0
    ) -> None:
        spec = self.spec
        for key, value in mapping.items():
            self.budget.spend()
            child_raw = join_path(raw, key)
            handler = spec.custom.get(child_raw)
            if handler is not None:
                handler(self, child_raw, value, out, tf)
                continue
            if child_raw in spec.hoist and isinstance(value, Mapping) and depth < MAX_DEPTH:
                self.paths.add(child_raw, tf)
                self.convert_mapping(value, child_raw, tf, out, depth + 1)
                continue
            tf_key = spec.rename.get(child_raw) or self.key(key)
            child_tf = join_path(tf, tf_key)
            if child_raw in spec.text:
                out[tf_key] = canonical_json(value)
                self.paths.add(child_raw, child_tf, collapse=True)
            elif child_raw in spec.free:
                out[tf_key] = value
                self.paths.add(child_raw, child_tf, collapse=True)
            elif child_raw in spec.listify:
                out[tf_key] = self.as_list(value, tf_key)
                self.paths.add(child_raw, child_tf, collapse=True)
            elif child_raw in spec.flags:
                out[tf_key] = enabled_flag(value)
                self.paths.add(child_raw, child_tf, collapse=True)
            elif child_raw in spec.blocks and isinstance(value, Mapping) and depth < MAX_DEPTH:
                block: dict[str, Any] = {}
                self.paths.add(child_raw, f"{child_tf}{_LIST}")
                self.convert_mapping(value, child_raw, f"{child_tf}{_LIST}", block, depth + 1)
                out[tf_key] = [block]
            else:
                if tf_key != self.key(key):
                    self.paths.add(child_raw, child_tf)
                out[tf_key] = self.convert_value(value, child_raw, child_tf, tf_key, depth + 1)

    def convert_value(self, value: Any, raw: str, tf: str, key: str, depth: int = 0) -> Any:
        self.budget.spend()
        if depth > MAX_DEPTH:
            return value
        if isinstance(value, Mapping):
            out: dict[str, Any] = {}
            self.convert_mapping(value, raw, tf, out, depth)
            return out
        if isinstance(value, list):
            return [self._item(item, raw, tf, key, depth) for item in value]
        return coerce_scalar(key, value)

    def _item(self, item: Any, raw: str, tf: str, key: str, depth: int) -> Any:
        if isinstance(item, Mapping):
            out: dict[str, Any] = {}
            self.convert_mapping(item, f"{raw}{_LIST}", f"{tf}{_LIST}", out, depth + 1)
            return out
        if isinstance(item, list):
            return [
                self._item(inner, f"{raw}{_LIST}", f"{tf}{_LIST}", key, depth + 1) for inner in item
            ]
        return coerce_scalar(key, item)

    @staticmethod
    def as_list(value: Any, key: str = "") -> list[Any]:
        if isinstance(value, list):
            return [coerce_scalar(key, item) for item in value]
        return [coerce_scalar(key, value)]


def enabled_flag(value: Any) -> Any:
    """ENABLED and DISABLED (ECS, load balancers) as booleans; anything else unchanged."""
    if isinstance(value, str) and not is_unknown(value):
        upper = value.strip().upper()
        if upper == "ENABLED":
            return True
        if upper == "DISABLED":
            return False
    return coerce_scalar("flag", value)


# ---------------------------------------------------------------------------
# Handlers shared by several types
# ---------------------------------------------------------------------------


def _tags(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """A `[{Key, Value}]` list (or a plain map) becomes a `tags` mapping."""
    target = join_path(tf, "tags")
    conv.paths.add(raw, target, collapse=True)
    if is_unknown(value):
        out["tags"] = value
        return
    tags: dict[str, Any] = {}
    if isinstance(value, list):
        for item in value:
            if isinstance(item, Mapping) and isinstance(item.get("Key"), str):
                if not is_unknown(item["Key"]):
                    tags[item["Key"]] = _tag_value(item.get("Value"))
    elif isinstance(value, Mapping):
        tags = {str(key): _tag_value(item) for key, item in value.items()}
    out["tags"] = tags


def _tag_value(value: Any) -> Any:
    if value is None or is_unknown(value) or isinstance(value, str):
        return "" if value is None else value
    return _text(value) or str(value)


def _inline_policies(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`Policies: [{PolicyName, PolicyDocument}]` becomes `inline_policy: [{name, policy}]`."""
    target = join_path(tf, "inline_policy")
    conv.paths.add(f"{raw}{_LIST}.PolicyDocument", f"{target}{_LIST}.policy", collapse=True)
    conv.paths.add(f"{raw}{_LIST}.PolicyName", f"{target}{_LIST}.name", collapse=True)
    conv.paths.add(raw, target)
    if is_unknown(value):
        out["inline_policy"] = value
        return
    policies: list[Any] = []
    for item in value if isinstance(value, list) else []:
        if isinstance(item, Mapping):
            policies.append(
                {
                    "name": item.get("PolicyName"),
                    "policy": canonical_json(item.get("PolicyDocument")),
                }
            )
    out["inline_policy"] = policies


def _first(value: Any) -> Any:
    if isinstance(value, list):
        return value[0] if value else None
    return value


def _instance_profile_roles(
    conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str
) -> None:
    """The first role of an instance profile is its `role`; `roles` keeps them all."""
    conv.paths.add(raw, join_path(tf, "role"), collapse=True)
    roles = value if isinstance(value, list) else [value]
    out["roles"] = roles
    first = _first(roles)
    if first is not None:
        out["role"] = first


# --- S3 ---------------------------------------------------------------------------------

_CANNED_ACLS = {
    "Private": "private",
    "PublicRead": "public-read",
    "PublicReadWrite": "public-read-write",
    "AuthenticatedRead": "authenticated-read",
    "LogDeliveryWrite": "log-delivery-write",
    "BucketOwnerRead": "bucket-owner-read",
    "BucketOwnerFullControl": "bucket-owner-full-control",
    "AwsExecRead": "aws-exec-read",
}


def _acl(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`AccessControl: PublicRead` is the `acl` `public-read`."""
    conv.paths.add(raw, join_path(tf, "acl"), collapse=True)
    out["acl"] = _CANNED_ACLS.get(value, value) if isinstance(value, str) else value


def _versioning(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`VersioningConfiguration.Status: Enabled` is `versioning: [{enabled: true}]`."""
    conv.paths.add(raw, join_path(tf, f"versioning{_LIST}"))
    if not isinstance(value, Mapping):
        out["versioning"] = value
        return
    status = value.get("Status")
    if isinstance(status, str) and not is_unknown(status):
        enabled: Any = status.strip().lower() == "enabled"
    else:
        enabled = status
    out["versioning"] = [{"enabled": enabled}]


def _bucket_encryption(
    conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str
) -> None:
    """`BucketEncryption` becomes the `server_side_encryption_configuration` block."""
    target = join_path(tf, "server_side_encryption_configuration")
    conv.paths.add(raw, f"{target}{_LIST}.rule{_LIST}", collapse=True)
    if not isinstance(value, Mapping):
        out["server_side_encryption_configuration"] = value
        return
    rules: list[Any] = []
    configured = value.get("ServerSideEncryptionConfiguration")
    for item in configured if isinstance(configured, list) else []:
        if not isinstance(item, Mapping):
            continue
        rule: dict[str, Any] = {}
        default = item.get("ServerSideEncryptionByDefault")
        if isinstance(default, Mapping):
            rule["apply_server_side_encryption_by_default"] = [
                {
                    "sse_algorithm": default.get("SSEAlgorithm"),
                    "kms_master_key_id": default.get("KMSMasterKeyID"),
                }
            ]
        if "BucketKeyEnabled" in item:
            rule["bucket_key_enabled"] = coerce_scalar("flag", item["BucketKeyEnabled"])
        rules.append(rule)
    out["server_side_encryption_configuration"] = [{"rule": rules}]


# --- Security groups --------------------------------------------------------------------

_RULE_PATHS = {
    "CidrIp": "cidr_blocks",
    "CidrIpv6": "ipv6_cidr_blocks",
    "IpProtocol": "protocol",
    "SourceSecurityGroupId": "security_groups",
    "SourceSecurityGroupName": "security_groups",
    "DestinationSecurityGroupId": "security_groups",
    "SourcePrefixListId": "prefix_list_ids",
    "DestinationPrefixListId": "prefix_list_ids",
    "Description": "description",
    "FromPort": "from_port",
    "ToPort": "to_port",
}


def _present_list(item: Mapping[str, Any], *keys: str) -> list[Any]:
    for key in keys:
        if item.get(key) is not None:
            return _as_list(item[key])
    return []


def _as_list(value: Any) -> list[Any]:
    return list(value) if isinstance(value, list) else [value]


def _port(value: Any) -> Any:
    return coerce_scalar("port", value)


def security_group_rule(item: Mapping[str, Any]) -> dict[str, Any]:
    """One `SecurityGroupIngress` or `SecurityGroupEgress` entry in the shape of a plan's rule."""
    protocol = item.get("IpProtocol")
    protocol_text = _text(protocol) if protocol is not None else None
    rule: dict[str, Any] = {
        "cidr_blocks": _present_list(item, "CidrIp"),
        "description": item.get("Description") or "",
        "ipv6_cidr_blocks": _present_list(item, "CidrIpv6"),
        "prefix_list_ids": _present_list(item, "SourcePrefixListId", "DestinationPrefixListId"),
        "security_groups": _present_list(
            item, "SourceSecurityGroupId", "DestinationSecurityGroupId", "SourceSecurityGroupName"
        ),
        "self": False,
    }
    if protocol is not None:
        rule["protocol"] = protocol_text if protocol_text is not None else protocol
    from_port, to_port = _port(item.get("FromPort")), _port(item.get("ToPort"))
    if protocol_text == "-1":
        from_port = 0 if from_port is None else from_port
        to_port = 0 if to_port is None else to_port
    if from_port is not None:
        rule["from_port"] = from_port
    if to_port is not None:
        rule["to_port"] = to_port
    return rule


def _sg_rules(name: str) -> Handler:
    def handler(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
        target = join_path(tf, name)
        conv.paths.add(raw, target)
        for cfn_key, leaf in _RULE_PATHS.items():
            conv.paths.add(f"{raw}{_LIST}.{cfn_key}", f"{target}{_LIST}.{leaf}", collapse=True)
        if is_unknown(value):
            out[name] = value
            return
        items = value if isinstance(value, list) else [value]
        out[name] = [security_group_rule(item) for item in items if isinstance(item, Mapping)]

    return handler


def _standalone_rule(direction: str) -> Post:
    """Finish an `AWS::EC2::SecurityGroupIngress` or `Egress` as an `aws_security_group_rule`."""

    def post(conv: _Converter, raw: Mapping[str, Any], out: dict[str, Any]) -> None:
        out["type"] = direction
        out.setdefault("self", False)
        for key in ("cidr_blocks", "ipv6_cidr_blocks", "prefix_list_ids"):
            out.setdefault(key, [])
        protocol = out.get("protocol")
        if protocol is not None and not isinstance(protocol, str):
            out["protocol"] = _text(protocol) or protocol
        if out.get("protocol") == "-1":
            out.setdefault("from_port", 0)
            out.setdefault("to_port", 0)

    return post


_STANDALONE_RENAME = {
    "GroupId": "security_group_id",
    "IpProtocol": "protocol",
    "SourceSecurityGroupId": "source_security_group_id",
    "DestinationSecurityGroupId": "source_security_group_id",
    "SourceSecurityGroupName": "source_security_group_name",
    "CidrIp": "cidr_blocks",
    "CidrIpv6": "ipv6_cidr_blocks",
    "SourcePrefixListId": "prefix_list_ids",
    "DestinationPrefixListId": "prefix_list_ids",
}
_STANDALONE_LISTIFY = ("CidrIp", "CidrIpv6", "SourcePrefixListId", "DestinationPrefixListId")


# --- EC2 --------------------------------------------------------------------------------


def _instance_post(conv: _Converter, raw: Mapping[str, Any], out: dict[str, Any]) -> None:
    """Hoist what a network interface says about the public IP and the subnet."""
    interfaces = raw.get("NetworkInterfaces")
    if not isinstance(interfaces, list):
        return
    flags = [
        coerce_scalar("flag", item.get("AssociatePublicIpAddress"))
        for item in interfaces
        if isinstance(item, Mapping) and "AssociatePublicIpAddress" in item
    ]
    if flags and "associate_public_ip_address" not in out:
        if any(flag is True for flag in flags):
            out["associate_public_ip_address"] = True
        elif any(is_unknown(flag) for flag in flags):
            out["associate_public_ip_address"] = next(f for f in flags if is_unknown(f))
        else:
            out["associate_public_ip_address"] = False
        conv.paths.add(
            f"NetworkInterfaces{_LIST}.AssociatePublicIpAddress",
            "associate_public_ip_address",
            collapse=True,
        )
    for item in interfaces:
        if isinstance(item, Mapping) and item.get("SubnetId") is not None:
            out.setdefault("subnet_id", item["SubnetId"])
            break
    groups = [
        group
        for item in interfaces
        if isinstance(item, Mapping)
        for group in _as_list(item.get("GroupSet") or [])
    ]
    if groups and "vpc_security_group_ids" not in out:
        out["vpc_security_group_ids"] = groups
        conv.paths.add(
            f"NetworkInterfaces{_LIST}.GroupSet", "vpc_security_group_ids", collapse=True
        )


_ROOT_DEVICES = ("/dev/xvda", "/dev/sda1", "xvda", "sda1")


def _block_devices(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`BlockDeviceMappings` becomes `root_block_device` and `ebs_block_device`."""
    conv.paths.add(raw, join_path(tf, "ebs_block_device"), collapse=True)
    if not isinstance(value, list):
        out["ebs_block_device"] = value
        return
    root: list[Any] = []
    others: list[Any] = []
    for item in value:
        ebs = item.get("Ebs") if isinstance(item, Mapping) else None
        if not isinstance(ebs, Mapping):
            continue
        device: dict[str, Any] = {}
        for key, child in ebs.items():
            tf_key = {"VolumeType": "volume_type", "VolumeSize": "volume_size"}.get(
                key, snake_case(key)
            )
            device[tf_key] = coerce_scalar(tf_key, child)
        name = item.get("DeviceName")
        if isinstance(name, str) and name.lower() in _ROOT_DEVICES and not root:
            root.append(device)
        else:
            device["device_name"] = name
            others.append(device)
    if root:
        out["root_block_device"] = root
    if others:
        out["ebs_block_device"] = others


_FLOW_LOG_TARGETS = {
    "VPC": "vpc_id",
    "Subnet": "subnet_id",
    "NetworkInterface": "eni_id",
    "TransitGateway": "transit_gateway_id",
    "TransitGatewayAttachment": "transit_gateway_attachment_id",
}


def _flow_log_post(conv: _Converter, raw: Mapping[str, Any], out: dict[str, Any]) -> None:
    kind = raw.get("ResourceType")
    resource_id = raw.get("ResourceId")
    key = _FLOW_LOG_TARGETS.get(kind) if isinstance(kind, str) else None
    if key is not None and resource_id is not None:
        out[key] = resource_id
        conv.paths.add("ResourceId", key, collapse=True)
    out.pop("resource_id", None)


# --- Load balancers ---------------------------------------------------------------------


def _lb_scheme(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`Scheme: internet-facing` is `internal: false`."""
    conv.paths.add(raw, join_path(tf, "internal"), collapse=True)
    if isinstance(value, str) and not is_unknown(value):
        out["internal"] = value.strip().lower() == "internal"
    elif is_unknown(value):
        out["internal"] = value


_LB_ATTRIBUTES = {
    "deletion_protection.enabled": "enable_deletion_protection",
    "idle_timeout.timeout_seconds": "idle_timeout",
    "routing.http.drop_invalid_header_fields.enabled": "drop_invalid_header_fields",
    "routing.http2.enabled": "enable_http2",
    "load_balancing.cross_zone.enabled": "enable_cross_zone_load_balancing",
}


def _lb_attributes(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`LoadBalancerAttributes: [{Key, Value}]` becomes the attributes Terraform names."""
    conv.paths.add(raw, join_path(tf, f"access_logs{_LIST}"), collapse=True)
    if not isinstance(value, list):
        return
    attributes = {
        item["Key"]: item.get("Value")
        for item in value
        if isinstance(item, Mapping) and isinstance(item.get("Key"), str)
    }
    for key, tf_key in _LB_ATTRIBUTES.items():
        if key in attributes:
            out[tf_key] = coerce_scalar(tf_key, attributes[key])
    enabled = coerce_scalar("flag", attributes.get("access_logs.s3.enabled"))
    if enabled is True or is_unknown(enabled):
        out["access_logs"] = [
            {
                "enabled": enabled,
                "bucket": attributes.get("access_logs.s3.bucket"),
                "prefix": attributes.get("access_logs.s3.prefix"),
            }
        ]


def _listener_certificates(
    conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str
) -> None:
    conv.paths.add(raw, join_path(tf, "certificate_arn"), collapse=True)
    first = _first(value)
    if isinstance(first, Mapping) and "CertificateArn" in first:
        out["certificate_arn"] = first["CertificateArn"]


# --- Data stores ------------------------------------------------------------------------


def _ddb_key_schema(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`KeySchema` becomes `hash_key` and `range_key`."""
    conv.paths.add(raw, join_path(tf, "hash_key"), collapse=True)
    for item in value if isinstance(value, list) else []:
        if not isinstance(item, Mapping):
            continue
        key_type = item.get("KeyType")
        if key_type == "HASH":
            out["hash_key"] = item.get("AttributeName")
        elif key_type == "RANGE":
            out["range_key"] = item.get("AttributeName")


# --- Containers -------------------------------------------------------------------------

_CONTAINER_FREE_KEYS = frozenset({"DockerLabels", "Options", "Labels"})


def _camel_keys(value: Any, depth: int = 0) -> Any:
    """ECS container definitions use camelCase keys in Terraform's JSON, PascalCase in templates."""
    if depth > MAX_DEPTH:
        return value
    if isinstance(value, Mapping):
        result: dict[str, Any] = {}
        for key, child in value.items():
            new_key = key[:1].lower() + key[1:] if key not in _CONTAINER_FREE_KEYS else key
            result[new_key] = (
                child if key in _CONTAINER_FREE_KEYS else _camel_keys(child, depth + 1)
            )
        return result
    if isinstance(value, list):
        return [_camel_keys(item, depth + 1) for item in value]
    return value


def _container_definitions(
    conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str
) -> None:
    conv.paths.add(raw, join_path(tf, "container_definitions"), collapse=True)
    out["container_definitions"] = canonical_json(_camel_keys(value))


def _eks_logging(conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str) -> None:
    """`Logging.ClusterLogging.EnabledTypes[].Type` becomes `enabled_cluster_log_types`."""
    conv.paths.add(raw, join_path(tf, "enabled_cluster_log_types"), collapse=True)
    cluster = value.get("ClusterLogging") if isinstance(value, Mapping) else None
    enabled = cluster.get("EnabledTypes") if isinstance(cluster, Mapping) else None
    if isinstance(enabled, list):
        types = [item.get("Type") for item in enabled if isinstance(item, Mapping)]
        if types:
            out["enabled_cluster_log_types"] = types


def _guardduty_volumes(
    conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str
) -> None:
    """`EbsVolumes: true` is the block `ebs_volumes { enable = true }`."""
    conv.paths.add(raw, join_path(tf, f"ebs_volumes{_LIST}"), collapse=True)
    if isinstance(value, Mapping):
        out["ebs_volumes"] = [{"enable": coerce_scalar("flag", value.get("Enable"))}]
    else:
        out["ebs_volumes"] = [{"enable": coerce_scalar("flag", value)}]


def _waf_default_action(
    conv: _Converter, raw: str, value: Any, out: dict[str, Any], tf: str
) -> None:
    """`DefaultAction: {Block: {}}` is `default_action { block {} }`."""
    conv.paths.add(raw, join_path(tf, f"default_action{_LIST}"), collapse=True)
    if not isinstance(value, Mapping):
        out["default_action"] = value
        return
    action: dict[str, Any] = {key.lower(): [{}] for key in ("Allow", "Block") if key in value}
    out["default_action"] = [action]


def _redshift_post(conv: _Converter, raw: Mapping[str, Any], out: dict[str, Any]) -> None:
    logging_block = out.get("logging")
    if isinstance(logging_block, list) and logging_block and isinstance(logging_block[0], dict):
        logging_block[0].setdefault("enable", True)


# ---------------------------------------------------------------------------
# The per-type table
# ---------------------------------------------------------------------------


def _spec(
    *,
    rename: Mapping[str, str] | None = None,
    blocks: tuple[str, ...] = (),
    text: tuple[str, ...] = (),
    free: tuple[str, ...] = (),
    hoist: tuple[str, ...] = (),
    listify: tuple[str, ...] = (),
    flags: tuple[str, ...] = (),
    custom: Mapping[str, Handler] | None = None,
    post: Post | None = None,
    snake_keys: bool = True,
) -> Spec:
    return Spec(
        rename=dict(rename or {}),
        blocks=frozenset(blocks),
        text=frozenset(text),
        free=frozenset(free),
        hoist=frozenset(hoist),
        listify=frozenset(listify),
        flags=frozenset(flags),
        custom={"Tags": _tags, **(custom or {})},
        post=post,
        snake_keys=snake_keys,
    )


_GENERIC = _spec()
_CUSTOM_RESOURCE = _spec(snake_keys=False)

_SEARCH_DOMAIN = _spec(
    rename={
        "EncryptionAtRestOptions": "encrypt_at_rest",
        "NodeToNodeEncryptionOptions": "node_to_node_encryption",
        "VPCOptions": "vpc_options",
    },
    blocks=(
        "EncryptionAtRestOptions",
        "NodeToNodeEncryptionOptions",
        "VPCOptions",
        "DomainEndpointOptions",
        "ClusterConfig",
        "EBSOptions",
        "AdvancedSecurityOptions",
        "AdvancedSecurityOptions.MasterUserOptions",
        "SnapshotOptions",
        "CognitoOptions",
    ),
    text=("AccessPolicies",),
)

SPECS: dict[str, Spec] = {
    "AWS::S3::Bucket": _spec(
        rename={
            "BucketName": "bucket",
            "LoggingConfiguration": "logging",
            "PublicAccessBlockConfiguration": "public_access_block",
            "WebsiteConfiguration": "website",
            "LoggingConfiguration.DestinationBucketName": "target_bucket",
            "LoggingConfiguration.LogFilePrefix": "target_prefix",
            "LifecycleConfiguration.Rules": "lifecycle_rule",
            "CorsConfiguration.CorsRules": "cors_rule",
        },
        blocks=("LoggingConfiguration", "PublicAccessBlockConfiguration", "WebsiteConfiguration"),
        hoist=("LifecycleConfiguration", "CorsConfiguration"),
        custom={
            "AccessControl": _acl,
            "VersioningConfiguration": _versioning,
            "BucketEncryption": _bucket_encryption,
        },
    ),
    "AWS::S3::BucketPolicy": _spec(rename={"PolicyDocument": "policy"}, text=("PolicyDocument",)),
    "AWS::EC2::SecurityGroup": _spec(
        rename={"GroupDescription": "description", "GroupName": "name"},
        custom={
            "SecurityGroupIngress": _sg_rules("ingress"),
            "SecurityGroupEgress": _sg_rules("egress"),
        },
    ),
    "AWS::EC2::SecurityGroupIngress": _spec(
        rename=_STANDALONE_RENAME,
        listify=_STANDALONE_LISTIFY,
        post=_standalone_rule("ingress"),
    ),
    "AWS::EC2::SecurityGroupEgress": _spec(
        rename=_STANDALONE_RENAME,
        listify=_STANDALONE_LISTIFY,
        post=_standalone_rule("egress"),
    ),
    "AWS::EC2::Instance": _spec(
        rename={
            "ImageId": "ami",
            "SecurityGroupIds": "vpc_security_group_ids",
            "SecurityGroups": "security_groups",
            "NetworkInterfaces": "network_interface",
        },
        blocks=("MetadataOptions",),
        custom={"BlockDeviceMappings": _block_devices},
        post=_instance_post,
    ),
    "AWS::EC2::LaunchTemplate": _spec(
        rename={
            "LaunchTemplateName": "name",
            "LaunchTemplateData.SecurityGroupIds": "vpc_security_group_ids",
            "LaunchTemplateData.SecurityGroups": "security_group_names",
        },
        blocks=(
            "LaunchTemplateData.MetadataOptions",
            "LaunchTemplateData.IamInstanceProfile",
            "LaunchTemplateData.BlockDeviceMappings[].Ebs",
        ),
        hoist=("LaunchTemplateData",),
    ),
    "AWS::EC2::Volume": _spec(rename={"VolumeType": "type"}),
    "AWS::EC2::VolumeAttachment": _spec(rename={"Device": "device_name"}),
    "AWS::EC2::EIP": _spec(rename={"InstanceId": "instance"}),
    "AWS::EC2::VPCEndpoint": _spec(rename={"PolicyDocument": "policy"}, text=("PolicyDocument",)),
    "AWS::EC2::FlowLog": _spec(
        rename={"DeliverLogsPermissionArn": "iam_role_arn"}, post=_flow_log_post
    ),
    "AWS::RDS::DBInstance": _spec(
        rename={
            "DBInstanceIdentifier": "identifier",
            "DBInstanceClass": "instance_class",
            "DBName": "db_name",
            "VPCSecurityGroups": "vpc_security_group_ids",
            "EnableIAMDatabaseAuthentication": "iam_database_authentication_enabled",
            "EnablePerformanceInsights": "performance_insights_enabled",
            "EnableCloudwatchLogsExports": "enabled_cloudwatch_logs_exports",
        },
    ),
    "AWS::RDS::DBCluster": _spec(
        rename={
            "DBClusterIdentifier": "cluster_identifier",
            "EnableIAMDatabaseAuthentication": "iam_database_authentication_enabled",
            "EnableCloudwatchLogsExports": "enabled_cloudwatch_logs_exports",
            "ServerlessV2ScalingConfiguration": "serverlessv2_scaling_configuration",
        },
        blocks=("ServerlessV2ScalingConfiguration",),
    ),
    "AWS::RDS::DBSubnetGroup": _spec(
        rename={"DBSubnetGroupName": "name", "DBSubnetGroupDescription": "description"}
    ),
    "AWS::ElasticLoadBalancingV2::LoadBalancer": _spec(
        rename={"Type": "load_balancer_type"},
        custom={"Scheme": _lb_scheme, "LoadBalancerAttributes": _lb_attributes},
    ),
    "AWS::ElasticLoadBalancingV2::Listener": _spec(
        rename={
            "DefaultActions": "default_action",
            "DefaultActions[].RedirectConfig": "redirect",
            "DefaultActions[].FixedResponseConfig": "fixed_response",
            "DefaultActions[].ForwardConfig": "forward",
            "DefaultActions[].AuthenticateCognitoConfig": "authenticate_cognito",
            "DefaultActions[].AuthenticateOidcConfig": "authenticate_oidc",
        },
        blocks=(
            "DefaultActions[].RedirectConfig",
            "DefaultActions[].FixedResponseConfig",
            "DefaultActions[].ForwardConfig",
            "DefaultActions[].AuthenticateCognitoConfig",
            "DefaultActions[].AuthenticateOidcConfig",
        ),
        custom={"Certificates": _listener_certificates},
    ),
    "AWS::Logs::LogGroup": _spec(rename={"LogGroupName": "name"}),
    "AWS::CloudTrail::Trail": _spec(
        rename={
            "TrailName": "name",
            "IsLogging": "enable_logging",
            "EventSelectors": "event_selector",
            "EventSelectors[].DataResources": "data_resource",
        },
    ),
    "AWS::IAM::Role": _spec(
        rename={"RoleName": "name", "AssumeRolePolicyDocument": "assume_role_policy"},
        text=("AssumeRolePolicyDocument",),
        custom={"Policies": _inline_policies},
    ),
    "AWS::IAM::User": _spec(rename={"UserName": "name"}, custom={"Policies": _inline_policies}),
    "AWS::IAM::Group": _spec(rename={"GroupName": "name"}, custom={"Policies": _inline_policies}),
    "AWS::IAM::Policy": _spec(
        rename={"PolicyName": "name", "PolicyDocument": "policy"}, text=("PolicyDocument",)
    ),
    "AWS::IAM::ManagedPolicy": _spec(
        rename={"ManagedPolicyName": "name", "PolicyDocument": "policy"}, text=("PolicyDocument",)
    ),
    "AWS::IAM::InstanceProfile": _spec(
        rename={"InstanceProfileName": "name"}, custom={"Roles": _instance_profile_roles}
    ),
    "AWS::IAM::AccessKey": _spec(rename={"UserName": "user"}),
    "AWS::KMS::Key": _spec(
        rename={
            "KeyPolicy": "policy",
            "PendingWindowInDays": "deletion_window_in_days",
            "KeySpec": "customer_master_key_spec",
            "Enabled": "is_enabled",
        },
        text=("KeyPolicy",),
    ),
    "AWS::SecretsManager::RotationSchedule": _spec(blocks=("RotationRules",)),
    "AWS::SecretsManager::ResourcePolicy": _spec(
        rename={"SecretId": "secret_arn", "ResourcePolicy": "policy"}, text=("ResourcePolicy",)
    ),
    "AWS::SNS::Topic": _spec(rename={"TopicName": "name"}),
    "AWS::SNS::TopicPolicy": _spec(rename={"PolicyDocument": "policy"}, text=("PolicyDocument",)),
    "AWS::SNS::Subscription": _spec(text=("FilterPolicy", "RedrivePolicy", "DeliveryPolicy")),
    "AWS::SQS::Queue": _spec(
        rename={"QueueName": "name"}, text=("RedrivePolicy", "RedriveAllowPolicy")
    ),
    "AWS::SQS::QueuePolicy": _spec(rename={"PolicyDocument": "policy"}, text=("PolicyDocument",)),
    "AWS::Lambda::Function": _spec(
        rename={"FileSystemConfigs": "file_system_config"},
        blocks=(
            "VpcConfig",
            "DeadLetterConfig",
            "TracingConfig",
            "Environment",
            "EphemeralStorage",
            "ImageConfig",
            "SnapStart",
        ),
        free=("Environment.Variables",),
        hoist=("Code",),
    ),
    "AWS::Lambda::Url": _spec(
        rename={"AuthType": "authorization_type", "TargetFunctionArn": "function_name"},
        blocks=("Cors",),
    ),
    "AWS::ApiGateway::RestApi": _spec(
        rename={"Policy": "policy"},
        blocks=("EndpointConfiguration",),
        text=("Policy",),
    ),
    "AWS::ApiGateway::Method": _spec(rename={"AuthorizationType": "authorization"}),
    "AWS::ApiGateway::Stage": _spec(
        rename={
            "AccessLogSetting": "access_log_settings",
            "TracingEnabled": "xray_tracing_enabled",
        },
        blocks=("AccessLogSetting",),
    ),
    "AWS::DynamoDB::Table": _spec(
        rename={
            "TableName": "name",
            "SSESpecification": "server_side_encryption",
            "SSESpecification.SSEEnabled": "enabled",
            "SSESpecification.KMSMasterKeyId": "kms_key_arn",
            "PointInTimeRecoverySpecification": "point_in_time_recovery",
            "PointInTimeRecoverySpecification.PointInTimeRecoveryEnabled": "enabled",
            "TimeToLiveSpecification": "ttl",
            "AttributeDefinitions": "attribute",
            "AttributeDefinitions[].AttributeName": "name",
            "AttributeDefinitions[].AttributeType": "type",
            "GlobalSecondaryIndexes": "global_secondary_index",
            "LocalSecondaryIndexes": "local_secondary_index",
            "ProvisionedThroughput.ReadCapacityUnits": "read_capacity",
            "ProvisionedThroughput.WriteCapacityUnits": "write_capacity",
        },
        blocks=("SSESpecification", "PointInTimeRecoverySpecification", "TimeToLiveSpecification"),
        hoist=("ProvisionedThroughput",),
        custom={"KeySchema": _ddb_key_schema},
    ),
    "AWS::ElastiCache::ReplicationGroup": _spec(
        rename={
            "ReplicationGroupDescription": "description",
            "CacheNodeType": "node_type",
            "CacheSubnetGroupName": "subnet_group_name",
            "CacheParameterGroupName": "parameter_group_name",
        },
    ),
    "AWS::ElastiCache::CacheCluster": _spec(
        rename={
            "CacheNodeType": "node_type",
            "VpcSecurityGroupIds": "security_group_ids",
            "CacheSubnetGroupName": "subnet_group_name",
        },
    ),
    "AWS::OpenSearchService::Domain": _SEARCH_DOMAIN,
    "AWS::Elasticsearch::Domain": _SEARCH_DOMAIN,
    "AWS::EKS::Cluster": _spec(
        rename={"ResourcesVpcConfig": "vpc_config", "EncryptionConfig": "encryption_config"},
        blocks=(
            "ResourcesVpcConfig",
            "EncryptionConfig[].Provider",
            "KubernetesNetworkConfig",
            "AccessConfig",
        ),
        custom={"Logging": _eks_logging},
    ),
    "AWS::EKS::Nodegroup": _spec(
        rename={
            "NodeRole": "node_role_arn",
            "NodegroupName": "node_group_name",
            "Subnets": "subnet_ids",
            "Taints": "taint",
            "RemoteAccess.SourceSecurityGroups": "source_security_group_ids",
        },
        blocks=("RemoteAccess", "ScalingConfig", "LaunchTemplate", "UpdateConfig"),
        free=("Labels",),
    ),
    "AWS::EKS::FargateProfile": _spec(
        rename={"Selectors": "selector", "Subnets": "subnet_ids"}, free=("Selectors[].Labels",)
    ),
    "AWS::ECS::Cluster": _spec(rename={"ClusterName": "name", "ClusterSettings": "setting"}),
    "AWS::ECS::TaskDefinition": _spec(
        rename={"Volumes": "volume"},
        blocks=("RuntimePlatform", "EphemeralStorage"),
        custom={"ContainerDefinitions": _container_definitions},
    ),
    "AWS::ECS::Service": _spec(
        rename={
            "NetworkConfiguration": "network_configuration",
            "LoadBalancers": "load_balancer",
            "NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp": "assign_public_ip",
        },
        blocks=("NetworkConfiguration",),
        hoist=("NetworkConfiguration.AwsvpcConfiguration",),
        flags=("NetworkConfiguration.AwsvpcConfiguration.AssignPublicIp",),
    ),
    "AWS::ECR::Repository": _spec(
        rename={"RepositoryName": "name", "RepositoryPolicyText": "repository_policy_text"},
        blocks=("ImageScanningConfiguration", "EncryptionConfiguration"),
        text=("RepositoryPolicyText",),
    ),
    "AWS::CloudFront::Distribution": _spec(
        rename={
            "DistributionConfig.Origins": "origin",
            "DistributionConfig.Origins[].Id": "origin_id",
            "DistributionConfig.Origins[].S3OriginConfig": "s3_origin_config",
            "DistributionConfig.Origins[].CustomOriginConfig": "custom_origin_config",
            "DistributionConfig.CacheBehaviors": "ordered_cache_behavior",
            "DistributionConfig.Logging": "logging_config",
            "DistributionConfig.IPV6Enabled": "is_ipv6_enabled",
            "DistributionConfig.CustomErrorResponses": "custom_error_response",
            "DistributionConfig.ViewerCertificate.CloudFrontDefaultCertificate": (
                "cloudfront_default_certificate"
            ),
        },
        blocks=(
            "DistributionConfig.DefaultCacheBehavior",
            "DistributionConfig.DefaultCacheBehavior.ForwardedValues",
            "DistributionConfig.Restrictions",
            "DistributionConfig.Restrictions.GeoRestriction",
            "DistributionConfig.Logging",
            "DistributionConfig.ViewerCertificate",
            "DistributionConfig.Origins[].S3OriginConfig",
            "DistributionConfig.Origins[].CustomOriginConfig",
        ),
        hoist=("DistributionConfig",),
    ),
    "AWS::WAFv2::WebACL": _spec(
        rename={"Rules": "rule", "VisibilityConfig": "visibility_config"},
        blocks=("VisibilityConfig",),
        custom={"DefaultAction": _waf_default_action},
    ),
    "AWS::GuardDuty::Detector": _spec(
        rename={"DataSources": "datasources"},
        blocks=(
            "DataSources",
            "DataSources.S3Logs",
            "DataSources.Kubernetes",
            "DataSources.Kubernetes.AuditLogs",
            "DataSources.MalwareProtection",
            "DataSources.MalwareProtection.ScanEc2InstanceWithFindings",
        ),
        custom={
            "DataSources.MalwareProtection.ScanEc2InstanceWithFindings.EbsVolumes": (
                _guardduty_volumes
            )
        },
    ),
    "AWS::Config::ConfigurationRecorder": _spec(blocks=("RecordingGroup",)),
    "AWS::Config::DeliveryChannel": _spec(
        rename={"ConfigSnapshotDeliveryProperties": "snapshot_delivery_properties"},
        blocks=("ConfigSnapshotDeliveryProperties",),
    ),
    "AWS::Config::ConfigurationAggregator": _spec(
        rename={
            "ConfigurationAggregatorName": "name",
            "AccountAggregationSources": "account_aggregation_source",
            "AccountAggregationSources[].AwsRegions": "regions",
            "AccountAggregationSources[].AllAwsRegions": "all_regions",
        },
        blocks=("OrganizationAggregationSource",),
    ),
    "AWS::Redshift::Cluster": _spec(
        rename={
            "DBName": "database_name",
            "LoggingProperties": "logging",
            "LoggingProperties.BucketName": "bucket_name",
        },
        blocks=("LoggingProperties",),
        post=_redshift_post,
    ),
    "AWS::SageMaker::NotebookInstance": _spec(
        rename={"NotebookInstanceName": "name", "SecurityGroupIds": "security_groups"}
    ),
    "AWS::Kinesis::Stream": _spec(
        rename={
            "RetentionPeriodHours": "retention_period",
            "StreamEncryption.KeyId": "kms_key_id",
        },
        blocks=("StreamModeDetails",),
        hoist=("StreamEncryption",),
    ),
    "AWS::Cognito::UserPool": _spec(
        rename={
            "UserPoolName": "name",
            "Policies.PasswordPolicy": "password_policy",
        },
        blocks=("Policies.PasswordPolicy", "AdminCreateUserConfig"),
        hoist=("Policies",),
    ),
    "AWS::Cognito::UserPoolClient": _spec(rename={"ClientName": "name"}),
    "AWS::AutoScaling::AutoScalingGroup": _spec(
        rename={
            "AutoScalingGroupName": "name",
            "LaunchConfigurationName": "launch_configuration",
            "LaunchTemplate.LaunchTemplateId": "id",
            "LaunchTemplate.LaunchTemplateName": "name",
        },
        blocks=("LaunchTemplate",),
    ),
    "AWS::Events::Rule": _spec(text=("EventPattern",)),
    "AWS::StepFunctions::StateMachine": _spec(
        rename={"StateMachineName": "name", "DefinitionString": "definition"},
        blocks=("LoggingConfiguration", "TracingConfiguration"),
    ),
    "AWS::CloudFormation::Stack": _spec(free=("Parameters",)),
    "AWS::Route53::RecordSet": _spec(
        rename={
            "ResourceRecords": "records",
            "HostedZoneId": "zone_id",
            "AliasTarget": "alias",
            "AliasTarget.DNSName": "name",
            "AliasTarget.HostedZoneId": "zone_id",
        },
        blocks=("AliasTarget",),
    ),
}

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


@dataclass
class Translation:
    """The result of translating one resource's properties."""

    properties: dict[str, Any]
    paths: PathMap
    # How many intrinsics became an Unknown
    unresolved: int = 0


def evaluate_condition(expression: Any, context: TemplateContext) -> bool | None:
    """Whether a condition (a name from ``Conditions`` or an expression) holds under the
    parameter defaults; None when the template cannot decide it."""
    return _Resolver(context).condition(expression)


def spec_for(cfn_type: str) -> Spec:
    """The translation spec of a CloudFormation type; a Custom:: type keeps its keys."""
    if cfn_type.startswith("Custom::") or cfn_type == "AWS::CloudFormation::CustomResource":
        return _CUSTOM_RESOURCE
    return SPECS.get(cfn_type, _GENERIC)


def translate(
    cfn_type: str,
    properties: Mapping[str, Any],
    context: TemplateContext | None = None,
) -> Translation:
    """Translate the properties of one resource to the attributes the rules read.

    Args:
        cfn_type: The CloudFormation type, such as ``AWS::S3::Bucket``.
        properties: The raw ``Properties`` mapping; it is not modified, and a reference to it
            is kept under ``properties["_cfn"]`` of the result.
        context: The template's parameters, conditions and mappings, which decide the
            intrinsics that can be decided. Without it only literals resolve.

    Returns:
        The translated properties, the path map from raw to translated attribute paths and
        the number of intrinsics left unresolved.

    Raises:
        ParseError: The properties hold more values than the context's work budget allows.
    """
    context = context or TemplateContext()
    resolver = _Resolver(context)
    resolved = resolver.resolve(properties)
    resolved_map: Mapping[str, Any] = resolved if isinstance(resolved, Mapping) else {}
    spec = spec_for(cfn_type)
    converter = _Converter(spec, context.budget)
    out: dict[str, Any] = {}
    converter.convert_mapping(resolved_map, "", "", out)
    if spec.post is not None:
        spec.post(converter, resolved_map, out)
    out[RAW_KEY] = properties
    return Translation(out, converter.paths, resolver.unresolved)
