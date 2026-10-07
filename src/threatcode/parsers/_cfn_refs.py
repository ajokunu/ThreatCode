"""Finding the resources a CloudFormation property tree refers to.

`scan_refs` walks the raw property tree of one resource, before any translation, and reports
every logical id that a ``Ref``, ``Fn::GetAtt`` or ``Fn::Sub`` names, with the attribute path
it was found under.
Only ids present in the template's ``Resources`` count, so parameters, pseudo parameters
(``AWS::Region``), conditions and mapping names produce nothing, and neither does an
``Fn::ImportValue``, which names another stack's export; those are returned separately.

Paths use ``.`` between keys and ``[]`` for every list of blocks, the same convention
as ``ParsedResource.references``.
A list whose items are all scalars or intrinsics is one attribute, so
``SubnetIds: [!Ref A, !Ref B]`` is found at ``SubnetIds``, while
``SecurityGroupIngress: [{SourceSecurityGroupId: !Ref G}]`` is found at
``SecurityGroupIngress[].SourceSecurityGroupId``.

The walk is bounded: it stops descending below ``MAX_DEPTH`` levels, never re-enters a
container it is already inside (a YAML anchor can make a structure contain itself), and
spends from a shared `WorkBudget`, because an alias bomb is cheap to load and enormous to
walk.
"""

from __future__ import annotations

import re
from collections.abc import Collection, Mapping
from dataclasses import dataclass, field
from typing import Any

from threatcode.exceptions import ParseError

# Levels of nesting read below a resource's properties; deeper values are left alone
MAX_DEPTH = 64
# Values (dict entries, list items and scalars) all passes of one template may visit
MAX_WORK = 3_000_000

_SUB_PLACEHOLDER = re.compile(r"\$\{([^}]*)\}")


class WorkBudget:
    """A shared count of the values a template's passes have visited."""

    def __init__(self, limit: int = MAX_WORK) -> None:
        self.limit = limit
        self.used = 0

    def spend(self, amount: int = 1) -> None:
        self.used += amount
        if self.used > self.limit:
            raise ParseError(
                f"CloudFormation template holds more than {self.limit:,} values once YAML "
                "aliases are expanded; refusing to read it. An alias that points at a "
                "structure containing aliases multiplies it at every level."
            )


@dataclass(frozen=True)
class RefHit:
    """One reference to a resource of the template."""

    path: str
    logical_id: str
    via: str  # "Ref", "GetAtt" or "Sub"


@dataclass
class RefScan:
    """What a property tree refers to."""

    hits: list[RefHit] = field(default_factory=list)
    # Names of other stacks' exports read with Fn::ImportValue, in first-seen order
    imports: list[str] = field(default_factory=list)

    @property
    def logical_ids(self) -> list[str]:
        """The referenced logical ids, ordered by first use and without repeats."""
        return list(dict.fromkeys(hit.logical_id for hit in self.hits))


def intrinsic_of(value: Any) -> tuple[str, Any] | None:
    """The ``(function, argument)`` of a single-key intrinsic mapping, else None.

    ``Ref`` and every ``Fn::`` key count; ``Condition`` does not, because it only appears
    in the Conditions section.
    """
    if isinstance(value, Mapping) and len(value) == 1:
        key = next(iter(value))
        if isinstance(key, str) and (key == "Ref" or key.startswith("Fn::")):
            return key, value[key]
    return None


def join_path(path: str, key: str) -> str:
    return f"{path}.{key}" if path else key


def sub_template(argument: Any) -> tuple[str, Mapping[str, Any]] | None:
    """The template text and variable map of an ``Fn::Sub`` argument, else None."""
    if isinstance(argument, str):
        return argument, {}
    if isinstance(argument, list) and argument and isinstance(argument[0], str):
        variables = argument[1] if len(argument) > 1 and isinstance(argument[1], Mapping) else {}
        return argument[0], variables
    return None


def sub_names(template: str) -> list[str]:
    """The variable names in a Sub template, without ``${!Literal}`` escapes.

    ``${Bucket.Arn}`` yields ``Bucket``; ``${AWS::Region}`` yields ``AWS::Region``.
    """
    names: list[str] = []
    for placeholder in _SUB_PLACEHOLDER.findall(template):
        text = placeholder.strip()
        if not text or text.startswith("!"):
            continue
        names.append(text.split(".", 1)[0])
    return names


def getatt_target(argument: Any) -> str | None:
    """The logical id an ``Fn::GetAtt`` argument names, in list or dotted form."""
    if isinstance(argument, str):
        return argument.split(".", 1)[0] or None
    if isinstance(argument, list) and argument and isinstance(argument[0], str):
        return argument[0].split(".", 1)[0] or None
    return None


class _Scanner:
    def __init__(self, logical_ids: Collection[str], budget: WorkBudget) -> None:
        self.logical_ids = logical_ids
        self.budget = budget
        self.scan = RefScan()
        self._seen_hits: set[tuple[str, str]] = set()
        self._active: set[int] = set()

    def hit(self, path: str, logical_id: str, via: str) -> None:
        if logical_id not in self.logical_ids or (path, logical_id) in self._seen_hits:
            return
        self._seen_hits.add((path, logical_id))
        self.scan.hits.append(RefHit(path, logical_id, via))

    def walk(self, value: Any, path: str, depth: int) -> None:
        self.budget.spend()
        if depth > MAX_DEPTH:
            return
        intrinsic = intrinsic_of(value)
        if intrinsic is not None:
            self._intrinsic(intrinsic[0], intrinsic[1], path, depth)
            return
        if isinstance(value, Mapping | list):
            marker = id(value)
            if marker in self._active:
                return  # a YAML anchor made the structure contain itself
            self._active.add(marker)
            try:
                if isinstance(value, Mapping):
                    for key, child in value.items():
                        self.walk(child, join_path(path, str(key)), depth + 1)
                else:
                    self._walk_list(value, path, depth)
            finally:
                self._active.discard(marker)

    def _walk_list(self, items: list[Any], path: str, depth: int) -> None:
        for item in items:
            nested = isinstance(item, list) or (
                isinstance(item, Mapping) and intrinsic_of(item) is None
            )
            self.walk(item, f"{path}[]" if nested else path, depth + 1)

    def _intrinsic(self, name: str, argument: Any, path: str, depth: int) -> None:
        if name == "Ref":
            if isinstance(argument, str):
                self.hit(path, argument, "Ref")
            return
        if name == "Fn::GetAtt":
            target = getatt_target(argument)
            if target is not None:
                self.hit(path, target, "GetAtt")
            if isinstance(argument, list):
                for extra in argument[1:]:
                    self.walk(extra, path, depth + 1)  # a dynamic attribute name
            return
        if name == "Fn::Sub":
            self._sub(argument, path, depth)
            return
        if name == "Fn::ImportValue":
            self._import(argument)
            self.walk(argument, path, depth + 1)
            return
        if name in ("Fn::If", "Fn::FindInMap") and isinstance(argument, list) and argument:
            # The first item names a condition or a mapping, which is not a resource
            for item in argument[1:] if isinstance(argument[0], str) else argument:
                self.walk(item, path, depth + 1)
            return
        self.walk(argument, path, depth + 1)

    def _sub(self, argument: Any, path: str, depth: int) -> None:
        parsed = sub_template(argument)
        if parsed is None:
            self.walk(argument, path, depth + 1)
            return
        template, variables = parsed
        for name in sub_names(template):
            if name not in variables:
                self.hit(path, name, "Sub")
        for variable in variables.values():
            self.walk(variable, path, depth + 1)

    def _import(self, argument: Any) -> None:
        if isinstance(argument, str):
            label = argument
        else:
            parsed = (
                sub_template(argument.get("Fn::Sub")) if isinstance(argument, Mapping) else None
            )
            label = parsed[0] if parsed else "(computed export name)"
        if label not in self.scan.imports:
            self.scan.imports.append(label)


def scan_refs(
    value: Any,
    logical_ids: Collection[str],
    *,
    budget: WorkBudget | None = None,
    base_path: str = "",
) -> RefScan:
    """Find the logical ids a raw property tree refers to, with their attribute paths.

    Args:
        value: The properties of one resource (or any part of a template).
        logical_ids: The ids declared in the template's ``Resources``; anything else is
            not a reference.
        budget: Shared work budget for the template; a private one when omitted.
        base_path: Prefix for every reported path.

    Raises:
        ParseError: The tree is larger than the budget allows.
    """
    scanner = _Scanner(logical_ids, budget or WorkBudget())
    scanner.walk(value, base_path, 0)
    return scanner.scan


def extract_refs(value: Any, logical_ids: Collection[str]) -> list[str]:
    """The logical ids a raw property tree refers to, ordered by first use, without repeats.

    ``Ref``, ``Fn::GetAtt`` (list and dotted form) and ``Fn::Sub`` (string and list form,
    ``${X}`` and ``${X.Attr}``) count, wherever they sit: inside ``Fn::Join``, ``Fn::If``,
    ``Fn::Select``, ``Fn::Split`` and any other intrinsic.
    ``${!Literal}``, pseudo parameters, names the Sub variable map supplies and ids that are
    not in ``logical_ids`` do not.
    """
    return scan_refs(value, logical_ids).logical_ids
