"""Structured IAM-style policy documents.

AWS policies reach the scan in many spellings.
A Terraform plan holds a JSON string, usually pretty printed.
python-hcl2 keeps backslashes in quoted strings, so a hand written policy arrives with escaped
quotes, and it renders ``jsonencode({...})`` as ``${jsonencode({...})}`` around the *Python*
repr of the value (single quotes, ``True``, ``False``).
CloudFormation and translated resources carry a mapping already.

`normalize_policy` reads all of those into a list of `Statement` and never raises.
It never evaluates anything: JSON goes through `json.loads` and the Python repr through
`ast.literal_eval`, which accepts literals only.
What cannot be read, or depends on a value the scan does not have, is an
`Unknown` (`threatcode.values`) and not an empty list, so a rule can tell "this policy
allows nothing" from "this policy could not be read".

Values inside a statement that are a lone ``${...}`` expression (``'${var.actions}'``) become an
`Unknown` entry in the matching tuple.
A string that merely contains an interpolation (``'${aws_s3_bucket.b.arn}/*'``) is kept as written.

``NotPrincipal`` is not modelled: a statement that uses it has no principals.
"""

from __future__ import annotations

import ast
import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from typing import Any

from threatcode.values import Unknown, is_unknown

# A policy larger than this is not parsed (AWS limits policies to 20 KB)
MAX_POLICY_CHARS = 1_000_000
# Statements beyond this many are not read; the policy is then Unknown
MAX_STATEMENTS = 5_000

_JSONENCODE = re.compile(r"^\$\{\s*jsonencode\((.*)\)\s*\}$", re.DOTALL)
_WHOLE_INTERPOLATION = re.compile(r"^\$\{(.*)\}$", re.DOTALL)

EFFECTS: tuple[str, ...] = ("Allow", "Deny")


@dataclass(frozen=True)
class Statement:
    """One policy statement with every field a rule needs, as tuples of strings."""

    effect: str
    actions: tuple[str, ...] = ()
    not_actions: tuple[str, ...] = ()
    resources: tuple[str, ...] = ()
    not_resources: tuple[str, ...] = ()
    # Flattened from "*", {"AWS": ...}, {"Service": ...}, {"Federated": ...}; "*" is kept
    principals: tuple[str, ...] = ()
    has_condition: bool = False
    condition_keys: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        """Plain data (lists, no dataclasses) for `node.properties['derived']`."""
        return {
            "effect": self.effect,
            "actions": list(self.actions),
            "not_actions": list(self.not_actions),
            "resources": list(self.resources),
            "not_resources": list(self.not_resources),
            "principals": list(self.principals),
            "has_condition": self.has_condition,
            "condition_keys": list(self.condition_keys),
        }


def normalize_policy(value: Any) -> list[Statement] | Unknown:
    """Read a policy document in any spelling into statements.

    Accepts a mapping, a list of statements, a JSON string (any whitespace, escaped quotes,
    doubled backslashes), the ``${jsonencode(...)}`` Python repr that python-hcl2 emits, and
    an `Unknown`.
    Returns `Unknown` for anything else, for malformed input, and for a statement
    without a valid ``Effect``.
    """
    if is_unknown(value):
        return value
    document = read_document(value)
    if is_unknown(document):
        return document
    statements = _statement_list(document)
    if statements is None or len(statements) > MAX_STATEMENTS:
        return Unknown()
    result: list[Statement] = []
    for raw in statements:
        statement = _statement(raw)
        if statement is None:
            return Unknown()
        result.append(statement)
    return result


def statements_to_dicts(statements: Iterable[Statement]) -> list[dict[str, Any]]:
    return [s.to_dict() for s in statements]


def principal_is_wildcard(statement: Mapping[str, Any]) -> bool:
    """True when a statement dict (`Statement.to_dict`) names ``*`` as a principal."""
    return "*" in (statement.get("principals") or [])


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------


def read_document(value: Any) -> Any:
    """Read a JSON document in any spelling: a mapping or list, or an Unknown.

    This is the reader `normalize_policy` uses; it is also right for the other JSON-valued
    attributes (ECS container definitions, an SQS redrive policy).
    """
    if isinstance(value, (Mapping, list)):
        return value
    if not isinstance(value, str):
        return Unknown()
    if len(value) > MAX_POLICY_CHARS:
        return Unknown()
    text = value.strip()
    if not text:
        return Unknown()
    encoded = _JSONENCODE.match(text)
    if encoded:
        return _literal(encoded.group(1).strip(), text)
    whole = _WHOLE_INTERPOLATION.match(text)
    if whole:
        return Unknown(whole.group(1).strip())
    if text[0] in "{[":
        loaded = _json(text)
        if loaded is not None:
            return loaded
        loaded = _literal(text, "")
        return loaded
    # A JSON document that is itself a JSON string
    loaded = _json(text)
    if isinstance(loaded, str):
        return read_document(loaded) if loaded.strip() != text else Unknown()
    return Unknown()


def _json(text: str) -> Any:
    """Parse JSON, retrying with the escaping python-hcl2 leaves in quoted strings."""
    attempts = (
        text,
        text.replace('\\"', '"'),
        text.replace("\\\\", "\\").replace('\\"', '"'),
    )
    for attempt in attempts:
        try:
            loaded = json.loads(attempt)
        except (ValueError, RecursionError):
            continue
        if isinstance(loaded, (dict, list, str)):
            return loaded
    return None


def _literal(text: str, original: str) -> Any:
    try:
        loaded = ast.literal_eval(text)
    except (ValueError, SyntaxError, MemoryError, RecursionError, TypeError):
        # Not a literal: a function call or a bare reference inside jsonencode
        return Unknown(original or text)
    if isinstance(loaded, (dict, list)):
        return loaded
    return Unknown(original or text)


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------


def _statement_list(document: Any) -> list[Any] | None:
    if isinstance(document, list):
        return document
    if isinstance(document, Mapping):
        if "Statement" in document:
            raw = document["Statement"]
        elif "statement" in document:
            raw = document["statement"]
        else:
            return None
        if isinstance(raw, Mapping):
            return [raw]
        if isinstance(raw, list):
            return raw
    return None


def _field(raw: Mapping[str, Any], name: str) -> Any:
    """Policy keys are case sensitive in AWS, but CloudFormation translators may lowercase."""
    if name in raw:
        return raw[name]
    lowered = name.lower()
    for key, value in raw.items():
        if isinstance(key, str) and key.lower() == lowered:
            return value
    return None


def _statement(raw: Any) -> Statement | None:
    if not isinstance(raw, Mapping):
        return None
    effect = _effect(_field(raw, "Effect"))
    if effect is None:
        return None
    condition = _field(raw, "Condition")
    return Statement(
        effect=effect,
        actions=_strings(_field(raw, "Action")),
        not_actions=_strings(_field(raw, "NotAction")),
        resources=_strings(_field(raw, "Resource")),
        not_resources=_strings(_field(raw, "NotResource")),
        principals=_principals(_field(raw, "Principal")),
        has_condition=bool(condition),
        condition_keys=_condition_keys(condition),
    )


def _effect(value: Any) -> str | None:
    if isinstance(value, str) and not is_unknown(value):
        for effect in EFFECTS:
            if value.strip().lower() == effect.lower():
                return effect
    return None


def _strings(value: Any) -> tuple[str, ...]:
    """A string or a list of strings; a lone ``${...}`` becomes an Unknown entry."""
    if value is None:
        return ()
    items: list[Any] = list(value) if isinstance(value, (list, tuple)) else [value]
    found: list[str] = []
    for item in items:
        if is_unknown(item):
            found.append(item)
        elif isinstance(item, str):
            whole = _WHOLE_INTERPOLATION.match(item.strip())
            found.append(Unknown(whole.group(1).strip()) if whole else item)
        elif isinstance(item, bool) or item is None:
            continue
        elif isinstance(item, (int, float)):
            found.append(str(item))
        else:
            found.append(Unknown())
    return tuple(found)


def _principals(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, Mapping):
        found: list[str] = []
        for key in sorted(value, key=str):
            found.extend(_strings(value[key]))
        return tuple(found)
    return _strings(value)


def _condition_keys(condition: Any) -> tuple[str, ...]:
    """Every condition key under every operator, in order of appearance, without repeats."""
    keys: dict[str, None] = {}
    if isinstance(condition, Mapping):
        for operands in condition.values():
            if isinstance(operands, Mapping):
                for key in operands:
                    if isinstance(key, str):
                        keys.setdefault(key)
    return tuple(keys)
