"""Safe declarative condition evaluator for rule matching.

Supports structured dict operators — no eval() ever.
Security: recursion depth is capped to prevent stack overflow from malicious rules.
"""

from __future__ import annotations

import logging
from typing import Any

from threatcode.engine.rules.loader import Rule
from threatcode.ir.nodes import InfraNode

logger = logging.getLogger(__name__)

# Max nesting depth for logical operators (all_of, any_of, none_of, not)
MAX_CONDITION_DEPTH = 10


def evaluate_condition(
    condition: dict[str, Any], node: InfraNode, _depth: int = 0
) -> bool:
    """Evaluate a rule condition against an infrastructure node."""
    if _depth > MAX_CONDITION_DEPTH:
        return False  # Fail closed on excessively nested conditions

    op = _detect_operator(condition)
    if op:
        return bool(_OPERATORS[op](condition[op], node, _depth + 1))
    return _evaluate_property_conditions(condition, node)


def matches_rule(rule: Rule, node: InfraNode) -> bool:
    """Check if a rule matches a given node."""
    # Check resource type match (prefix matching)
    if not node.resource_type.startswith(rule.resource_type):
        return False
    return evaluate_condition(rule.condition, node)


def _detect_operator(condition: dict[str, Any]) -> str | None:
    """Detect top-level logical operator."""
    found: list[str] = [op for op in ("all_of", "any_of", "none_of", "not") if op in condition]
    if len(found) > 1:
        logger.warning("Condition has multiple operator keys %s — using first", found)
    return found[0] if found else None


def _evaluate_property_conditions(condition: dict[str, Any], node: InfraNode) -> bool:
    """Evaluate a flat dict of property conditions (implicit AND)."""
    for key, check in condition.items():
        if not _evaluate_single(key, check, node):
            return False
    return True


def _evaluate_single(key: str, check: Any, node: InfraNode) -> bool:
    """Evaluate a single property condition."""
    props = node.properties
    value = _resolve_path(props, key)

    if isinstance(check, dict):
        return _evaluate_check_operators(check, value, props, key)

    # Direct equality
    return bool(value == check)


def _evaluate_check_operators(
    check: dict[str, Any], value: Any, props: dict[str, Any], key: str
) -> bool:
    """Evaluate operator-based checks on a property value."""
    for op, expected in check.items():
        if op == "not_exists":
            result = value is None
            if not (result if expected else not result):
                return False
        elif op == "exists":
            result = value is not None
            if not (result if expected else not result):
                return False
        elif op == "equals":
            if value != expected:
                return False
        elif op == "not_equals":
            if value == expected:
                return False
        elif op == "contains":
            if not isinstance(value, str | list | dict):
                return False
            if expected not in value:
                return False
        elif op == "not_contains":
            if isinstance(value, str | list | dict) and expected in value:
                return False
        elif op == "matches_any":
            if not isinstance(expected, list):
                return False
            if value not in expected:
                return False
        elif op == "greater_than":
            if not isinstance(value, int | float) or value <= expected:
                return False
        elif op == "less_than":
            if not isinstance(value, int | float) or value >= expected:
                return False
        elif op == "is_true":
            if bool(value) != expected:
                return False
        elif op == "is_empty":
            result = value is None or value == "" or value == [] or value == {}
            if not (result if expected else not result):
                return False
        elif op == "property_path":
            # Check a nested path
            nested_value = _resolve_path(props, expected)
            if nested_value is None:
                return False
        else:
            # Unknown operator — fail closed
            return False
    return True


def _resolve_path(data: dict[str, Any], path: str) -> Any:
    """Resolve a dot-separated path in nested data."""
    current: Any = data
    for part in path.split("."):
        if isinstance(current, dict):
            current = current.get(part)
        elif isinstance(current, list):
            try:
                current = current[int(part)]
            except (ValueError, IndexError):
                return None
        else:
            return None
    return current


# Logical operators (depth-limited)
def _op_all_of(conditions: list[dict[str, Any]], node: InfraNode, depth: int) -> bool:
    if not isinstance(conditions, list):
        return False
    return all(evaluate_condition(c, node, depth) for c in conditions)


def _op_any_of(conditions: list[dict[str, Any]], node: InfraNode, depth: int) -> bool:
    if not isinstance(conditions, list):
        return False
    return any(evaluate_condition(c, node, depth) for c in conditions)


def _op_none_of(conditions: list[dict[str, Any]], node: InfraNode, depth: int) -> bool:
    if not isinstance(conditions, list):
        return False
    return not any(evaluate_condition(c, node, depth) for c in conditions)


def _op_not(condition: dict[str, Any], node: InfraNode, depth: int) -> bool:
    if not isinstance(condition, dict):
        return False
    return not evaluate_condition(condition, node, depth)


_OPERATORS: dict[str, Any] = {
    "all_of": _op_all_of,
    "any_of": _op_any_of,
    "none_of": _op_none_of,
    "not": _op_not,
}
