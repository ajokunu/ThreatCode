"""Structural check that a JSON document has the shape ``terraform show -json`` emits.

A plan fixture that stores only ``planned_values`` and resolved attribute values
passes every parser test and hides the product gap that matters: real plans leave
create-time ids unknown, record them in ``after_unknown`` and put relationships in
``configuration.expressions.references``. This check rejects fixtures that lack those parts,
so an unrealistic plan cannot be added without saying so.

The check covers the parts the parsers and rules read, not the whole schema:

* top level: ``format_version`` 1.x, ``terraform_version``, ``planned_values``,
  ``resource_changes`` and ``configuration``;
* every planned resource has a matching ``resource_changes`` entry with the change keys
  ``actions``, ``before``, ``after`` and ``after_unknown``;
* an attribute that ``after_unknown`` marks unknown is absent from the planned values;
* every planned resource has a configuration entry (same address with the index removed).
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

_INDEX_RE = re.compile(r"\[(?:\d+|\"[^\"]*\"|'[^']*')\]")
_CHANGE_KEYS = ("actions", "before", "after", "after_unknown")


def base_address(address: str) -> str:
    """Remove ``[0]`` and ``["key"]`` instance keys at every level."""
    return _INDEX_RE.sub("", address)


def _planned_resources(module: dict[str, Any]) -> Iterator[dict[str, Any]]:
    yield from module.get("resources", []) or []
    for child in module.get("child_modules", []) or []:
        yield from _planned_resources(child)


def _config_addresses(module: dict[str, Any], prefix: str = "") -> Iterator[str]:
    for resource in module.get("resources", []) or []:
        address = resource.get("address") or f"{resource.get('type')}.{resource.get('name')}"
        yield f"{prefix}{address}" if not prefix or address.startswith(prefix) else address
    for name, call in (module.get("module_calls", {}) or {}).items():
        child_prefix = f"{prefix}module.{name}."
        for address in _config_addresses(call.get("module", {}) or {}, child_prefix):
            yield address if address.startswith(child_prefix) else f"{child_prefix}{address}"


def plan_shape_problems(data: Any) -> list[str]:
    """What is missing or unrealistic in a plan document; empty when it has the real shape."""
    if not isinstance(data, dict):
        return ["the document is not a JSON object"]
    problems: list[str] = []
    version = data.get("format_version")
    if not isinstance(version, str) or not version.startswith("1."):
        problems.append(f"format_version must be a 1.x string, got {version!r}")
    for key in ("terraform_version", "planned_values", "resource_changes", "configuration"):
        if key not in data:
            problems.append(f"missing top-level key {key}")
    if problems:
        return problems

    planned_root = (data["planned_values"] or {}).get("root_module")
    if not isinstance(planned_root, dict):
        return ["planned_values.root_module is missing"]
    changes = data["resource_changes"]
    if not isinstance(changes, list):
        return ["resource_changes must be a list"]
    by_address = {c.get("address"): c for c in changes if isinstance(c, dict)}
    config_root = (data["configuration"] or {}).get("root_module")
    if not isinstance(config_root, dict):
        return ["configuration.root_module is missing"]
    configured = {base_address(a) for a in _config_addresses(config_root)}

    for resource in _planned_resources(planned_root):
        address = resource.get("address", "<no address>")
        change = by_address.get(address)
        if change is None:
            problems.append(f"{address}: no resource_changes entry")
            continue
        body = change.get("change")
        if not isinstance(body, dict):
            problems.append(f"{address}: resource_changes entry has no change object")
            continue
        for key in _CHANGE_KEYS:
            if key not in body:
                problems.append(f"{address}: change is missing {key}")
        if resource.get("mode") != "data" and base_address(address) not in configured:
            problems.append(f"{address}: no configuration entry")
        unknown = body.get("after_unknown")
        values = resource.get("values") or {}
        if isinstance(unknown, dict):
            for attribute, flag in unknown.items():
                if flag is True and values.get(attribute) is not None:
                    problems.append(
                        f"{address}: {attribute} is unknown after apply but has the planned "
                        f"value {values.get(attribute)!r}"
                    )
    return problems
