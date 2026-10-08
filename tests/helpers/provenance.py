"""Which properties do rules read, and which does anything produce?

The provenance gate (tests/test_engine/test_rule_property_provenance.py) answers one question
for every builtin rule: when the rule reads ``<property>`` on a ``<resource type>``, can any
parser or enrichment module put that property there?
A rule that reads a property nothing produces never fires, and nothing says so: the finding is
simply absent (that is how seven Docker and Kubernetes rules, and sixteen Terraform ones, died).

This module has the two halves of the answer.

``rule_reads()`` walks every builtin rule condition and returns the ``(resource type, key)``
pairs it reads at the top level of the resource: the first segment of each property path, or
``derived.<fact>`` for the enrichment namespace.
Keys under ``any_item`` and the other quantifiers are properties of list elements and are not
read from the resource; ``port_overlaps`` is an operator written as a key.

``observed_properties()`` runs every parser and the enrichment over a corpus and records which
keys really appear on which resource types.
The corpus is the example snippets of the rule cases (tests/test_rules/cases), the fixtures,
and the example stacks: so a key that is observed was delivered by the real parser for a
realistic input.
"""

from __future__ import annotations

import importlib
from collections import defaultdict
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from functools import cache
from pathlib import Path
from typing import Any

from tests.test_rules.harness import discover_cases, graph_for
from threatcode.engine.rules.loader import Rule, load_builtin_rules
from threatcode.engine.rules.matcher import (
    ELEMENT_PREDICATES,
    LOGICAL_OPERATORS,
    parse_path,
    resource_type_matches,
)
from threatcode.ir.enrich import DERIVED, enrichment_modules
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import detect_and_parse

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES = REPO_ROOT / "tests" / "fixtures"
EXAMPLES = REPO_ROOT / "examples"

# Fixture directories that are not scan inputs
_NOT_INPUTS = frozenset({"golden", "schemas", "stix", "ingest", "secrets", "input_shapes"})
_INPUT_SUFFIXES = (".tf", ".json", ".yml", ".yaml")


@dataclass(frozen=True)
class Read:
    """One top-level property a rule reads on the resources it applies to."""

    rule_id: str
    resource_type: str
    key: str  # the first path segment, or ``derived.<fact>``


def condition_keys(condition: Any) -> Iterator[str]:
    """The property paths a condition tests on the resource itself.

    A logical operator is descended into; a property check is not, because what sits under a
    quantifier such as ``any_item`` is a condition on list elements.
    """
    if isinstance(condition, dict):
        for key, value in condition.items():
            if key in LOGICAL_OPERATORS:
                for part in value if isinstance(value, list | tuple) else [value]:
                    yield from condition_keys(part)
            elif key not in ELEMENT_PREDICATES:
                yield key
    elif isinstance(condition, list | tuple):
        for part in condition:
            yield from condition_keys(part)


def key_of(path: str) -> str:
    """``derived.<fact>`` for a derived path, else the first segment of the path."""
    atoms = parse_path(path)
    first = atoms[0].text
    if first == DERIVED and len(atoms) > 1:
        return f"{DERIVED}.{atoms[1].text}"
    return first


def reads_of(rule: Rule) -> set[Read]:
    return {
        Read(rule.id, resource_type, key_of(path))
        for path in condition_keys(rule.condition)
        for resource_type in rule.resource_types
    }


def rule_reads() -> list[Read]:
    return sorted(
        (read for rule in load_builtin_rules() for read in reads_of(rule)),
        key=lambda r: (r.resource_type, r.key, r.rule_id),
    )


def _keys_of(graph: InfraGraph) -> Iterator[tuple[str, str]]:
    for node in graph.nodes.values():
        for key, value in node.properties.items():
            if key == DERIVED and isinstance(value, dict):
                for fact in value:
                    yield node.resource_type, f"{DERIVED}.{fact}"
            else:
                yield node.resource_type, key


def _fixture_files() -> Iterator[Path]:
    for path in sorted(FIXTURES.rglob("*")):
        relative = path.relative_to(FIXTURES)
        if not path.is_file() or relative.parts[0] in _NOT_INPUTS:
            continue
        if path.suffix in _INPUT_SUFFIXES or path.name.startswith("Dockerfile"):
            yield path


def _graphs() -> Iterator[InfraGraph]:
    for case in discover_cases():
        for text in (case.bad, case.good):
            yield graph_for(case.fmt, text)
    for path in _fixture_files():
        try:
            yield InfraGraph.from_parsed(detect_and_parse(path))
        except Exception:  # noqa: BLE001 - fixtures made to fail a parser are not evidence
            continue
    # Directories go through discovery, which groups a module and finds a chart or a manifest set
    from threatcode.pipeline import ScanRequest, run_scan

    stacks = [p for p in sorted(EXAMPLES.iterdir()) if p.is_dir()]
    stacks += [p for p in sorted((FIXTURES / "helm").iterdir()) if p.is_dir()]
    for directory in stacks:
        result = run_scan(ScanRequest(paths=(str(directory),)))
        yield result.graph


@cache
def observed_properties() -> dict[str, frozenset[str]]:
    """Resource type to every property key (and ``derived.<fact>``) seen on it in the corpus."""
    seen: dict[str, set[str]] = defaultdict(set)
    for graph in _graphs():
        for resource_type, key in _keys_of(graph):
            seen[resource_type].add(key)
    return {resource_type: frozenset(keys) for resource_type, keys in seen.items()}


def observed_for(
    pattern: str, observed: Mapping[str, frozenset[str]] | None = None
) -> frozenset[str]:
    """Every key observed on a resource type matching ``pattern`` (exact, or a ``prefix*``)."""
    data = observed_properties() if observed is None else observed
    keys: set[str] = set()
    for resource_type, found in data.items():
        if resource_type_matches([pattern], resource_type):
            keys |= found
    return frozenset(keys)


def types_matching(patterns: Iterable[str], resource_type: str) -> bool:
    return resource_type_matches(list(patterns), resource_type)


# ---------------------------------------------------------------------------------------
# The PRODUCED registries
# ---------------------------------------------------------------------------------------

# The modules outside the enrichment package that write properties rules read.
# Every module of threatcode.ir.enrichment is added by producer_modules().
PARSER_MODULES = (
    "threatcode.parsers.cloudformation",
    "threatcode.parsers.dockerfile",
    "threatcode.parsers.helm",
    "threatcode.parsers.kubernetes",
    "threatcode.parsers.mcp_config",
    "threatcode.parsers.terraform_hcl",
    "threatcode.parsers.terraform_plan",
)
GRAPH_MODULES = ("threatcode.ir.enrich", "threatcode.ir.iam")


def producer_modules() -> list[str]:
    """Every module that is expected to export ``PRODUCED``."""
    enrichment = [module.__name__ for module in enrichment_modules()]
    return [*PARSER_MODULES, *GRAPH_MODULES, *enrichment]


def registry_of(module_name: str) -> Mapping[str, frozenset[str]]:
    registry: Mapping[str, frozenset[str]] = importlib.import_module(module_name).PRODUCED
    return registry


@cache
def declared_properties() -> dict[str, frozenset[str]]:
    """Every ``PRODUCED`` registry merged: resource type pattern to the properties declared."""
    merged: dict[str, set[str]] = defaultdict(set)
    for name in producer_modules():
        for pattern, keys in registry_of(name).items():
            merged[pattern] |= set(keys)
    return {pattern: frozenset(keys) for pattern, keys in merged.items()}


def _overlap(pattern: str, resource_type: str) -> bool:
    """Whether a registry pattern and a rule's resource type can name the same type.

    Either side may end in '*', which is a prefix.
    """
    if pattern == resource_type:
        return True
    left = pattern[:-1] if pattern.endswith("*") else None
    right = resource_type[:-1] if resource_type.endswith("*") else None
    if left is not None and right is not None:
        return left.startswith(right) or right.startswith(left)
    if left is not None:
        return resource_type.startswith(left)
    if right is not None:
        return pattern.startswith(right)
    return False


def declared_for(
    resource_type: str, declared: Mapping[str, frozenset[str]] | None = None
) -> frozenset[str]:
    """The properties some module declares for a resource type (a rule's type may be a glob)."""
    table = declared_properties() if declared is None else declared
    keys: set[str] = set()
    for pattern, names in table.items():
        if _overlap(pattern, resource_type):
            keys |= names
    return frozenset(keys)


def is_produced(
    read: Read,
    declared: Mapping[str, frozenset[str]] | None = None,
    observed: Mapping[str, frozenset[str]] | None = None,
) -> bool:
    """Whether a module declares the property, or the corpus shows a parser delivering it."""
    if read.key in declared_for(read.resource_type, declared):
        return True
    return read.key in observed_for(read.resource_type, observed)


def unproduced_reads(
    reads: Iterable[Read],
    declared: Mapping[str, frozenset[str]] | None = None,
    observed: Mapping[str, frozenset[str]] | None = None,
) -> list[Read]:
    return [read for read in reads if not is_produced(read, declared, observed)]
