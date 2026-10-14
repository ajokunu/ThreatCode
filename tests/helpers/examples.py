"""Loaders and matchers for the demo examples under ``examples/``.

Each example directory holds a small, realistic input set and an ``expected.yml`` naming the nodes a
scan must model, the attack paths from the internet to the data and the key findings. The tests in
``tests/test_examples_paths.py`` and ``tests/test_examples_ingest.py`` read the files through this
module, so the two test files never import from each other and stay free to change in different
waves of the rework.
"""

from __future__ import annotations

from functools import cache
from pathlib import Path
from typing import Any

import yaml

from tests.helpers.kinds import KIND_PATTERNS
from tests.helpers.pending import validate_pending
from tests.helpers.scan import ScanResult, scan_files

REPO_ROOT = Path(__file__).resolve().parents[2]
EXAMPLES_DIR = REPO_ROOT / "examples"
EXAMPLES = sorted(p.name for p in EXAMPLES_DIR.iterdir() if (p / "expected.yml").is_file())

_TOP_KEYS = {
    "example",
    "inputs",
    "scanner_inputs",
    "nodes",
    "node_types",
    "attack_paths",
    "key_findings",
    "scanner",
}
_PATH_KEYS = {"id", "entry", "target", "via", "why"}
_FINDING_KEYS = {"resource", "rule_ids", "kind", "why", "pending"}


class ExampleError(Exception):
    """A malformed expected.yml."""


def validate_expected(data: Any, source: str) -> dict[str, Any]:
    """Check the shape of one expected.yml and return it."""
    if not isinstance(data, dict):
        raise ExampleError(f"{source}: must be a mapping")
    extra = set(data) - _TOP_KEYS
    if extra:
        raise ExampleError(f"{source}: unknown keys {sorted(extra)}")
    for key in ("example", "inputs", "attack_paths", "key_findings"):
        if key not in data:
            raise ExampleError(f"{source}: missing '{key}'")
    if not isinstance(data["inputs"], list) or not data["inputs"]:
        raise ExampleError(f"{source}: 'inputs' must list at least one file")
    seen: set[str] = set()
    for index, entry in enumerate(data["attack_paths"]):
        where = f"{source} attack_paths[{index}]"
        if not isinstance(entry, dict) or set(entry) - _PATH_KEYS:
            raise ExampleError(f"{where}: keys must be among {sorted(_PATH_KEYS)}")
        for key in ("id", "entry", "target", "why"):
            if not isinstance(entry.get(key), str) or not entry[key].strip():
                raise ExampleError(f"{where}: needs a non-empty '{key}'")
        if entry["id"] in seen:
            raise ExampleError(f"{where}: duplicate path id {entry['id']!r}")
        seen.add(entry["id"])
        via = entry.get("via", [])
        if not isinstance(via, list) or not all(isinstance(v, str) for v in via):
            raise ExampleError(f"{where}: 'via' must be a list of node ids")
    for index, entry in enumerate(data["key_findings"]):
        where = f"{source} key_findings[{index}]"
        if not isinstance(entry, dict) or set(entry) - _FINDING_KEYS:
            raise ExampleError(f"{where}: keys must be among {sorted(_FINDING_KEYS)}")
        if not isinstance(entry.get("resource"), str) or not entry.get("why"):
            raise ExampleError(f"{where}: needs 'resource' and 'why'")
        if not entry.get("rule_ids") and entry.get("kind") not in KIND_PATTERNS:
            raise ExampleError(f"{where}: needs rule_ids or a known kind")
        if "pending" in entry:
            package = (
                entry["pending"].get("package") if isinstance(entry["pending"], dict) else None
            )
            try:
                validate_pending(package, entry["pending"].get("reason"))
            except (ValueError, AttributeError) as exc:
                raise ExampleError(f"{where}: invalid pending: {exc}") from exc
    return data


@cache
def expected_for(name: str) -> dict[str, Any]:
    path = EXAMPLES_DIR / name / "expected.yml"
    return validate_expected(yaml.safe_load(path.read_text(encoding="utf-8")), str(path))


def input_paths(name: str) -> list[Path]:
    return [EXAMPLES_DIR / name / rel for rel in expected_for(name)["inputs"]]


@cache
def scan_example(name: str) -> ScanResult:
    return scan_files(input_paths(name))


def path_node_ids(path: dict[str, Any]) -> list[str]:
    """The node ids an attack path visits, in order.

    The report writes an attack path as ``hops``, each with a ``node_id`` (see
    ``models.attack_path.AttackHop``). Older shapes are still read: a ``nodes`` list, or hops that
    name their far end (the first also its near end). A path in none of them is an error that names
    the keys it has.
    """
    nodes = path.get("nodes")
    if isinstance(nodes, list) and nodes:
        return [n if isinstance(n, str) else str(n.get("id") or n.get("address")) for n in nodes]
    hops = path.get("hops")
    if isinstance(hops, list) and hops:
        ids: list[str] = []
        first = hops[0]
        for key in ("from", "source", "src"):
            if isinstance(first.get(key), str):
                ids.append(first[key])
                break
        for hop in hops:
            for key in ("node_id", "node", "to", "target", "address", "resource", "id"):
                if isinstance(hop.get(key), str):
                    ids.append(hop[key])
                    break
        return ids
    raise AssertionError(f"cannot read node ids from an attack path with keys {sorted(path)}")


def is_subsequence(needles: list[str], haystack: list[str]) -> bool:
    it = iter(haystack)
    return all(any(n == h for h in it) for n in needles)


def resolve_address(result: ScanResult, resource: str) -> str:
    """The node id a resource name stands for.

    An exact id wins. Otherwise ``<type>.<name>`` names the one node of that type with that name,
    which keeps a cluster-scoped Kubernetes kind findable whether or not its id carries a
    namespace segment.
    """
    nodes = result.graph.nodes
    if resource in nodes:
        return resource
    resource_type, _, name = resource.partition(".")
    matches = [n.id for n in nodes.values() if n.resource_type == resource_type and n.name == name]
    return matches[0] if len(matches) == 1 else resource


def finding_present(result: ScanResult, entry: dict[str, Any]) -> bool:
    """True when a finding on the resource is one of the rules or the kind."""
    rule_ids = set(entry.get("rule_ids") or [])
    kind = entry.get("kind")
    address = resolve_address(result, entry["resource"])
    for threat in result.threats:
        if threat.resource_address != address:
            continue
        if threat.rule_id in rule_ids:
            return True
        text = f"{threat.rule_id} {threat.title} {threat.description}"
        if kind and KIND_PATTERNS[kind].search(text):
            return True
    return False
