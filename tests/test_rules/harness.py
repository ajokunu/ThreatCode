"""Per-rule example harness: discover builtin rules, load their cases, run them.

Every builtin rule is meant to have a real-syntax ``bad`` example it fires on and a
``good`` example (the fix its mitigation text recommends) it stays silent on. Both go
through the full path a scan takes: write the snippet to a file, ``detect_and_parse``,
``InfraGraph.from_parsed``, then ``matches_rule`` for that one rule on every graph node.
Evaluating one rule at a time keeps unrelated rules from masking a dead condition,
and going through ``matches_rule`` tests the resource type matching as well as the
condition. This module never reads ``Rule.resource_type`` or ``resource_types``:
whether a rule fired on a node of a declared type is whatever ``matches_rule`` says.

Case layout, under ``tests/test_rules/cases/<group>/``:

* ``<RULE_ID>/bad.<ext>`` and ``<RULE_ID>/good.<ext>`` where ``<ext>`` picks the parser:
  ``tf``, ``plan.json``, ``cfn.yaml``, ``k8s.yaml``, ``Dockerfile`` or ``mcp.json``.
  A rule may carry several extensions; each ``bad`` needs its ``good`` and vice versa.
* ``<RULE_ID>.yml`` with ``cases: [{format, bad, good}]`` for short inline snippets.
* An optional ``pending.yml`` beside the files of a directory (or a ``pending`` key on an
  inline case) maps a format to ``{package, reason}``. The case is written now and skipped
  until that package delivers; it does not count as coverage while it is pending.

The group is ``<provider dir>__<file stem>`` of the builtin file the rule was loaded from
(``aws__s3`` for ``builtin/aws/s3.yml``), taken from the path, not from a Rule attribute.
``tests/test_rules/uncovered/<group>.txt`` lists the rules of a group that still have no
active case; the ratchet in ``check_ratchet`` keeps that list honest in both directions.

Run ``python -m tests.test_rules.harness`` for a coverage report.
"""

from __future__ import annotations

import sys
import tempfile
from collections import Counter
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from tests.helpers.pending import validate_pending
from threatcode.engine.rules.loader import Rule, load_rules_from_file
from threatcode.engine.rules.matcher import matches_rule
from threatcode.ir.graph import InfraGraph
from threatcode.parsers import detect_and_parse

HERE = Path(__file__).parent
CASES_DIR = HERE / "cases"
UNCOVERED_DIR = HERE / "uncovered"


def _builtin_dir() -> Path:
    import threatcode.engine.rules as rules_pkg

    return Path(rules_pkg.__file__).parent / "builtin"


BUILTIN_DIR = _builtin_dir()


@dataclass(frozen=True)
class FormatSpec:
    name: str
    extension: str  # the suffix of bad.<ext> and good.<ext>
    filename: str  # the file name the snippet is written under, which selects the parser


FORMATS: dict[str, FormatSpec] = {
    spec.name: spec
    for spec in (
        FormatSpec("hcl", "tf", "main.tf"),
        FormatSpec("plan", "plan.json", "tfplan.json"),
        FormatSpec("cfn", "cfn.yaml", "template.yaml"),
        FormatSpec("k8s", "k8s.yaml", "manifest.yaml"),
        FormatSpec("docker", "Dockerfile", "Dockerfile"),
        FormatSpec("mcp", "mcp.json", ".mcp.json"),
    )
}
_BY_EXTENSION = {spec.extension: spec for spec in FORMATS.values()}


class CaseError(Exception):
    """A malformed case file. The message names the rule and the file."""


@dataclass(frozen=True)
class Pending:
    package: str
    reason: str


@dataclass(frozen=True)
class Case:
    group: str
    rule_id: str
    fmt: str
    bad: str
    good: str
    origin: str  # a path or path#index, for failure messages
    pending: Pending | None = None

    @property
    def test_id(self) -> str:
        return f"{self.group}/{self.rule_id}/{self.fmt}"


# ---------------------------------------------------------------------------------------
# Rules by group
# ---------------------------------------------------------------------------------------


def group_of(path: Path, builtin_dir: Path = BUILTIN_DIR) -> str:
    """``aws__s3`` for ``<builtin>/aws/s3.yml``; nested directories join with ``__``."""
    relative = path.relative_to(builtin_dir)
    return "__".join([*relative.parent.parts, relative.stem])


def load_rules_by_group(builtin_dir: Path = BUILTIN_DIR) -> dict[str, list[Rule]]:
    """Load every rule file on its own and key the rules by the file they came from."""
    groups: dict[str, list[Rule]] = {}
    for path in sorted(builtin_dir.rglob("*.yml")):
        groups[group_of(path, builtin_dir)] = load_rules_from_file(path)
    return groups


def all_rules(builtin_dir: Path = BUILTIN_DIR) -> dict[tuple[str, str], Rule]:
    """``(group, rule id)`` to rule, for every builtin rule."""
    return {
        (group, rule.id): rule
        for group, rules in load_rules_by_group(builtin_dir).items()
        for rule in rules
    }


# ---------------------------------------------------------------------------------------
# Case discovery
# ---------------------------------------------------------------------------------------


def _read(path: Path, rule_id: str) -> str:
    try:
        text = path.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError) as exc:
        raise CaseError(f"{rule_id}: cannot read case file {path}: {exc}") from exc
    if not text.strip():
        raise CaseError(f"{rule_id}: case file {path} is empty")
    return text


def _pending_from(raw: object, rule_id: str, origin: str) -> Pending:
    if not isinstance(raw, Mapping) or set(raw) != {"package", "reason"}:
        raise CaseError(f"{rule_id}: pending in {origin} must be a mapping with package and reason")
    try:
        package, reason = validate_pending(raw["package"], raw["reason"])
    except ValueError as exc:
        raise CaseError(f"{rule_id}: pending in {origin}: {exc}") from exc
    return Pending(package, reason)


def _load_yaml(path: Path, rule_id: str) -> Any:
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise CaseError(f"{rule_id}: cannot parse {path}: {exc}") from exc


def _cases_from_directory(group: str, rule_dir: Path) -> list[Case]:
    rule_id = rule_dir.name
    pending_map: dict[str, Any] = {}
    sidecar = rule_dir / "pending.yml"
    if sidecar.is_file():
        loaded = _load_yaml(sidecar, rule_id) or {}
        if not isinstance(loaded, Mapping):
            raise CaseError(f"{rule_id}: {sidecar} must map a format to {{package, reason}}")
        pending_map = dict(loaded)
    sides: dict[str, dict[str, Path]] = {}
    for path in sorted(rule_dir.iterdir()):
        if path.name in ("pending.yml", "README.md"):
            continue
        side, _, extension = path.name.partition(".")
        if side not in ("bad", "good") or extension not in _BY_EXTENSION:
            raise CaseError(
                f"{rule_id}: unexpected file {path.name} in {rule_dir}. Expected bad.<ext> or "
                f"good.<ext> with <ext> one of {sorted(_BY_EXTENSION)}."
            )
        sides.setdefault(extension, {})[side] = path
    if not sides:
        raise CaseError(f"{rule_id}: case directory {rule_dir} has no bad/good files")
    unknown = set(pending_map) - {_BY_EXTENSION[e].name for e in sides}
    if unknown:
        raise CaseError(f"{rule_id}: pending.yml names formats with no case: {sorted(unknown)}")
    cases: list[Case] = []
    for extension, pair in sorted(sides.items()):
        spec = _BY_EXTENSION[extension]
        for needed in ("bad", "good"):
            if needed not in pair:
                raise CaseError(
                    f"{rule_id}: {spec.name} case in {rule_dir} has no {needed}.{extension}"
                )
        pending = None
        if spec.name in pending_map:
            pending = _pending_from(pending_map[spec.name], rule_id, str(sidecar))
        cases.append(
            Case(
                group,
                rule_id,
                spec.name,
                _read(pair["bad"], rule_id),
                _read(pair["good"], rule_id),
                str(rule_dir),
                pending,
            )
        )
    return cases


def _cases_from_inline(group: str, path: Path) -> list[Case]:
    rule_id = path.stem
    data = _load_yaml(path, rule_id)
    if (
        not isinstance(data, Mapping)
        or set(data) != {"cases"}
        or not isinstance(data["cases"], list)
    ):
        raise CaseError(f"{rule_id}: {path} must hold a single 'cases' list")
    cases: list[Case] = []
    for index, entry in enumerate(data["cases"]):
        origin = f"{path}#{index}"
        if not isinstance(entry, Mapping):
            raise CaseError(f"{rule_id}: case {origin} must be a mapping")
        extra = set(entry) - {"format", "bad", "good", "pending"}
        if extra:
            raise CaseError(f"{rule_id}: case {origin} has unknown keys {sorted(extra)}")
        fmt = entry.get("format")
        if fmt not in FORMATS:
            raise CaseError(
                f"{rule_id}: case {origin} has format {fmt!r}; expected one of {sorted(FORMATS)}"
            )
        texts: dict[str, str] = {}
        for side in ("bad", "good"):
            value = entry.get(side)
            if not isinstance(value, str) or not value.strip():
                raise CaseError(f"{rule_id}: case {origin} needs a non-empty '{side}' snippet")
            texts[side] = value
        pending = None
        if "pending" in entry:
            pending = _pending_from(entry["pending"], rule_id, origin)
        cases.append(Case(group, rule_id, fmt, texts["bad"], texts["good"], origin, pending))
    return cases


def discover_cases(cases_dir: Path = CASES_DIR) -> list[Case]:
    """Load every case under ``cases_dir``. Malformed files raise ``CaseError`` naming the rule."""
    cases: list[Case] = []
    if not cases_dir.is_dir():
        return cases
    for group_dir in sorted(p for p in cases_dir.iterdir() if p.is_dir()):
        for entry in sorted(group_dir.iterdir()):
            if entry.name == "README.md":
                continue
            if entry.is_dir():
                cases.extend(_cases_from_directory(group_dir.name, entry))
            elif entry.suffix == ".yml":
                cases.extend(_cases_from_inline(group_dir.name, entry))
            else:
                raise CaseError(
                    f"{group_dir.name}: unexpected file {entry.name}; "
                    "cases are <RULE_ID>/ directories or <RULE_ID>.yml files"
                )
    return cases


# ---------------------------------------------------------------------------------------
# Running one case
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Outcome:
    """What one snippet did: how many nodes it produced and which the rule matched."""

    node_count: int
    node_types: frozenset[str]
    matched_nodes: tuple[str, ...]
    matched_types: frozenset[str]


def graph_for(fmt: str, text: str, directory: Path | None = None) -> InfraGraph:
    """Parse a snippet the way a scan would and build its graph."""
    spec = FORMATS[fmt]
    if directory is not None:
        return _graph_in(directory, spec, text)
    with tempfile.TemporaryDirectory(prefix="threatcode-rule-case-") as tmp:
        return _graph_in(Path(tmp), spec, text)


def _graph_in(directory: Path, spec: FormatSpec, text: str) -> InfraGraph:
    path = directory / spec.filename
    path.write_text(text, encoding="utf-8")
    return InfraGraph.from_parsed(detect_and_parse(path))


def run_snippet(rule: Rule, fmt: str, text: str, directory: Path | None = None) -> Outcome:
    """Parse, build the graph and evaluate ``rule`` alone against every node."""
    graph = graph_for(fmt, text, directory)
    nodes = [node for node in graph.nodes.values() if not node.is_synthetic]
    matched = [node for node in nodes if matches_rule(rule, node)]
    return Outcome(
        node_count=len(nodes),
        node_types=frozenset(node.resource_type for node in nodes),
        matched_nodes=tuple(node.id for node in matched),
        matched_types=frozenset(node.resource_type for node in matched),
    )


def check_case(rule: Rule, case: Case, directory: Path | None = None) -> list[str]:
    """Problems a case reveals about its rule; an empty list means the example holds.

    The bad snippet must make the rule match at least one node. The good snippet must make
    it match none and must still contain a node of a type the bad snippet matched, so a good
    example that merely lacks the resource cannot pass vacuously.
    """
    problems: list[str] = []
    try:
        bad = run_snippet(rule, case.fmt, case.bad, directory)
    except Exception as exc:
        return [f"bad snippet does not parse as {case.fmt}: {type(exc).__name__}: {exc}"]
    if not bad.matched_nodes:
        problems.append(
            f"rule {rule.id} did not fire on the bad {case.fmt} snippet "
            f"({bad.node_count} node(s): {', '.join(sorted(bad.node_types)) or 'none'})"
        )
        return problems
    try:
        good = run_snippet(rule, case.fmt, case.good, directory)
    except Exception as exc:
        return [f"good snippet does not parse as {case.fmt}: {type(exc).__name__}: {exc}"]
    if good.matched_nodes:
        problems.append(
            f"rule {rule.id} fired on the good {case.fmt} snippet: {', '.join(good.matched_nodes)}"
        )
    if not good.node_types & bad.matched_types:
        problems.append(
            f"the good {case.fmt} snippet has no resource of the type the rule fired on "
            f"({', '.join(sorted(bad.matched_types))}); it would pass without testing anything"
        )
    return problems


# ---------------------------------------------------------------------------------------
# Coverage ratchet
# ---------------------------------------------------------------------------------------


def read_uncovered(uncovered_dir: Path = UNCOVERED_DIR) -> dict[str, list[str]]:
    """Rule ids named in each ``<group>.txt``; ``#`` starts a comment, blank lines are skipped."""
    lists: dict[str, list[str]] = {}
    if not uncovered_dir.is_dir():
        return lists
    for path in sorted(uncovered_dir.glob("*.txt")):
        ids = []
        for raw in path.read_text(encoding="utf-8").splitlines():
            line = raw.split("#", 1)[0].strip()
            if line:
                ids.append(line)
        lists[path.stem] = ids
    return lists


def covered_rules(cases: Iterable[Case]) -> set[tuple[str, str]]:
    """Rules with at least one active case. A rule whose cases are all pending is not covered."""
    return {(c.group, c.rule_id) for c in cases if c.pending is None}


def check_ratchet(
    rules: Mapping[str, Iterable[str]],
    cases: Iterable[Case],
    uncovered: Mapping[str, list[str]],
) -> list[str]:
    """Violations of the coverage ratchet; an empty list means it holds.

    * a listed rule that has active cases fails: remove it from the list;
    * a rule with neither a case nor a list entry fails: add a case;
    * a listed id that is not a rule of the group fails: it is stale;
    * a list file for a group with no rules, or a group without a list file, fails;
    * a case for a rule that does not exist fails: the rule was renamed or removed.
    """
    cases = list(cases)
    covered = covered_rules(cases)
    problems: list[str] = []
    for group in sorted(set(uncovered) - set(rules)):
        problems.append(f"uncovered/{group}.txt: no builtin rule group {group}; delete the file")
    for group, rule_ids in sorted(rules.items()):
        ids = list(rule_ids)
        if group not in uncovered:
            problems.append(f"uncovered/{group}.txt is missing; create it (it may be empty)")
            continue
        listed = uncovered[group]
        for rule_id in sorted({r for r in listed if listed.count(r) > 1}):
            problems.append(f"uncovered/{group}.txt lists {rule_id} more than once")
        for rule_id in sorted(set(listed) - set(ids)):
            problems.append(
                f"uncovered/{group}.txt lists {rule_id}, which is not a rule of {group}"
            )
        for rule_id in sorted(set(listed) & {r for r in ids if (group, r) in covered}):
            problems.append(
                f"{group}/{rule_id} has cases but is still in uncovered/{group}.txt; remove it"
            )
        for rule_id in ids:
            if (group, rule_id) not in covered and rule_id not in listed:
                problems.append(
                    f"{group}/{rule_id} has no active case; add bad/good examples under "
                    f"tests/test_rules/cases/{group}/{rule_id}/ or list it in uncovered/{group}.txt"
                )
    known = {(group, rule_id) for group, ids in rules.items() for rule_id in ids}
    for case in cases:
        if (case.group, case.rule_id) not in known:
            problems.append(
                f"case {case.test_id} ({case.origin}) names no builtin rule; "
                "the rule was renamed, moved or removed"
            )
    return problems


# ---------------------------------------------------------------------------------------
# Format parity
# ---------------------------------------------------------------------------------------


def compare_formats(results: Mapping[str, Counter[str]], reference: str) -> list[str]:
    """Differences between the rules each format fired, measured against ``reference``.

    ``results`` maps a format name to how often each focused rule fired. The same
    configuration written in HCL, plan JSON and CloudFormation should trip the same rules the
    same number of times; every difference is reported as a line naming both formats.
    """
    if reference not in results:
        raise KeyError(f"reference format {reference!r} is not in the results")
    base = results[reference]
    problems: list[str] = []
    for fmt, counts in sorted(results.items()):
        if fmt == reference:
            continue
        for rule_id in sorted(set(base) | set(counts)):
            want, got = base.get(rule_id, 0), counts.get(rule_id, 0)
            if want != got:
                problems.append(f"{rule_id}: fired {want}x for {reference} but {got}x for {fmt}")
    return problems


def coverage_report(builtin_dir: Path = BUILTIN_DIR, cases_dir: Path = CASES_DIR) -> str:
    """A table of covered and uncovered rules per group, for humans."""
    by_group = load_rules_by_group(builtin_dir)
    covered = covered_rules(discover_cases(cases_dir))
    lines = [f"{'group':28} {'rules':>5} {'covered':>7} {'uncovered':>9}"]
    total = total_covered = 0
    for group, rules in by_group.items():
        n_covered = sum((group, r.id) in covered for r in rules)
        total += len(rules)
        total_covered += n_covered
        lines.append(f"{group:28} {len(rules):>5} {n_covered:>7} {len(rules) - n_covered:>9}")
    lines.append(f"{'total':28} {total:>5} {total_covered:>7} {total - total_covered:>9}")
    return "\n".join(lines)


def write_uncovered_lists(
    builtin_dir: Path = BUILTIN_DIR,
    cases_dir: Path = CASES_DIR,
    uncovered_dir: Path = UNCOVERED_DIR,
) -> list[Path]:
    """Create ``<group>.txt`` for every group that lacks one, listing its uncovered rules.

    Existing files are left alone: the lists only shrink, and an author removes lines by hand.
    """
    covered = covered_rules(discover_cases(cases_dir))
    uncovered_dir.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []
    for group, rules in load_rules_by_group(builtin_dir).items():
        path = uncovered_dir / f"{group}.txt"
        if path.exists():
            continue
        ids = [r.id for r in rules if (group, r.id) not in covered]
        path.write_text("".join(f"{i}\n" for i in ids), encoding="utf-8")
        written.append(path)
    return written


def main(argv: list[str]) -> int:
    if argv[1:] == ["init"]:
        for path in write_uncovered_lists():
            print(f"wrote {path.relative_to(HERE.parent.parent)}")
        return 0
    print(coverage_report())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
