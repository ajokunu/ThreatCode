"""Planted-issue benchmark: how many known issues does a scan report, and what noise does it add.

Each realistic fixture plants issues (open security groups, wildcard roles, public buckets,
IMDSv1) and marks them with TODO comments, ticket ids and names such as ``TempAllowAll_RemoveMe``.
``expected/<fixture stem>.yml`` lists them as ``must_find`` and lists hardened resources and
companion resources as ``must_not_find``. The harness scans every fixture through the library path,
checks the lists against the findings and reports recall and violations per fixture and in total.

An expectation entry looks like this::

    must_find:
      - resource: aws_security_group.temp_debug        # a node id of the fixture graph
        rule_ids: [SG_UNRESTRICTED_INGRESS]            # any of these rules on that resource ...
        kind: open_ingress                             # ... or any finding of this class
        why: 'FIXME: opened for debugging (NET-1247)'  # the comment or attribute that plants it
    must_not_find:
      - resource: aws_s3_bucket_versioning.logs
        rule_ids: [S3_NO_ENCRYPTION]                   # omitted: no finding at all may sit here
        why: a versioning companion is not a bucket

``kind`` is a class of finding that does not depend on which rule reports it, so an issue stays
findable when a rule is renamed or replaced. A kind is a regular expression applied to a
finding's rule id, title and description (see ``KIND_PATTERNS``).

The same file format is meant to be reused by the design-input extraction eval (#12).
Ratchets are optional: ``expected/ratchet.yml`` with ``min_recall``, ``max_violations`` and
``max_companion_duplicates`` makes ``check_ratchet`` fail below the recorded baseline.
"""

from __future__ import annotations

import difflib
from collections import defaultdict
from dataclasses import dataclass, field
from functools import cache
from pathlib import Path
from typing import Any

import pytest
import yaml

from tests.helpers.kinds import KIND_PATTERNS
from tests.helpers.scan import ScanResult, scan_files

HERE = Path(__file__).parent
EXPECTED_DIR = HERE / "expected"
REALISTIC_DIR = HERE.parent / "fixtures" / "realistic"

# The report a test leaves on the pytest config; conftest.py prints it in the terminal summary as
# (table, detail). The detail lists every missed issue and violation and prints only with -v.
REPORT_KEY: pytest.StashKey[tuple[str, str]] = pytest.StashKey()

_MUST_FIND_KEYS = {"resource", "rule_ids", "kind", "why"}
_MUST_NOT_FIND_KEYS = {"resource", "rule_ids", "why"}


class ExpectationError(Exception):
    """An expectation file that is malformed or names a resource the scan does not produce."""


@dataclass(frozen=True)
class MustFind:
    resource: str
    why: str
    rule_ids: tuple[str, ...] = ()
    kind: str | None = None


@dataclass(frozen=True)
class MustNotFind:
    resource: str
    why: str
    rule_ids: tuple[str, ...] = ()  # empty: any finding on the resource violates


@dataclass(frozen=True)
class Expected:
    fixture: str
    must_find: tuple[MustFind, ...]
    must_not_find: tuple[MustNotFind, ...]


@dataclass
class FixtureResult:
    fixture: str
    found: list[MustFind] = field(default_factory=list)
    missed: list[MustFind] = field(default_factory=list)
    violations: list[tuple[MustNotFind, list[str]]] = field(default_factory=list)
    companion_duplicates: list[str] = field(default_factory=list)
    finding_count: int = 0

    @property
    def total(self) -> int:
        return len(self.found) + len(self.missed)

    @property
    def recall(self) -> float:
        return len(self.found) / self.total if self.total else 1.0

    def summary(self) -> str:
        return (
            f"{self.fixture}: recall {len(self.found)}/{self.total} ({self.recall:.0%}), "
            f"{len(self.violations)} must_not_find violation(s), "
            f"{len(self.companion_duplicates)} companion duplicate(s), "
            f"{self.finding_count} findings"
        )


@dataclass
class Totals:
    found: int
    total: int
    violations: int
    companion_duplicates: int

    @property
    def recall(self) -> float:
        return self.found / self.total if self.total else 1.0


@dataclass(frozen=True)
class Ratchet:
    min_recall: float = 0.0
    max_violations: int | None = None
    max_companion_duplicates: int | None = None


# ---------------------------------------------------------------------------------------
# Loading expectations
# ---------------------------------------------------------------------------------------


def _strings(value: Any, where: str, key: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list) or not all(isinstance(v, str) and v for v in value):
        raise ExpectationError(f"{where}: {key} must be a list of non-empty strings")
    return tuple(value)


def _entry(raw: Any, allowed: set[str], where: str) -> dict[str, Any]:
    if not isinstance(raw, dict):
        raise ExpectationError(f"{where}: entry must be a mapping")
    extra = set(raw) - allowed
    if extra:
        raise ExpectationError(f"{where}: unknown keys {sorted(extra)}")
    for key in ("resource", "why"):
        if not isinstance(raw.get(key), str) or not raw[key].strip():
            raise ExpectationError(f"{where}: needs a non-empty '{key}'")
    return raw


def parse_expected(data: Any, source: str) -> Expected:
    """Validate one expectation document."""
    if not isinstance(data, dict) or set(data) - {"fixture", "must_find", "must_not_find"}:
        raise ExpectationError(f"{source}: expected keys fixture, must_find and must_not_find")
    fixture = data.get("fixture")
    if not isinstance(fixture, str) or not fixture:
        raise ExpectationError(f"{source}: needs a 'fixture' file name")
    must_find: list[MustFind] = []
    for index, raw in enumerate(data.get("must_find") or []):
        where = f"{source} must_find[{index}]"
        entry = _entry(raw, _MUST_FIND_KEYS, where)
        rule_ids = _strings(entry.get("rule_ids"), where, "rule_ids")
        kind = entry.get("kind")
        if kind is not None and kind not in KIND_PATTERNS:
            raise ExpectationError(
                f"{where}: unknown kind {kind!r}; known kinds are {sorted(KIND_PATTERNS)}"
            )
        if not rule_ids and kind is None:
            raise ExpectationError(f"{where}: needs rule_ids or a kind to decide what counts")
        must_find.append(MustFind(entry["resource"], entry["why"], rule_ids, kind))
    must_not_find: list[MustNotFind] = []
    for index, raw in enumerate(data.get("must_not_find") or []):
        where = f"{source} must_not_find[{index}]"
        entry = _entry(raw, _MUST_NOT_FIND_KEYS, where)
        must_not_find.append(
            MustNotFind(
                entry["resource"], entry["why"], _strings(entry.get("rule_ids"), where, "rule_ids")
            )
        )
    return Expected(fixture, tuple(must_find), tuple(must_not_find))


def load_expected(path: Path) -> Expected:
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ExpectationError(f"{path}: cannot read: {exc}") from exc
    return parse_expected(data, path.name)


def load_all_expected(expected_dir: Path = EXPECTED_DIR) -> list[Expected]:
    return [load_expected(p) for p in sorted(expected_dir.glob("*.yml")) if p.name != "ratchet.yml"]


def load_ratchet(expected_dir: Path = EXPECTED_DIR) -> Ratchet | None:
    """The recorded ratchet, or ``None`` while no package has set one."""
    path = expected_dir / "ratchet.yml"
    if not path.is_file():
        return None
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    extra = set(data) - {"min_recall", "max_violations", "max_companion_duplicates"}
    if extra:
        raise ExpectationError(f"ratchet.yml: unknown keys {sorted(extra)}")
    return Ratchet(
        float(data.get("min_recall", 0.0)),
        data.get("max_violations"),
        data.get("max_companion_duplicates"),
    )


# ---------------------------------------------------------------------------------------
# Scoring
# ---------------------------------------------------------------------------------------


@cache
def scan_fixture(fixture: str, directory: Path = REALISTIC_DIR) -> ScanResult:
    """Scan one fixture through the library path; cached because every test reads the result."""
    return scan_files([directory / fixture])


def _finding_text(threat: Any) -> str:
    return f"{threat.rule_id} {threat.title} {threat.description}"


def matches(threat: Any, resource: str, rule_ids: tuple[str, ...], kind: str | None) -> bool:
    """True when ``threat`` sits on ``resource`` and is one of the rules or the kind."""
    if threat.resource_address != resource:
        return False
    if threat.rule_id in rule_ids:
        return True
    return kind is not None and bool(KIND_PATTERNS[kind].search(_finding_text(threat)))


def require_resources(expected: Expected, node_ids: set[str]) -> None:
    """Fail hard when an expectation names a resource the scan does not produce.

    A renamed or removed resource would otherwise turn a must_find into a silent miss and a
    must_not_find into a silent pass, and the file would rot without anyone noticing.
    """
    for entry in (*expected.must_find, *expected.must_not_find):
        if entry.resource not in node_ids:
            near = difflib.get_close_matches(entry.resource, sorted(node_ids), n=3, cutoff=0.5)
            hint = f" Did you mean: {', '.join(near)}?" if near else ""
            raise ExpectationError(
                f"{expected.fixture}: expectation names {entry.resource!r}, which is not a node "
                f"of the graph.{hint}"
            )


def companion_duplicates(result: ScanResult, dropped: frozenset[str] = frozenset()) -> list[str]:
    """Findings that repeat a rule on a companion resource of the resource it already hit.

    ``aws_s3_bucket_versioning.logs`` is a companion of ``aws_s3_bucket.logs``: its type extends the
    bucket's type and its name starts with the bucket's name. A rule that fires on both is counting
    one issue twice, which is what prefix matching on resource types does.
    """
    nodes = result.graph.nodes
    fired: dict[str, list[str]] = defaultdict(list)
    for threat in result.threats:
        if threat.rule_id and threat.rule_id not in dropped and threat.resource_address in nodes:
            fired[threat.rule_id].append(threat.resource_address)
    duplicates: list[str] = []
    for rule_id, addresses in sorted(fired.items()):
        for companion in addresses:
            c = nodes[companion]
            for primary in addresses:
                p = nodes[primary]
                if (
                    primary != companion
                    and c.resource_type.startswith(p.resource_type + "_")
                    and c.name.startswith(p.name)
                ):
                    duplicates.append(f"{rule_id} on {companion} repeats {primary}")
                    break
    return duplicates


def run_fixture(
    expected: Expected,
    result: ScanResult | None = None,
    dropped_rules: frozenset[str] = frozenset(),
) -> FixtureResult:
    """Score one fixture. ``dropped_rules`` simulates deleting rules, for the self-tests."""
    result = result if result is not None else scan_fixture(expected.fixture)
    require_resources(expected, set(result.graph.nodes))
    threats = [t for t in result.threats if t.rule_id not in dropped_rules]
    scored = FixtureResult(expected.fixture, finding_count=len(threats))
    for entry in expected.must_find:
        hit = any(matches(t, entry.resource, entry.rule_ids, entry.kind) for t in threats)
        (scored.found if hit else scored.missed).append(entry)
    for entry in expected.must_not_find:
        offenders = [
            t.rule_id or t.title
            for t in threats
            if t.resource_address == entry.resource
            and t.rule_id
            and (not entry.rule_ids or t.rule_id in entry.rule_ids)
        ]
        if offenders:
            scored.violations.append((entry, sorted(offenders)))
    scored.companion_duplicates = companion_duplicates(result, dropped_rules)
    return scored


def totals(results: list[FixtureResult]) -> Totals:
    return Totals(
        found=sum(len(r.found) for r in results),
        total=sum(r.total for r in results),
        violations=sum(len(r.violations) for r in results),
        companion_duplicates=sum(len(r.companion_duplicates) for r in results),
    )


def check_ratchet(total: Totals, ratchet: Ratchet) -> list[str]:
    """Ways the totals fall below the recorded ratchet; empty when they hold."""
    problems: list[str] = []
    if total.recall + 1e-9 < ratchet.min_recall:
        problems.append(f"recall {total.recall:.1%} is below the ratchet {ratchet.min_recall:.1%}")
    if ratchet.max_violations is not None and total.violations > ratchet.max_violations:
        problems.append(
            f"{total.violations} must_not_find violations exceed the ratchet "
            f"{ratchet.max_violations}"
        )
    limit = ratchet.max_companion_duplicates
    if limit is not None and total.companion_duplicates > limit:
        problems.append(
            f"{total.companion_duplicates} companion duplicates exceed the ratchet {limit}"
        )
    return problems


def render_text(results: list[FixtureResult]) -> str:
    lines = [r.summary() for r in results]
    total = totals(results)
    lines.append(
        f"TOTAL: recall {total.found}/{total.total} ({total.recall:.0%}), "
        f"{total.violations} violation(s), {total.companion_duplicates} companion duplicate(s)"
    )
    return "\n".join(lines)


def render_markdown(results: list[FixtureResult]) -> str:
    """A GitHub step summary table; ``THREATCODE_QUALITY_SUMMARY`` writes it from the test."""
    rows = ["| Fixture | Recall | Violations | Companion duplicates |", "| --- | --- | --- | --- |"]
    for r in results:
        rows.append(
            f"| {r.fixture} | {len(r.found)}/{r.total} ({r.recall:.0%}) | {len(r.violations)} "
            f"| {len(r.companion_duplicates)} |"
        )
    t = totals(results)
    rows.append(
        f"| **Total** | **{t.found}/{t.total} ({t.recall:.0%})** | **{t.violations}** "
        f"| **{t.companion_duplicates}** |"
    )
    return "\n".join(rows) + "\n"


def missed_report(results: list[FixtureResult]) -> str:
    """Every missed planted issue with the comment that plants it, for the printed report."""
    lines: list[str] = []
    for r in results:
        for entry in r.missed:
            lines.append(f"MISSED {r.fixture} {entry.resource}: {entry.why}")
        for entry, offenders in r.violations:
            lines.append(f"VIOLATION {r.fixture} {entry.resource} {offenders}: {entry.why}")
    return "\n".join(lines)
