"""Builtin rule files load and every rule belongs to exactly one group.

Totals are not asserted. A floor such as "at least 220 rules" passes while 200 rules sit
dead and fails when a package deliberately deletes a rule that never could fire. What
matters is that each file loads, each id is defined once, and the loader returns exactly
the rules the files hold. The totals are printed (``pytest -s``) and generated for the docs.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import threatcode.engine.rules as rules_pkg
from threatcode.engine.rules.loader import load_all_rules, load_rules_from_file

BUILTIN_DIR = Path(rules_pkg.__file__).parent / "builtin"


def _files() -> list[Path]:
    return sorted(BUILTIN_DIR.rglob("*.yml"))


def _group(path: Path) -> str:
    relative = path.relative_to(BUILTIN_DIR)
    return "__".join([*relative.parent.parts, relative.stem])


class TestRuleFiles:
    def test_builtin_directory_has_rule_files(self) -> None:
        assert _files(), f"no rule files found under {BUILTIN_DIR}"

    def test_every_rule_file_loads_and_holds_rules(self) -> None:
        for path in _files():
            rules = load_rules_from_file(path)
            assert rules, f"{path.relative_to(BUILTIN_DIR)} loads but defines no rules"

    def test_every_rule_belongs_to_exactly_one_group(self) -> None:
        owners: dict[str, list[str]] = {}
        for path in _files():
            for rule in load_rules_from_file(path):
                owners.setdefault(rule.id, []).append(_group(path))
        shared = {rule_id: groups for rule_id, groups in owners.items() if len(groups) != 1}
        assert not shared, f"rule ids defined in more than one place: {shared}"

    def test_no_duplicate_rule_ids(self) -> None:
        ids = [r.id for r in load_all_rules()]
        dupes = sorted(rule_id for rule_id, n in Counter(ids).items() if n > 1)
        assert not dupes, f"Duplicate rule IDs found: {dupes}"

    def test_the_loader_returns_exactly_the_rules_in_the_files(self) -> None:
        from_files = sorted(r.id for path in _files() for r in load_rules_from_file(path))
        assert sorted(r.id for r in load_all_rules()) == from_files

    def test_group_names_are_provider_and_file_stem(self) -> None:
        groups = {_group(path) for path in _files()}
        assert "aws__s3" in groups
        assert "mcp__servers" in groups
        assert all("__" in group for group in groups)


def test_print_rule_totals(capsys: object) -> None:
    """Totals are generated, never asserted; run with ``-s`` to see them."""
    per_group = {_group(p): len(load_rules_from_file(p)) for p in _files()}
    print(f"{len(per_group)} groups, {sum(per_group.values())} rules")
    assert per_group
