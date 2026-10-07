"""Every builtin rule has an example, or is on its group's shrinking uncovered list."""

from __future__ import annotations

from tests.test_rules.harness import (
    CASES_DIR,
    UNCOVERED_DIR,
    check_ratchet,
    coverage_report,
    discover_cases,
    load_rules_by_group,
    read_uncovered,
)


def test_coverage_ratchet_holds() -> None:
    rules = {group: [r.id for r in rs] for group, rs in load_rules_by_group().items()}
    problems = check_ratchet(rules, discover_cases(), read_uncovered())
    assert not problems, (
        "rule example coverage ratchet violated:\n  "
        + "\n  ".join(problems)
        + f"\n\nCases live in {CASES_DIR}; lists in {UNCOVERED_DIR}."
    )


def test_coverage_report_prints_a_total(capsys: object) -> None:
    report = coverage_report()
    print(report)
    assert report.splitlines()[-1].startswith("total")
