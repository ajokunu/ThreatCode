"""Run every rule's bad and good example through the full parse-to-matcher path."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.pending import pending
from tests.helpers.plan_shape import plan_shape_problems
from tests.test_rules.harness import (
    FORMATS,
    Case,
    all_rules,
    check_case,
    discover_cases,
)

RULES = all_rules()
CASES = discover_cases()


def _params() -> list[object]:
    params = []
    for case in CASES:
        marks = []
        if case.pending is not None:
            marks.append(pending(case.pending.package, case.pending.reason))
        params.append(pytest.param(case, id=case.test_id, marks=marks))
    return params


@pytest.mark.parametrize("case", _params())
def test_bad_fires_and_good_is_silent(case: Case, tmp_path: Path) -> None:
    rule = RULES.get((case.group, case.rule_id))
    if rule is None:
        pytest.fail(f"{case.test_id} names no builtin rule ({case.origin})")
    problems = check_case(rule, case, tmp_path)
    assert not problems, f"{case.test_id} ({case.origin}):\n  " + "\n  ".join(problems)


@pytest.mark.parametrize(
    "case",
    [c for c in CASES if c.fmt == "plan"],
    ids=lambda c: c.test_id,
)
def test_plan_cases_have_the_shape_terraform_emits(case: Case) -> None:
    import json

    for side, text in (("bad", case.bad), ("good", case.good)):
        problems = plan_shape_problems(json.loads(text))
        assert not problems, f"{case.test_id} {side}.plan.json: " + "; ".join(problems)


def test_the_corpus_is_not_empty_and_uses_known_formats() -> None:
    assert CASES, "no rule cases found under tests/test_rules/cases"
    assert {c.fmt for c in CASES} <= set(FORMATS)
