"""Self-tests for the plan shape check."""

from __future__ import annotations

import copy
import json
from pathlib import Path

from tests.helpers.plan_shape import base_address, plan_shape_problems

CASE = (
    Path(__file__).parent.parent
    / "test_rules"
    / "cases"
    / "aws__s3"
    / "S3_PUBLIC_ACCESS"
    / "good.plan.json"
)


def _plan() -> dict:
    return json.loads(CASE.read_text(encoding="utf-8"))


def test_a_complete_plan_has_no_problems() -> None:
    assert plan_shape_problems(_plan()) == []


def test_rule_case_plans_have_the_real_shape() -> None:
    from tests.test_rules.harness import CASES_DIR

    paths = sorted(CASES_DIR.rglob("*.plan.json"))
    assert paths, "expected at least one plan case"
    for path in paths:
        assert plan_shape_problems(json.loads(path.read_text(encoding="utf-8"))) == [], path


def test_the_legacy_planned_values_only_shape_is_rejected() -> None:
    legacy = {"format_version": "1.0", "planned_values": {"root_module": {"resources": []}}}
    problems = plan_shape_problems(legacy)
    assert "missing top-level key resource_changes" in problems
    assert "missing top-level key configuration" in problems


def test_a_resource_without_a_change_entry_is_reported() -> None:
    plan = _plan()
    plan["resource_changes"] = []
    assert any("no resource_changes entry" in p for p in plan_shape_problems(plan))


def test_missing_change_keys_are_reported() -> None:
    plan = _plan()
    del plan["resource_changes"][0]["change"]["after_unknown"]
    assert any("change is missing after_unknown" in p for p in plan_shape_problems(plan))


def test_an_unknown_attribute_with_a_planned_value_is_reported() -> None:
    plan = _plan()
    resource = plan["planned_values"]["root_module"]["resources"][0]
    resource["values"]["arn"] = "arn:aws:s3:::acme-assets"
    problems = plan_shape_problems(plan)
    assert any("arn is unknown after apply but has the planned value" in p for p in problems)


def test_a_resource_missing_from_configuration_is_reported() -> None:
    plan = copy.deepcopy(_plan())
    plan["configuration"]["root_module"]["resources"] = []
    assert any("no configuration entry" in p for p in plan_shape_problems(plan))


def test_not_an_object_is_reported() -> None:
    assert plan_shape_problems([1, 2]) == ["the document is not a JSON object"]


def test_base_address_strips_instance_keys_at_every_level() -> None:
    assert base_address('module.net["a"].aws_subnet.x[1]') == "module.net.aws_subnet.x"
    assert base_address("aws_instance.web[0]") == "aws_instance.web"
