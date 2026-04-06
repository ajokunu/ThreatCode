"""Test that the total rule count meets the v0.9.0 target."""

from __future__ import annotations

from threatcode.engine.rules.loader import load_all_rules


class TestRuleCount:
    def test_total_rules_at_least_220(self) -> None:
        rules = load_all_rules()
        assert len(rules) >= 220, (
            f"Expected at least 220 rules, got {len(rules)}. New rule files may be missing."
        )

    def test_no_duplicate_rule_ids(self) -> None:
        rules = load_all_rules()
        ids = [r.id for r in rules]
        dupes = [rid for rid in ids if ids.count(rid) > 1]
        assert len(dupes) == 0, f"Duplicate rule IDs found: {set(dupes)}"
