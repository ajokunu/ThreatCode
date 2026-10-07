"""The rule harness must catch what it exists to catch: dead rules, drifted lists, bad cases."""

from __future__ import annotations

from collections import Counter
from pathlib import Path

import pytest

from tests.test_rules.harness import (
    BUILTIN_DIR,
    Case,
    CaseError,
    Pending,
    check_case,
    check_ratchet,
    compare_formats,
    covered_rules,
    discover_cases,
    group_of,
    load_rules_by_group,
    read_uncovered,
    run_snippet,
    write_uncovered_lists,
)
from threatcode.engine.rules.loader import Rule, load_rules_from_file

RULE_TEMPLATE = """\
rules:
  - id: {rule_id}
    title: Synthetic rule
    description: A rule written for the harness self-test.
    stride_category: information_disclosure
    severity: high
    resource_type: aws_s3_bucket
    condition:
{condition}
    mitigation: Set the ACL to private.
"""

BAD_TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  acl    = "public-read"\n}\n'
GOOD_TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  acl    = "private"\n}\n'


def synthetic_rule(tmp_path: Path, condition: str, rule_id: str = "SYNTHETIC_RULE") -> Rule:
    path = tmp_path / "synthetic.yml"
    path.write_text(RULE_TEMPLATE.format(rule_id=rule_id, condition=condition), encoding="utf-8")
    return load_rules_from_file(path)[0]


def case_for(rule: Rule, bad: str = BAD_TF, good: str = GOOD_TF, fmt: str = "hcl") -> Case:
    return Case("synthetic__rules", rule.id, fmt, bad, good, "self-test")


HEALTHY = "      acl:\n        equals: public-read"


class TestDeadRuleDetection:
    def test_a_healthy_rule_passes(self, tmp_path: Path) -> None:
        rule = synthetic_rule(tmp_path, HEALTHY)
        assert check_case(rule, case_for(rule), tmp_path) == []

    def test_a_dead_rule_is_caught_because_it_never_fires_on_its_bad_case(
        self, tmp_path: Path
    ) -> None:
        # A typo in the condition key: the property never exists, so the rule is dead.
        dead = synthetic_rule(tmp_path, "      accesss_control:\n        equals: public-read")
        problems = check_case(dead, case_for(dead), tmp_path)
        assert len(problems) == 1
        assert "SYNTHETIC_RULE did not fire on the bad hcl snippet" in problems[0]
        assert "aws_s3_bucket" in problems[0]

    def test_a_rule_for_a_type_the_snippet_lacks_is_dead_too(self, tmp_path: Path) -> None:
        wrong_type = BAD_TF.replace("aws_s3_bucket", "aws_sqs_queue")
        rule = synthetic_rule(tmp_path, HEALTHY)
        problems = check_case(rule, case_for(rule, bad=wrong_type), tmp_path)
        assert problems and "did not fire" in problems[0]

    def test_a_rule_that_fires_on_the_good_case_is_caught(self, tmp_path: Path) -> None:
        too_broad = synthetic_rule(tmp_path, "      bucket:\n        exists: true")
        problems = check_case(too_broad, case_for(too_broad), tmp_path)
        assert any("fired on the good hcl snippet" in p for p in problems)

    def test_a_good_case_without_the_resource_cannot_pass_vacuously(self, tmp_path: Path) -> None:
        rule = synthetic_rule(tmp_path, HEALTHY)
        unrelated = 'resource "aws_sqs_queue" "q" {\n  name = "q"\n}\n'
        problems = check_case(rule, case_for(rule, good=unrelated), tmp_path)
        assert len(problems) == 1
        assert "no resource of the type the rule fired on" in problems[0]

    def test_unparseable_snippets_are_problems_not_crashes(self, tmp_path: Path) -> None:
        rule = synthetic_rule(tmp_path, HEALTHY)
        broken = "this is { not hcl"
        bad_problems = check_case(rule, case_for(rule, bad=broken), tmp_path)
        assert "bad snippet does not parse as hcl" in bad_problems[0]
        good_problems = check_case(rule, case_for(rule, good=broken), tmp_path)
        assert "good snippet does not parse as hcl" in good_problems[0]

    def test_run_snippet_evaluates_only_the_given_rule(self, tmp_path: Path) -> None:
        rule = synthetic_rule(tmp_path, HEALTHY)
        outcome = run_snippet(rule, "hcl", BAD_TF, tmp_path)
        assert outcome.matched_nodes == ("aws_s3_bucket.b",)
        assert outcome.matched_types == frozenset({"aws_s3_bucket"})
        assert outcome.node_count == 1


class TestRatchet:
    RULES = {"g__one": ["A", "B"], "g__two": ["C"]}

    @staticmethod
    def case(group: str, rule_id: str, pending: Pending | None = None) -> Case:
        return Case(group, rule_id, "hcl", "x", "y", "test", pending)

    def test_a_consistent_state_has_no_problems(self) -> None:
        cases = [self.case("g__one", "A"), self.case("g__two", "C")]
        uncovered = {"g__one": ["B"], "g__two": []}
        assert check_ratchet(self.RULES, cases, uncovered) == []

    def test_a_listed_rule_that_gained_cases_fails(self) -> None:
        cases = [self.case("g__one", "A"), self.case("g__one", "B"), self.case("g__two", "C")]
        problems = check_ratchet(self.RULES, cases, {"g__one": ["B"], "g__two": []})
        assert problems == ["g__one/B has cases but is still in uncovered/g__one.txt; remove it"]

    def test_an_unlisted_rule_without_cases_fails(self) -> None:
        problems = check_ratchet(
            self.RULES, [self.case("g__one", "A")], {"g__one": [], "g__two": ["C"]}
        )
        assert len(problems) == 1
        assert problems[0].startswith("g__one/B has no active case")

    def test_a_new_rule_added_without_a_case_fails(self) -> None:
        rules = {**self.RULES, "g__two": ["C", "NEW_RULE"]}
        cases = [self.case("g__one", "A"), self.case("g__two", "C")]
        problems = check_ratchet(rules, cases, {"g__one": ["B"], "g__two": []})
        assert [p for p in problems if "g__two/NEW_RULE has no active case" in p]

    def test_a_case_whose_rules_are_all_pending_does_not_count_as_coverage(self) -> None:
        waiting = self.case("g__one", "B", Pending("WP-3-2", "not yet"))
        cases = [self.case("g__one", "A"), waiting, self.case("g__two", "C")]
        assert covered_rules(cases) == {("g__one", "A"), ("g__two", "C")}
        assert check_ratchet(self.RULES, cases, {"g__one": ["B"], "g__two": []}) == []

    def test_stale_and_duplicate_list_entries_fail(self) -> None:
        cases = [self.case("g__one", "A"), self.case("g__two", "C")]
        uncovered = {"g__one": ["B", "B", "GONE"], "g__two": [], "g__old": ["X"]}
        problems = check_ratchet(self.RULES, cases, uncovered)
        assert "uncovered/g__one.txt lists B more than once" in problems
        assert "uncovered/g__one.txt lists GONE, which is not a rule of g__one" in problems
        assert "uncovered/g__old.txt: no builtin rule group g__old; delete the file" in problems

    def test_a_group_without_a_list_file_fails(self) -> None:
        problems = check_ratchet(self.RULES, [], {"g__one": ["A", "B"]})
        assert "uncovered/g__two.txt is missing; create it (it may be empty)" in problems

    def test_a_case_for_a_removed_rule_fails(self) -> None:
        cases = [self.case("g__one", "A"), self.case("g__two", "C"), self.case("g__one", "OLD")]
        problems = check_ratchet(self.RULES, cases, {"g__one": ["B"], "g__two": []})
        assert any("g__one/OLD/hcl" in p and "names no builtin rule" in p for p in problems)


class TestGroups:
    def test_group_comes_from_the_file_path(self) -> None:
        assert group_of(BUILTIN_DIR / "aws" / "s3.yml") == "aws__s3"
        assert group_of(BUILTIN_DIR / "mcp" / "servers.yml") == "mcp__servers"
        assert group_of(BUILTIN_DIR / "a" / "b" / "c.yml") == "a__b__c"

    def test_every_rule_belongs_to_exactly_one_group(self) -> None:
        seen: dict[str, str] = {}
        for group, rules in load_rules_by_group().items():
            for rule in rules:
                assert rule.id not in seen, f"{rule.id} is in {seen[rule.id]} and {group}"
                seen[rule.id] = group
        assert seen, "no builtin rules were loaded"


class TestMalformedCases:
    def make(self, tmp_path: Path, rule_id: str, files: dict[str, str]) -> Path:
        cases_dir = tmp_path / "cases"
        rule_dir = cases_dir / "aws__s3" / rule_id
        rule_dir.mkdir(parents=True)
        for name, text in files.items():
            (rule_dir / name).write_text(text, encoding="utf-8")
        return cases_dir

    def test_a_bad_without_a_good_names_the_rule(self, tmp_path: Path) -> None:
        cases_dir = self.make(tmp_path, "S3_BROKEN", {"bad.tf": BAD_TF})
        with pytest.raises(CaseError, match=r"S3_BROKEN: hcl case .* has no good\.tf"):
            discover_cases(cases_dir)

    def test_a_good_without_a_bad_names_the_rule(self, tmp_path: Path) -> None:
        cases_dir = self.make(tmp_path, "S3_BROKEN", {"good.tf": GOOD_TF})
        with pytest.raises(CaseError, match=r"S3_BROKEN: hcl case .* has no bad\.tf"):
            discover_cases(cases_dir)

    def test_an_unknown_extension_is_rejected(self, tmp_path: Path) -> None:
        cases_dir = self.make(tmp_path, "S3_BROKEN", {"bad.hcl": BAD_TF, "good.hcl": GOOD_TF})
        with pytest.raises(CaseError, match=r"S3_BROKEN: unexpected file bad\.hcl"):
            discover_cases(cases_dir)

    def test_an_empty_case_file_is_rejected(self, tmp_path: Path) -> None:
        cases_dir = self.make(tmp_path, "S3_BROKEN", {"bad.tf": "  \n", "good.tf": GOOD_TF})
        with pytest.raises(CaseError, match=r"S3_BROKEN: case file .*bad\.tf is empty"):
            discover_cases(cases_dir)

    def test_an_empty_rule_directory_is_rejected(self, tmp_path: Path) -> None:
        cases_dir = self.make(tmp_path, "S3_EMPTY", {})
        with pytest.raises(CaseError, match=r"S3_EMPTY: case directory .* has no bad/good files"):
            discover_cases(cases_dir)

    def test_a_pending_entry_for_a_format_without_a_case_is_rejected(self, tmp_path: Path) -> None:
        cases_dir = self.make(
            tmp_path,
            "S3_BROKEN",
            {
                "bad.tf": BAD_TF,
                "good.tf": GOOD_TF,
                "pending.yml": "cfn:\n  package: WP-2-3\n  reason: later\n",
            },
        )
        with pytest.raises(CaseError, match=r"S3_BROKEN: pending\.yml names formats with no case"):
            discover_cases(cases_dir)

    def test_a_pending_entry_naming_an_unowned_package_is_rejected(self, tmp_path: Path) -> None:
        cases_dir = self.make(
            tmp_path,
            "S3_BROKEN",
            {
                "bad.tf": BAD_TF,
                "good.tf": GOOD_TF,
                "pending.yml": "hcl:\n  package: WP-9-9\n  reason: later\n",
            },
        )
        with pytest.raises(CaseError, match=r"S3_BROKEN: pending in .*pending\.yml"):
            discover_cases(cases_dir)

    def test_a_valid_pending_entry_marks_only_its_format(self, tmp_path: Path) -> None:
        cases_dir = self.make(
            tmp_path,
            "S3_OK",
            {
                "bad.tf": BAD_TF,
                "good.tf": GOOD_TF,
                "bad.plan.json": "{}",
                "good.plan.json": "{}",
                "pending.yml": "plan:\n  package: WP-2-1\n  reason: unknown values\n",
            },
        )
        by_format = {c.fmt: c for c in discover_cases(cases_dir)}
        assert by_format["hcl"].pending is None
        assert by_format["plan"].pending == Pending("WP-2-1", "unknown values")

    def test_inline_cases_validate_their_keys_and_format(self, tmp_path: Path) -> None:
        group = tmp_path / "cases" / "aws__s3"
        group.mkdir(parents=True)
        (group / "S3_INLINE.yml").write_text(
            "cases:\n  - format: terraform\n    bad: x\n    good: y\n", encoding="utf-8"
        )
        with pytest.raises(CaseError, match=r"S3_INLINE: case .* has format 'terraform'"):
            discover_cases(tmp_path / "cases")
        (group / "S3_INLINE.yml").write_text(
            "cases:\n  - format: hcl\n    bad: x\n    good: y\n    note: no\n", encoding="utf-8"
        )
        with pytest.raises(CaseError, match=r"S3_INLINE: case .* has unknown keys \['note'\]"):
            discover_cases(tmp_path / "cases")
        (group / "S3_INLINE.yml").write_text(
            "cases:\n  - format: hcl\n    bad: x\n    good: ''\n", encoding="utf-8"
        )
        with pytest.raises(CaseError, match=r"S3_INLINE: case .* needs a non-empty 'good'"):
            discover_cases(tmp_path / "cases")

    def test_inline_cases_load(self, tmp_path: Path) -> None:
        group = tmp_path / "cases" / "docker__image"
        group.mkdir(parents=True)
        (group / "DOCKER_ROOT_USER.yml").write_text(
            "cases:\n  - format: docker\n    bad: 'FROM a:1'\n    good: 'FROM a:2'\n",
            encoding="utf-8",
        )
        cases = discover_cases(tmp_path / "cases")
        assert [(c.group, c.rule_id, c.fmt) for c in cases] == [
            ("docker__image", "DOCKER_ROOT_USER", "docker")
        ]


class TestUncoveredLists:
    def test_lists_ignore_comments_and_blank_lines(self, tmp_path: Path) -> None:
        (tmp_path / "g__x.txt").write_text("# header\nA\n\nB  # trailing\n", encoding="utf-8")
        assert read_uncovered(tmp_path) == {"g__x": ["A", "B"]}

    def test_init_creates_only_missing_lists_and_leaves_existing_ones_alone(
        self, tmp_path: Path
    ) -> None:
        builtin = tmp_path / "builtin" / "aws"
        builtin.mkdir(parents=True)
        (builtin / "s3.yml").write_text(
            RULE_TEMPLATE.format(rule_id="S3_X", condition=HEALTHY), encoding="utf-8"
        )
        uncovered = tmp_path / "uncovered"
        uncovered.mkdir()
        (uncovered / "aws__s3.txt").write_text("HAND_EDITED\n", encoding="utf-8")
        written = write_uncovered_lists(tmp_path / "builtin", tmp_path / "cases", uncovered)
        assert written == []
        assert (uncovered / "aws__s3.txt").read_text(encoding="utf-8") == "HAND_EDITED\n"
        (uncovered / "aws__s3.txt").unlink()
        written = write_uncovered_lists(tmp_path / "builtin", tmp_path / "cases", uncovered)
        assert [p.name for p in written] == ["aws__s3.txt"]
        assert (uncovered / "aws__s3.txt").read_text(encoding="utf-8") == "S3_X\n"


class TestParityComparison:
    def test_identical_results_have_no_differences(self) -> None:
        counts = Counter({"A": 1, "B": 2})
        assert compare_formats({"plan": counts, "hcl": Counter(counts)}, "plan") == []

    def test_a_format_disagreement_is_reported_in_both_directions(self) -> None:
        results = {
            "plan": Counter({"A": 1, "B": 1}),
            "hcl": Counter({"A": 1}),
            "cfn": Counter({"A": 2, "B": 1, "C": 1}),
        }
        assert compare_formats(results, "plan") == [
            "A: fired 1x for plan but 2x for cfn",
            "C: fired 0x for plan but 1x for cfn",
            "B: fired 1x for plan but 0x for hcl",
        ]

    def test_an_unknown_reference_is_an_error(self) -> None:
        with pytest.raises(KeyError):
            compare_formats({"hcl": Counter()}, "plan")
