"""The benchmark harness must score correctly, or its numbers mean nothing."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.pending import pending
from tests.test_quality.harness import (
    ExpectationError,
    Expected,
    FixtureResult,
    MustFind,
    MustNotFind,
    Ratchet,
    check_ratchet,
    companion_duplicates,
    load_all_expected,
    load_expected,
    matches,
    parse_expected,
    require_resources,
    run_fixture,
    scan_fixture,
    totals,
)

TF = """\
resource "aws_s3_bucket" "public_assets" {
  bucket = "public-assets"
  acl    = "public-read"
}

resource "aws_s3_bucket" "private_data" {
  bucket = "private-data"
  acl    = "private"
}

resource "aws_s3_bucket_versioning" "private_data" {
  bucket = aws_s3_bucket.private_data.id

  versioning_configuration {
    status = "Enabled"
  }
}
"""


@pytest.fixture
def synthetic(tmp_path: Path) -> Path:
    (tmp_path / "main.tf").write_text(TF, encoding="utf-8")
    return tmp_path


def score(synthetic: Path, doc: dict, dropped: frozenset[str] = frozenset()) -> FixtureResult:
    expected = parse_expected({"fixture": "main.tf", **doc}, "synthetic")
    return run_fixture(expected, scan_fixture("main.tf", synthetic), dropped)


class TestRecallArithmetic:
    def test_found_and_missed_are_counted_per_entry(self, synthetic: Path) -> None:
        result = score(
            synthetic,
            {
                "must_find": [
                    {
                        "resource": "aws_s3_bucket.public_assets",
                        "rule_ids": ["S3_PUBLIC_ACCESS"],
                        "why": "acl is public-read",
                    },
                    {
                        "resource": "aws_s3_bucket.private_data",
                        "rule_ids": ["S3_PUBLIC_ACCESS"],
                        "why": "this bucket is private, so the rule must not hit",
                    },
                ]
            },
        )
        assert [e.resource for e in result.found] == ["aws_s3_bucket.public_assets"]
        assert [e.resource for e in result.missed] == ["aws_s3_bucket.private_data"]
        assert result.total == 2
        assert result.recall == 0.5

    def test_recall_of_an_empty_list_is_one(self) -> None:
        assert FixtureResult("none").recall == 1.0

    def test_totals_add_across_fixtures(self) -> None:
        a = FixtureResult(
            "a", found=[MustFind("r", "why", ("X",))], missed=[MustFind("s", "why", ("X",))]
        )
        b = FixtureResult("b", found=[MustFind("t", "why", ("X",))] * 3)
        t = totals([a, b])
        assert (t.found, t.total, t.recall) == (4, 5, 0.8)

    def test_a_missing_must_find_is_a_miss_not_a_pass(self, synthetic: Path) -> None:
        result = score(
            synthetic,
            {
                "must_find": [
                    {
                        "resource": "aws_s3_bucket.public_assets",
                        "rule_ids": ["NO_SUCH_RULE"],
                        "why": "no rule by this name exists",
                    }
                ]
            },
        )
        assert result.recall == 0.0
        assert len(result.missed) == 1


class TestMatching:
    class Threat:
        def __init__(self, address: str, rule_id: str, title: str, description: str = "") -> None:
            self.resource_address = address
            self.rule_id = rule_id
            self.title = title
            self.description = description

    def test_rule_id_matches_only_on_the_named_resource(self) -> None:
        threat = self.Threat("a.b", "S3_PUBLIC_ACCESS", "t")
        assert matches(threat, "a.b", ("S3_PUBLIC_ACCESS",), None)
        assert not matches(threat, "a.c", ("S3_PUBLIC_ACCESS",), None)
        assert not matches(threat, "a.b", ("OTHER",), None)

    def test_a_kind_matches_whatever_rule_reports_it(self) -> None:
        threat = self.Threat("a.b", "NEW_RULE_NAME", "Instance metadata service allows IMDSv1")
        assert matches(threat, "a.b", (), "imdsv1")
        assert not matches(threat, "a.b", (), "wildcard_iam")
        assert not matches(threat, "a.other", (), "imdsv1")


class TestViolations:
    def test_a_finding_on_a_hardened_resource_is_a_violation(self, synthetic: Path) -> None:
        result = score(
            synthetic,
            {
                "must_not_find": [
                    {
                        "resource": "aws_s3_bucket_versioning.private_data",
                        "rule_ids": ["S3_NO_ENCRYPTION"],
                        "why": "a versioning companion is not a bucket",
                    }
                ]
            },
        )
        assert len(result.violations) == 1
        entry, offenders = result.violations[0]
        assert entry.resource == "aws_s3_bucket_versioning.private_data"
        assert offenders == ["S3_NO_ENCRYPTION"]

    def test_omitted_rule_ids_mean_any_rule_finding(self, synthetic: Path) -> None:
        doc = {
            "must_not_find": [
                {"resource": "aws_s3_bucket.public_assets", "why": "this bucket has findings"}
            ]
        }
        assert len(score(synthetic, doc).violations) == 1

    def test_a_clean_resource_is_not_a_violation(self, synthetic: Path) -> None:
        doc = {
            "must_not_find": [
                {
                    "resource": "aws_s3_bucket.private_data",
                    "rule_ids": ["S3_PUBLIC_ACCESS"],
                    "why": "private acl",
                }
            ]
        }
        assert score(synthetic, doc).violations == []

    def test_dropping_a_rule_removes_its_findings(self, synthetic: Path) -> None:
        doc = {
            "must_find": [
                {
                    "resource": "aws_s3_bucket.public_assets",
                    "rule_ids": ["S3_PUBLIC_ACCESS"],
                    "why": "acl is public-read",
                }
            ]
        }
        assert score(synthetic, doc).recall == 1.0
        assert score(synthetic, doc, frozenset({"S3_PUBLIC_ACCESS"})).recall == 0.0


class TestRatchet:
    def test_holding_the_baseline_passes(self) -> None:
        baseline = totals([FixtureResult("a", found=[MustFind("r", "w", ("X",))])])
        assert check_ratchet(baseline, Ratchet(1.0, 0, 0)) == []

    def test_recall_below_the_ratchet_fails(self) -> None:
        low = totals(
            [
                FixtureResult(
                    "a", found=[MustFind("r", "w", ("X",))], missed=[MustFind("s", "w", ("X",))]
                )
            ]
        )
        problems = check_ratchet(low, Ratchet(min_recall=0.9))
        assert problems == ["recall 50.0% is below the ratchet 90.0%"]

    def test_more_violations_or_duplicates_than_the_ratchet_fail(self) -> None:
        noisy = totals(
            [
                FixtureResult(
                    "a",
                    violations=[(MustNotFind("r", "w"), ["X"])] * 3,
                    companion_duplicates=["d"] * 5,
                )
            ]
        )
        problems = check_ratchet(noisy, Ratchet(0.0, max_violations=2, max_companion_duplicates=4))
        assert len(problems) == 2
        assert "3 must_not_find violations exceed the ratchet 2" in problems[0]
        assert "5 companion duplicates exceed the ratchet 4" in problems[1]

    def test_unset_limits_are_not_enforced(self) -> None:
        noisy = totals([FixtureResult("a", violations=[(MustNotFind("r", "w"), ["X"])] * 9)])
        assert check_ratchet(noisy, Ratchet()) == []

    def test_deleting_a_rule_fails_a_ratchet_set_at_the_baseline(self) -> None:
        """Deleting S3_PUBLIC_ACCESS must make the benchmark fail once a ratchet is recorded."""
        expected = [e for e in load_all_expected() if e.fixture.startswith("01_")]
        assert len(expected) == 1
        baseline = totals([run_fixture(e) for e in expected])
        ratchet = Ratchet(min_recall=baseline.recall)
        assert check_ratchet(baseline, ratchet) == []
        without_rule = totals(
            [run_fixture(e, dropped_rules=frozenset({"S3_PUBLIC_ACCESS"})) for e in expected]
        )
        assert without_rule.found == baseline.found - 1
        assert check_ratchet(without_rule, ratchet), "the ratchet must catch the deleted rule"


class TestResourceExistence:
    def test_an_unknown_resource_fails_hard_with_a_suggestion(self) -> None:
        expected = Expected(
            "x", (MustFind("aws_s3_bucket.publc_assets", "typo in the resource id", ("X",)),), ()
        )
        with pytest.raises(ExpectationError, match=r"not a node of the graph.*Did you mean"):
            require_resources(expected, {"aws_s3_bucket.public_assets", "aws_vpc.main"})

    def test_run_fixture_refuses_to_score_a_rotted_expectation(self, synthetic: Path) -> None:
        doc = {
            "must_not_find": [{"resource": "aws_s3_bucket.gone", "why": "the resource was removed"}]
        }
        with pytest.raises(ExpectationError, match="aws_s3_bucket.gone"):
            score(synthetic, doc)


class TestMalformedExpectations:
    @pytest.mark.parametrize(
        ("doc", "message"),
        [
            ({"must_find": [{"resource": "r", "why": "w"}]}, "needs rule_ids or a kind"),
            ({"must_find": [{"resource": "r", "kind": "nope", "why": "w"}]}, "unknown kind 'nope'"),
            ({"must_find": [{"resource": "r", "rule_ids": ["X"]}]}, "needs a non-empty 'why'"),
            ({"must_find": [{"rule_ids": ["X"], "why": "w"}]}, "needs a non-empty 'resource'"),
            (
                {"must_find": [{"resource": "r", "rule_ids": "X", "why": "w"}]},
                "rule_ids must be a list",
            ),
            (
                {"must_find": [{"resource": "r", "rule_ids": ["X"], "why": "w", "extra": 1}]},
                "unknown keys",
            ),
            ({"must_not_find": [{"resource": "r", "why": "w", "kind": "imdsv1"}]}, "unknown keys"),
            ({"unexpected": []}, "expected keys"),
        ],
    )
    def test_invalid_documents_are_rejected_with_the_location(
        self, doc: dict, message: str
    ) -> None:
        with pytest.raises(ExpectationError, match=message):
            parse_expected({"fixture": "f", **doc}, "synthetic.yml")

    def test_a_missing_fixture_name_is_rejected(self) -> None:
        with pytest.raises(ExpectationError, match="needs a 'fixture'"):
            parse_expected({"must_find": []}, "synthetic.yml")

    def test_an_unreadable_file_is_reported_by_name(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.yml"
        bad.write_text("fixture: [unclosed", encoding="utf-8")
        with pytest.raises(ExpectationError, match="bad.yml: cannot read"):
            load_expected(bad)


class TestCompanionDuplicates:
    def test_a_rule_firing_on_a_resource_and_its_companion_is_counted(
        self, synthetic: Path
    ) -> None:
        duplicates = companion_duplicates(scan_fixture("main.tf", synthetic))
        assert any(
            "aws_s3_bucket_versioning.private_data repeats aws_s3_bucket.private_data" in d
            for d in duplicates
        )

    def test_dropping_the_rules_removes_the_duplicates(self, synthetic: Path) -> None:
        result = scan_fixture("main.tf", synthetic)
        dropped = frozenset(
            {"S3_NO_ENCRYPTION", "S3_NO_LOGGING", "S3_NO_VERSIONING", "S3_PUBLIC_ACCESS"}
        )
        assert companion_duplicates(result, dropped) == []

    @pending("WP-1-1", "exact resource typing: no rule fires on the versioning companion")
    def test_exact_typing_leaves_no_duplicate_on_the_synthetic_bucket(
        self, synthetic: Path
    ) -> None:
        assert companion_duplicates(scan_fixture("main.tf", synthetic)) == []
