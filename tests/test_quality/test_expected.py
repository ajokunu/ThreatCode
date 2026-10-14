"""Run the planted-issue benchmark on the realistic fixtures and report recall and violations.

This test asserts that the harness runs, that the expectation files are sound and that the build
has not fallen below the numbers recorded in ``expected/ratchet.yml``. The ratchet holds the
measured result of the build: raise it when a change finds more, never lower it to let a change
pass. ``docs/benchmark.md`` publishes the same numbers (``scripts/gen_docs_counts.py``).

Run ``pytest tests/test_quality -s`` to see the report. ``THREATCODE_QUALITY_SUMMARY=<path>``
writes it as a Markdown table, for a CI step summary.
"""

from __future__ import annotations

import os
from collections import Counter
from pathlib import Path

import pytest

from tests.test_quality.harness import (
    EXPECTED_DIR,
    REALISTIC_DIR,
    REPORT_KEY,
    Expected,
    FixtureResult,
    MustFind,
    MustNotFind,
    check_ratchet,
    load_all_expected,
    load_ratchet,
    missed_report,
    render_markdown,
    render_text,
    require_resources,
    run_fixture,
    scan_fixture,
    totals,
)
from threatcode.engine.rules.loader import load_builtin_rules
from threatcode.engine.secrets.builtin import get_builtin_rules as get_secret_rules

EXPECTED = load_all_expected()
FIXTURES = sorted(p.name for p in REALISTIC_DIR.iterdir() if p.is_file())


def _entries(expected: Expected) -> list[MustFind | MustNotFind]:
    return [*expected.must_find, *expected.must_not_find]


def _results() -> list[FixtureResult]:
    return [run_fixture(e) for e in EXPECTED]


class TestExpectationFiles:
    def test_every_realistic_fixture_has_an_expectation_file(self) -> None:
        assert sorted(e.fixture for e in EXPECTED) == FIXTURES

    def test_the_file_name_is_the_fixture_stem(self) -> None:
        for path in sorted(EXPECTED_DIR.glob("[0-9]*.yml")):
            expected = next(e for e in EXPECTED if (REALISTIC_DIR / e.fixture).stem == path.stem)
            assert expected.fixture.startswith(path.stem)

    def test_the_seed_covers_the_planted_issues(self) -> None:
        """The audit counted 39 planted issues across the ten fixtures."""
        assert sum(len(e.must_find) for e in EXPECTED) >= 39
        for expected in EXPECTED:
            assert len(expected.must_find) >= 2, expected.fixture
            assert expected.must_not_find, f"{expected.fixture} lists no hardened resource"

    def test_every_entry_quotes_the_comment_or_attribute_that_plants_it(self) -> None:
        for expected in EXPECTED:
            for entry in _entries(expected):
                assert len(entry.why.split()) >= 3, f"{expected.fixture} {entry.resource}"

    @pytest.mark.parametrize("expected", EXPECTED, ids=lambda e: e.fixture)
    def test_named_resources_exist_in_the_graph(self, expected: Expected) -> None:
        require_resources(expected, set(scan_fixture(expected.fixture).graph.nodes))

    def test_a_resource_listed_as_must_find_is_never_also_listed_as_hardened(self) -> None:
        for expected in EXPECTED:
            planted = {(e.resource, r) for e in expected.must_find for r in e.rule_ids}
            hardened = {
                (e.resource, r) for e in expected.must_not_find for r in (e.rule_ids or ("*",))
            }
            overlap = {p for p in planted if p in hardened or (p[0], "*") in hardened}
            assert not overlap, f"{expected.fixture}: {sorted(overlap)}"


class TestBenchmarkRuns:
    def test_it_scores_every_fixture_and_prints_the_numbers(
        self, capsys: pytest.CaptureFixture[str], pytestconfig: pytest.Config
    ) -> None:
        results = _results()
        report = render_text(results)
        detail = missed_report(results)
        print("\n" + report + ("\n\n" + detail if detail else ""))
        # Left on the config so the terminal summary shows it even when output is captured
        pytestconfig.stash[REPORT_KEY] = (report, detail)
        output = capsys.readouterr().out
        assert "TOTAL: recall" in output
        for result in results:
            assert result.total == len(
                next(e for e in EXPECTED if e.fixture == result.fixture).must_find
            )
            assert 0.0 <= result.recall <= 1.0
        total = totals(results)
        assert total.total >= 39
        assert 0 <= total.found <= total.total

    def test_the_markdown_summary_has_a_row_per_fixture_and_a_total(self) -> None:
        results = _results()
        summary = render_markdown(results)
        assert summary.count("\n| 0") + summary.count("\n| 1") >= len(results)
        assert "**Total**" in summary
        path = os.environ.get("THREATCODE_QUALITY_SUMMARY")
        if path:
            Path(path).write_text(summary, encoding="utf-8")

    def test_the_ratchet_is_recorded_and_holds(self) -> None:
        ratchet = load_ratchet()
        assert ratchet is not None, "expected/ratchet.yml records the measured baseline"
        assert check_ratchet(totals(_results()), ratchet) == []

    def test_the_ratchet_is_not_looser_than_the_measurement_by_more_than_rounding(self) -> None:
        """A ratchet far below the measurement lets recall fall without the build noticing."""
        ratchet = load_ratchet()
        assert ratchet is not None
        total = totals(_results())
        assert total.recall - ratchet.min_recall < 0.001, (
            f"measured recall {total.recall:.4f} is above the ratchet {ratchet.min_recall:.4f}: "
            "raise min_recall in expected/ratchet.yml"
        )
        assert ratchet.max_violations == total.violations
        assert ratchet.max_companion_duplicates == total.companion_duplicates

    def test_scoring_is_deterministic(self) -> None:
        first = render_text(_results())
        second = render_text(_results())
        assert first == second


class TestFindingIntegrity:
    @pytest.mark.parametrize("fixture", FIXTURES)
    def test_no_two_threats_share_an_id(self, fixture: str) -> None:
        counts = Counter(t.id for t in scan_fixture(fixture).threats)
        dupes = {tid: n for tid, n in counts.items() if n > 1}
        assert not dupes, f"{fixture}: duplicate threat ids {dupes}"

    def test_no_rule_fires_on_a_companion_of_a_resource_it_already_hit(self) -> None:
        from tests.test_quality.harness import companion_duplicates

        offenders = {
            fixture: dups
            for fixture in FIXTURES
            if (dups := companion_duplicates(scan_fixture(fixture)))
        }
        assert not offenders, offenders


class TestEveryMissIsExplained:
    """A planted issue the product does not find is either a regression or a known limit."""

    def test_no_planted_issue_is_missed_without_an_explanation(self) -> None:
        unexplained = {
            r.fixture: [e.resource for e in r.unexplained_misses]
            for r in _results()
            if r.unexplained_misses
        }
        assert not unexplained, (
            f"planted issues the scan no longer finds: {unexplained}. Fix the regression, or add "
            "known_miss: <reason> to the entry if the product cannot honestly find it"
        )

    def test_no_known_miss_is_found_after_all(self) -> None:
        stale = {
            r.fixture: [e.resource for e in r.stale_known_misses]
            for r in _results()
            if r.stale_known_misses
        }
        assert not stale, f"found now, remove known_miss from: {stale}"

    def test_the_known_misses_stay_few(self) -> None:
        """The reasons are listed in docs/benchmark.md; a long list would be a hiding place."""
        known = sum(len([e for e in r.missed if e.known_miss]) for r in _results())
        assert known <= 3


class TestExpectationsNameCurrentRules:
    def test_every_rule_id_is_a_builtin_rule_or_a_secret_detector(self) -> None:
        known = {r.id for r in load_builtin_rules()} | {r.id for r in get_secret_rules()}
        stale = {
            f"{e.fixture} {entry.resource}": [i for i in entry.rule_ids if i not in known]
            for e in EXPECTED
            for entry in _entries(e)
            if any(i not in known for i in entry.rule_ids)
        }
        assert not stale, f"expectations naming a removed or misspelled rule: {stale}"


class TestFindingsSitOnTheirRulesTypes:
    @pytest.mark.parametrize("fixture", FIXTURES)
    def test_no_finding_sits_on_a_resource_type_its_rule_does_not_declare(
        self, fixture: str
    ) -> None:
        """Rules match their type exactly; a finding elsewhere is a sibling-type duplicate."""
        rules = {r.id: r for r in load_builtin_rules()}
        wrong = [
            f"{t.rule_id} on {t.resource_address} ({t.resource_type})"
            for t in scan_fixture(fixture).threats
            if t.rule_id in rules and not rules[t.rule_id].matches_type(t.resource_type)
        ]
        assert not wrong, f"{fixture}: {wrong}"
