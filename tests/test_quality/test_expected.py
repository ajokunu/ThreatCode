"""Run the planted-issue benchmark on the realistic fixtures and report recall and violations.

This test asserts that the harness runs and that the expectation files are sound. It does not
set a recall target: the numbers it prints are the measurement, and ratchets are recorded in
``expected/ratchet.yml`` by the package that owns the release gates. When that file exists, this
test enforces it.

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

EXPECTED = load_all_expected()
FIXTURES = sorted(p.name for p in REALISTIC_DIR.iterdir() if p.is_file())


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
            for entry in (*expected.must_find, *expected.must_not_find):
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

    def test_the_ratchet_holds_when_one_is_recorded(self) -> None:
        ratchet = load_ratchet()
        if ratchet is None:
            pytest.skip("no expected/ratchet.yml yet; the release-gate package records it")
        assert check_ratchet(totals(_results()), ratchet) == []

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
