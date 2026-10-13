"""Tests for how the terminal lists coverage gaps: once, and aggregated per file."""

from __future__ import annotations

from typing import Any

import pytest

from threatcode.formatters.terminal_coverage import (
    AGGREGATE_ABOVE,
    error_text,
    gap_lines,
    gap_summary,
    unique_gaps,
)


def gap(
    code: str = "hcl.module_call_skipped", file: str = "main.tf", **fields: Any
) -> dict[str, Any]:
    return {"level": "warning", "code": code, "message": "m", "file": file, **fields}


class TestUniqueGaps:
    def test_a_gap_reported_twice_is_one_gap(self) -> None:
        first = gap(line=3)
        assert unique_gaps([first, dict(first), gap(line=4)]) == [first, gap(line=4)]

    def test_two_gaps_that_differ_in_any_of_code_file_line_message_are_two(self) -> None:
        base = gap(line=1)
        variants = [
            {**base, "code": "other"},
            {**base, "file": "other.tf"},
            {**base, "line": 2},
            {**base, "message": "other"},
        ]
        assert len(unique_gaps([base, *variants])) == 5

    def test_the_order_of_the_first_report_is_kept(self) -> None:
        a, b = gap(file="a.tf"), gap(file="b.tf")
        assert unique_gaps([b, a, dict(b), dict(a)]) == [b, a]

    def test_the_input_is_not_changed(self) -> None:
        original = [gap(), gap()]
        unique_gaps(original)
        assert len(original) == 2


class TestGapLines:
    def test_a_gap_with_a_file_and_a_line_names_both(self) -> None:
        (line,) = gap_lines([gap(line=7, message="module vpc is not analysed")])
        assert line.text() == "[hcl.module_call_skipped] main.tf:7: module vpc is not analysed"

    def test_a_gap_without_a_line_or_a_file_is_still_one_clear_line(self) -> None:
        assert gap_lines([gap(file="")])[0].text() == "[hcl.module_call_skipped]: m"
        assert gap_lines([gap()])[0].text() == "[hcl.module_call_skipped] main.tf: m"

    def test_up_to_the_threshold_every_gap_has_its_own_line(self) -> None:
        gaps = [gap(line=n, message=f"m{n}") for n in range(1, AGGREGATE_ABOVE + 1)]
        assert len(gap_lines(gaps)) == AGGREGATE_ABOVE

    def test_beyond_the_threshold_a_file_s_gaps_of_one_code_are_one_counted_line(self) -> None:
        gaps = [gap(line=n, message=f"m{n}") for n in range(1, 253)]
        (line,) = gap_lines(gaps)
        assert line.count == 252
        assert line.text() == "[hcl.module_call_skipped] main.tf: 252 times, first at line 1: m1"

    def test_other_files_and_codes_are_not_swallowed_by_an_aggregate(self) -> None:
        noisy = [gap(line=n, message=f"m{n}") for n in range(1, 10)]
        other_file = gap(file="b.tf", line=1)
        other_code = gap(code="parse.failed", line=2)
        lines = gap_lines([*noisy, other_file, other_code])
        assert [line.count for line in lines] == [9, 1, 1]
        assert lines[1].file == "b.tf" and lines[2].code == "parse.failed"

    def test_repeats_are_merged_before_they_are_counted(self) -> None:
        gaps = [gap(line=1)] * 10
        (line,) = gap_lines(gaps)
        assert line.count == 1

    def test_only_the_first_line_of_a_message_is_printed(self) -> None:
        (line,) = gap_lines([gap(message="first\nsecond")])
        assert line.message == "first"

    def test_text_from_the_input_is_made_safe(self) -> None:
        (line,) = gap_lines([gap(file="a\x1b[2J.tf", message="bad\x07news", code="c\x9bd")])
        assert "\x1b" not in line.text() and "\x07" not in line.text() and "\x9b" not in line.text()
        assert "\\x1b[2J" in line.text()


class TestAMessageThatNamesItsFile:
    def test_a_message_that_begins_with_the_file_is_not_given_the_file_twice(self) -> None:
        (line,) = gap_lines(
            [gap(file="Chart.yaml", message="Chart.yaml was rendered without helm (no helm)")]
        )
        assert (
            line.text()
            == "[hcl.module_call_skipped] Chart.yaml was rendered without helm (no helm)"
        )

    def test_a_message_with_a_colon_after_the_file_counts_too(self) -> None:
        (line,) = gap_lines([gap(file="a.tf", message="a.tf: unresolved")])
        assert line.text() == "[hcl.module_call_skipped] a.tf: unresolved"

    def test_a_gap_with_a_line_keeps_file_and_line_whatever_the_message_says(self) -> None:
        (line,) = gap_lines([gap(file="a.tf", line=4, message="a.tf has a problem")])
        assert line.text() == "[hcl.module_call_skipped] a.tf:4: a.tf has a problem"

    def test_a_message_that_merely_contains_the_file_is_left_as_it_is(self) -> None:
        (line,) = gap_lines([gap(file="a.tf", message="see a.tf for details")])
        assert line.text() == "[hcl.module_call_skipped] a.tf: see a.tf for details"

    def test_a_file_that_is_only_a_prefix_of_a_longer_name_is_not_mistaken_for_it(self) -> None:
        (line,) = gap_lines([gap(file="a.tf", message="a.tfvars was not read")])
        assert line.text() == "[hcl.module_call_skipped] a.tf: a.tfvars was not read"

    def test_the_counted_line_of_a_noisy_file_is_unchanged(self) -> None:
        gaps = [gap(file="a.tf", line=n, message=f"a.tf var {n}") for n in range(1, 10)]
        (line,) = gap_lines(gaps)
        assert line.text() == (
            "[hcl.module_call_skipped] a.tf: 9 times, first at line 1: a.tf var 1"
        )


class TestGapSummary:
    def test_the_codes_are_counted_most_frequent_first(self) -> None:
        gaps = [gap(line=n) for n in range(4)] + [gap(code="helm.fallback_render", line=1)]
        assert gap_summary(gaps) == "5 gaps (hcl.module_call_skipped x4, helm.fallback_render x1)"

    def test_one_gap_is_singular(self) -> None:
        assert gap_summary([gap()]) == "1 gap (hcl.module_call_skipped x1)"

    def test_many_codes_end_with_a_count_of_the_rest(self) -> None:
        gaps = [gap(code=f"c.{n}") for n in range(7)]
        assert gap_summary(gaps, limit=2).endswith("5 more codes)")

    def test_repeats_do_not_inflate_the_count(self) -> None:
        assert gap_summary([gap(), gap(), gap()]) == "1 gap (hcl.module_call_skipped x1)"


class TestErrorText:
    def test_a_file_and_a_message_that_does_not_name_it(self) -> None:
        error = {"file": "bad.tf", "code": "parse.failed", "message": "unexpected token"}
        assert error_text(error) == "bad.tf: unexpected token"

    def test_a_message_that_names_the_file_is_not_prefixed_with_it_again(self) -> None:
        error = {"file": "main.tf", "message": "Invalid HCL in main.tf, line 2, column 1"}
        assert error_text(error) == "Invalid HCL in main.tf, line 2, column 1"

    def test_a_file_in_a_directory_is_kept_when_the_message_names_only_its_base(self) -> None:
        error = {"file": "bad/main.tf", "message": "Invalid HCL in main.tf, line 2"}
        assert error_text(error) == "bad/main.tf: Invalid HCL in main.tf, line 2"

    @pytest.mark.parametrize("file", [".", ""])
    def test_the_scan_root_is_not_a_file_name(self, file: str) -> None:
        assert error_text({"file": file, "message": "no supported files"}) == "no supported files"

    def test_text_from_the_input_is_made_safe(self) -> None:
        text = error_text({"file": "a\x1b[2J.tf", "message": "bad\x07"})
        assert "\x1b" not in text and "\x07" not in text
