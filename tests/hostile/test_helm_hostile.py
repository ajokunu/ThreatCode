"""Helm templates that open an action and never close it must not stall a scan.

The fallback renderer used when the ``helm`` binary is missing reads templates with regular
expressions of the form ``{{ ... }}`` and backtracks over every unterminated ``{{`` to the end of
the line, so the cost grows with the square of the line length: 80 KB of ``{{`` takes the shipped
renderer about fourteen seconds and 400 KB several minutes. A chart in a repository someone else
controls can therefore hold a scan for as long as it likes.

A scan of such a chart must end quickly, with either a graph or the tool's own error.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.pending import pending
from tests.hostile import generators as gen
from tests.hostile.support import DEFAULT_BUDGET_SECONDS, scan_in_child

# What a tolerable scan costs: the interpreter starts in about half a second
FAST_SECONDS = 5.0


class TestUnterminatedActionsAreBounded:
    @pending("WP-2-4", "the fallback renderer is a single-pass tokenizer that copies '{{' through")
    @pytest.mark.parametrize("shape", ["braces", "if_blocks"])
    def test_a_scan_ends_quickly_with_a_graph_or_the_tools_own_error(
        self, tmp_path: Path, shape: str
    ) -> None:
        chart_yaml = gen.unterminated_helm_chart(tmp_path, shape)
        outcome = scan_in_child(chart_yaml, budget=DEFAULT_BUDGET_SECONDS)
        assert not outcome.timed_out, f"{shape}: the scan did not finish in {outcome.seconds:.0f}s"
        assert outcome.clean, f"{shape}: {outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    @pending("WP-2-4", "per-file and per-line size caps bound the renderer's work")
    def test_cost_does_not_grow_with_the_square_of_the_template(self, tmp_path: Path) -> None:
        small = scan_in_child(gen.unterminated_helm_chart(tmp_path / "s", "braces", 5_000))
        large = scan_in_child(gen.unterminated_helm_chart(tmp_path / "l", "braces", 20_000))
        assert small.clean and large.clean
        # Four times the input may cost about four times the time, never sixteen
        assert large.seconds < max(small.seconds * 8, 2.0)

    def test_a_long_unterminated_action_that_no_pattern_backtracks_over_is_fast_today(
        self, tmp_path: Path
    ) -> None:
        """The control shape is long and unterminated but cheap, so it needs no bound."""
        outcome = scan_in_child(gen.unterminated_helm_chart(tmp_path, "dash_whitespace"))
        assert not outcome.timed_out
        assert outcome.seconds < FAST_SECONDS

    def test_a_short_unterminated_template_still_yields_its_resource(self, tmp_path: Path) -> None:
        """Bounding the work must not drop the ConfigMap that holds the action."""
        outcome = scan_in_child(gen.unterminated_helm_chart(tmp_path, "braces", units=500))
        assert outcome.status == "ok"
        assert outcome.nodes == 1
