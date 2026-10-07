"""Helm templates that open an action and never close it must not stall a scan.

The first fallback renderer, used when the ``helm`` binary is missing, read templates with regular
expressions of the form ``{{ ... }}`` and backtracked over every unterminated ``{{`` to the end of
the line, so the cost grew with the square of the line length: 80 KB of ``{{`` took it about
fourteen seconds and 400 KB several minutes. A chart in a repository someone else controls could
therefore hold a scan for as long as it liked.

The renderer is now one left-to-right pass that copies an unterminated action through, and it caps
the size of a template file and of a single line. A scan of such a chart must end quickly, with
either a graph or the tool's own error.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.hostile import generators as gen
from tests.hostile.support import DEFAULT_BUDGET_SECONDS, scan_in_child

# What a tolerable scan costs: the interpreter starts in about half a second
FAST_SECONDS = 5.0


class TestUnterminatedActionsAreBounded:
    @pytest.mark.parametrize("shape", ["braces", "if_blocks"])
    def test_a_scan_ends_quickly_with_a_graph_or_the_tools_own_error(
        self, tmp_path: Path, shape: str
    ) -> None:
        chart_yaml = gen.unterminated_helm_chart(tmp_path, shape)
        outcome = scan_in_child(chart_yaml, budget=DEFAULT_BUDGET_SECONDS)
        assert not outcome.timed_out, f"{shape}: the scan did not finish in {outcome.seconds:.0f}s"
        assert outcome.clean, f"{shape}: {outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

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


def _chart(root: Path, template: str, values: str = "enabled: true\n") -> Path:
    """A chart with one template and the given values; returns its Chart.yaml."""
    chart = root / "chart"
    (chart / "templates").mkdir(parents=True)
    (chart / "Chart.yaml").write_text(gen.CHART_YAML, encoding="utf-8")
    (chart / "values.yaml").write_text(values, encoding="utf-8")
    (chart / "templates" / "t.yaml").write_text(template, encoding="utf-8")
    return chart / "Chart.yaml"


CONFIG_MAP = "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: hostile\ndata:\n  v: x\n"


class TestOtherHostileCharts:
    """Whatever a chart holds, a scan ends with a graph or the tool's own error, and quickly."""

    def test_a_huge_template_is_skipped_and_the_rest_still_scans(self, tmp_path: Path) -> None:
        chart_yaml = _chart(tmp_path, CONFIG_MAP)
        huge = chart_yaml.parent / "templates" / "huge.yaml"
        huge.write_text("# " + "x" * (3 * 1024 * 1024) + "\nkind: Huge\n", encoding="utf-8")
        outcome = scan_in_child(chart_yaml)
        assert outcome.status == "ok", outcome.message
        assert outcome.nodes == 1
        assert outcome.seconds < FAST_SECONDS

    def test_a_template_that_is_one_enormous_line_costs_little(self, tmp_path: Path) -> None:
        template = CONFIG_MAP + "x: " + "a" * 5_000_000 + "\n"
        outcome = scan_in_child(_chart(tmp_path, template))
        assert outcome.clean, outcome.message
        assert outcome.seconds < FAST_SECONDS

    def test_a_deeply_nested_template_does_not_crash_the_interpreter(self, tmp_path: Path) -> None:
        template = CONFIG_MAP + "{{ if .Values.enabled }}" * 5_000 + "x" + "{{ end }}" * 5_000
        outcome = scan_in_child(_chart(tmp_path, template))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    def test_templates_that_include_each_other_forever_stop(self, tmp_path: Path) -> None:
        template = (
            '{{ define "a" }}{{ include "b" . }}{{ end }}'
            '{{ define "b" }}{{ include "a" . }}{{ end }}' + CONFIG_MAP + '{{ include "a" . }}'
        )
        outcome = scan_in_child(_chart(tmp_path, template))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    def test_tpl_that_calls_itself_forever_stops(self, tmp_path: Path) -> None:
        template = CONFIG_MAP + "{{ tpl .Values.loop . }}"
        values = 'loop: "{{ tpl .Values.loop . }}"\n'
        outcome = scan_in_child(_chart(tmp_path, template, values))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    def test_nested_ranges_over_huge_integers_stop(self, tmp_path: Path) -> None:
        template = CONFIG_MAP + "{{ range 999999999 }}{{ range 999999999 }}x{{ end }}{{ end }}"
        outcome = scan_in_child(_chart(tmp_path, template))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    def test_a_regular_expression_written_to_backtrack_is_never_run(self, tmp_path: Path) -> None:
        template = CONFIG_MAP + '{{ regexMatch "(a+)+$" "' + "a" * 40 + '!" }}'
        outcome = scan_in_child(_chart(tmp_path, template))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    def test_values_that_expand_through_aliases_are_not_walked(self, tmp_path: Path) -> None:
        bomb = "a: &a [x, x, x, x, x, x, x, x, x, x]\n"
        previous = "a"
        refs = ", ".join(["*{}"] * 10)
        for name in "bcdefghijklmnop":
            bomb += f"{name}: &{name} [{refs.format(*[previous] * 10)}]\n"
            previous = name
        template = CONFIG_MAP + "{{ toYaml .Values.p }}"
        outcome = scan_in_child(_chart(tmp_path, template, bomb))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS

    def test_a_template_that_prints_gigabytes_is_cut_off(self, tmp_path: Path) -> None:
        template = CONFIG_MAP + '{{ range 5000 }}{{ repeat 1000 "y" }}{{ end }}' * 40
        outcome = scan_in_child(_chart(tmp_path, template))
        assert outcome.clean, f"{outcome.exception} {outcome.message}"
        assert outcome.seconds < FAST_SECONDS
        assert outcome.peak_mb < 1500

    def test_links_in_a_chart_are_not_followed_out_of_it(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        outside.mkdir()
        (outside / "secret.yaml").write_text("kind: Leaked\nmetadata:\n  name: leaked\n")
        chart_yaml = _chart(tmp_path, CONFIG_MAP)
        templates = chart_yaml.parent / "templates"
        (templates / "link.yaml").symlink_to(outside / "secret.yaml")
        (templates / "dir").symlink_to(outside, target_is_directory=True)
        outcome = scan_in_child(chart_yaml)
        assert outcome.status == "ok"
        assert outcome.nodes == 1

    def test_a_named_pipe_among_the_templates_does_not_block_the_scan(self, tmp_path: Path) -> None:
        import os

        if not hasattr(os, "mkfifo"):
            pytest.skip("no mkfifo on this platform")
        chart_yaml = _chart(tmp_path, CONFIG_MAP)
        os.mkfifo(chart_yaml.parent / "templates" / "pipe.yaml")
        outcome = scan_in_child(chart_yaml)
        assert not outcome.timed_out
        assert outcome.status == "ok"
        assert outcome.nodes == 1
