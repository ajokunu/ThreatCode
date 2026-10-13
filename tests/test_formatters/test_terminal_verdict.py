"""The verdict of a chart that was only partly analysed says so (RW-09), in words and in count."""

from __future__ import annotations

import re
import shutil
from pathlib import Path
from typing import Any

import pytest

from tests.test_formatters.test_text import analysis_of, make_threat
from threatcode.formatters import RenderOptions
from threatcode.formatters.terminal_verdict import (
    incomplete_phrase,
    unanalysed_templates,
    verdict_items,
)
from threatcode.formatters.text import format_text
from threatcode.models.report import Coverage, ThreatReport
from threatcode.models.threat import Severity


def gap(code: str, file: str, message: str = "m", level: str = "warning", **extra: Any) -> dict:
    return {"level": level, "code": code, "message": message, "file": file, **extra}


def skipped(template: str) -> dict:
    return gap(
        "helm.render_warning",
        template,
        f"{template} rendered to invalid YAML and was skipped: line 9",
    )


DEPENDENCY = gap(
    "helm.render_warning",
    "Chart.yaml",
    "dependency common is not vendored in charts/, so the templates that include its "
    "definitions and the resources of its subchart are not analysed",
)
FALLBACK = gap("helm.fallback_render", "Chart.yaml", "Chart.yaml was rendered without helm")


def report(gaps: list[dict], *threats: Any, **coverage: Any) -> ThreatReport:
    return ThreatReport(
        threats=list(threats), coverage=Coverage(units_parsed=1, gaps=gaps, **coverage)
    )


def text_of(items: list[tuple[str, str]]) -> str:
    return " ".join(text for text, _ in items)


class TestUnanalysedTemplates:
    def test_a_template_is_named_by_the_file_its_warning_is_filed_under(self) -> None:
        gaps = [skipped("templates/svc.yaml"), skipped("templates/sts.yaml"), DEPENDENCY]
        assert unanalysed_templates(gaps) == ["templates/svc.yaml", "templates/sts.yaml"]

    def test_a_template_warned_about_twice_counts_once(self) -> None:
        gaps = [skipped("templates/svc.yaml"), skipped("templates/svc.yaml")]
        assert unanalysed_templates(gaps) == ["templates/svc.yaml"]

    def test_a_warning_about_the_chart_as_a_whole_names_no_template(self) -> None:
        assert unanalysed_templates([DEPENDENCY, gap("helm.render_warning", "sub/Chart.yml")]) == []

    def test_gaps_of_other_codes_name_no_template(self) -> None:
        gaps = [gap("hcl.module_call_skipped", "templates/x.tf"), FALLBACK]
        assert unanalysed_templates(gaps) == []

    def test_a_warning_with_no_file_names_no_template(self) -> None:
        assert unanalysed_templates([gap("helm.render_warning", "")]) == []


class TestIncompletePhrase:
    def test_templates_are_counted_with_the_right_plural(self) -> None:
        assert incomplete_phrase([skipped("templates/a.yaml")]) == "1 template not analysed"
        two = [skipped("templates/a.yaml"), skipped("templates/b.yaml")]
        assert incomplete_phrase(two) == "2 templates not analysed"

    def test_only_a_chart_level_warning_says_the_chart_was_not_fully_analysed(self) -> None:
        assert incomplete_phrase([DEPENDENCY]) == "Helm chart not fully analysed"

    def test_an_error_level_gap_is_counted_whatever_its_code(self) -> None:
        errors = [gap("parse.failed", "a.tf", level="error")]
        assert incomplete_phrase(errors) == "1 error"
        both = [skipped("templates/a.yaml"), *errors]
        assert incomplete_phrase(both) == "1 template not analysed, 1 error"

    @pytest.mark.parametrize(
        "gaps",
        [
            [],
            [FALLBACK],
            [gap("hcl.module_call_skipped", "main.tf", line=4)],
            [gap("plan.unknown_values", "tfplan.json"), gap("cfn.unresolved_intrinsic", "t.json")],
        ],
    )
    def test_gaps_that_only_approximate_or_describe_a_module_say_nothing(
        self, gaps: list[dict]
    ) -> None:
        assert incomplete_phrase(gaps) == ""


class TestTheVerdict:
    def test_the_findings_of_the_rest_follow_the_count_of_templates_left_out(self) -> None:
        analysis = report([skipped("templates/svc.yaml"), DEPENDENCY])
        analysis.threats = [make_threat(1, Severity.MEDIUM), make_threat(2, Severity.LOW)]
        items = verdict_items(analysis)
        assert text_of(items) == "incomplete (1 template not analysed); in the rest: 1 medium 1 low"
        assert items[0][1] == "high"

    def test_a_chart_whose_templates_were_dropped_is_never_reported_as_having_no_findings(
        self,
    ) -> None:
        verdict = text_of(verdict_items(report([skipped("a.yaml"), skipped("b.yaml")])))
        assert verdict == "incomplete (2 templates not analysed); in the rest: nothing found"
        assert "no findings" not in verdict

    def test_a_clean_chart_still_says_no_findings(self) -> None:
        assert text_of(verdict_items(report([]))) == "no findings"
        assert text_of(verdict_items(report([FALLBACK]))) == "no findings"

    def test_a_module_gap_alone_does_not_change_the_verdict(self) -> None:
        threat = make_threat(1, Severity.HIGH)
        gaps = [gap("hcl.module_call_skipped", "main.tf", line=4)]
        assert text_of(verdict_items(report(gaps, threat))) == "1 high"

    def test_an_input_error_keeps_its_own_wording_and_is_not_prefixed_twice(self) -> None:
        errors = [{"file": "a.tf", "code": "parse.failed", "message": "bad"}]
        analysis = report([skipped("templates/a.yaml")], make_threat(1, Severity.HIGH))
        analysis.coverage.errors = errors
        assert text_of(verdict_items(analysis)) == "incomplete (1 input error); in the rest: 1 high"

    def test_what_a_baseline_accepted_is_kept_after_the_prefix(self) -> None:
        analysis = report([skipped("templates/a.yaml")], baselined=3, baselined_paths=1)
        assert text_of(verdict_items(analysis)) == (
            "incomplete (1 template not analysed); in the rest: "
            "no new findings (2 findings and 1 attack path baselined)"
        )


class TestWorstStaysTogether:
    def path(self) -> Any:
        from threatcode.models.attack_path import AttackHop, AttackPath

        return AttackPath(
            id="p",
            entry="internet",
            target="t",
            hops=[AttackHop(node_id="internet", zone="internet"), AttackHop(node_id="t")],
            severity=Severity.CRITICAL,
            target_kind="data store",
        )

    def test_a_worst_critical_is_never_split_across_two_lines(self) -> None:
        threats = [make_threat(i, s) for i, s in enumerate(Severity, start=1)]
        paths = [self.path(), self.path()]
        for width in range(44, 130):
            analysis = analysis_of(*threats, attack_paths=paths)
            text = format_text(analysis, RenderOptions(width=width))
            head = text.split("Verdict: ")[1].split("\n\n")[0]
            assert not re.search(r"worst\s*\n\s*critical", head), width
            assert "worst critical" in " ".join(head.split())

    def test_the_tie_is_not_in_the_phrases_the_report_prints(self) -> None:
        text = format_text(
            analysis_of(make_threat(1), attack_paths=[self.path()]), RenderOptions(width=60)
        )
        assert "\u2060" not in text


class TestInTheTextReport:
    def test_the_verdict_line_of_the_report_leads_with_incomplete(self) -> None:
        analysis = analysis_of(
            make_threat(1, Severity.MEDIUM),
            coverage=Coverage(units_parsed=1, gaps=[skipped("templates/svc.yaml"), DEPENDENCY]),
        )
        lines = format_text(analysis, RenderOptions(width=120)).splitlines()
        assert lines[2] == "Verdict: incomplete (1 template not analysed); in the rest: 1 medium"

    def test_the_verdict_wraps_with_its_hanging_indent_and_loses_nothing(self) -> None:
        analysis = analysis_of(
            make_threat(1, Severity.MEDIUM),
            coverage=Coverage(units_parsed=1, gaps=[skipped("templates/svc.yaml")]),
        )
        text = format_text(analysis, RenderOptions(width=40))
        head = text.split("Verdict: ")[1].split("\n\n")[0]
        assert "".join(head.split()) == "incomplete(1templatenotanalysed);intherest:1medium"
        assert all(len(line) <= 40 for line in text.splitlines())

    @staticmethod
    def library_chart(root: Path, *, plain_template: bool) -> Path:
        chart = root / "app"
        (chart / "templates").mkdir(parents=True)
        (chart / "Chart.yaml").write_text(
            "apiVersion: v2\nname: app\nversion: 1.0.0\n"
            "dependencies:\n  - name: common\n    version: 2.x.x\n    repository: oci://x\n"
        )
        (chart / "templates" / "svc.yaml").write_text(
            "apiVersion: v1\nkind: Service\nmetadata:\n"
            '  name: {{ include "common.names.fullname" . }}\n'
            '  namespace: {{ include "common.names.namespace" . | quote }}\n'
            '  labels: {{- include "common.labels.standard" . | nindent 4 }}\n'
            "    app.kubernetes.io/component: primary\nspec:\n  ports:\n    - port: 80\n"
        )
        if plain_template:
            (chart / "templates" / "cm.yaml").write_text(
                "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: settings\ndata:\n  a: b\n"
            )
        return chart

    def verdict_of(self, chart: Path) -> str:
        from threatcode.pipeline import prepare_request, run_scan

        prepared = prepare_request([chart], no_ignore=True, no_timestamp=True, env={})
        text = format_text(run_scan(prepared.request).analysis, RenderOptions(width=140))
        return text.split("Verdict: ")[1].splitlines()[0]

    def test_a_chart_that_lost_a_template_to_a_missing_library_chart_is_not_reported_clean(
        self, tmp_path: Path
    ) -> None:
        if shutil.which("helm"):
            pytest.skip("helm renders the library chart's includes itself")
        verdict = self.verdict_of(self.library_chart(tmp_path, plain_template=True))
        assert verdict.startswith("incomplete (1 template not analysed); in the rest: ")
        assert "no findings" not in verdict

    def test_a_chart_with_nothing_left_to_model_is_an_input_error_and_says_so(
        self, tmp_path: Path
    ) -> None:
        if shutil.which("helm"):
            pytest.skip("helm renders the library chart's includes itself")
        verdict = self.verdict_of(self.library_chart(tmp_path, plain_template=False))
        assert verdict.startswith("incomplete (1 input error)")
