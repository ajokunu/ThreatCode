"""Tests for threatcode.formatters.text and the formatter registry."""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.helpers.scan import scan_files
from threatcode.exceptions import ThreatCodeError, UsageError
from threatcode.formatters import (
    FORMATTERS,
    RenderOptions,
    format_names,
    get_formatter,
    render,
    write_text_file,
)
from threatcode.formatters.text import format_text, plural
from threatcode.models.analysis import AnalysisResult
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import Coverage
from threatcode.models.threat import Severity

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(scope="module")
def analysis() -> AnalysisResult:
    result = scan_files([FIXTURES / "terraform" / "simple.tf"])
    result.report.input_file = "simple.tf"
    for threat in result.report.threats:
        threat.location_file = "simple.tf"
        threat.location_start_line = 3
    result.report.coverage = Coverage(files_discovered=1, units_parsed=1)
    return AnalysisResult(graph=result.graph, report=result.report)


class TestPlural:
    @pytest.mark.parametrize(
        ("count", "text"),
        [(0, "0 findings"), (1, "1 finding"), (2, "2 findings")],
    )
    def test_plural(self, count: int, text: str) -> None:
        assert plural(count, "finding") == text

    def test_irregular_plural(self) -> None:
        assert plural(2, "active entry", "active entries") == "2 active entries"
        assert plural(1, "active entry", "active entries") == "1 active entry"


class TestTextReport:
    def test_header_counts_and_one_line_per_finding(self, analysis: AnalysisResult) -> None:
        text = format_text(analysis)
        lines = text.splitlines()
        assert lines[0] == "ThreatCode scan of simple.tf: 2 resources, 5 findings"
        assert lines[2].startswith("critical 0  high 1  medium 4  low 0  info 0")
        findings = [line for line in lines if line.split(" ")[0] in {"HIGH", "MEDIUM", "LOW"}]
        assert len(findings) == 5

    def test_findings_are_sorted_most_severe_first_then_by_address(
        self, analysis: AnalysisResult
    ) -> None:
        lines = [
            line
            for line in format_text(analysis).splitlines()
            if line.split(" ")[0] in {"HIGH", "MEDIUM", "LOW"}
        ]
        severities = [line.split(" ")[0] for line in lines]
        assert severities == sorted(severities, key=["HIGH", "MEDIUM", "LOW"].index)
        mediums = [line for line in lines if line.startswith("MEDIUM")]
        addresses = [line.split()[1] for line in mediums]
        assert addresses == sorted(addresses)

    def test_a_line_names_the_resource_the_rule_and_the_location(
        self, analysis: AnalysisResult
    ) -> None:
        text = format_text(analysis)
        assert "aws_s3_bucket.test  S3_NO_ENCRYPTION  S3 bucket without server-side" in text
        assert "(simple.tf:3)" in text

    def test_plain_text_has_no_escape_codes_by_default(self, analysis: AnalysisResult) -> None:
        assert "\x1b[" not in format_text(analysis)
        assert "\x1b[" not in format_text(analysis, RenderOptions(color=False))

    def test_color_adds_escape_codes(self, analysis: AnalysisResult) -> None:
        assert "\x1b[" in format_text(analysis, RenderOptions(color=True))

    def test_no_color_wins_over_color(
        self, analysis: AnalysisResult, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert "\x1b[" not in format_text(analysis, RenderOptions(color=True))

    def test_attack_paths_are_listed(self, analysis: AnalysisResult) -> None:
        analysis.report.attack_paths.append(
            AttackPath(
                id="abc123abc123",
                entry="internet",
                target="aws_s3_bucket.test",
                hops=[AttackHop(node_id="internet"), AttackHop(node_id="aws_s3_bucket.test")],
                severity=Severity.CRITICAL,
            )
        )
        try:
            text = format_text(analysis)
        finally:
            analysis.report.attack_paths.clear()
        assert "Attack paths (1)" in text
        assert "internet -> aws_s3_bucket.test  (1 hop, id abc123abc123)" in text

    def test_a_report_without_findings_says_so_and_still_has_coverage(self) -> None:
        result = scan_files([FIXTURES / "kubernetes" / "secure_deployment.yml"])
        result.report.threats.clear()
        text = format_text(AnalysisResult(graph=result.graph, report=result.report))
        assert ", 0 findings" in text
        assert "Coverage:" in text


class TestCoverageSummary:
    def _report(self, analysis: AnalysisResult, coverage: Coverage) -> str:
        original = analysis.report.coverage
        analysis.report.coverage = coverage
        try:
            return format_text(analysis)
        finally:
            analysis.report.coverage = original

    def test_a_clean_scan_says_nothing_was_recorded(self, analysis: AnalysisResult) -> None:
        text = self._report(analysis, Coverage(files_discovered=3, units_parsed=3))
        assert "Coverage: 3 files discovered, 3 units parsed" in text
        assert "No input errors or coverage gaps were recorded." in text

    def test_errors_gaps_and_skips_are_listed(self, analysis: AnalysisResult) -> None:
        coverage = Coverage(
            files_discovered=5,
            units_parsed=3,
            not_iac_count=2,
            symlinks_skipped=1,
            special_files_skipped=1,
            suppressed=4,
            baselined=2,
            rule_errors=3,
            errors=[{"file": "bad.tf", "code": "parse.failed", "message": "unexpected token"}],
            gaps=[
                {
                    "level": "warning",
                    "code": "hcl.module_call_skipped",
                    "message": "module vpc not analysed",
                    "file": "main.tf",
                }
            ],
        )
        text = self._report(analysis, coverage)
        assert "2 not infrastructure" in text
        assert "Skipped: 1 symlink, 1 special file (never opened)" in text
        assert "Set aside: 4 suppressed, 2 baselined" in text
        assert "Errors (1):" in text and "bad.tf: unexpected token" in text
        assert "Gaps (1):" in text
        assert "[hcl.module_call_skipped] main.tf: module vpc not analysed" in text
        assert "Rule errors: 3 rule evaluations failed" in text
        assert "No input errors" not in text

    def test_long_lists_are_summarised(self, analysis: AnalysisResult) -> None:
        errors = [{"file": f"f{i}", "code": "parse.failed", "message": "m"} for i in range(14)]
        text = self._report(analysis, Coverage(errors=errors))
        assert "... and 4 more" in text
        assert text.count("    f") == 10


class TestRegistry:
    def test_the_formats_are_the_documented_seven(self) -> None:
        assert format_names() == [
            "json",
            "sarif",
            "markdown",
            "bitbucket",
            "matrix",
            "diagram",
            "text",
        ]

    def test_every_spec_has_an_extension_and_a_description(self) -> None:
        for name, spec in FORMATTERS.items():
            assert spec.extension.startswith("."), name
            assert spec.description, name
            assert callable(spec.render)

    def test_an_unknown_name_is_a_usage_error_listing_the_choices(self) -> None:
        with pytest.raises(UsageError, match="unknown output format 'yaml'.*json, sarif"):
            get_formatter("yaml")

    @pytest.mark.parametrize("name", ["json", "sarif", "markdown", "bitbucket", "matrix", "text"])
    def test_every_format_renders_a_scan(self, analysis: AnalysisResult, name: str) -> None:
        assert render(name, analysis).strip()

    def test_the_diagram_renders_svg(self, analysis: AnalysisResult) -> None:
        assert "<svg" in render("diagram", analysis)

    def test_the_json_format_is_the_report_dict(self, analysis: AnalysisResult) -> None:
        import json

        assert json.loads(render("json", analysis)) == analysis.report.to_dict()


class TestWriteTextFile:
    def test_creates_parent_directories_and_returns_the_absolute_path(self, tmp_path: Path) -> None:
        target = tmp_path / "a" / "b" / "out.txt"
        assert write_text_file(target, "hello") == target
        assert target.read_text(encoding="utf-8") == "hello"

    def test_a_directory_is_rejected_with_one_line(self, tmp_path: Path) -> None:
        with pytest.raises(ThreatCodeError) as info:
            write_text_file(tmp_path, "x")
        assert str(info.value) == f"cannot write {tmp_path}: it is a directory, not a file"

    def test_an_oserror_becomes_one_line_naming_the_path_and_the_reason(
        self, tmp_path: Path
    ) -> None:
        blocker = tmp_path / "file"
        blocker.write_text("x", encoding="utf-8")
        with pytest.raises(ThreatCodeError) as info:
            write_text_file(blocker / "child.txt", "x")
        message = str(info.value)
        assert message.startswith(f"cannot write {blocker / 'child.txt'}: ")
        assert "\n" not in message
