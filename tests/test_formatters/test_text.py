"""Tests for threatcode.formatters.text and the formatter registry."""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Any

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
from threatcode.formatters.text import format_text, plural, terminal_width
from threatcode.models.analysis import AnalysisResult
from threatcode.models.attack_path import AttackHop, AttackPath
from threatcode.models.report import Coverage, ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures"


@pytest.fixture(scope="module")
def analysis() -> AnalysisResult:
    result = scan_files([FIXTURES / "terraform" / "simple_exposed.tf"])
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


def table_rows(text: str) -> list[list[str]]:
    """The findings table as rows of cells; cells are separated by two or more spaces."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("SEVERITY"))
    rows = []
    for line in lines[start + 1 :]:
        if not line.strip():
            break
        rows.append(re.split(r"\s{2,}", line.strip()))
    return rows


def make_threat(index: int, severity: Severity = Severity.HIGH, **fields: Any) -> Threat:
    return Threat(
        id=f"t{index}",
        title=fields.pop("title", f"Finding number {index}"),
        description="d",
        stride_category=fields.pop("stride", "tampering"),
        severity=severity,
        source=ThreatSource.RULE,
        resource_type="aws_s3_bucket",
        resource_address=fields.pop("address", f"aws_s3_bucket.b{index}"),
        rule_id=fields.pop("rule_id", f"R{index}"),
        location_file=fields.pop("file", "main.tf"),
        location_start_line=fields.pop("line", index + 1),
        **fields,
    )


def analysis_of(*threats: Threat, **report_fields: Any) -> AnalysisResult:
    scan = scan_files([FIXTURES / "terraform" / "simple.tf"])
    report = ThreatReport(threats=list(threats), scanned_resources=3, **report_fields)
    return AnalysisResult(graph=scan.graph, report=report)


class TestTextReport:
    def test_header_verdict_and_one_row_per_finding(self, analysis: AnalysisResult) -> None:
        text = format_text(analysis)
        lines = text.splitlines()
        assert lines[0] == "ThreatCode scan of simple.tf: 3 resources, 6 findings"
        assert lines[2] == "Verdict: 1 high, 3 medium, 2 low"
        assert len(table_rows(text)) == 6

    def test_findings_are_sorted_most_severe_first_then_by_address(
        self, analysis: AnalysisResult
    ) -> None:
        rows = table_rows(format_text(analysis))
        severities = [row[0] for row in rows]
        assert severities == sorted(severities, key=["HIGH", "MEDIUM", "LOW"].index)
        addresses = [row[1] for row in rows if row[0] == "MEDIUM"]
        assert addresses == sorted(addresses)

    def test_a_row_names_the_resource_the_title_and_the_location(
        self, analysis: AnalysisResult
    ) -> None:
        text = format_text(analysis, RenderOptions(width=160))
        row = next(r for r in table_rows(text) if r[1] == "aws_s3_bucket.test" and "KMS" in r[3])
        assert row[2] == "S3_NO_ENCRYPTION"
        assert row[3] == "S3 bucket not encrypted with a customer-managed KMS key"
        assert row[-1] == "simple.tf:3"
        assert "STRIDE" in text and "ATT&CK" in text

    def test_plain_text_has_no_escape_codes_by_default(self, analysis: AnalysisResult) -> None:
        assert "\x1b[" not in format_text(analysis)
        assert "\x1b[" not in format_text(analysis, RenderOptions(color=False))

    def test_color_adds_escape_codes(self, analysis: AnalysisResult) -> None:
        assert "\x1b[" in format_text(analysis, RenderOptions(color=True))

    def test_color_only_wraps_severity_text_so_the_columns_stay_aligned(
        self, analysis: AnalysisResult
    ) -> None:
        plain = format_text(analysis, RenderOptions(color=False))
        colored = format_text(analysis, RenderOptions(color=True))
        assert re.sub(r"\x1b\[[0-9;]*m", "", colored) == plain

    def test_no_color_wins_over_color(
        self, analysis: AnalysisResult, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert "\x1b[" not in format_text(analysis, RenderOptions(color=True))

    def test_attack_paths_come_before_the_findings(self, analysis: AnalysisResult) -> None:
        analysis.report.attack_paths.append(
            AttackPath(
                id="abc123abc123",
                entry="internet",
                target="aws_s3_bucket.test",
                hops=[
                    AttackHop(node_id="internet", zone="internet"),
                    AttackHop(node_id="aws_s3_bucket.test", zone="data"),
                ],
                severity=Severity.CRITICAL,
            )
        )
        try:
            text = format_text(analysis)
        finally:
            analysis.report.attack_paths.clear()
        assert "Attack paths (1)" in text
        assert "internet -> aws_s3_bucket.test  (1 hop, id abc123abc123)" in text
        assert "internet > aws_s3_bucket.test" in text
        assert text.index("Attack paths (1)") < text.index("Findings (6)")
        assert "Verdict: 1 high, 3 medium, 2 low, 1 attack path from the internet to data" in text

    def test_the_verdict_counts_effective_severities(self) -> None:
        threats = [
            make_threat(1, Severity.MEDIUM, effective_severity=Severity.CRITICAL),
            make_threat(2, Severity.HIGH),
            make_threat(3, Severity.HIGH),
        ]
        text = format_text(analysis_of(*threats))
        assert "Verdict: 1 critical, 2 high" in text
        assert table_rows(text)[0][0] == "CRITICAL"

    def test_a_report_without_findings_says_so_and_still_has_coverage(self) -> None:
        result = scan_files([FIXTURES / "kubernetes" / "secure_deployment.yml"])
        result.report.threats.clear()
        text = format_text(AnalysisResult(graph=result.graph, report=result.report))
        assert ", 0 findings" in text
        assert "Verdict: no findings" in text
        assert "Findings (" not in text
        assert "Coverage:" in text

    def test_findings_with_one_root_cause_on_one_resource_share_a_row(self) -> None:
        threats = [
            make_threat(i, Severity.MEDIUM, address="k.web", root_cause="container-hardening")
            for i in range(1, 5)
        ]
        threats.append(make_threat(9, Severity.LOW, address="k.web"))
        text = format_text(analysis_of(*threats), RenderOptions(width=200))
        rows = table_rows(text)
        assert len(rows) == 2
        assert "(+3 related: container hardening)" in rows[0][3]
        assert "Findings (5)" in text

    def test_every_finding_names_its_rule_at_any_width(self, analysis: AnalysisResult) -> None:
        rule_ids = {t.rule_id for t in analysis.report.threats}
        for width in (100, 160):
            text = format_text(analysis, RenderOptions(width=width))
            assert all(rule in text for rule in rule_ids), width

    def test_the_stride_category_and_techniques_are_shown_when_there_is_room(self) -> None:
        threat = make_threat(
            1, stride="information_disclosure", mitre_techniques=["T1530", "T1078"]
        )
        wide = format_text(analysis_of(threat), RenderOptions(width=200))
        assert "InfoDisc" in wide and "T1530,T1078" in wide

    def test_a_narrow_terminal_drops_the_least_useful_columns(self) -> None:
        threat = make_threat(1, mitre_techniques=["T1530"])
        narrow = format_text(analysis_of(threat), RenderOptions(width=60))
        header = next(line for line in narrow.splitlines() if line.startswith("SEVERITY"))
        assert "LOCATION" not in header and "ATT&CK" not in header and "STRIDE" not in header
        assert "RESOURCE" in header and "FINDING" in header

    @pytest.mark.parametrize("width", [60, 80, 100, 140])
    def test_no_line_is_wider_than_the_terminal(self, width: int) -> None:
        threats = [
            make_threat(
                i,
                address="module.network.aws_security_group_rule.very_long_name_for_a_rule["
                + "x" * 40,
                title="A very long finding title that goes on and on " * 3,
                file="deep/dir/" * 5 + "main.tf",
            )
            for i in range(1, 4)
        ]
        text = format_text(analysis_of(*threats), RenderOptions(width=width))
        table = text.split("Findings (3)")[1].split("Coverage:")[0]
        assert all(len(line) <= max(width, 60) for line in table.splitlines())
        assert "..." in table

    def test_a_long_address_is_cut_in_the_middle_so_its_name_survives(self) -> None:
        threat = make_threat(1, address="module.network.aws_security_group.bastion_host_ssh")
        text = format_text(analysis_of(threat), RenderOptions(width=70))
        row = table_rows(text)[0]
        assert "..." in row[1]
        assert row[1].startswith("module.") and row[1].endswith("host_ssh")

    def test_a_finding_without_a_location_takes_its_nodes(self) -> None:
        scan = scan_files([FIXTURES / "terraform" / "simple.tf"])
        address = sorted(scan.graph.nodes)[0]
        node = scan.graph.nodes[address]
        threat = make_threat(1, address=address, file="", line=None)
        assert threat.location_file == ""
        report = ThreatReport(threats=[threat])
        text = format_text(
            AnalysisResult(graph=scan.graph, report=report), RenderOptions(width=200)
        )
        assert f"simple.tf:{node.start_line}" in text

    def test_a_long_location_keeps_its_file_name(self) -> None:
        threat = make_threat(1, file="very/deep/directory/structure/with/main.tf", line=12)
        text = format_text(analysis_of(threat), RenderOptions(width=100))
        assert "/main.tf:12" in text and "..." in text

    def test_the_width_comes_from_columns_then_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("COLUMNS", raising=False)
        assert terminal_width() == 100
        monkeypatch.setenv("COLUMNS", "132")
        assert terminal_width() == 132
        monkeypatch.setenv("COLUMNS", "10")
        assert terminal_width() == 60
        assert terminal_width(RenderOptions(width=90)) == 90

    def test_a_terminal_width_is_read_from_the_terminal(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("COLUMNS", raising=False)
        monkeypatch.setattr("sys.stdout.isatty", lambda: True, raising=False)
        monkeypatch.setattr(
            "shutil.get_terminal_size", lambda fallback=(100, 24): os.terminal_size((150, 40))
        )
        assert terminal_width() == 150

    def test_the_llm_status_is_reported(self) -> None:
        ran = analysis_of(
            make_threat(1), llm={"status": "ran", "provider": "p", "model": "m", "threat_count": 2}
        )
        assert "LLM: ran (p/m), 2 advisory findings" in format_text(ran)
        failed = analysis_of(make_threat(1), llm={"status": "failed", "error": "timed out"})
        assert "LLM: failed: timed out. Only rule-based findings are shown." in format_text(failed)
        assert "LLM:" not in format_text(analysis_of(make_threat(1), llm={"status": "skipped"}))

    def test_suppressed_and_baselined_counts_are_always_visible(self) -> None:
        text = format_text(
            analysis_of(make_threat(1), coverage=Coverage(suppressed=3, baselined=5))
        )
        assert "Set aside: 3 suppressed, 5 baselined" in text


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
    def test_the_formats_are_the_documented_ones(self) -> None:
        assert format_names() == [
            "json",
            "sarif",
            "markdown",
            "bitbucket",
            "navigator",
            "mermaid",
            "diagram",
            "text",
            "matrix",
        ]

    def test_matrix_is_the_old_name_of_navigator(self, analysis: AnalysisResult) -> None:
        assert render("matrix", analysis) == render("navigator", analysis)
        assert "Deprecated alias of navigator" == get_formatter("matrix").description

    def test_every_spec_has_an_extension_and_a_description(self) -> None:
        for name, spec in FORMATTERS.items():
            assert spec.extension.startswith("."), name
            assert spec.description, name
            assert callable(spec.render)

    def test_an_unknown_name_is_a_usage_error_listing_the_choices(self) -> None:
        with pytest.raises(UsageError, match="unknown output format 'yaml'.*json, sarif"):
            get_formatter("yaml")

    @pytest.mark.parametrize(
        "name",
        ["json", "sarif", "markdown", "bitbucket", "navigator", "matrix", "mermaid", "text"],
    )
    def test_every_format_renders_a_scan(self, analysis: AnalysisResult, name: str) -> None:
        assert render(name, analysis).strip()

    def test_the_diagram_renders_svg(self, analysis: AnalysisResult) -> None:
        assert "<svg" in render("diagram", analysis)

    def test_the_json_format_is_the_report_dict(self, analysis: AnalysisResult) -> None:
        import json

        expected = analysis.report.to_dict()
        data = json.loads(render("json", analysis))
        # The formatter puts the findings in report order; a bare engine report has none yet
        expected["threats"] = sorted(
            expected["threats"],
            key=lambda t: (
                ["critical", "high", "medium", "low", "info"].index(
                    t.get("effective_severity") or t["severity"]
                ),
                t["resource_address"],
                t["rule_id"],
                t["id"],
            ),
        )
        assert data == expected

    def test_the_json_graph_is_an_option(self, analysis: AnalysisResult) -> None:
        import json

        data = json.loads(render("json", analysis, RenderOptions(include_graph=True)))
        assert set(data["graph"]) == {"nodes", "edges"}
        assert "graph" not in json.loads(render("json", analysis))


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
