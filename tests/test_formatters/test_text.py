"""Tests for threatcode.formatters.text and the formatter registry."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from functools import cache
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
EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
ENTRY_START = re.compile(r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)([\^v]?)\s")
WIDTHS = (40, 50, 60, 70, 80, 100, 120, 160, 200)


@dataclass
class Entry:
    """One finding of the report: the identity line and the lines under it."""

    severity: str
    marker: str
    cells: list[str]
    body: list[str]

    @property
    def resource(self) -> str:
        return self.cells[0]

    @property
    def rule(self) -> str:
        return self.cells[1] if len(self.cells) > 1 else ""

    @property
    def paths(self) -> str:
        return self.cells[2] if len(self.cells) > 2 else ""

    @property
    def text(self) -> str:
        return " ".join(self.body)


def entries(text: str) -> list[Entry]:
    """The findings of a report: each starts with its severity at the left edge."""
    lines = text.splitlines()
    start = next(i for i, line in enumerate(lines) if line.startswith("SEVERITY"))
    found: list[Entry] = []
    for line in lines[start + 1 :]:
        if not line.strip() or line.startswith("Key:"):
            break
        match = ENTRY_START.match(line)
        if match:
            cells = re.split(r"\s{2,}", line[len(match.group(0)) :].strip())
            found.append(Entry(match.group(1), match.group(2), cells, []))
        elif found:
            found[-1].body.append(line.strip())
    return found


@cache
def example(name: str, ingest: bool = False) -> AnalysisResult:
    """The analysis of ``examples/<name>``, scanned the way ``threatcode scan`` scans it."""
    from threatcode.pipeline import prepare_request, run_scan

    extra = [EXAMPLES / "aws-webapp" / "scanner" / "trivy-app-image.json"] if ingest else []
    prepared = prepare_request(
        [EXAMPLES / name],
        min_severity="info",
        no_ignore=True,
        no_timestamp=True,
        ingest=extra,
        env={},
    )
    result = run_scan(prepared.request)
    assert not result.coverage.errors
    return result.analysis


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


def make_threat(index: int, severity: Severity = Severity.HIGH, **fields: Any) -> Threat:
    return Threat(
        id=f"t{index}",
        title=fields.pop("title", f"Finding number {index}"),
        description="d",
        stride_category=fields.pop("stride", "tampering"),
        severity=severity,
        source=fields.pop("source", ThreatSource.RULE),
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
    def test_header_verdict_and_one_entry_per_finding(self, analysis: AnalysisResult) -> None:
        text = format_text(analysis)
        lines = text.splitlines()
        assert lines[0] == "ThreatCode scan of simple.tf: 3 resources, 6 findings"
        assert lines[2] == "Verdict: 1 high, 3 medium, 2 low"
        assert len(entries(text)) == 6

    def test_findings_are_sorted_most_severe_first_then_by_address(
        self, analysis: AnalysisResult
    ) -> None:
        found = entries(format_text(analysis))
        severities = [e.severity for e in found]
        assert severities == sorted(severities, key=["HIGH", "MEDIUM", "LOW"].index)
        addresses = [e.resource for e in found if e.severity == "MEDIUM"]
        assert addresses == sorted(addresses)

    def test_an_entry_names_the_resource_the_rule_the_title_and_the_location(
        self, analysis: AnalysisResult
    ) -> None:
        text = format_text(analysis, RenderOptions(width=160))
        entry = next(
            e for e in entries(text) if e.resource == "aws_s3_bucket.test" and "KMS" in e.text
        )
        assert entry.rule == "S3_NO_ENCRYPTION"
        assert entry.body[0].startswith("S3 bucket not encrypted with a customer-managed KMS key")
        assert "simple.tf:3" in entry.text
        assert "STRIDE" in text and "ATT&CK" in text and "LOCATION" in text

    def test_plain_text_has_no_escape_codes_by_default(self, analysis: AnalysisResult) -> None:
        assert "\x1b[" not in format_text(analysis)
        assert "\x1b[" not in format_text(analysis, RenderOptions(color=False))

    def test_color_adds_escape_codes(self, analysis: AnalysisResult) -> None:
        assert "\x1b[" in format_text(analysis, RenderOptions(color=True))

    def test_color_only_wraps_text_so_the_layout_stays_the_same(
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
        assert "P1  CRITICAL  internet -> aws_s3_bucket.test" in text
        assert "internet > aws_s3_bucket.test" in text
        assert "ignore id: abc123abc123" in text
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
        assert entries(text)[0].severity == "CRITICAL"

    def test_a_report_without_findings_says_so_and_still_has_coverage(self) -> None:
        result = scan_files([FIXTURES / "kubernetes" / "secure_deployment.yml"])
        result.report.threats.clear()
        text = format_text(AnalysisResult(graph=result.graph, report=result.report))
        assert ", 0 findings" in text
        assert "Verdict: no findings" in text
        assert "Findings (" not in text
        assert "Coverage:" in text

    def test_every_finding_names_its_rule_at_any_width(self, analysis: AnalysisResult) -> None:
        rule_ids = {t.rule_id for t in analysis.report.threats}
        for width in (40, 60, 100, 160):
            text = format_text(analysis, RenderOptions(width=width))
            assert all(rule in text for rule in rule_ids), width

    def test_the_stride_category_and_techniques_follow_the_title(self) -> None:
        threat = make_threat(
            1, stride="information_disclosure", mitre_techniques=["T1530", "T1078"]
        )
        text = format_text(analysis_of(threat), RenderOptions(width=200))
        assert "Finding number 1  main.tf:2  T1530,T1078  Info disclosure" in text

    def test_a_long_technique_list_ends_in_a_count_never_in_half_an_id(self) -> None:
        techniques = ["T1548", "T1611", "T1105", "T1190", "T1078.004"]
        text = format_text(
            analysis_of(make_threat(1, mitre_techniques=techniques)), RenderOptions(width=200)
        )
        assert "T1548,T1611,T1105 +2" in text

    def test_columns_with_nothing_in_them_are_not_printed(self) -> None:
        threat = make_threat(1, file="", line=None)
        text = format_text(analysis_of(threat), RenderOptions(width=200))
        head = next(line for line in text.splitlines() if line.startswith("SEVERITY"))
        assert "PATHS" not in head
        assert "FINDING" in text and "LOCATION" not in text and "ATT&CK" not in text

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

    def test_the_width_comes_from_columns_then_the_default(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("COLUMNS", raising=False)
        assert terminal_width() == 100
        monkeypatch.setenv("COLUMNS", "132")
        assert terminal_width() == 132
        monkeypatch.setenv("COLUMNS", "10")
        assert terminal_width() == 40
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

    def test_model_findings_that_named_no_resource_are_said_to_be_set_aside(self) -> None:
        llm = {"status": "ran", "provider": "p", "model": "m", "threat_count": 1}
        wide = RenderOptions(width=200)
        one = format_text(analysis_of(make_threat(1), llm={**llm, "unattributed_count": 1}), wide)
        assert (
            "LLM: 1 model finding named no resource in the scan and was set aside "
            "(see llm.unattributed in the JSON report)"
        ) in one
        two = format_text(analysis_of(make_threat(1), llm={**llm, "unattributed_count": 2}), wide)
        assert "LLM: 2 model findings named no resource in the scan and were set aside" in two
        none = format_text(analysis_of(make_threat(1), llm={**llm, "unattributed_count": 0}))
        assert "named no resource" not in none

    def test_a_finding_with_an_empty_title_is_still_an_entry(self) -> None:
        text = format_text(analysis_of(make_threat(1, title=""), make_threat(2)))
        found = entries(text)
        assert len(found) == 2
        assert found[0].body[0].startswith("-")


class TestTextFromTheInputIsInert:
    """Names, titles, file names and messages come from the scanned files and are hostile."""

    ESC = "\x1b[2J\x1b[H\x1b]0;TITLE\x07\x9b31m\u202e"
    UNSAFE = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e]")

    def hostile_analysis(self) -> AnalysisResult:
        evil = f"evil{self.ESC}name"
        threat = make_threat(
            1,
            address=f"mcp_server.{evil}",
            title=f"Title {evil}",
            rule_id=f"RULE_{evil}",
            file=f"dir{self.ESC}/main.tf",
            root_cause=f"cause{self.ESC}",
            mitre_techniques=[f"T{self.ESC}"],
        )
        related = make_threat(
            2,
            address=f"mcp_server.{evil}",
            title="Another",
            rule_id=f"OTHER_{evil}",
            root_cause=f"cause{self.ESC}",
        )
        coverage = Coverage(
            files_discovered=2,
            units_parsed=1,
            not_iac_count=1,
            not_iac_paths=[f"data{self.ESC}.json"],
            min_severity=f"sev{self.ESC}",
            errors=[
                {"file": f"bad{self.ESC}.tf", "code": "parse.failed", "message": f"m{self.ESC}"}
            ],
            gaps=[
                {
                    "level": "warning",
                    "code": f"hcl.{self.ESC}",
                    "message": f"gap {self.ESC}",
                    "file": f"g{self.ESC}.tf",
                }
            ],
        )
        return analysis_of(
            threat,
            related,
            input_file=f"in{self.ESC}put",
            coverage=coverage,
            llm={"status": "failed", "error": f"boom {self.ESC}", "provider": f"p{self.ESC}"},
        )

    def test_no_control_character_reaches_the_report(self) -> None:
        text = format_text(self.hostile_analysis(), RenderOptions(width=200))
        assert not self.UNSAFE.search(text)
        assert "\\x1b[2J" in text and "\\x07" in text

    def test_with_color_the_only_escapes_are_the_styles(self) -> None:
        text = format_text(self.hostile_analysis(), RenderOptions(color=True, width=200))
        assert not self.UNSAFE.search(re.sub(r"\x1b\[[0-9;]*m", "", text))
        # Nothing the input said could have introduced a sequence of its own
        assert text.count("\x1b") == len(re.findall(r"\x1b\[[0-9;]*m", text))

    def test_an_attack_path_through_a_hostile_name_is_inert(self) -> None:
        evil = f"evil{self.ESC}name"
        finding = make_threat(1, address=f"mcp_server.{evil}", rule_id=f"R_{evil}")
        path = AttackPath(
            id=f"id{self.ESC}",
            entry="internet",
            target=f"mcp_server.{evil}",
            hops=[
                AttackHop(
                    node_id="internet",
                    zone="internet",
                    edge_type_to_next="network_flow",
                    via={"protocol": f"p{self.ESC}", "ports": [f"80{self.ESC}"]},
                    enabled_by=[finding.id],
                ),
                AttackHop(node_id=f"mcp_server.{evil}", zone="private"),
            ],
            severity=Severity.HIGH,
            rationale=f"The internet reaches {evil}",
            target_kind=f"kind{self.ESC}",
        )
        text = format_text(analysis_of(finding, attack_paths=[path]))
        assert not self.UNSAFE.search(text)
        assert "internet > mcp_server.evil\\x1b[2J" in text

    def test_the_diff_report_is_inert_too(self) -> None:
        from threatcode.formatters.diff import format_diff

        diff = {
            "baseline_total": 0,
            "current_total": 1,
            "unchanged_count": 0,
            "attack_paths_added": [
                {
                    "id": "x",
                    "entry": "internet",
                    "target": f"t{self.ESC}",
                    "severity": "high",
                    "hops": 1,
                }
            ],
            "attack_paths_removed": [],
            "added": [
                {
                    "id": "a",
                    "severity": "high",
                    "title": f"title {self.ESC}",
                    "resource_address": f"addr {self.ESC}",
                }
            ],
            "removed": [],
            "changed": [],
        }
        text = format_diff(diff, "text")
        assert not self.UNSAFE.search(text.replace("\n", " "))
        assert "\\x1b[2J" in text


class TestCoverageSummary:
    def _report(self, analysis: AnalysisResult, coverage: Coverage, width: int = 200) -> str:
        original = analysis.report.coverage
        analysis.report.coverage = coverage
        try:
            return format_text(analysis, RenderOptions(width=width))
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
        assert "Set aside: 4 findings suppressed, 2 findings baselined" in text
        assert "Errors (1):" in text and "bad.tf: unexpected token" in text
        assert "Gaps (1):" in text
        assert "[hcl.module_call_skipped] main.tf: module vpc not analysed" in text
        assert "Rule errors: 3 rule evaluations failed" in text
        assert "No input errors" not in text

    def test_attack_paths_set_aside_are_counted_apart_from_findings(
        self, analysis: AnalysisResult
    ) -> None:
        coverage = Coverage(
            units_parsed=1, suppressed=3, suppressed_paths=1, baselined=8, baselined_paths=2
        )
        text = self._report(analysis, coverage)
        assert (
            "Set aside: 2 findings and 1 attack path suppressed, "
            "6 findings and 2 attack paths baselined"
        ) in text

    def test_what_min_severity_hid_is_said_with_the_flag_that_hid_it(
        self, analysis: AnalysisResult
    ) -> None:
        coverage = Coverage(
            units_parsed=1, hidden_findings=7, hidden_paths=2, min_severity="medium"
        )
        text = self._report(analysis, coverage)
        assert "Hidden: 7 findings and 2 attack paths below medium (--min-severity)" in text
        assert "ThreatCode scan of simple.tf: 3 resources, 6 of 13 findings shown" in text
        assert "Findings (6 of 13 shown)" in text

    def test_long_lists_are_summarised(self, analysis: AnalysisResult) -> None:
        errors = [{"file": f"f{i}", "code": "parse.failed", "message": "m"} for i in range(14)]
        text = self._report(analysis, Coverage(errors=errors))
        assert "... and 4 more (see coverage.errors in the JSON report)" in text
        assert text.count("    f") == 10

    def test_a_gap_reported_twice_is_listed_once(self, analysis: AnalysisResult) -> None:
        gap = {
            "level": "warning",
            "code": "parse.failed",
            "message": "m",
            "file": "a.tf",
            "line": 3,
        }
        text = self._report(analysis, Coverage(units_parsed=1, gaps=[gap, dict(gap), dict(gap)]))
        assert "Gaps (1, 2 repeats merged):" in text
        assert text.count("[parse.failed] a.tf:3: m") == 1

    def test_many_gaps_of_one_code_in_one_file_are_one_line_with_a_count(
        self, analysis: AnalysisResult
    ) -> None:
        gaps = [
            {
                "level": "warning",
                "code": "hcl.unresolved_reference",
                "message": f"var.v{i} is not resolved",
                "file": "modules/iam/iam.tf",
                "line": 10 + i,
            }
            for i in range(252)
        ]
        text = self._report(analysis, Coverage(units_parsed=1, gaps=gaps))
        assert "Gaps (252):" in text
        assert (
            "[hcl.unresolved_reference] modules/iam/iam.tf: 252 times, first at line 10: "
            "var.v0 is not resolved"
        ) in text
        assert text.count("hcl.unresolved_reference") == 1

    def test_a_few_gaps_of_one_code_are_each_listed_with_their_line(
        self, analysis: AnalysisResult
    ) -> None:
        gaps = [
            {"level": "warning", "code": "c", "message": f"m{i}", "file": "a.tf", "line": i + 1}
            for i in range(3)
        ]
        text = self._report(analysis, Coverage(units_parsed=1, gaps=gaps))
        assert all(f"[c] a.tf:{i + 1}: m{i}" in text for i in range(3))

    def test_a_long_message_wraps_with_a_hanging_indent_at_the_terminal_width(
        self, analysis: AnalysisResult
    ) -> None:
        gap = {"level": "warning", "code": "x.y", "message": "word " * 60, "file": "a.tf"}
        analysis.report.coverage = Coverage(units_parsed=1, gaps=[gap])
        text = format_text(analysis, RenderOptions(width=70))
        gap_lines = text.split("Gaps (1):")[1].splitlines()[1:]
        assert len(gap_lines) > 3
        assert all(len(line) <= 70 for line in gap_lines)
        assert gap_lines[0].startswith("    [x.y]")
        assert all(line.startswith("      ") for line in gap_lines[1:] if line.strip())


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
