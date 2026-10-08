"""Tests for threatcode.cli: the exit-code matrix, options, output and error handling."""

from __future__ import annotations

import builtins
import json
import os
import re
import shutil
import socket
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner, Result

from threatcode import __version__
from threatcode.cli import cli
from threatcode.engine.rules.loader import load_builtin_rules
from threatcode.exceptions import LLMError
from threatcode.formatters import format_names

if TYPE_CHECKING:
    from tests.conftest import FakeLLMServer

REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SHAPES = FIXTURES_DIR / "input_shapes"
K8S_FIXTURE = FIXTURES_DIR / "kubernetes" / "insecure_deployment.yml"
SIMPLE_TF = FIXTURES_DIR / "terraform" / "simple_exposed.tf"
SIMPLE_PLAN = FIXTURES_DIR / "terraform" / "simple_s3.plan.json"
INSECURE_PLAN = FIXTURES_DIR / "terraform" / "multi_service_insecure.plan.json"
WEBAPP_EXAMPLE = REPO_ROOT / "examples" / "aws-webapp"
HYBRID_TF = FIXTURES_DIR / "realistic" / "05_hybrid_vpn_datacenter.tf"
SECRETS_TREE = FIXTURES_DIR / "secrets" / "iac"
GITLEAKS_SARIF = FIXTURES_DIR / "ingest" / "sarif-gitleaks.json"
CHECKOV_SARIF = FIXTURES_DIR / "ingest" / "sarif-checkov.json"
BUCKET = 'resource "aws_s3_bucket" "{name}" {{\n  bucket = "{name}"\n}}\n'
EXPOSED = (
    'resource "aws_lambda_function_url" "{name}" {{\n'
    '  function_name      = "{name}"\n'
    '  authorization_type = "NONE"\n'
    "}}\n"
)
BAD_TF = 'resource "aws_s3_bucket" "broken" {\n  bucket = \n'
ANSI = re.compile(r"\x1b\[[0-9;]*m")

REMOVED_COMMANDS = ["image", "vuln", "db", "sbom", "license", "repo", "fs", "secret"]


@pytest.fixture(autouse=True)
def hermetic_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    """No home config, no THREATCODE_* variables and no API key leak into a test."""
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    for name in (
        "CI",
        "NO_COLOR",
        "SOURCE_DATE_EPOCH",
        "THREATCODE_FAIL_ON",
        "THREATCODE_MIN_SEVERITY",
        "THREATCODE_FORMAT",
        "THREATCODE_LLM",
        "THREATCODE_DEBUG",
        "ANTHROPIC_API_KEY",
    ):
        monkeypatch.delenv(name, raising=False)


def invoke(*args: str | Path, input: str | bytes | None = None, color: bool = False) -> Result:
    return CliRunner().invoke(cli, [str(a) for a in args], input=input, color=color)


def report_of(result: Result) -> dict[str, Any]:
    data: dict[str, Any] = json.loads(result.stdout)
    return data


def write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def bucket(name: str) -> str:
    return BUCKET.format(name=name)


def exposed(name: str) -> str:
    """A function URL with no authentication: the one high finding a gate test can rely on."""
    return EXPOSED.format(name=name)


class TestFindingProvenance:
    """A finding says how sure its rule is and what has to change, as the rule declares it."""

    CONFIDENCE = {"definitive": 1.0, "heuristic": 0.7, "absence": 0.5}

    def test_a_rule_finding_carries_the_confidence_and_root_cause_of_its_rule(self) -> None:
        rules = {rule.id: rule for rule in load_builtin_rules()}
        data = report_of(invoke("scan", INSECURE_PLAN, "--no-timestamp"))
        findings = [t for t in data["threats"] if t["source"] == "rule"]
        assert findings
        for finding in findings:
            rule = rules[finding["rule_id"]]
            assert finding["confidence"] == self.CONFIDENCE[rule.confidence], rule.id
            assert finding.get("root_cause", "") == rule.root_cause, rule.id
        # Not vacuous: the fixture trips rules of all three kinds and some that name a cause
        assert {f["confidence"] for f in findings} == {1.0, 0.7, 0.5}
        assert any(f.get("root_cause") for f in findings)

    def test_absence_findings_are_the_least_certain_and_never_critical(self) -> None:
        data = report_of(invoke("scan", INSECURE_PLAN))
        rules = {rule.id: rule for rule in load_builtin_rules()}
        absent = [
            t
            for t in data["threats"]
            if rules.get(t["rule_id"], None) and rules[t["rule_id"]].confidence == "absence"
        ]
        assert absent
        assert all(t["confidence"] == 0.5 for t in absent)
        assert all(t["severity"] in ("medium", "low", "info") for t in absent)

    def test_sarif_precision_follows_the_confidence(self) -> None:
        """A rule is as precise as its least certain finding: 1.0 high, 0.7 medium, 0.5 low."""
        report = report_of(invoke("scan", INSECURE_PLAN, "--no-timestamp"))
        least: dict[str, float] = {}
        for finding in report["threats"]:
            if finding["source"] == "rule":
                rule_id = finding["rule_id"]
                least[rule_id] = min(finding["confidence"], least.get(rule_id, 1.0))
        sarif = json.loads(invoke("scan", INSECURE_PLAN, "-f", "sarif").stdout)
        precision = {
            rule["id"]: rule["properties"]["precision"]
            for rule in sarif["runs"][0]["tool"]["driver"]["rules"]
        }
        expected = {1.0: "high", 0.7: "medium", 0.5: "low"}
        assert {precision[rule_id] for rule_id in least} == {"high", "medium", "low"}
        for rule_id, confidence in least.items():
            assert precision[rule_id] == expected[confidence], rule_id


class TestScanFormats:
    def test_json_output_is_the_v2_report(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", "json")
        assert result.exit_code == 1
        data = report_of(result)
        assert data["schema_version"] == "2"
        assert data["threats"]
        assert set(data) >= {"attack_paths", "coverage", "summary", "total_threats"}

    @pytest.mark.parametrize(
        ("fmt", "needle"),
        [
            ("markdown", "ThreatCode Threat Model Report"),
            ("sarif", '"version": "2.1.0"'),
            ("bitbucket", '"report"'),
            ("navigator", '"techniques"'),
            ("diagram", "<svg"),
            ("text", "ThreatCode scan of simple_s3.plan.json"),
        ],
    )
    def test_every_format_renders(self, fmt: str, needle: str) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", fmt)
        assert result.exit_code == 1, result.stderr
        assert needle in result.stdout

    def test_the_matrix_alias_still_renders_the_navigator_layer(self) -> None:
        """``matrix`` is the old name of ``navigator``; it keeps working and says nothing new."""
        old = invoke("scan", SIMPLE_PLAN, "-f", "matrix", "--no-timestamp")
        new = invoke("scan", SIMPLE_PLAN, "-f", "navigator", "--no-timestamp")
        assert old.exit_code == 1
        assert new.exit_code == 1
        assert old.stdout == new.stdout

    def test_the_format_choices_come_from_the_registry(self) -> None:
        scan_command = cli.commands["scan"]
        choice = next(p for p in scan_command.params if p.name == "output_format").type
        assert list(choice.choices) == format_names()  # type: ignore[attr-defined]

    def test_an_unknown_format_is_a_usage_error(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", "yaml")
        assert result.exit_code == 2
        assert "Invalid value for '--format'" in result.stderr

    def test_hcl_file(self) -> None:
        result = invoke("scan", SIMPLE_TF)
        assert result.exit_code == 1
        assert len(report_of(result)["threats"]) == 6


class TestExitCodeMatrix:
    @pytest.mark.parametrize(
        ("fail_on", "expected"),
        [("critical", 0), ("high", 1), ("medium", 1), ("low", 1), ("info", 1), ("none", 0)],
    )
    def test_findings_at_and_below_the_threshold(self, fail_on: str, expected: int) -> None:
        # simple_exposed.tf: one high, three medium and two low findings, nothing critical
        assert invoke("scan", SIMPLE_TF, "--fail-on", fail_on).exit_code == expected

    def test_the_default_threshold_is_high(self) -> None:
        # secure_deployment.yml has medium and low findings and nothing above
        secure = FIXTURES_DIR / "kubernetes" / "secure_deployment.yml"
        severities = {
            t["severity"] for t in report_of(invoke("scan", secure, "--fail-on", "none"))["threats"]
        }
        assert severities == {"medium", "low"}
        assert invoke("scan", secure).exit_code == 0
        assert invoke("scan", secure, "--fail-on", "high").exit_code == 0
        assert invoke("scan", secure, "--fail-on", "medium").exit_code == 1

    def test_findings_below_the_gate_exit_zero(self) -> None:
        """The hardened Dockerfile has a low finding; the default gate is high."""
        result = invoke("scan", FIXTURES_DIR / "docker" / "secure.Dockerfile", "-f", "json")
        assert result.exit_code == 0
        summary = report_of(result)["summary"]
        assert summary
        assert set(summary) <= {"medium", "low", "info"}
        assert "found 1 finding" in result.stderr

    def test_a_parse_failure_exits_two_and_names_the_file(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", BAD_TF)
        result = invoke("scan", tmp_path)
        assert result.exit_code == 2
        assert "Error: " in result.stderr
        assert "input error" in result.stderr
        assert "Traceback" not in result.output

    def test_a_parse_failure_still_prints_the_partial_report(self, tmp_path: Path) -> None:
        write(tmp_path, "good/main.tf", bucket("fine"))
        write(tmp_path, "bad/main.tf", BAD_TF)
        result = invoke("scan", tmp_path)
        assert result.exit_code == 2
        data = report_of(result)
        assert data["coverage"]["errors"][0]["file"] == "bad"
        assert any(t["resource_address"] == "aws_s3_bucket.fine" for t in data["threats"])

    def test_nothing_found_exits_two(self, tmp_path: Path) -> None:
        write(tmp_path, "README.md", "# nothing\n")
        result = invoke("scan", tmp_path)
        assert result.exit_code == 2
        assert "no supported infrastructure files found" in result.stderr

    def test_zero_resources_exits_two(self, tmp_path: Path) -> None:
        write(tmp_path, "vars.tf", 'variable "region" {\n  default = "x"\n}\n')
        result = invoke("scan", tmp_path)
        assert result.exit_code == 2
        assert "produced no resources" in result.stderr

    def test_the_ingest_seam_exits_two_naming_the_file(self, tmp_path: Path) -> None:
        junk = write(tmp_path, "junk.json", "{}")
        result = invoke("scan", SIMPLE_TF, "--ingest", junk)
        assert result.exit_code == 2
        assert "Error: " in result.stderr
        assert "junk.json" in result.stderr
        assert "Traceback" not in result.output

    def test_a_missing_path_exits_two(self, tmp_path: Path) -> None:
        result = invoke("scan", tmp_path / "nope.tf")
        assert result.exit_code == 2
        assert "Error: path not found" in result.stderr

    @pytest.mark.parametrize(
        "args",
        [
            ["scan"],
            ["scan", str(SIMPLE_TF), "--fail-on", "sometimes"],
            ["scan", str(SIMPLE_TF), "--min-severity", "none"],
            ["scan", str(SIMPLE_TF), "--bogus"],
            ["scan", str(SIMPLE_TF), "--max-nodes", "0"],
            ["bogus-command"],
        ],
    )
    def test_click_usage_errors_stay_two(self, args: list[str]) -> None:
        result = invoke(*args)
        assert result.exit_code == 2
        assert "Usage:" in result.stderr

    def test_fully_suppressed_scans_exit_zero(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        rules = sorted(
            {
                t["rule_id"]
                for t in report_of(invoke("scan", tmp_path, "--fail-on", "none"))["threats"]
            }
        )
        write(tmp_path, ".threatcodeignore", "\n".join(rules) + "\n")
        result = invoke("scan", tmp_path, "--fail-on", "info")
        assert result.exit_code == 0
        assert report_of(result)["threats"] == []

    def test_write_baseline_exits_zero_unless_an_input_error_occurred(self, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        ok = invoke("scan", SIMPLE_TF, "--write-baseline", baseline)
        assert ok.exit_code == 0
        assert json.loads(baseline.read_text())["entries"]
        bad = write(tmp_path / "bad", "main.tf", BAD_TF)
        failed = invoke("scan", bad, "--write-baseline", tmp_path / "other.json")
        assert failed.exit_code == 2
        assert not (tmp_path / "other.json").exists()


class TestStrictAndGaps:
    @pytest.fixture
    def gappy(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import threatcode.parsers as parsers
        from threatcode.diagnostics import Diagnostic

        real = parsers.detect_and_parse

        def patched(path: str | Path) -> Any:
            parsed = real(path)
            parsed.diagnostics.append(
                Diagnostic(
                    "warning",
                    "hcl.module_call_skipped",
                    "module call 'vpc' was not analysed",
                    file=str(path),
                    line=7,
                )
            )
            return parsed

        monkeypatch.setattr(parsers, "detect_and_parse", patched)

    def test_gaps_are_printed_on_stderr_and_do_not_fail_by_default(self, gappy: None) -> None:
        result = invoke("scan", SIMPLE_TF, "--fail-on", "none")
        assert result.exit_code == 0
        assert "Coverage gaps (1)" in result.stderr
        assert "[hcl.module_call_skipped] simple_exposed.tf:7" in result.stderr
        assert "Coverage gaps" not in result.stdout
        assert report_of(result)["coverage"]["gaps"][0]["code"] == "hcl.module_call_skipped"

    def test_gaps_survive_quiet(self, gappy: None) -> None:
        result = invoke("-q", "scan", SIMPLE_TF, "--fail-on", "none")
        assert "Coverage gaps (1)" in result.stderr
        assert "Scanned " not in result.stderr

    def test_strict_turns_a_gap_into_exit_two(self, gappy: None) -> None:
        result = invoke("scan", SIMPLE_TF, "--fail-on", "none", "--strict")
        assert result.exit_code == 2
        assert "--strict: coverage gaps make this scan fail" in result.stderr

    def test_strict_without_gaps_changes_nothing(self) -> None:
        result = invoke("scan", SIMPLE_TF, "--strict", "--fail-on", "none", "-f", "json")
        assert result.exit_code == 0
        assert "Coverage gaps" not in result.stderr
        assert report_of(result)["threats"]

    def test_errors_survive_quiet(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", BAD_TF)
        result = invoke("-q", "scan", tmp_path)
        assert result.exit_code == 2
        assert "Error: " in result.stderr
        assert "the scan is incomplete" in result.stderr

    def test_text_report_lists_the_gap_too(self, gappy: None) -> None:
        result = invoke("scan", SIMPLE_TF, "-f", "text", "--fail-on", "none")
        assert "Gaps (1):" in result.stdout
        assert "[hcl.module_call_skipped]" in result.stdout

    def test_failed_rules_are_counted_once_on_stderr(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import threatcode.engine.hybrid as hybrid

        real = hybrid.matches_rule

        def flaky(rule: Any, node: Any) -> Any:
            if rule.id.startswith("S3_NO_"):
                raise RuntimeError("boom")
            return real(rule, node)

        monkeypatch.setattr(hybrid, "matches_rule", flaky)
        result = invoke("scan", SIMPLE_TF, "--fail-on", "none")
        assert result.stderr.count("rule evaluations failed") == 1
        assert "see rule_errors in the JSON report" in result.stderr
        assert report_of(result)["coverage"]["rule_errors"] == len(report_of(result)["rule_errors"])


class TestOutputFiles:
    def test_output_goes_to_the_file_and_the_message_to_stderr(self, tmp_path: Path) -> None:
        out = tmp_path / "out" / "report.json"
        result = invoke("scan", SIMPLE_PLAN, "-f", "json", "-o", out)
        assert result.stdout == ""
        assert f"Report written to {out}" in result.stderr
        assert json.loads(out.read_text())["threats"]
        assert out.read_text().endswith("\n")

    def test_the_acceptance_invocation(self, tmp_path: Path) -> None:
        out = tmp_path / "tc_scan.json"
        result = invoke(
            "scan", SIMPLE_TF, "--no-timestamp", "--fail-on", "info", "-f", "json", "-o", out
        )
        assert result.exit_code == 1
        assert "timestamp" not in json.loads(out.read_text())

    def test_a_directory_is_rejected_before_scanning_without_a_traceback(
        self, tmp_path: Path
    ) -> None:
        result = invoke("scan", SIMPLE_TF, "-o", tmp_path)
        assert result.exit_code == 2
        assert f"Error: cannot write {tmp_path}: it is a directory, not a file" in result.stderr
        assert "Traceback" not in result.output
        assert result.stdout == ""

    def test_an_unwritable_path_is_one_line(self, tmp_path: Path) -> None:
        blocker = write(tmp_path, "file", "x")
        result = invoke("scan", SIMPLE_TF, "-o", blocker / "child.json")
        assert result.exit_code == 2
        lines = [line for line in result.stderr.splitlines() if line.startswith("Error:")]
        assert len(lines) == 1
        assert f"cannot write {blocker / 'child.json'}:" in lines[0]
        assert "Traceback" not in result.output

    def test_the_baseline_path_is_checked_too(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_TF, "--write-baseline", tmp_path)
        assert result.exit_code == 2
        assert f"Error: cannot write {tmp_path}: it is a directory" in result.stderr

    def test_quiet_hides_the_written_to_message(self, tmp_path: Path) -> None:
        result = invoke("-q", "scan", SIMPLE_TF, "-o", tmp_path / "r.json")
        assert "written to" not in result.stderr
        assert (tmp_path / "r.json").exists()

    def test_the_baseline_message_names_the_file(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_TF, "--write-baseline", tmp_path / "b.json")
        assert f"Baseline written to {tmp_path / 'b.json'}" in result.stderr


class TestStdin:
    def test_a_named_stdin_is_detected_by_the_name(self) -> None:
        result = invoke(
            "scan", "-", "--stdin-name", "main.tf", "--fail-on", "none", input=bucket("piped")
        )
        assert result.exit_code == 0
        data = report_of(result)
        assert data["input_file"] == "main.tf"
        assert {t["resource_address"] for t in data["threats"]} == {"aws_s3_bucket.piped"}

    def test_a_terraform_plan_pipe(self) -> None:
        result = invoke("scan", "-", "-f", "json", input=SIMPLE_PLAN.read_text())
        assert result.exit_code == 1
        assert report_of(result)["input_file"] == "stdin.json"

    def test_an_empty_pipe_is_a_usage_error(self) -> None:
        result = invoke("scan", "-", input="")
        assert result.exit_code == 2
        assert "standard input is empty" in result.stderr

    def test_a_bad_stdin_name_is_a_usage_error(self) -> None:
        result = invoke("scan", "-", "--stdin-name", "../x.tf", input=bucket("p"))
        assert result.exit_code == 2
        assert "--stdin-name must be a plain file name" in result.stderr


class TestTtyDefaultAndColor:
    @pytest.fixture
    def tty(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr("threatcode.cli._stdout_is_tty", lambda: True)

    def test_a_pipe_gets_json(self) -> None:
        assert invoke("scan", SIMPLE_TF).stdout.lstrip().startswith("{")

    def test_a_terminal_gets_text(self, tty: None) -> None:
        out = invoke("scan", SIMPLE_TF).stdout
        assert out.startswith("ThreatCode scan of simple_exposed.tf")
        assert not out.lstrip().startswith("{")

    def test_a_terminal_with_an_output_file_still_gets_json(
        self, tty: None, tmp_path: Path
    ) -> None:
        invoke("scan", SIMPLE_TF, "-o", tmp_path / "r.out")
        assert (tmp_path / "r.out").read_text().lstrip().startswith("{")

    def test_an_explicit_format_wins_over_the_terminal_default(self, tty: None) -> None:
        assert invoke("scan", SIMPLE_TF, "-f", "json").stdout.lstrip().startswith("{")

    def test_the_config_format_wins_over_the_terminal_default(
        self, tty: None, tmp_path: Path
    ) -> None:
        config = write(tmp_path, "c.yml", "output_format: markdown\n")
        out = invoke("scan", SIMPLE_TF, "-c", config).stdout
        assert out.startswith("# ThreatCode Threat Model Report")

    def test_a_terminal_gets_color(self, tty: None) -> None:
        assert ANSI.search(invoke("scan", SIMPLE_TF, color=True).stdout)

    def test_no_color_env_removes_it(self, tty: None, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("NO_COLOR", "1")
        assert not ANSI.search(invoke("scan", SIMPLE_TF, color=True).stdout)

    def test_the_no_color_flag_removes_it(self, tty: None) -> None:
        assert not ANSI.search(invoke("--no-color", "scan", SIMPLE_TF, color=True).stdout)

    def test_a_pipe_never_gets_color_even_when_text_is_asked_for(self) -> None:
        out = invoke("scan", SIMPLE_TF, "-f", "text", color=True).stdout
        assert not ANSI.search(out)
        assert out.startswith("ThreatCode scan")

    def test_diagram_to_a_terminal_without_a_file_is_refused(self, tty: None) -> None:
        result = invoke("scan", SIMPLE_TF, "-f", "diagram")
        assert result.exit_code == 2
        assert "pass -o file.svg" in result.stderr
        assert "<svg" not in result.stdout


class TestSettingsPrecedence:
    def test_the_flag_beats_the_environment_beats_the_config(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        config = write(tmp_path, "c.yml", "fail_on: none\n")
        assert invoke("scan", SIMPLE_TF, "-c", config).exit_code == 0
        monkeypatch.setenv("THREATCODE_FAIL_ON", "high")
        assert invoke("scan", SIMPLE_TF, "-c", config).exit_code == 1
        assert invoke("scan", SIMPLE_TF, "-c", config, "--fail-on", "critical").exit_code == 0

    def test_min_severity_precedence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = write(tmp_path, "c.yml", "min_severity: critical\nfail_on: none\n")
        assert report_of(invoke("scan", SIMPLE_TF, "-c", config))["threats"] == []
        monkeypatch.setenv("THREATCODE_MIN_SEVERITY", "high")
        assert len(report_of(invoke("scan", SIMPLE_TF, "-c", config))["threats"]) == 1
        flagged = invoke("scan", SIMPLE_TF, "-c", config, "--min-severity", "medium")
        assert len(report_of(flagged)["threats"]) == 4

    def test_format_precedence(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
        config = write(tmp_path, "c.yml", "output_format: markdown\nfail_on: none\n")
        assert invoke("scan", SIMPLE_TF, "-c", config).stdout.startswith("# ThreatCode")
        monkeypatch.setenv("THREATCODE_FORMAT", "text")
        assert invoke("scan", SIMPLE_TF, "-c", config).stdout.startswith("ThreatCode scan")
        assert invoke("scan", SIMPLE_TF, "-c", config, "-f", "json").stdout.startswith("{")

    def test_min_severity_is_display_only_the_gate_still_sees_everything(self) -> None:
        shown = invoke("scan", SIMPLE_TF, "--min-severity", "critical")
        assert report_of(shown)["threats"] == []
        assert shown.exit_code == 1

    def test_the_click_options_default_to_none_so_presence_is_detectable(self) -> None:
        params = {p.name: p for p in cli.commands["scan"].params}
        for name in ("output_format", "min_severity", "fail_on", "llm"):
            assert params[name].default is None, name

    def test_an_invalid_environment_value_is_a_config_error(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_FAIL_ON", "sometimes")
        result = invoke("scan", SIMPLE_TF)
        assert result.exit_code == 2
        assert "Error: THREATCODE_FAIL_ON must be one of" in result.stderr

    def test_config_errors_are_exit_two_and_one_line(self, tmp_path: Path) -> None:
        config = write(tmp_path, "c.yml", "min_severty: high\n")
        result = invoke("scan", SIMPLE_TF, "-c", config)
        assert result.exit_code == 2
        assert "min_severty: unknown key (did you mean 'min_severity'?)" in result.stderr
        assert "Traceback" not in result.output

    def test_a_config_that_is_a_list_is_exit_two_not_a_traceback(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_TF, "-c", write(tmp_path, "c.yml", "- a\n- b\n"))
        assert result.exit_code == 2
        assert "must be a mapping" in result.stderr
        assert "AttributeError" not in result.output

    def test_a_missing_config_file_is_a_clean_error(self, tmp_path: Path) -> None:
        result = invoke("scan", K8S_FIXTURE, "-c", tmp_path / "missing.yml")
        assert result.exit_code == 2
        assert "Error: Config file not found" in result.stderr
        assert "Traceback" not in result.output


class TestAutoDiscoveredConfig:
    def _tree(self, tmp_path: Path, config: str) -> Path:
        root = tmp_path / "repo"
        write(root, "main.tf", exposed("one"))
        write(root, ".threatcode.yml", config)
        return root

    def test_the_gate_cannot_be_disabled_by_the_scanned_repository(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path, "fail_on: none\n")
        result = invoke("scan", root)
        assert result.exit_code == 1
        assert "restricted fields ['fail_on']" in result.stderr
        assert "honored only from --config" in result.stderr

    def test_the_safe_fields_are_used_and_announced(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path, "min_severity: high\noutput_format: markdown\n")
        result = invoke("scan", root, "--fail-on", "none")
        assert result.stdout.startswith("# ThreatCode Threat Model Report")
        assert "(auto-discovered); fields used: min_severity, output_format" in result.stderr
        assert str(root / ".threatcode.yml") in result.stderr

    def test_quiet_hides_the_announcement_but_not_the_ignored_warning(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path, "min_severity: high\nfail_on: none\n")
        result = invoke("-q", "scan", root)
        assert "auto-discovered" not in result.stderr
        assert "restricted fields ['fail_on']" in result.stderr

    def test_an_explicit_config_may_set_the_gate_and_is_not_announced_as_discovered(
        self, tmp_path: Path
    ) -> None:
        root = self._tree(tmp_path, "fail_on: none\n")
        trusted = write(tmp_path, "trusted.yml", "fail_on: none\n")
        result = invoke("scan", root, "-c", trusted)
        assert result.exit_code == 0
        assert "auto-discovered" not in result.stderr

    def test_a_config_in_the_current_directory_is_found_too(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        elsewhere = tmp_path / "elsewhere"
        write(elsewhere, "main.tf", bucket("one"))
        cwd = tmp_path / "cwd"
        write(cwd, ".threatcode.yml", "min_severity: critical\n")
        monkeypatch.chdir(cwd)
        result = invoke("scan", elsewhere, "--fail-on", "none")
        assert report_of(result)["threats"] == []
        assert "auto-discovered" in result.stderr

    def test_a_bad_safe_field_in_a_discovered_config_is_an_error(self, tmp_path: Path) -> None:
        root = self._tree(tmp_path, "min_severity: extreme\n")
        result = invoke("scan", root)
        assert result.exit_code == 2
        assert "min_severity" in result.stderr


class TestSuppressionsAndBaselineFlags:
    def test_the_ignore_file_used_and_the_count_are_printed(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        write(tmp_path, ".threatcodeignore", "S3_NO_ENCRYPTION\nS3_NO_LOGGING\nGHOST\n")
        result = invoke("scan", tmp_path, "--fail-on", "none")
        assert (
            f"Using ignore file {tmp_path / '.threatcodeignore'} (3 active entries)"
            in result.stderr
        )
        assert "suppressed 2 findings" in result.stderr
        assert "GHOST matched no finding" in result.stderr
        assert report_of(result)["coverage"]["suppressed"] == 2

    def test_an_entry_naming_a_rule_a_user_rule_file_deprecated_warns(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        rules = write(tmp_path, "mine.yml", "deprecated_ids:\n  - MY_OLD_RULE\nrules: []\n")
        write(tmp_path, ".threatcodeignore", 'MY_OLD_RULE exp:2099-12-31 reason="was accepted"\n')
        with_rules = invoke("scan", tmp_path, "--rules", rules, "--fail-on", "none")
        assert "MY_OLD_RULE names a rule that was removed or renamed" in with_rules.stderr
        without = invoke("scan", tmp_path, "--fail-on", "none")
        assert "removed or renamed" not in without.stderr

    def test_no_ignore(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", exposed("one"))
        write(tmp_path, ".threatcodeignore", "LAMBDA_URL_NO_AUTH\n")
        result = invoke("scan", tmp_path, "--no-ignore")
        assert result.exit_code == 1
        assert "ignore file" not in result.stderr

    def test_an_explicit_ignore_file(self, tmp_path: Path) -> None:
        write(tmp_path / "src", "main.tf", bucket("one"))
        custom = write(tmp_path, "mine.ignore", "S3_NO_ENCRYPTION\n")
        result = invoke("scan", tmp_path / "src", "--ignore-file", custom, "--fail-on", "none")
        assert report_of(result)["coverage"]["suppressed"] == 1

    def test_a_missing_explicit_ignore_file_is_exit_two(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_TF, "--ignore-file", tmp_path / "nope")
        assert result.exit_code == 2
        assert "Ignore file not found" in result.stderr

    def test_ignore_file_and_no_ignore_together_are_a_usage_error(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_TF, "--ignore-file", tmp_path / "x", "--no-ignore")
        assert result.exit_code == 2
        assert "contradict" in result.stderr

    def test_an_expired_entry_is_warned_and_does_not_suppress(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", exposed("one"))
        write(tmp_path, ".threatcodeignore", "LAMBDA_URL_NO_AUTH exp:2020-01-01\n")
        result = invoke("scan", tmp_path)
        assert result.exit_code == 1
        assert "expired on 2020-01-01" in result.stderr

    def test_a_baseline_hides_known_findings_from_the_gate(self, tmp_path: Path) -> None:
        baseline = tmp_path / "baseline.json"
        assert invoke("scan", SIMPLE_TF, "--write-baseline", baseline).exit_code == 0
        again = invoke("scan", SIMPLE_TF, "--baseline", baseline, "--fail-on", "info")
        assert again.exit_code == 0
        data = report_of(again)
        assert data["threats"] == []
        assert data["coverage"]["baselined"] == 6
        assert "6 baselined" in again.stderr

    def test_a_bad_baseline_is_exit_two(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_TF, "--baseline", write(tmp_path, "b.json", "{}"))
        assert result.exit_code == 2
        assert "not a ThreatCode baseline" in result.stderr


class TestAttackPathsHonorSuppressionsAndBaselines:
    """An attack path gates the exit code, so the ways to set a known one aside must reach it."""

    @staticmethod
    def path_ids(result: Result) -> list[str]:
        return [path["id"] for path in report_of(result)["attack_paths"]]

    @pytest.fixture
    def baseline(self, tmp_path: Path) -> Path:
        written = tmp_path / "baseline.json"
        assert invoke("scan", WEBAPP_EXAMPLE, "--write-baseline", written).exit_code == 0
        return written

    def test_the_example_fails_the_gate_on_its_attack_paths(self) -> None:
        result = invoke("scan", WEBAPP_EXAMPLE)
        assert result.exit_code == 1
        assert len(self.path_ids(result)) == 3

    def test_the_baseline_records_every_finding_and_attack_path(self, baseline: Path) -> None:
        document = json.loads(baseline.read_text(encoding="utf-8"))
        again = invoke("scan", WEBAPP_EXAMPLE, "--fail-on", "none")
        assert [p["id"] for p in document["attack_paths"]] == sorted(self.path_ids(again))
        assert len(document["attack_paths"]) == 3
        assert document["entries"]

    def test_a_baseline_hides_known_attack_paths_from_the_gate_and_the_listing(
        self, baseline: Path
    ) -> None:
        before = report_of(invoke("scan", WEBAPP_EXAMPLE, "--fail-on", "none"))
        again = invoke("scan", WEBAPP_EXAMPLE, "--baseline", baseline)
        assert again.exit_code == 0
        data = report_of(again)
        assert data["threats"] == []
        assert data["attack_paths"] == []
        assert data["coverage"]["baselined"] == len(before["threats"]) + len(before["attack_paths"])

    def test_the_summary_line_counts_what_the_baseline_set_aside(self, baseline: Path) -> None:
        again = invoke("scan", WEBAPP_EXAMPLE, "--baseline", baseline)
        assert re.search(r"found 0 findings \(\d+ baselined\)", again.stderr)

    def test_an_attack_path_the_baseline_does_not_list_still_fails_the_gate(
        self, baseline: Path
    ) -> None:
        document = json.loads(baseline.read_text(encoding="utf-8"))
        new = document["attack_paths"].pop(0)["id"]
        baseline.write_text(json.dumps(document), encoding="utf-8")
        again = invoke("scan", WEBAPP_EXAMPLE, "--baseline", baseline)
        assert again.exit_code == 1
        data = report_of(again)
        assert data["threats"] == []
        assert self.path_ids(again) == [new]

    def test_a_baseline_without_attack_paths_does_not_hide_them(self, baseline: Path) -> None:
        # The format written before attack paths were recorded has no attack_paths key.
        document = json.loads(baseline.read_text(encoding="utf-8"))
        del document["attack_paths"]
        baseline.write_text(json.dumps(document), encoding="utf-8")
        again = invoke("scan", WEBAPP_EXAMPLE, "--baseline", baseline)
        assert again.exit_code == 1
        data = report_of(again)
        assert data["threats"] == []
        assert len(data["attack_paths"]) == 3

    def test_an_ignore_entry_with_a_path_id_removes_that_path(self, tmp_path: Path) -> None:
        plan = tmp_path / "plan"
        plan.mkdir()
        shutil.copy(WEBAPP_EXAMPLE / "tfplan.json", plan / "tfplan.json")
        ids = self.path_ids(invoke("scan", plan, "--fail-on", "none"))
        (plan / ".threatcodeignore").write_text(
            f'{ids[0]} exp:2099-12-31 reason="accepted for this test"\n', encoding="utf-8"
        )
        result = invoke("scan", plan, "--fail-on", "none")
        assert self.path_ids(result) == ids[1:]
        assert report_of(result)["coverage"]["suppressed"] == 1
        assert "suppressed 0 findings and 1 attack path" in result.stderr
        assert "matched no finding or attack path" not in result.stderr

    def test_ignoring_every_path_and_baselining_the_findings_reaches_green(
        self, tmp_path: Path, baseline: Path
    ) -> None:
        document = json.loads(baseline.read_text(encoding="utf-8"))
        ids = [p["id"] for p in document["attack_paths"]]
        document["attack_paths"] = []
        baseline.write_text(json.dumps(document), encoding="utf-8")
        plan = tmp_path / "plan"
        plan.mkdir()
        shutil.copy(WEBAPP_EXAMPLE / "tfplan.json", plan / "tfplan.json")
        lines = [f'{i} exp:2099-12-31 reason="accepted for this test"' for i in ids]
        (plan / ".threatcodeignore").write_text("\n".join(lines) + "\n", encoding="utf-8")
        result = invoke("scan", plan, "--baseline", baseline)
        assert result.exit_code == 0
        assert report_of(result)["attack_paths"] == []
        assert report_of(result)["coverage"]["suppressed"] == 3

    def test_an_ignore_entry_that_names_no_path_still_warns(self, tmp_path: Path) -> None:
        plan = tmp_path / "plan"
        plan.mkdir()
        shutil.copy(WEBAPP_EXAMPLE / "tfplan.json", plan / "tfplan.json")
        (plan / ".threatcodeignore").write_text(
            'ffffffffffff exp:2099-12-31 reason="a path that is gone"\n', encoding="utf-8"
        )
        result = invoke("scan", plan, "--fail-on", "none")
        assert len(self.path_ids(result)) == 3
        assert "ffffffffffff matched no finding or attack path" in result.stderr


def sarif_with_results(source: Path, uri: str, lines: list[int], target: Path) -> Path:
    """A copy of a SARIF fixture whose first result is repeated at ``lines`` of file ``uri``."""
    document = json.loads(source.read_text(encoding="utf-8"))
    run = document["runs"][0]
    first = run["results"][0]
    results = []
    for line in lines:
        result = json.loads(json.dumps(first))
        physical = result["locations"][0]["physicalLocation"]
        physical["artifactLocation"]["uri"] = uri
        physical["region"] = {"startLine": line, "endLine": line}
        results.append(result)
    run["results"] = results
    target.write_text(json.dumps(document), encoding="utf-8")
    return target


class TestIngestedFindingsAreReconciledWithNativeOnes:
    """A scanner finding at the file and line of ThreatCode's own finding is reported once."""

    @staticmethod
    def scan(tree: Path, sarif: Path) -> dict[str, Any]:
        result = invoke("scan", tree, "--ingest", sarif, "--fail-on", "none")
        assert result.exit_code == 0, result.stderr
        return report_of(result)

    def test_a_scanner_secret_on_the_line_of_a_native_secret_is_dropped(
        self, tmp_path: Path
    ) -> None:
        sarif = sarif_with_results(
            GITLEAKS_SARIF, "terraform/main.tf", [7, 2], tmp_path / "g.sarif"
        )
        data = self.scan(SECRETS_TREE, sarif)
        scanner = [t for t in data["threats"] if t["source"] == "scanner"]
        assert [t["location_start_line"] for t in scanner] == [2]
        (native,) = [
            t
            for t in data["threats"]
            if t["source"] == "secret"
            and (t["location_file"], t["location_start_line"]) == ("terraform/main.tf", 7)
        ]
        assert native["metadata"]["corroborated_by"] == ["gitleaks"]

    def test_the_kept_scanner_finding_is_not_marked_as_corroborating_anything(
        self, tmp_path: Path
    ) -> None:
        sarif = sarif_with_results(GITLEAKS_SARIF, "terraform/main.tf", [2], tmp_path / "g.sarif")
        data = self.scan(SECRETS_TREE, sarif)
        assert len([t for t in data["threats"] if t["source"] == "scanner"]) == 1
        assert not any(
            "corroborated_by" in t["metadata"] for t in data["threats"] if t["source"] == "secret"
        )

    def test_the_source_counts_the_duplicate_it_lost(self, tmp_path: Path) -> None:
        sarif = sarif_with_results(
            GITLEAKS_SARIF, "terraform/main.tf", [7, 2], tmp_path / "g.sarif"
        )
        (source,) = self.scan(SECRETS_TREE, sarif)["ingest"]
        assert (source["findings"], source["attached"], source["duplicates"]) == (2, 2, 1)

    def test_a_scanner_finding_in_another_file_is_never_a_duplicate(self, tmp_path: Path) -> None:
        sarif = sarif_with_results(GITLEAKS_SARIF, "terraform/other.tf", [7], tmp_path / "g.sarif")
        data = self.scan(SECRETS_TREE, sarif)
        assert len([t for t in data["threats"] if t["source"] == "scanner"]) == 1
        (source,) = data["ingest"]
        assert source["duplicates"] == 0

    def test_the_report_without_the_overlap_equals_the_report_without_the_ingest(
        self, tmp_path: Path
    ) -> None:
        sarif = sarif_with_results(GITLEAKS_SARIF, "terraform/main.tf", [7], tmp_path / "g.sarif")
        with_ingest = self.scan(SECRETS_TREE, sarif)
        plain = report_of(invoke("scan", SECRETS_TREE, "--fail-on", "none"))
        natives = [t for t in with_ingest["threats"] if t["source"] != "scanner"]
        assert [t["id"] for t in natives] == [t["id"] for t in plain["threats"]]
        assert with_ingest["total_threats"] == plain["total_threats"]

    def test_a_dropped_duplicate_leaves_no_dangling_reference_on_an_attack_path(
        self, tmp_path: Path
    ) -> None:
        tree = tmp_path / "hybrid"
        tree.mkdir()
        shutil.copy(HYBRID_TF, tree / "main.tf")
        lines = (tree / "main.tf").read_text(encoding="utf-8").splitlines()
        start = 1 + lines.index('resource "aws_s3_bucket" "vpn_logs" {')
        sarif = sarif_with_results(CHECKOV_SARIF, "main.tf", [start], tmp_path / "c.sarif")
        data = self.scan(tree, sarif)
        assert not any(t["source"] == "scanner" for t in data["threats"])
        assert data["attack_paths"]
        known = {t["id"] for t in data["threats"]}
        enablers = [i for p in data["attack_paths"] for h in p["hops"] for i in h["enabled_by"]]
        assert enablers
        assert set(enablers) <= known
        (source,) = data["ingest"]
        assert source["duplicates"] == 1


class TestLlmIsOptIn:
    @pytest.fixture
    def built(self, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
        from threatcode.engine.llm.client import BaseLLMClient

        class Quiet(BaseLLMClient):
            def analyze(self, prompt: str) -> str:
                return '{"threats": []}'

        calls: list[Any] = []

        def build(settings: Any) -> BaseLLMClient:
            calls.append(settings)
            return Quiet()

        monkeypatch.setattr("threatcode.engine.llm.factory.build_client", build)
        return calls

    def test_no_client_without_a_request_even_with_an_api_key(
        self, built: list[Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test")
        result = invoke("scan", SIMPLE_TF)
        assert built == []
        assert "LLM" not in result.stderr
        assert "API key" not in result.stderr

    def test_the_flag_builds_a_client_and_says_where_the_graph_goes(self, built: list[Any]) -> None:
        result = invoke("scan", SIMPLE_TF, "--llm")
        assert len(built) == 1
        assert "LLM enrichment enabled: sending a redacted graph to anthropic/" in result.stderr

    def test_dry_run_implies_the_llm_path(self, built: list[Any]) -> None:
        result = invoke("scan", SIMPLE_TF, "--dry-run")
        assert len(built) == 1 and built[0].dry_run
        assert "Dry run: the LLM request is built and nothing is sent" in result.stderr

    def test_dry_run_with_no_llm_is_a_usage_error(self, built: list[Any]) -> None:
        result = invoke("scan", SIMPLE_TF, "--dry-run", "--no-llm")
        assert result.exit_code == 2
        assert "cannot be combined with --no-llm" in result.stderr
        assert built == []

    def test_no_llm_wins_over_an_enabled_config(self, built: list[Any], tmp_path: Path) -> None:
        config = write(tmp_path, "c.yml", "llm:\n  enabled: true\n")
        invoke("scan", SIMPLE_TF, "-c", config, "--no-llm")
        assert built == []
        invoke("scan", SIMPLE_TF, "-c", config)
        assert len(built) == 1

    def test_the_environment_variable_enables_it(
        self, built: list[Any], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_LLM", "1")
        invoke("scan", SIMPLE_TF)
        assert len(built) == 1

    def test_the_missing_key_warning_appears_only_when_the_llm_was_requested(self) -> None:
        quiet = invoke("scan", SIMPLE_TF)
        assert "No Anthropic API key" not in quiet.stderr
        asked = invoke("scan", SIMPLE_TF, "--llm")
        assert "No Anthropic API key" in asked.stderr
        assert "Continuing with rules only" in asked.stderr
        assert asked.exit_code == 1  # the rules still ran

    def test_a_failed_llm_run_is_visible_and_changes_nothing_else(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        from threatcode.engine.llm.client import BaseLLMClient

        class Failing(BaseLLMClient):
            def analyze(self, prompt: str) -> str:
                raise LLMError("the server is down")

        monkeypatch.setattr("threatcode.engine.llm.factory.build_client", lambda s: Failing())
        result = invoke("scan", SIMPLE_TF, "--llm")
        assert result.exit_code == 1
        assert (
            "LLM analysis failed (the server is down); rule results are unaffected" in result.stderr
        )
        assert report_of(result)["llm"]["status"] == "failed"
        assert len(report_of(result)["threats"]) == 6


class TestScanLLMConfig:
    """scan with the ollama/local providers and the allow_local_network opt-in."""

    def _scan(self, tmp_path: Path, config_yaml: str, *flags: str) -> Result:
        config_file = write(tmp_path, "threatcode.yml", config_yaml)
        return invoke("scan", K8S_FIXTURE, "-c", config_file, "--llm", *flags)

    def test_ollama_on_localhost_without_opt_in_is_a_clean_error(self, tmp_path: Path) -> None:
        result = self._scan(
            tmp_path,
            "llm:\n  provider: ollama\n  base_url: http://localhost:11434\n  model: llama3.2\n",
        )
        assert result.exit_code == 2
        assert "Error: Unsafe URL scheme 'http'" in result.stderr
        assert "llm.allow_local_network: true" in result.stderr
        assert "Traceback" not in result.output

    def test_opt_in_rejected_for_openai_provider(self, tmp_path: Path) -> None:
        result = self._scan(
            tmp_path,
            "llm:\n  provider: openai\n  base_url: http://localhost:11434\n"
            "  allow_local_network: true\n",
        )
        assert result.exit_code == 2
        assert "llm: allow_local_network requires provider 'ollama' or 'local'" in result.stderr

    def test_missing_base_url_is_a_clean_error(self, tmp_path: Path) -> None:
        result = self._scan(tmp_path, "llm:\n  provider: ollama\n  allow_local_network: true\n")
        assert result.exit_code == 2
        assert "provider 'ollama' requires llm.base_url" in result.stderr

    def test_metadata_endpoint_still_blocked_with_opt_in(self, tmp_path: Path) -> None:
        result = self._scan(
            tmp_path,
            "llm:\n  provider: local\n  base_url: http://169.254.169.254\n"
            "  allow_local_network: true\n",
        )
        assert result.exit_code == 2
        assert "link-local" in result.stderr

    def test_ollama_with_opt_in_reaches_local_server(
        self, tmp_path: Path, fake_llm_server: FakeLLMServer
    ) -> None:
        fake_llm_server.reply = json.dumps(
            {
                "threats": [
                    {
                        "title": "Local model marker threat",
                        "description": "Returned by the fake local model server.",
                        "stride_category": "elevation_of_privilege",
                        "severity": "high",
                        "resource_address": "kubernetes_deployment.default.insecure-app",
                    }
                ]
            }
        )
        result = self._scan(
            tmp_path,
            f"llm:\n  provider: ollama\n  base_url: {fake_llm_server.base_url}\n"
            "  model: llama3.2\n  allow_local_network: true\n",
            "-f",
            "json",
        )
        assert result.exit_code == 1  # the insecure fixture has rule findings
        assert len(fake_llm_server.requests) == 1
        assert fake_llm_server.requests[0]["body"]["model"] == "llama3.2"
        report = report_of(result)
        advisory = [t for t in report["threats"] if t["source"] == "llm"]
        assert [(t["title"], t["resource_address"]) for t in advisory] == [
            ("Local model marker threat", "kubernetes_deployment.default.insecure-app")
        ]
        # The reply was attributed to a node, not parked in the unattributed list
        assert report["llm"]["unattributed_count"] == 0
        assert report["llm"]["status"] == "ran"
        assert "LLM analysis failed" not in result.stderr
        assert "sending a redacted graph to ollama/llama3.2" in result.stderr

    def test_the_server_is_not_contacted_without_the_flag(
        self, tmp_path: Path, fake_llm_server: FakeLLMServer
    ) -> None:
        config = write(
            tmp_path,
            "c.yml",
            f"llm:\n  provider: ollama\n  base_url: {fake_llm_server.base_url}\n"
            "  allow_local_network: true\n",
        )
        result = invoke("scan", K8S_FIXTURE, "-c", config)
        assert result.exit_code == 1
        assert fake_llm_server.requests == []

    def test_unreachable_local_server_falls_back_to_rules(self, tmp_path: Path) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        result = self._scan(
            tmp_path,
            f"llm:\n  provider: ollama\n  base_url: http://127.0.0.1:{port}\n"
            "  allow_local_network: true\n",
        )
        assert result.exit_code == 1  # rule findings still reported
        assert report_of(result)["threats"]
        assert "Traceback" not in result.output
        assert "LLM analysis failed" in result.stderr


class TestDiffCommand:
    def _reports(
        self, tmp_path: Path, before: list[dict[str, Any]], after: list[dict[str, Any]]
    ) -> tuple[Path, Path]:
        def report(threats: list[dict[str, Any]]) -> str:
            return json.dumps({"schema_version": "2", "version": "1", "threats": threats})

        return write(tmp_path, "b.json", report(before)), write(tmp_path, "c.json", report(after))

    @staticmethod
    def threat(threat_id: str, severity: str = "high", title: str = "T") -> dict[str, Any]:
        return {"id": threat_id, "title": title, "severity": severity, "resource_address": "a.b"}

    def test_json_output(self, tmp_path: Path) -> None:
        base, cur = self._reports(
            tmp_path, [self.threat("t1")], [self.threat("t1"), self.threat("t2")]
        )
        result = invoke("diff", base, cur, "-f", "json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert [t["id"] for t in data["added"]] == ["t2"]
        assert data["unchanged_count"] == 1

    def test_markdown_output(self, tmp_path: Path) -> None:
        base, cur = self._reports(tmp_path, [], [])
        result = invoke("diff", base, cur, "-f", "markdown")
        assert result.exit_code == 0
        assert "Threat Model Diff" in result.stdout

    def test_text_output_and_the_terminal_default(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        base, cur = self._reports(tmp_path, [], [self.threat("t1", "critical", "Fresh")])
        assert invoke("diff", base, cur).stdout.lstrip().startswith("{")
        monkeypatch.setattr("threatcode.cli._stdout_is_tty", lambda: True)
        text = invoke("diff", base, cur).stdout
        assert text.startswith("Baseline 0 threats, current 1 threat")
        assert "+ critical" in text

    def test_output_file_and_summary_on_stderr(self, tmp_path: Path) -> None:
        base, cur = self._reports(
            tmp_path,
            [self.threat("gone")],
            [self.threat("n1", "critical"), self.threat("n2", "high")],
        )
        out = tmp_path / "d" / "diff.json"
        result = invoke("diff", base, cur, "-o", out)
        assert result.stdout == ""
        assert f"Diff written to {out}" in result.stderr
        assert "2 new threats (1 critical, 1 high), 1 resolved, 0 changed." in result.stderr
        assert json.loads(out.read_text())["added"]

    def test_a_directory_output_is_exit_two(self, tmp_path: Path) -> None:
        base, cur = self._reports(tmp_path, [], [])
        result = invoke("diff", base, cur, "-o", tmp_path)
        assert result.exit_code == 2
        assert "it is a directory" in result.stderr

    @pytest.mark.parametrize(
        ("content", "message"),
        [
            ('{"runs": [], "version": "2.1.0"}', "is a SARIF file"),
            ('{"foo": 1}', "not a ThreatCode scan report"),
            ("[1]", "expected a JSON object"),
            ("not json", "is not valid JSON"),
        ],
    )
    def test_wrong_inputs_are_exit_two_with_a_specific_message(
        self, tmp_path: Path, content: str, message: str
    ) -> None:
        base, cur = self._reports(tmp_path, [], [])
        wrong = write(tmp_path, "wrong.json", content)
        for args in ((wrong, cur), (base, wrong)):
            result = invoke("diff", *args)
            assert result.exit_code == 2
            assert message in result.stderr
            assert "Traceback" not in result.output
            assert result.stdout == ""

    def test_a_directory_argument_is_a_usage_error(self, tmp_path: Path) -> None:
        base, _ = self._reports(tmp_path, [], [])
        result = invoke("diff", base, tmp_path)
        assert result.exit_code == 2
        assert "is a directory" in result.stderr

    def test_fail_on_new_gates_on_added_and_worsened_threats(self, tmp_path: Path) -> None:
        base, cur = self._reports(
            tmp_path,
            [self.threat("worse", "low")],
            [self.threat("worse", "high"), self.threat("fresh", "medium")],
        )
        assert invoke("diff", base, cur).exit_code == 0
        assert invoke("diff", base, cur, "--fail-on-new", "high").exit_code == 1
        assert invoke("diff", base, cur, "--fail-on-new", "critical").exit_code == 0
        gated = invoke("diff", base, cur, "--fail-on-new", "medium")
        assert gated.exit_code == 1
        assert "2 threats added or worsened at or above medium, exiting 1" in gated.stderr

    def test_resolved_threats_never_fail_the_gate(self, tmp_path: Path) -> None:
        base, cur = self._reports(tmp_path, [self.threat("old", "critical")], [])
        result = invoke("diff", base, cur, "--fail-on-new", "info", "-f", "json")
        assert result.exit_code == 0
        data = json.loads(result.stdout)
        assert [t["id"] for t in data["removed"]] == ["old"]
        assert data["added"] == []

    def test_a_real_scan_report_diffs_clean_against_itself(self, tmp_path: Path) -> None:
        out = tmp_path / "scan.json"
        invoke("scan", SIMPLE_TF, "-o", out)
        result = invoke("diff", out, out, "--fail-on-new", "info", "-f", "text")
        assert result.exit_code == 0
        assert "No changes detected." in result.stdout

    def test_diff_works_between_two_real_scans(self, tmp_path: Path) -> None:
        write(tmp_path / "v1", "main.tf", exposed("one"))
        write(tmp_path / "v2", "main.tf", exposed("one") + exposed("two"))
        invoke("scan", tmp_path / "v1", "-o", tmp_path / "v1.json")
        invoke("scan", tmp_path / "v2", "-o", tmp_path / "v2.json")
        result = invoke("diff", tmp_path / "v1.json", tmp_path / "v2.json", "--fail-on-new", "high")
        assert result.exit_code == 1
        added = json.loads(result.stdout)["added"]
        assert {t["resource_address"] for t in added} == {"aws_lambda_function_url.two"}


class TestHelpAndDiscoverability:
    def test_the_group_help_has_examples_exit_codes_and_environment(self) -> None:
        out = invoke("--help").stdout
        assert "Examples:" in out
        assert "Exit codes:" in out
        assert "Environment:" in out
        for variable in (
            "THREATCODE_FAIL_ON",
            "THREATCODE_MIN_SEVERITY",
            "THREATCODE_FORMAT",
            "THREATCODE_LLM",
            "ANTHROPIC_API_KEY",
            "SOURCE_DATE_EPOCH",
            "NO_COLOR",
            "THREATCODE_DEBUG",
        ):
            assert variable in out

    def test_the_scan_help_lists_every_option(self) -> None:
        out = invoke("scan", "--help").stdout
        for option in (
            "--format",
            "--output",
            "--min-severity",
            "--fail-on",
            "--strict",
            "--config",
            "--rules",
            "--ignore-file",
            "--no-ignore",
            "--baseline",
            "--write-baseline",
            "--ingest",
            "--llm",
            "--no-llm",
            "--dry-run",
            "--dry-run-output",
            "--no-timestamp",
            "--stdin-name",
        ):
            assert option in out, option
        assert "Exit codes:" in out and "Examples:" in out and "Environment:" in out

    def test_the_diff_help(self) -> None:
        out = invoke("diff", "--help").stdout
        assert "--fail-on-new SEVERITY" in out
        assert "--output" in out
        assert "Exit codes:" in out

    def test_the_group_options(self) -> None:
        out = invoke("--help").stdout
        for option in ("--verbose", "--quiet", "--debug", "--no-color", "--version"):
            assert option in out

    def test_both_commands_have_a_short_help_that_is_not_truncated(self) -> None:
        out = invoke("--help").stdout
        assert "Build a threat model from files, directories or stdin." in out
        assert "Compare two JSON reports." in out

    def test_short_help_flag(self) -> None:
        result = invoke("-h")
        assert result.exit_code == 0
        assert "Usage:" in result.stdout


class TestErrorHandling:
    @pytest.fixture
    def exploding(self, monkeypatch: pytest.MonkeyPatch) -> None:
        def boom(request: Any) -> Any:
            raise RuntimeError("something nobody planned for")

        monkeypatch.setattr("threatcode.pipeline.run_scan", boom)

    def test_an_unexpected_error_is_one_line_with_exit_two(self, exploding: None) -> None:
        result = invoke("scan", SIMPLE_TF)
        assert result.exit_code == 2
        lines = result.stderr.strip().splitlines()
        assert len(lines) == 1
        assert lines[0].startswith("Error: unexpected RuntimeError: something nobody planned for")
        assert "--debug" in lines[0]
        assert "Traceback" not in result.output

    def test_debug_shows_the_traceback_and_still_exits_two(self, exploding: None) -> None:
        result = invoke("--debug", "scan", SIMPLE_TF)
        assert result.exit_code == 2
        assert "Traceback (most recent call last)" in result.stderr
        assert "RuntimeError: something nobody planned for" in result.stderr
        assert result.stderr.startswith("Error: unexpected RuntimeError")

    def test_the_debug_variable_shows_the_traceback_and_still_exits_two(
        self, exploding: None, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_DEBUG", "1")
        result = invoke("scan", SIMPLE_TF)
        assert result.exit_code == 2
        assert "Traceback (most recent call last)" in result.stderr

    def test_the_traceback_is_absent_without_debug(self, exploding: None) -> None:
        assert "Traceback" not in invoke("scan", SIMPLE_TF).stderr

    def test_threatcode_errors_print_the_bare_message(self, tmp_path: Path) -> None:
        result = invoke("scan", SHAPES / "terraform_state.json")
        assert "ParseError" not in result.output
        assert "Error: terraform_state.json: This is Terraform state, not a plan" in result.stderr
        assert "terraform plan -out tfplan && terraform show -json tfplan" in result.stderr

    def test_logging_is_configured_once_per_invocation(self) -> None:
        import logging

        before = list(logging.getLogger("threatcode").handlers)
        invoke("-v", "scan", SIMPLE_TF)
        invoke("-vv", "scan", SIMPLE_TF)
        assert list(logging.getLogger("threatcode").handlers) == before

    def test_verbose_logs_reach_stderr(self) -> None:
        result = invoke("-vv", "scan", SIMPLE_TF)
        assert "DEBUG: " in result.stderr or "INFO: " in result.stderr

    def test_quiet_hides_the_summary_line_and_the_default_shows_it(self) -> None:
        assert (
            "Scanned 3 resources in 1 unit, found 6 findings." in invoke("scan", SIMPLE_TF).stderr
        )
        assert "Scanned" not in invoke("-q", "scan", SIMPLE_TF).stderr

    def test_the_summary_pluralizes(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        everything = report_of(invoke("scan", tmp_path, "--fail-on", "none"))["threats"]
        rules = sorted({t["rule_id"] for t in everything})
        assert len(rules) == 3
        write(tmp_path, ".threatcodeignore", "\n".join(rules[:2]) + "\n")
        one = invoke("scan", tmp_path, "--fail-on", "none").stderr
        assert "found 1 finding (2 suppressed)." in one
        write(tmp_path, ".threatcodeignore", "\n".join(rules) + "\n")
        none = invoke("scan", tmp_path, "--fail-on", "none").stderr
        assert "found 0 findings (3 suppressed)." in none
        assert "found 3 findings." in invoke("scan", tmp_path, "--no-ignore").stderr


class TestDeterminism:
    def test_two_runs_with_source_date_epoch_are_byte_identical(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        first = invoke("scan", INSECURE_PLAN).stdout
        second = invoke("scan", INSECURE_PLAN).stdout
        assert first == second
        assert '"timestamp": "2023-11-14T22:13:20+00:00"' in first

    def test_no_timestamp_makes_two_runs_identical_without_a_clock(self) -> None:
        first = invoke("scan", INSECURE_PLAN, "--no-timestamp").stdout
        second = invoke("scan", INSECURE_PLAN, "--no-timestamp").stdout
        assert first == second
        assert "timestamp" not in first

    def test_without_either_the_timestamp_is_present(self) -> None:
        assert "timestamp" in report_of(invoke("scan", SIMPLE_TF))

    def test_the_markdown_and_text_formats_are_deterministic_too(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        for fmt in ("markdown", "text", "sarif", "bitbucket", "navigator", "diagram"):
            assert (
                invoke("scan", INSECURE_PLAN, "-f", fmt).stdout
                == invoke("scan", INSECURE_PLAN, "-f", fmt).stdout
            ), fmt

    def test_a_bad_epoch_is_exit_two(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "later")
        result = invoke("scan", SIMPLE_TF)
        assert result.exit_code == 2
        assert "SOURCE_DATE_EPOCH must be an integer" in result.stderr


class TestVersionOption:
    def test_version_flag(self) -> None:
        result = invoke("--version")
        assert result.exit_code == 0
        assert "threatcode" in result.stdout

    def test_version_flag_prints_the_package_version(self) -> None:
        assert invoke("--version").stdout.strip().endswith(__version__)

    def test_python_dash_m_works(self) -> None:
        done = subprocess.run(
            [sys.executable, "-m", "threatcode", "--version"],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
            check=False,
        )
        assert done.returncode == 0
        assert __version__ in done.stdout

    def test_the_cli_starts_without_importing_the_heavy_stack(self) -> None:
        code = (
            "import sys\n"
            "import threatcode.cli\n"
            "heavy = [m for m in ('pydantic', 'networkx', 'yaml', 'hcl2', 'anthropic') "
            "if m in sys.modules]\n"
            "assert not heavy, heavy\n"
        )
        done = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            env={**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")},
            check=False,
        )
        assert done.returncode == 0, done.stderr


class TestSlimmedSurface:
    """The scanning layer is gone: the CLI has scan and diff and nothing else."""

    def test_only_scan_and_diff_are_commands(self) -> None:
        assert sorted(cli.commands) == ["diff", "scan"]

    @pytest.mark.parametrize("command", REMOVED_COMMANDS)
    def test_removed_command_is_not_found(self, command: str) -> None:
        result = invoke(command, K8S_FIXTURE)
        assert result.exit_code == 2
        assert "No such command" in result.stderr
        assert command in result.stderr

    @pytest.mark.parametrize(
        "option", ["--scanners=misconfig", "--ignore-unfixed", "--severity=high"]
    )
    def test_removed_scan_options_are_not_found(self, option: str) -> None:
        result = invoke("scan", K8S_FIXTURE, option)
        assert result.exit_code == 2
        assert "No such option" in result.stderr

    def test_help_lists_scan_and_diff_only(self) -> None:
        out = invoke("--help").stdout
        assert "scan" in out and "diff" in out
        for command in REMOVED_COMMANDS:
            assert f"\n  {command} " not in out

    def test_group_help_does_not_describe_the_removed_scanners(self) -> None:
        out = invoke("--help").stdout
        for word in ("SBOM", "vulnerabilit", "license"):
            assert word not in out


class TestScanInputs:
    def test_short_form_cloudformation_scans(self) -> None:
        result = invoke("scan", SHAPES / "cfn_short_form.yml", "--fail-on", "none")
        assert result.exit_code == 0
        assert report_of(result)["threats"]

    def test_terraform_directory_scans_as_one_module(self) -> None:
        result = invoke("scan", SHAPES / "tf_module", "--fail-on", "none")
        assert result.exit_code == 0
        assert report_of(result)["scanned_resources"] == 3

    def test_tofu_and_json_syntax_files_scan(self) -> None:
        for name in ("main.tofu", "cdk.tf.json"):
            result = invoke("scan", SHAPES / name, "--fail-on", "none")
            assert result.exit_code == 0, result.stderr
            assert report_of(result)["threats"]

    def test_a_directory_with_several_formats_is_one_graph(self) -> None:
        result = invoke("scan", FIXTURES_DIR / "kubernetes", "--fail-on", "none")
        data = report_of(result)
        assert data["coverage"]["units_parsed"] == len(
            list((FIXTURES_DIR / "kubernetes").iterdir())
        )
        assert data["scanned_resources"] == 48

    def test_several_paths_are_accepted(self) -> None:
        result = invoke("scan", SIMPLE_TF, K8S_FIXTURE, "--fail-on", "none")
        data = report_of(result)
        assert data["coverage"]["units_parsed"] == 2
        assert (
            data["input_file"] == "kubernetes/insecure_deployment.yml, terraform/simple_exposed.tf"
        )

    def test_state_json_is_rejected_with_the_corrective_command(self) -> None:
        result = invoke("scan", SHAPES / "terraform_state.json")
        assert result.exit_code == 2
        assert "This is Terraform state, not a plan" in result.stderr
        assert "terraform plan -out tfplan && terraform show -json tfplan" in result.stderr
        assert "Scanned" not in result.stderr
        assert "found 0 findings" not in result.stderr

    def test_destroy_only_plan_is_rejected(self) -> None:
        result = invoke("scan", SHAPES / "terraform_destroy.plan.json")
        assert result.exit_code == 2
        assert "destroys every resource" in result.stderr

    def test_empty_file_is_reported_as_empty(self, tmp_path: Path) -> None:
        result = invoke("scan", write(tmp_path, "empty.yaml", ""))
        assert result.exit_code == 2
        assert "file is empty" in result.stderr
        assert "Traceback" not in result.output

    def test_binary_file_is_reported_as_not_text(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob.json"
        blob.write_bytes(b"\x89PNG\r\n\x1a\n\x00")
        result = invoke("scan", blob)
        assert result.exit_code == 2
        assert "not valid UTF-8 text" in result.stderr
        assert "UnicodeDecodeError" not in result.output

    def test_a_directory_without_infrastructure_names_the_problem(self, tmp_path: Path) -> None:
        result = invoke("scan", tmp_path)
        assert result.exit_code == 2
        assert "no supported infrastructure files found" in result.stderr
        assert "IsADirectoryError" not in result.output

    def test_unsupported_input_lists_what_is_supported(self, tmp_path: Path) -> None:
        result = invoke("scan", write(tmp_path, "notes.xml", "<root/>"))
        assert result.exit_code == 2
        assert "Cannot detect format for notes.xml" in result.stderr
        assert "Supported inputs:" in result.stderr

    def test_not_infrastructure_files_in_a_tree_are_counted_not_failed(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", bucket("one"))
        write(tmp_path, "tsconfig.json", "{}")
        data = report_of(invoke("scan", tmp_path, "--fail-on", "none"))
        assert data["coverage"]["not_iac"] == {"count": 1, "paths": ["tsconfig.json"]}
        assert data["coverage"]["errors"] == []

    def test_symlinks_in_a_tree_are_skipped_and_counted(self, tmp_path: Path) -> None:
        outside = write(tmp_path / "outside", "leak.tf", bucket("leaked_outside"))
        root = tmp_path / "scan"
        write(root, "main.tf", bucket("inside"))
        (root / "link.tf").symlink_to(outside)
        result = invoke("scan", root, "--fail-on", "none")
        assert "leaked_outside" not in result.stdout
        assert report_of(result)["coverage"]["symlinks_skipped"] == 1

    def test_graph_limits_can_be_set_on_the_command_line(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", bucket("a") + bucket("b") + bucket("c"))
        result = invoke("scan", tmp_path, "--max-nodes", "2")
        assert result.exit_code == 2
        assert "2 node limit" in result.stderr


class TestCoreInstall:
    """The anthropic SDK belongs to the llm extra; a rules-only run never needs it."""

    def test_rules_only_scan_does_not_import_anthropic(self) -> None:
        code = (
            "import sys\n"
            "import threatcode\n"
            "import threatcode.cli\n"
            f"threatcode.scan({str(K8S_FIXTURE)!r})\n"
            "assert 'anthropic' not in sys.modules, 'anthropic was imported'\n"
            "print('ok')\n"
        )
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
        result = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False
        )
        assert result.returncode == 0, result.stderr
        assert "ok" in result.stdout

    def _block_anthropic(self, monkeypatch: pytest.MonkeyPatch) -> None:
        real_import = builtins.__import__

        def fake_import(name: str, *args: Any, **kwargs: Any) -> Any:
            if name == "anthropic" or name.startswith("anthropic."):
                raise ImportError("No module named 'anthropic'")
            return real_import(name, *args, **kwargs)

        monkeypatch.setattr(builtins, "__import__", fake_import)

    def test_missing_sdk_error_names_the_extra(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from threatcode.engine.llm.client import AnthropicLLMClient

        self._block_anthropic(monkeypatch)
        with pytest.raises(LLMError, match=r"pip install 'threatcode\[llm\]'"):
            AnthropicLLMClient(api_key="test")

    def test_cli_reports_the_missing_sdk_without_a_traceback(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        self._block_anthropic(monkeypatch)
        result = invoke("scan", K8S_FIXTURE, "--llm")
        assert result.exit_code == 2
        assert "pip install 'threatcode[llm]'" in result.stderr
        assert "Traceback" not in result.output

    def test_the_sdk_is_not_even_looked_for_without_the_flag(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("ANTHROPIC_API_KEY", "test-key")
        self._block_anthropic(monkeypatch)
        result = invoke("scan", K8S_FIXTURE)
        assert result.exit_code == 1
        assert "pip install" not in result.stderr


class TestPackagingMetadata:
    @staticmethod
    def _pyproject() -> dict[str, Any]:
        if sys.version_info >= (3, 11):
            import tomllib
        else:
            import tomli as tomllib
        with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
            return tomllib.load(handle)

    def test_version_is_single_sourced(self) -> None:
        data = self._pyproject()
        assert "version" not in data["project"]
        assert data["project"]["dynamic"] == ["version"]
        assert data["tool"]["setuptools"]["dynamic"]["version"] == {
            "attr": "threatcode.__version__"
        }

    def test_installed_metadata_matches_the_module_version(self) -> None:
        from importlib import metadata

        try:
            installed = metadata.version("threatcode")
        except metadata.PackageNotFoundError:
            pytest.skip("threatcode is not installed as a distribution")
        assert installed == __version__

    def test_core_dependencies_exclude_the_removed_scanning_stack(self) -> None:
        names = {
            dep.split(";")[0].split(">")[0].split("<")[0].split("=")[0].strip().lower()
            for dep in self._pyproject()["project"]["dependencies"]
        }
        assert {"click", "pydantic", "python-hcl2", "pyyaml", "networkx"} <= names
        assert not names & {"anthropic", "httpx", "packaging"}

    def test_llm_extra_is_the_only_runtime_path_to_anthropic(self) -> None:
        extras = self._pyproject()["project"]["optional-dependencies"]
        assert any(dep.startswith("anthropic") for dep in extras["llm"])
        assert any(dep.startswith("anthropic") for dep in extras["all"])
        assert any(dep.startswith("anthropic") for dep in extras["dev"])
        for name in ("jsonschema", "hypothesis", "build"):
            assert any(dep.startswith(name) for dep in extras["dev"])

    def test_py_typed_is_shipped(self) -> None:
        data = self._pyproject()
        assert "py.typed" in data["tool"]["setuptools"]["package-data"]["threatcode"]
        assert (REPO_ROOT / "src" / "threatcode" / "py.typed").is_file()

    def test_the_new_subpackages_are_found_by_setuptools(self) -> None:
        for package in ("ingest", "engine/secrets", "engine/llm", "formatters"):
            assert (REPO_ROOT / "src" / "threatcode" / package / "__init__.py").is_file()


class TestHostileNamesNeverReachTheTerminal:
    """A server key or file name with an escape sequence is shown as text on both streams."""

    EVIL = "evil\x1b[2J\x1b[Hpwned\x1b]0;TITLE\x07"
    UNSAFE = re.compile("[\x00-\x09\x0b-\x1f\x7f-\x9f]")

    def _tree(self, root: Path) -> Path:
        config = {
            "mcpServers": {
                self.EVIL: {"command": "npx", "args": ["-y", "some-server"]},
                "fs": {
                    "command": "npx",
                    "args": ["-y", "@modelcontextprotocol/server-filesystem", "/"],
                },
            }
        }
        write(root, ".mcp.json", json.dumps(config))
        write(root, f"main{self.EVIL}.tf", bucket("b"))
        write(root, "modules/main.tf", 'module "net" {\n  source = "./modules/net"\n}\n')
        return root

    def test_the_text_report_and_stderr_carry_no_raw_control_character(
        self, tmp_path: Path
    ) -> None:
        tree = self._tree(tmp_path / "tree")
        result = invoke("scan", tree, "-f", "text", "--fail-on", "none", "--strict")
        assert result.exit_code == 2
        for stream in (result.stdout, result.stderr):
            assert not self.UNSAFE.search(stream.replace("\n", " ").replace("\t", " "))
        assert "\\x07" in result.stdout

    def test_an_error_message_that_quotes_the_input_is_inert(self, tmp_path: Path) -> None:
        write(tmp_path, f"bad{self.EVIL}.tf", BAD_TF)
        result = invoke("scan", tmp_path)
        assert result.exit_code == 2
        assert not self.UNSAFE.search(result.stderr.replace("\n", " "))
        assert not self.UNSAFE.search(result.stdout.replace("\n", " "))

    def test_a_path_named_on_the_command_line_is_inert_in_the_error(self, tmp_path: Path) -> None:
        result = invoke("scan", tmp_path / f"no{self.EVIL}such")
        assert result.exit_code == 2
        assert not self.UNSAFE.search(result.output.replace("\n", " "))
