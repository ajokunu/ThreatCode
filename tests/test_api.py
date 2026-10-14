"""Tests for the public Python API in threatcode/__init__.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

import threatcode
from threatcode.cli import cli
from threatcode.exceptions import ThreatCodeError

REPO_ROOT = Path(__file__).resolve().parent.parent
FIXTURES = Path(__file__).resolve().parent / "fixtures"
SIMPLE_TF = FIXTURES / "terraform" / "simple_exposed.tf"
K8S = FIXTURES / "kubernetes" / "insecure_deployment.yml"

PUBLIC_NAMES = [
    "scan",
    "analyze",
    "run_scan",
    "ScanRequest",
    "ScanResult",
    "AnalysisResult",
    "ThreatReport",
    "Threat",
    "Severity",
    "ThreatCodeError",
    "ParseError",
    "UnsupportedFormatError",
    "RuleLoadError",
    "ConfigError",
    "LLMError",
    "UsageError",
    "__version__",
]


@pytest.fixture(autouse=True)
def hermetic_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
    home = tmp_path_factory.mktemp("home")
    monkeypatch.setenv("HOME", str(home))
    monkeypatch.setenv("USERPROFILE", str(home))
    monkeypatch.delenv("CI", raising=False)
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    for name in ("THREATCODE_FAIL_ON", "THREATCODE_MIN_SEVERITY", "THREATCODE_LLM"):
        monkeypatch.delenv(name, raising=False)


class TestImportSurface:
    @pytest.mark.parametrize("name", PUBLIC_NAMES)
    def test_every_public_name_imports(self, name: str) -> None:
        namespace: dict[str, Any] = {}
        exec(f"from threatcode import {name}", namespace)
        assert namespace[name] is getattr(threatcode, name)

    def test_all_lists_exactly_the_public_names(self) -> None:
        assert sorted(threatcode.__all__) == sorted(PUBLIC_NAMES)

    def test_every_name_in_all_resolves(self) -> None:
        for name in threatcode.__all__:
            assert getattr(threatcode, name) is not None

    def test_the_exception_hierarchy_is_exported(self) -> None:
        for name in (
            "ParseError",
            "UnsupportedFormatError",
            "RuleLoadError",
            "ConfigError",
            "LLMError",
            "UsageError",
        ):
            assert issubclass(getattr(threatcode, name), threatcode.ThreatCodeError)
        assert issubclass(threatcode.UnsupportedFormatError, threatcode.ParseError)

    def test_the_exported_types_are_the_real_ones(self) -> None:
        from threatcode.models.analysis import AnalysisResult
        from threatcode.models.report import ThreatReport
        from threatcode.models.threat import Severity, Threat
        from threatcode.pipeline import ScanRequest, ScanResult, run_scan

        assert threatcode.AnalysisResult is AnalysisResult
        assert threatcode.ThreatReport is ThreatReport
        assert threatcode.Severity is Severity
        assert threatcode.Threat is Threat
        assert threatcode.ScanRequest is ScanRequest
        assert threatcode.ScanResult is ScanResult
        assert threatcode.run_scan is run_scan

    def test_an_unknown_attribute_is_an_attribute_error(self) -> None:
        with pytest.raises(AttributeError, match="no attribute 'scan_filesystem'"):
            threatcode.scan_filesystem  # noqa: B018

    def test_the_ignored_output_format_parameter_is_refused_not_swallowed(self) -> None:
        with pytest.raises(TypeError, match="no output_format"):
            threatcode.scan(SIMPLE_TF, output_format="sarif")
        with pytest.raises(TypeError, match="no output_format"):
            threatcode.analyze(SIMPLE_TF, output_format="json")

    def test_an_unknown_setting_is_a_type_error(self) -> None:
        with pytest.raises(TypeError, match="unexpected keyword argument"):
            threatcode.scan(SIMPLE_TF, no_such_setting=True)

    def test_importing_the_package_is_lazy(self) -> None:
        code = (
            "import sys\n"
            "import threatcode\n"
            "heavy = [m for m in ('networkx', 'pydantic', 'hcl2', 'yaml', 'anthropic', "
            "'threatcode.pipeline', 'threatcode.engine.hybrid') if m in sys.modules]\n"
            "assert not heavy, heavy\n"
            "threatcode.scan\n"
            "print('ok')\n"
        )
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
        done = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False
        )
        assert done.returncode == 0, done.stderr
        assert "ok" in done.stdout

    def test_the_library_never_imports_the_cli(self) -> None:
        code = (
            "import sys\n"
            "import threatcode\n"
            f"threatcode.scan({str(SIMPLE_TF)!r})\n"
            "assert 'threatcode.cli' not in sys.modules, 'the library imported the CLI'\n"
            "assert 'anthropic' not in sys.modules, 'anthropic was imported'\n"
            "print('ok')\n"
        )
        env = {**os.environ, "PYTHONPATH": str(REPO_ROOT / "src")}
        done = subprocess.run(
            [sys.executable, "-c", code], capture_output=True, text=True, env=env, check=False
        )
        assert done.returncode == 0, done.stderr


class TestScan:
    def test_returns_the_report_as_a_dict_with_the_v2_contract(self) -> None:
        report = threatcode.scan(SIMPLE_TF)
        assert report["schema_version"] == "2"
        assert report["total_threats"] == len(report["threats"]) == 6
        assert report["attack_paths"] == []
        assert report["coverage"]["units_parsed"] == 1
        # The way it was typed, so the directory a file sits in is not lost
        assert report["input_file"] == "tests/fixtures/terraform/simple_exposed.tf"

    def test_accepts_a_string_a_path_or_a_list(self) -> None:
        one = threatcode.scan(str(SIMPLE_TF), no_timestamp=True)
        two = threatcode.scan(SIMPLE_TF, no_timestamp=True)
        three = threatcode.scan([SIMPLE_TF], no_timestamp=True)
        assert one == two == three

    def test_several_paths_are_one_scan(self) -> None:
        report = threatcode.scan([SIMPLE_TF, K8S])
        assert report["coverage"]["units_parsed"] == 2
        assert {t["location_file"] for t in report["threats"]} == {
            "terraform/simple_exposed.tf",
            "kubernetes/insecure_deployment.yml",
        }

    def test_a_directory_is_scanned(self) -> None:
        report = threatcode.scan(FIXTURES / "kubernetes")
        assert report["coverage"]["units_parsed"] == len(list((FIXTURES / "kubernetes").iterdir()))
        assert report["input_file"] == "tests/fixtures/kubernetes"

    def test_a_finding_does_not_raise_whatever_the_gate(self) -> None:
        assert threatcode.scan(SIMPLE_TF, fail_on="info")["total_threats"] == 6

    def test_min_severity_filters_the_listing(self) -> None:
        report = threatcode.scan(SIMPLE_TF, min_severity="high")
        assert [t["severity"] for t in report["threats"]] == ["high"]
        assert report["summary"] == {"high": 1}

    def test_an_input_that_could_not_be_analysed_raises_rather_than_looking_clean(
        self, tmp_path: Path
    ) -> None:
        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = \n')
        with pytest.raises(ThreatCodeError) as info:
            threatcode.scan(tmp_path)
        assert "could not analyse its input" in str(info.value)
        assert "run_scan()" in str(info.value)

    def test_nothing_to_scan_raises(self, tmp_path: Path) -> None:
        (tmp_path / "README.md").write_text("x")
        with pytest.raises(ThreatCodeError, match="no supported infrastructure files"):
            threatcode.scan(tmp_path)

    def test_a_state_file_raises_with_the_corrective_command(self) -> None:
        with pytest.raises(ThreatCodeError, match="This is Terraform state, not a plan"):
            threatcode.scan(FIXTURES / "input_shapes" / "terraform_state.json")

    def test_a_missing_path_raises_a_usage_error(self, tmp_path: Path) -> None:
        with pytest.raises(threatcode.UsageError, match="path not found"):
            threatcode.scan(tmp_path / "nope.tf")

    def test_an_invalid_setting_raises_before_scanning(self) -> None:
        with pytest.raises(threatcode.UsageError, match="fail_on must be one of"):
            threatcode.scan(SIMPLE_TF, fail_on="sometimes")

    def test_run_scan_returns_the_partial_result_that_scan_refuses_to(self, tmp_path: Path) -> None:
        (tmp_path / "good.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
        (tmp_path / "sub").mkdir()
        (tmp_path / "sub" / "bad.tf").write_text('resource "aws_s3_bucket" "x" {\n  bucket = \n')
        from threatcode.pipeline import prepare_request

        result = threatcode.run_scan(prepare_request([str(tmp_path)]).request)
        assert result.exit_code == 2
        assert result.report.coverage.errors
        assert result.graph.node_count >= 1

    def test_strict_applies_to_the_api_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        import threatcode.parsers as parsers
        from threatcode.diagnostics import Diagnostic

        real = parsers.detect_and_parse

        def gappy(path: str | Path) -> Any:
            parsed = real(path)
            parsed.diagnostics.append(
                Diagnostic("warning", "hcl.module_call_skipped", "module vpc not analysed")
            )
            return parsed

        monkeypatch.setattr(parsers, "detect_and_parse", gappy)
        report = threatcode.scan(SIMPLE_TF)
        assert [g["code"] for g in report["coverage"]["gaps"]] == ["hcl.module_call_skipped"]
        with pytest.raises(ThreatCodeError, match=r"strict mode: .*\[hcl.module_call_skipped\]"):
            threatcode.scan(SIMPLE_TF, strict=True)

    def test_config_notices_are_logged_not_printed(
        self, tmp_path: Path, caplog: pytest.LogCaptureFixture, capsys: pytest.CaptureFixture[str]
    ) -> None:
        import logging

        (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n')
        (tmp_path / ".threatcode.yml").write_text("fail_on: none\n")
        with caplog.at_level(logging.WARNING, logger="threatcode"):
            threatcode.scan(tmp_path)
        assert "restricted fields" in caplog.text
        assert capsys.readouterr().err == ""


class TestAnalyze:
    def test_returns_the_graph_and_the_report(self) -> None:
        result = threatcode.analyze(SIMPLE_TF)
        assert isinstance(result, threatcode.AnalysisResult)
        assert result.graph.node_count == 3
        assert len(result.report.threats) == 6
        assert result.attack_paths == []
        assert "<svg" in result.to_svg()

    def test_the_report_carries_the_coverage_block(self) -> None:
        result = threatcode.analyze(FIXTURES / "kubernetes")
        expected = len(list((FIXTURES / "kubernetes").iterdir()))
        assert result.report.coverage.units_parsed == expected
        assert result.report.coverage.files_discovered == expected

    def test_takes_the_same_settings_as_scan(self) -> None:
        result = threatcode.analyze(SIMPLE_TF, min_severity="high", fail_on="none")
        assert [t.severity.value for t in result.report.threats] == ["high"]

    def test_an_input_that_could_not_be_analysed_raises(self, tmp_path: Path) -> None:
        (tmp_path / "x.tf").write_text("resource {")
        with pytest.raises(ThreatCodeError):
            threatcode.analyze(tmp_path)


class TestParityWithTheCli:
    def _cli_json(self, *args: str) -> dict[str, Any]:
        result = CliRunner().invoke(cli, ["scan", *args, "-f", "json", "--fail-on", "none"])
        assert result.exit_code == 0, result.stderr
        data: dict[str, Any] = json.loads(result.stdout)
        return data

    def test_scan_and_the_cli_print_the_same_report(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        assert threatcode.scan(SIMPLE_TF) == self._cli_json(str(SIMPLE_TF))

    def test_parity_holds_for_a_directory_and_for_options(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("SOURCE_DATE_EPOCH", "1700000000")
        api = threatcode.scan(FIXTURES / "kubernetes", min_severity="medium")
        cli_report = self._cli_json(str(FIXTURES / "kubernetes"), "--min-severity", "medium")
        assert api == cli_report

    def test_run_scan_and_the_cli_agree_on_the_exit_code(self, tmp_path: Path) -> None:
        from threatcode.pipeline import prepare_request

        for fail_on in ("critical", "high", "none"):
            expected = threatcode.run_scan(
                prepare_request([str(SIMPLE_TF)], fail_on=fail_on).request
            ).exit_code
            actual = CliRunner().invoke(cli, ["scan", str(SIMPLE_TF), "--fail-on", fail_on])
            assert actual.exit_code == expected

    def test_the_text_and_json_reports_describe_the_same_findings(self) -> None:
        text = (
            CliRunner()
            .invoke(cli, ["scan", str(SIMPLE_TF), "-f", "text", "--fail-on", "none"])
            .stdout
        )
        for threat in threatcode.scan(SIMPLE_TF)["threats"]:
            assert threat["rule_id"] in text


class TestThreatIdsAreUnique:
    """An id names one finding in a diff, in ``enabled_by`` and in an ignore entry."""

    @pytest.mark.parametrize("name", ["agent-workstation", "aws-webapp", "k8s-platform"])
    def test_no_demo_stack_reports_an_id_twice(self, name: str) -> None:
        result = threatcode.analyze(REPO_ROOT / "examples" / name, fail_on="none")
        assert result.report.threats, "a stack with no finding would prove nothing"
        assert result.report.duplicate_ids() == []

    def test_duplicate_ids_names_each_repeated_id_once(self) -> None:
        from threatcode.models.report import ThreatReport
        from threatcode.models.threat import Severity, Threat, ThreatSource

        def make(threat_id: str) -> Threat:
            return Threat(
                id=threat_id,
                title="t",
                description="d",
                stride_category="tampering",
                severity=Severity.HIGH,
                source=ThreatSource.RULE,
                resource_type="aws_s3_bucket",
                resource_address="aws_s3_bucket.a",
                mitigation="m",
            )

        report = ThreatReport(threats=[make("b"), make("a"), make("b"), make("b"), make("c")])
        assert report.duplicate_ids() == ["b"]
        assert ThreatReport(threats=[make("a"), make("c")]).duplicate_ids() == []
        assert ThreatReport().duplicate_ids() == []

    def test_the_api_warns_when_an_id_repeats_and_stays_quiet_otherwise(
        self, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
    ) -> None:
        import logging

        from threatcode.models.report import ThreatReport

        with caplog.at_level(logging.WARNING, logger="threatcode"):
            threatcode.scan(SIMPLE_TF, fail_on="none")
        assert not [r for r in caplog.records if "more than once" in r.getMessage()]

        monkeypatch.setattr(ThreatReport, "duplicate_ids", lambda self: ["abc123", "def456"])
        with caplog.at_level(logging.WARNING, logger="threatcode"):
            threatcode.scan(SIMPLE_TF, fail_on="none")
        (record,) = [r for r in caplog.records if "more than once" in r.getMessage()]
        assert "abc123, def456" in record.getMessage()
