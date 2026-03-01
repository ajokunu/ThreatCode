"""Tests for threatcode.cli."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from threatcode.cli import cli

FIXTURES_DIR = Path(__file__).parent / "fixtures"


class TestScanCommand:
    def test_scan_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
            "--no-llm",
            "--format", "json",
        ])
        # Exit code 1 means threats were found (expected for insecure fixture)
        assert result.exit_code in (0, 1)
        assert '"threats"' in result.output

    def test_scan_markdown_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
            "--no-llm",
            "--format", "markdown",
        ])
        assert result.exit_code in (0, 1)
        assert "ThreatCode" in result.output

    def test_scan_sarif_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
            "--no-llm",
            "--format", "sarif",
        ])
        assert result.exit_code in (0, 1)
        assert "sarifLog" in result.output or "$schema" in result.output

    def test_scan_nonexistent_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "/nonexistent/file.json", "--no-llm"])
        assert result.exit_code != 0

    def test_scan_with_min_severity_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
            "--no-llm",
            "--min-severity", "critical",
            "--format", "json",
        ])
        assert result.exit_code in (0, 1)

    def test_scan_write_to_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "output.json"
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
            "--no-llm",
            "--format", "json",
            "--output", str(out_file),
        ])
        assert result.exit_code in (0, 1)
        assert out_file.exists()
        assert '"threats"' in out_file.read_text()

    def test_scan_secure_fixture_runs_successfully(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "multi_service_secure.plan.json"),
            "--no-llm",
            "--format", "json",
        ])
        # Boundary threats may still be generated, so exit code 0 or 1
        assert result.exit_code in (0, 1)
        assert '"threats"' in result.output

    def test_scan_bitbucket_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
            "--no-llm",
            "--format", "bitbucket",
        ])
        assert result.exit_code in (0, 1)
        assert '"report"' in result.output

    def test_scan_hcl_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, [
            "scan",
            str(FIXTURES_DIR / "terraform" / "simple.tf"),
            "--no-llm",
            "--format", "json",
        ])
        assert result.exit_code in (0, 1)


class TestDiffCommand:
    def test_diff_json_output(self, tmp_path: Path) -> None:
        import json
        threat1 = {
            "id": "t1", "title": "Threat 1",
            "severity": "high", "resource_address": "a.b",
        }
        report = {"input_file": "test.json", "threats": [threat1]}
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        baseline.write_text(json.dumps(report))
        threat2 = {
            "id": "t2", "title": "New Threat",
            "severity": "medium", "resource_address": "c.d",
        }
        report["threats"].append(threat2)
        current.write_text(json.dumps(report))

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current), "--format", "json"])
        assert result.exit_code == 0
        assert '"added"' in result.output

    def test_diff_markdown_output(self, tmp_path: Path) -> None:
        import json
        report = {"threats": []}
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        baseline.write_text(json.dumps(report))
        current.write_text(json.dumps(report))

        runner = CliRunner()
        result = runner.invoke(cli, ["diff", str(baseline), str(current), "--format", "markdown"])
        assert result.exit_code == 0
        assert "Threat Model Diff" in result.output


class TestVersionOption:
    def test_version_flag(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["--version"])
        assert result.exit_code == 0
        assert "threatcode" in result.output
