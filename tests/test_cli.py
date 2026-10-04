"""Tests for threatcode.cli."""

from __future__ import annotations

import json
import socket
from pathlib import Path
from typing import TYPE_CHECKING

from click.testing import CliRunner

from threatcode.cli import cli

if TYPE_CHECKING:
    from tests.conftest import FakeLLMServer

FIXTURES_DIR = Path(__file__).parent / "fixtures"
K8S_FIXTURE = FIXTURES_DIR / "kubernetes" / "insecure_deployment.yml"


class TestScanCommand:
    def test_scan_json_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
                "--no-llm",
                "--format",
                "json",
            ],
        )
        # Exit code 1 means threats were found (expected for insecure fixture)
        assert result.exit_code in (0, 1)
        assert '"threats"' in result.output

    def test_scan_markdown_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
                "--no-llm",
                "--format",
                "markdown",
            ],
        )
        assert result.exit_code in (0, 1)
        assert "ThreatCode" in result.output

    def test_scan_sarif_output(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
                "--no-llm",
                "--format",
                "sarif",
            ],
        )
        assert result.exit_code in (0, 1)
        assert "sarifLog" in result.output or "$schema" in result.output

    def test_scan_nonexistent_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(cli, ["scan", "/nonexistent/file.json", "--no-llm"])
        assert result.exit_code != 0

    def test_scan_with_min_severity_filter(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
                "--no-llm",
                "--min-severity",
                "critical",
                "--format",
                "json",
            ],
        )
        assert result.exit_code in (0, 1)

    def test_scan_write_to_file(self, tmp_path: Path) -> None:
        out_file = tmp_path / "output.json"
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
                "--no-llm",
                "--format",
                "json",
                "--output",
                str(out_file),
            ],
        )
        assert result.exit_code in (0, 1)
        assert out_file.exists()
        assert '"threats"' in out_file.read_text()

    def test_scan_secure_fixture_runs_successfully(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "multi_service_secure.plan.json"),
                "--no-llm",
                "--format",
                "json",
            ],
        )
        # Boundary threats may still be generated, so exit code 0 or 1
        assert result.exit_code in (0, 1)
        assert '"threats"' in result.output

    def test_scan_bitbucket_format(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple_s3.plan.json"),
                "--no-llm",
                "--format",
                "bitbucket",
            ],
        )
        assert result.exit_code in (0, 1)
        assert '"report"' in result.output

    def test_scan_hcl_file(self) -> None:
        runner = CliRunner()
        result = runner.invoke(
            cli,
            [
                "scan",
                str(FIXTURES_DIR / "terraform" / "simple.tf"),
                "--no-llm",
                "--format",
                "json",
            ],
        )
        assert result.exit_code in (0, 1)


class TestScanLLMConfig:
    """scan with the ollama/local providers and the allow_local_network opt-in."""

    def _scan(self, tmp_path: Path, config_yaml: str) -> tuple[int, str]:
        config_file = tmp_path / "threatcode.yml"
        config_file.write_text(config_yaml)
        result = CliRunner().invoke(cli, ["scan", str(K8S_FIXTURE), "-c", str(config_file)])
        return result.exit_code, result.output

    def test_ollama_on_localhost_without_opt_in_is_a_clean_error(self, tmp_path: Path) -> None:
        exit_code, output = self._scan(
            tmp_path,
            "llm:\n  provider: ollama\n  base_url: http://localhost:11434\n  model: llama3.2\n",
        )
        assert exit_code == 1
        assert "Error: invalid LLM configuration: Unsafe URL scheme 'http'" in output
        assert "llm.allow_local_network: true" in output
        assert "Traceback" not in output

    def test_opt_in_rejected_for_openai_provider(self, tmp_path: Path) -> None:
        exit_code, output = self._scan(
            tmp_path,
            "llm:\n  provider: openai\n  base_url: http://localhost:11434\n"
            "  allow_local_network: true\n",
        )
        assert exit_code == 1
        assert "llm: allow_local_network requires provider 'ollama' or 'local'" in output
        assert "Traceback" not in output

    def test_missing_base_url_is_a_clean_error(self, tmp_path: Path) -> None:
        exit_code, output = self._scan(
            tmp_path, "llm:\n  provider: ollama\n  allow_local_network: true\n"
        )
        assert exit_code == 1
        assert "provider 'ollama' requires llm.base_url" in output

    def test_missing_config_file_is_a_clean_error(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(
            cli, ["scan", str(K8S_FIXTURE), "-c", str(tmp_path / "missing.yml")]
        )
        assert result.exit_code == 1
        assert "Error: Config file not found" in result.output
        assert "Traceback" not in result.output

    def test_metadata_endpoint_still_blocked_with_opt_in(self, tmp_path: Path) -> None:
        exit_code, output = self._scan(
            tmp_path,
            "llm:\n  provider: local\n  base_url: http://169.254.169.254\n"
            "  allow_local_network: true\n",
        )
        assert exit_code == 1
        assert "link-local" in output

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
                        "resource_address": "Deployment/insecure-app",
                    }
                ]
            }
        )
        exit_code, output = self._scan(
            tmp_path,
            f"llm:\n  provider: ollama\n  base_url: {fake_llm_server.base_url}\n"
            "  model: llama3.2\n  allow_local_network: true\n",
        )
        assert exit_code == 1  # the insecure fixture has rule findings
        assert len(fake_llm_server.requests) == 1
        assert fake_llm_server.requests[0]["body"]["model"] == "llama3.2"
        assert "Local model marker threat" in output
        assert "LLM analysis failed" not in output

    def test_unreachable_local_server_falls_back_to_rules(self, tmp_path: Path) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        exit_code, output = self._scan(
            tmp_path,
            f"llm:\n  provider: ollama\n  base_url: http://127.0.0.1:{port}\n"
            "  allow_local_network: true\n",
        )
        assert exit_code == 1  # rule findings still reported
        assert '"threats"' in output
        assert "Traceback" not in output


class TestDiffCommand:
    def test_diff_json_output(self, tmp_path: Path) -> None:
        import json

        threat1 = {
            "id": "t1",
            "title": "Threat 1",
            "severity": "high",
            "resource_address": "a.b",
        }
        report = {"input_file": "test.json", "threats": [threat1]}
        baseline = tmp_path / "baseline.json"
        current = tmp_path / "current.json"
        baseline.write_text(json.dumps(report))
        threat2 = {
            "id": "t2",
            "title": "New Threat",
            "severity": "medium",
            "resource_address": "c.d",
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
