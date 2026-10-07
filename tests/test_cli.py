"""Tests for threatcode.cli."""

from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess
import sys
from pathlib import Path
from typing import TYPE_CHECKING, Any

import pytest
from click.testing import CliRunner

from threatcode import __version__
from threatcode.cli import cli
from threatcode.exceptions import LLMError

if TYPE_CHECKING:
    from tests.conftest import FakeLLMServer

REPO_ROOT = Path(__file__).parent.parent
FIXTURES_DIR = Path(__file__).parent / "fixtures"
SHAPES = FIXTURES_DIR / "input_shapes"
K8S_FIXTURE = FIXTURES_DIR / "kubernetes" / "insecure_deployment.yml"

REMOVED_COMMANDS = ["image", "vuln", "db", "sbom", "license", "repo", "fs", "secret"]


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

    def test_version_flag_prints_the_package_version(self) -> None:
        result = CliRunner().invoke(cli, ["--version"])
        assert result.output.strip().endswith(__version__)


class TestSlimmedSurface:
    """The scanning layer is gone: the CLI has scan and diff and nothing else."""

    def test_only_scan_and_diff_are_commands(self) -> None:
        assert sorted(cli.commands) == ["diff", "scan"]

    @pytest.mark.parametrize("command", REMOVED_COMMANDS)
    def test_removed_command_is_not_found(self, command: str) -> None:
        result = CliRunner().invoke(cli, [command, str(K8S_FIXTURE)])
        assert result.exit_code == 2
        assert "No such command" in result.output
        assert command in result.output

    @pytest.mark.parametrize("option", ["--scanners=misconfig", "-s", "--ignore-unfixed"])
    def test_removed_scan_options_are_not_found(self, option: str) -> None:
        args = ["scan", str(K8S_FIXTURE), option]
        if option == "-s":
            args.append("misconfig")
        result = CliRunner().invoke(cli, args)
        assert result.exit_code == 2
        assert "No such option" in result.output

    def test_help_lists_scan_and_diff_only(self) -> None:
        result = CliRunner().invoke(cli, ["--help"])
        assert result.exit_code == 0
        assert "scan" in result.output
        assert "diff" in result.output
        for command in REMOVED_COMMANDS:
            assert f"\n  {command} " not in result.output

    def test_short_help_flag(self) -> None:
        result = CliRunner().invoke(cli, ["-h"])
        assert result.exit_code == 0
        assert "Usage:" in result.output

    def test_scan_help_has_no_scanner_options(self) -> None:
        result = CliRunner().invoke(cli, ["scan", "--help"])
        assert result.exit_code == 0
        assert "--scanners" not in result.output
        assert "--ignore-unfixed" not in result.output
        assert "--format" in result.output
        assert "--min-severity" in result.output

    def test_group_help_does_not_describe_the_removed_scanners(self) -> None:
        result = CliRunner().invoke(cli, ["--help"])
        for word in ("SBOM", "vulnerabilit", "license", "image"):
            assert word not in result.output


class TestScanInputs:
    def _scan(self, tmp_path: Path, source: Path) -> tuple[int, str, dict[str, Any]]:
        out = tmp_path / "report.json"
        result = CliRunner().invoke(cli, ["scan", str(source), "--no-llm", "-o", str(out)])
        report = json.loads(out.read_text(encoding="utf-8")) if out.exists() else {}
        return result.exit_code, result.output, report

    def test_short_form_cloudformation_scans(self, tmp_path: Path) -> None:
        code, output, report = self._scan(tmp_path, SHAPES / "cfn_short_form.yml")
        assert code in (0, 1)
        assert "Error" not in output
        assert "threats" in report

    def test_terraform_directory_scans_as_one_module(self, tmp_path: Path) -> None:
        code, output, report = self._scan(tmp_path, SHAPES / "tf_module")
        assert code in (0, 1)
        assert "Error" not in output
        assert report["scanned_resources"] == 3

    def test_tofu_and_json_syntax_files_scan(self, tmp_path: Path) -> None:
        for name in ("main.tofu", "cdk.tf.json"):
            code, output, report = self._scan(tmp_path, SHAPES / name)
            assert code in (0, 1), output
            assert "threats" in report

    def test_state_json_is_rejected_with_the_corrective_command(self) -> None:
        result = CliRunner().invoke(cli, ["scan", str(SHAPES / "terraform_state.json"), "--no-llm"])
        assert result.exit_code != 0
        assert "This is Terraform state, not a plan" in result.output
        assert "terraform plan -out tfplan && terraform show -json tfplan" in result.output
        assert "Scanned 0 resources" not in result.output

    def test_destroy_only_plan_is_rejected(self) -> None:
        source = SHAPES / "terraform_destroy.plan.json"
        result = CliRunner().invoke(cli, ["scan", str(source), "--no-llm"])
        assert result.exit_code != 0
        assert "destroys every resource" in result.output

    def test_empty_file_is_reported_as_empty(self, tmp_path: Path) -> None:
        empty = tmp_path / "empty.yaml"
        empty.write_text("", encoding="utf-8")
        result = CliRunner().invoke(cli, ["scan", str(empty), "--no-llm"])
        assert result.exit_code != 0
        assert "file is empty" in result.output
        assert "Traceback" not in result.output

    def test_binary_file_is_reported_as_not_text(self, tmp_path: Path) -> None:
        blob = tmp_path / "blob.json"
        blob.write_bytes(b"\x89PNG\r\n\x1a\n\x00")
        result = CliRunner().invoke(cli, ["scan", str(blob), "--no-llm"])
        assert result.exit_code != 0
        assert "not valid UTF-8 text" in result.output
        assert "UnicodeDecodeError" not in result.output

    def test_error_messages_do_not_carry_exception_class_names(self) -> None:
        source = SHAPES / "terraform_state.json"
        result = CliRunner().invoke(cli, ["scan", str(source), "--no-llm"])
        assert "ParseError" not in result.output
        assert "Error parsing input file: This is Terraform state" in result.output

    def test_directory_without_terraform_files_names_the_problem(self, tmp_path: Path) -> None:
        result = CliRunner().invoke(cli, ["scan", str(tmp_path), "--no-llm"])
        assert result.exit_code != 0
        assert "no Terraform files" in result.output
        assert "IsADirectoryError" not in result.output

    def test_unsupported_input_lists_what_is_supported(self, tmp_path: Path) -> None:
        other = tmp_path / "notes.xml"
        other.write_text("<root/>", encoding="utf-8")
        result = CliRunner().invoke(cli, ["scan", str(other), "--no-llm"])
        assert result.exit_code != 0
        assert "Cannot detect format for notes.xml" in result.output
        assert "Supported inputs:" in result.output


class TestCoreInstall:
    """The anthropic SDK belongs to the llm extra; a rules-only run never needs it."""

    def test_rules_only_scan_does_not_import_anthropic(self) -> None:
        code = (
            "import sys\n"
            "import threatcode\n"
            "import threatcode.cli\n"
            f"threatcode.scan({str(K8S_FIXTURE)!r}, no_llm=True)\n"
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
        result = CliRunner().invoke(cli, ["scan", str(K8S_FIXTURE)])
        assert result.exit_code == 1
        assert "pip install 'threatcode[llm]'" in result.output
        assert "Traceback" not in result.output


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
