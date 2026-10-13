"""The command line surface that must never surprise: options, aliases, outputs and refusals.

Each test drives the real CLI on a demo input and checks what a person sees.
Behavior of the scan itself is in ``tests/test_cli.py``.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner, Result

from threatcode import cli as cli_module
from threatcode.cli import (
    DEFAULT_DIAGRAM_MAX_ROWS,
    DEFAULT_MAX_EDGES,
    DEFAULT_MAX_NODES,
    _incomplete_phrase,
    cli,
)
from threatcode.formatters.diagram import DEFAULT_LOD_THRESHOLD, DEFAULT_MAX_ROWS
from threatcode.models.report import Coverage

REPO_ROOT = Path(__file__).parent.parent
FIXTURES = Path(__file__).parent / "fixtures"
SIMPLE_PLAN = FIXTURES / "terraform" / "simple_s3.plan.json"
INSECURE_PLAN = FIXTURES / "terraform" / "multi_service_insecure.plan.json"
WEBAPP = REPO_ROOT / "examples" / "aws-webapp"
HELM_CHART = FIXTURES / "helm" / "test-chart"
ANSI = re.compile(r"\x1b\[[0-9;]*m")


@pytest.fixture(autouse=True)
def hermetic_environment(
    tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
) -> None:
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


def invoke(*args: str | Path, color: bool = False) -> Result:
    return CliRunner().invoke(cli, [str(a) for a in args], color=color)


def environment_section(help_text: str) -> str:
    """The ``Environment:`` block of a help page, to the end."""
    return help_text[help_text.index("Environment:") :]


# ── FR-11, RW-15, CH-11, TUX-16(a): global options after the command ──


class TestGlobalOptionsAfterTheCommand:
    def test_quiet_after_scan_hides_the_summary_like_quiet_before(self) -> None:
        before = invoke(
            "-q", "scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json", "--no-timestamp"
        )
        after = invoke(
            "scan", INSECURE_PLAN, "-q", "--fail-on", "none", "-f", "json", "--no-timestamp"
        )
        shown = invoke("scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json", "--no-timestamp")
        assert after.exit_code == before.exit_code == 0
        assert "Scanned" in shown.stderr
        assert "Scanned" not in after.stderr
        assert after.stderr == before.stderr
        assert after.stdout == before.stdout

    def test_quiet_after_scan_still_shows_coverage_gaps_and_errors(self, tmp_path: Path) -> None:
        broken = tmp_path / "bad.tf"
        broken.write_text('resource "aws_s3_bucket" "b" {\n  bucket = \n')
        result = invoke("scan", broken, "-q")
        assert result.exit_code == 2
        assert "Error" in result.stderr

    def test_verbose_after_scan_adds_log_detail(self) -> None:
        plain = invoke("scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json")
        verbose = invoke("scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json", "-v")
        assert "INFO:" not in plain.stderr
        assert "INFO: Analysis started" in verbose.stderr
        # one handler: each line is printed once
        assert verbose.stderr.count("INFO: Analysis started") == 1

    def test_verbose_before_and_after_the_command_add_up(self) -> None:
        result = invoke("-v", "scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json", "-v")
        assert "DEBUG:" in result.stderr
        assert result.stderr.count("INFO: Analysis started") == 1

    def test_no_color_after_scan_turns_colors_off(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli_module, "_stdout_is_tty", lambda: True)
        colored = invoke("scan", INSECURE_PLAN, "--fail-on", "none", "-f", "text", color=True)
        plain = invoke(
            "scan", INSECURE_PLAN, "--fail-on", "none", "-f", "text", "--no-color", color=True
        )
        assert "\x1b[" in colored.stdout or "\x1b[" in colored.output
        assert "\x1b[" not in plain.stdout
        assert ANSI.sub("", colored.stdout) == plain.stdout

    def test_the_options_work_after_diff_too(self, tmp_path: Path) -> None:
        report = tmp_path / "r.json"
        report.write_text(invoke("scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json").stdout)
        loud = invoke("diff", report, report)
        quiet = invoke("diff", report, report, "-q")
        assert loud.exit_code == quiet.exit_code == 0
        assert "resolved" in loud.stderr
        assert quiet.stderr == ""
        assert invoke("diff", report, report, "--no-color", "-v").exit_code == 0

    @pytest.mark.parametrize("command", ["scan", "diff"])
    def test_each_command_help_lists_them(self, command: str) -> None:
        out = invoke(command, "--help").stdout
        for option in ("-q, --quiet", "-v, --verbose", "--no-color"):
            assert option in out
        assert "Also works before the command" in out

    def test_the_group_help_says_where_they_go(self) -> None:
        out = invoke("--help").stdout
        assert "before or after the command" in out
        assert "--debug goes before it" in out

    def test_debug_is_still_a_group_option(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--debug")
        assert result.exit_code == 2
        assert "No such option" in result.stderr

    def test_one_environment_list_in_every_help_page(self) -> None:
        pages = [invoke(*args, "--help").stdout for args in ((), ("scan",), ("diff",))]
        sections = [environment_section(page) for page in pages]
        assert sections[0] == sections[1] == sections[2]
        for variable in (
            "THREATCODE_MAX_NODES",
            "THREATCODE_MAX_EDGES",
            "THREATCODE_DEBUG",
            "THREATCODE_FORMAT",
            "ANTHROPIC_API_KEY",
        ):
            assert variable in sections[1]


# ── FR-11, CH-11, FV-28: -o - and -o /dev/stdout ──


class TestOutputToStandardOutput:
    def test_dash_means_stdout_and_creates_no_file(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json", "-o", "-")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["schema_version"]
        assert "written to" not in result.stderr
        assert list(tmp_path.iterdir()) == []

    def test_dash_on_diff_means_stdout(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        report = tmp_path / "r.json"
        report.write_text(invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json").stdout)
        result = invoke("diff", report, report, "-o", "-")
        assert result.exit_code == 0
        assert json.loads(result.stdout)["added"] == []
        assert sorted(p.name for p in tmp_path.iterdir()) == ["r.json"]

    def test_dev_stdout_works_into_a_pipe_and_into_a_file(self, tmp_path: Path) -> None:
        code = "from threatcode.cli import cli; cli()"
        args = [sys.executable, "-c", code, "scan", str(SIMPLE_PLAN), "--fail-on", "none"]
        args += ["-f", "navigator", "-o", "/dev/stdout"]
        piped = subprocess.run(args, capture_output=True, text=True, check=False)
        assert piped.returncode == 0, piped.stderr
        assert "techniques" in json.loads(piped.stdout)
        assert "written to" not in piped.stderr
        target = tmp_path / "layer.json"
        with target.open("w") as handle:
            redirected = subprocess.run(
                args, stdout=handle, stderr=subprocess.PIPE, text=True, check=False
            )
        assert redirected.returncode == 0, redirected.stderr
        assert "techniques" in json.loads(target.read_text())

    def test_a_real_file_still_reports_where_it_wrote(self, tmp_path: Path) -> None:
        out = tmp_path / "r.json"
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-o", out)
        assert result.exit_code == 0
        assert f"Report written to {out.resolve()}" in result.stderr
        assert out.exists()


# ── FR-15: the format follows the -o extension ──


class TestFormatFromTheExtension:
    @pytest.mark.parametrize(
        ("name", "needle"),
        [
            ("results.sarif", '"version": "2.1.0"'),
            ("report.md", "ThreatCode Threat Model Report"),
            ("flow.mmd", "flowchart"),
            ("map.svg", "<svg"),
            ("out.json", '"schema_version"'),
            ("noext", '"schema_version"'),
            ("out.dat", '"schema_version"'),
        ],
    )
    def test_the_extension_picks_the_format(self, tmp_path: Path, name: str, needle: str) -> None:
        out = tmp_path / name
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-o", out)
        assert result.exit_code == 0, result.stderr
        assert needle in out.read_text()
        assert "has the extension" not in result.stderr

    def test_an_explicit_format_wins_and_a_mismatch_is_warned_about(self, tmp_path: Path) -> None:
        out = tmp_path / "results.sarif"
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json", "-o", out)
        assert result.exit_code == 0
        assert '"schema_version"' in out.read_text()
        assert "results.sarif has the extension of the sarif format" in result.stderr
        assert "pass -f sarif" in result.stderr

    def test_the_mismatch_warning_survives_quiet(self, tmp_path: Path) -> None:
        out = tmp_path / "results.sarif"
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json", "-o", out, "-q")
        assert "has the extension of the sarif format" in result.stderr

    def test_a_format_that_fits_the_extension_is_not_warned_about(self, tmp_path: Path) -> None:
        for fmt, name in (("sarif", "r.sarif"), ("json", "r.json"), ("markdown", "r.md")):
            result = invoke(
                "scan", SIMPLE_PLAN, "--fail-on", "none", "-f", fmt, "-o", tmp_path / name
            )
            assert "has the extension" not in result.stderr, fmt

    def test_the_environment_format_counts_as_explicit(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("THREATCODE_FORMAT", "json")
        out = tmp_path / "results.sarif"
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-o", out)
        assert '"schema_version"' in out.read_text()
        assert "has the extension of the sarif format" in result.stderr

    def test_no_output_file_keeps_the_stdout_default(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none")
        assert json.loads(result.stdout)["schema_version"]


# ── FR-18: removed commands ──


class TestRemovedCommandsPointToTheMigrationPage:
    COMMANDS = ("fs", "repo", "image", "vuln", "db", "secret", "sbom", "license")

    @pytest.mark.parametrize("command", COMMANDS)
    def test_each_exits_2_with_one_line_naming_the_page(self, command: str) -> None:
        result = invoke(command)
        assert result.exit_code == 2
        lines = result.stderr.strip().splitlines()
        assert len(lines) == 1
        assert lines[0].startswith(f"Error: 'threatcode {command}' was removed in 1.0")
        assert "docs/migrating.md" in lines[0]

    @pytest.mark.parametrize("command", COMMANDS)
    def test_arguments_and_options_of_the_old_command_do_not_change_the_answer(
        self, command: str
    ) -> None:
        result = invoke(command, "--severity", "high", "-f", "json", "somewhere", "--help")
        assert result.exit_code == 2
        assert "was removed in 1.0" in result.stderr
        assert "No such option" not in result.stderr

    def test_they_name_what_replaces_them(self) -> None:
        assert "threatcode scan DIR" in invoke("fs").stderr
        assert "--ingest" in invoke("image").stderr
        assert "--ingest" in invoke("vuln").stderr
        assert "Gitleaks" in invoke("secret").stderr
        assert "Syft" in invoke("sbom").stderr

    def test_they_stay_out_of_the_help(self) -> None:
        out = invoke("--help").stdout
        for command in self.COMMANDS:
            assert f"\n  {command} " not in out

    def test_a_genuinely_unknown_command_is_still_not_found(self) -> None:
        result = invoke("frobnicate")
        assert result.exit_code == 2
        assert "No such command" in result.stderr


# ── CH-06, FR-20: the deprecated alias and the format choice ──


class TestTheFormatChoice:
    def test_the_metavar_is_short_and_the_choices_are_in_the_description(self) -> None:
        out = invoke("scan", "--help").stdout
        flat = " ".join(out.split())
        assert "-f, --format FORMAT" in flat
        assert (
            "Output format: json, sarif, markdown, bitbucket, navigator, mermaid, diagram, text"
            in flat
        )
        assert "matrix" not in out

    def test_the_invalid_value_error_does_not_offer_matrix(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", "yaml")
        assert result.exit_code == 2
        assert "'yaml' is not one of" in result.stderr
        assert "'text'" in result.stderr
        assert "matrix" not in result.stderr

    def test_matrix_is_still_accepted_and_renders_the_navigator_layer(self) -> None:
        old = invoke("scan", SIMPLE_PLAN, "-f", "matrix", "--no-timestamp", "--fail-on", "none")
        new = invoke("scan", SIMPLE_PLAN, "-f", "navigator", "--no-timestamp", "--fail-on", "none")
        assert old.exit_code == new.exit_code == 0
        assert old.stdout == new.stdout

    def test_matrix_warns_once_and_the_warning_survives_quiet(self) -> None:
        for flags in ((), ("-q",)):
            result = invoke("scan", SIMPLE_PLAN, "-f", "matrix", "--fail-on", "none", *flags)
            assert result.stderr.count("-f matrix is deprecated, use -f navigator") == 1, flags
            assert "Warning: -f matrix is deprecated" in result.stderr

    def test_navigator_says_nothing_about_deprecation(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", "navigator", "--fail-on", "none")
        assert "deprecated" not in result.stderr

    def test_matrix_from_the_environment_warns_too(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("THREATCODE_FORMAT", "matrix")
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-q")
        assert "-f matrix is deprecated" in result.stderr


class TestHelpStatesDefaults:
    def test_graph_limits_show_their_defaults(self) -> None:
        flat = " ".join(invoke("scan", "--help").stdout.split())
        assert f"Graph node limit (default {DEFAULT_MAX_NODES:,})" in flat
        assert f"Graph edge limit (default {DEFAULT_MAX_EDGES:,})" in flat
        assert "INTEGER RANGE" not in flat.split("--max-nodes")[1].split("--max-edges")[0]

    def test_the_stated_defaults_are_the_real_ones(self) -> None:
        from threatcode.ir.graph import MAX_EDGES, MAX_NODES

        assert DEFAULT_MAX_NODES == MAX_NODES
        assert DEFAULT_MAX_EDGES == MAX_EDGES
        assert DEFAULT_DIAGRAM_MAX_ROWS == DEFAULT_MAX_ROWS

    def test_diff_fail_on_new_takes_the_same_choices_as_fail_on(self) -> None:
        scan_param = next(p for p in cli.commands["scan"].params if p.name == "fail_on")
        diff_param = next(p for p in cli.commands["diff"].params if p.name == "fail_on_new")
        assert list(scan_param.type.choices) == list(diff_param.type.choices)  # type: ignore[attr-defined]

    def test_diff_rejects_an_unknown_severity(self, tmp_path: Path) -> None:
        report = tmp_path / "r.json"
        report.write_text(invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json").stdout)
        result = invoke("diff", report, report, "--fail-on-new", "severe")
        assert result.exit_code == 2
        assert "Invalid value for '--fail-on-new'" in result.stderr

    def test_diff_fail_on_new_none_never_fails(self, tmp_path: Path) -> None:
        base = tmp_path / "base.json"
        base.write_text('{"schema_version": "2", "version": "1", "threats": []}')
        current = tmp_path / "current.json"
        current.write_text(invoke("scan", INSECURE_PLAN, "--fail-on", "none", "-f", "json").stdout)
        assert invoke("diff", base, current, "--fail-on-new", "high").exit_code == 1
        assert invoke("diff", base, current, "--fail-on-new", "none").exit_code == 0


# ── TUX-16(f): formats that are not for a terminal ──


class TestRefuseBinaryishFormatsOnATerminal:
    @pytest.fixture(autouse=True)
    def terminal(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(cli_module, "_stdout_is_tty", lambda: True)

    @pytest.mark.parametrize("fmt", ["diagram", "navigator", "matrix"])
    def test_refused_before_scanning(self, fmt: str) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", fmt, "--fail-on", "none")
        assert result.exit_code == 2
        assert "instead of printing it" in result.stderr
        assert "-o" in result.stderr
        assert result.stdout == ""
        assert "Scanned" not in result.stderr

    def test_dash_is_the_terminal_too(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", "diagram", "-o", "-")
        assert result.exit_code == 2

    @pytest.mark.parametrize("fmt", ["diagram", "navigator"])
    def test_a_file_is_fine(self, fmt: str, tmp_path: Path) -> None:
        out = tmp_path / "out.dat"
        result = invoke("scan", SIMPLE_PLAN, "-f", fmt, "--fail-on", "none", "-o", out)
        assert result.exit_code == 0
        assert out.read_text()

    @pytest.mark.parametrize("fmt", ["text", "markdown", "json", "sarif", "mermaid"])
    def test_readable_formats_are_not_refused(self, fmt: str) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", fmt, "--fail-on", "none")
        assert result.exit_code == 0


# ── FV-22, FV-29: values handed to the renderers ──


def make_checkout(root: Path) -> Path:
    """A checkout with no .git directory: ``root/infra/main.tf``."""
    infra = root / "infra"
    infra.mkdir(parents=True)
    (infra / "main.tf").write_text(
        'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n  acl    = "public-read"\n}\n'
    )
    return infra


def sarif_uris(result: Result) -> set[str]:
    sarif = json.loads(result.stdout)
    found: set[str] = set()
    for run in sarif["runs"]:
        for item in run["results"]:
            for location in item.get("locations", []):
                found.add(location["physicalLocation"]["artifactLocation"]["uri"])
    return found


class TestSourceRoot:
    def test_source_root_anchors_sarif_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        infra = make_checkout(tmp_path / "repo")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        plain = invoke("scan", infra, "-f", "sarif", "--fail-on", "none")
        rooted = invoke(
            "scan", infra, "-f", "sarif", "--fail-on", "none", "--source-root", tmp_path / "repo"
        )
        assert sarif_uris(plain) == {"main.tf"}
        assert sarif_uris(rooted) == {"infra/main.tf"}

    def test_source_root_anchors_bitbucket_paths(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        infra = make_checkout(tmp_path / "repo")
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        monkeypatch.chdir(elsewhere)
        result = invoke(
            "scan",
            infra,
            "-f",
            "bitbucket",
            "--fail-on",
            "none",
            "--source-root",
            tmp_path / "repo",
        )
        paths = {a.get("path") for a in json.loads(result.stdout)["annotations"] if a.get("path")}
        assert paths == {"infra/main.tf"}

    def test_a_missing_directory_is_a_usage_error(self, tmp_path: Path) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--source-root", tmp_path / "nope")
        assert result.exit_code == 2
        assert "--source-root" in result.stderr

    def test_a_file_is_not_a_source_root(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--source-root", SIMPLE_PLAN)
        assert result.exit_code == 2


class TestBitbucketResultFollowsTheGate:
    @staticmethod
    def result_of(*flags: str) -> tuple[int, str]:
        run = invoke("scan", WEBAPP, "-f", "bitbucket", *flags)
        return run.exit_code, json.loads(run.stdout)["report"]["result"]

    def test_fail_on_none_is_passed(self) -> None:
        assert self.result_of("--fail-on", "none") == (0, "PASSED")

    def test_the_default_gate_fails(self) -> None:
        assert self.result_of() == (1, "FAILED")

    def test_a_stricter_gate_than_the_findings_passes(self) -> None:
        code, result = self.result_of("--fail-on", "critical")
        assert (code == 0) == (result == "PASSED")


# ── --diagram-* options ──


class TestDiagramOptions:
    @pytest.fixture
    def calls(self, monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
        seen: list[dict[str, Any]] = []

        def fake(report: object, graph: object, **kwargs: Any) -> str:
            seen.append(kwargs)
            return "<svg/>"

        monkeypatch.setattr("threatcode.formatters.diagram.format_diagram", fake)
        return seen

    def test_the_defaults_are_the_renderers_own(self, calls: list[dict[str, Any]]) -> None:
        assert invoke("scan", SIMPLE_PLAN, "-f", "diagram", "--fail-on", "none").exit_code == 0
        assert calls == [
            {
                "max_rows": DEFAULT_MAX_ROWS,
                "expand_docker": False,
                "lod_threshold": DEFAULT_LOD_THRESHOLD,
            }
        ]

    def test_every_option_reaches_the_renderer(self, calls: list[dict[str, Any]]) -> None:
        invoke(
            "scan",
            SIMPLE_PLAN,
            "-f",
            "diagram",
            "--fail-on",
            "none",
            "--diagram-max-rows",
            "7",
            "--diagram-expand-docker",
            "--diagram-detail",
            "full",
        )
        assert calls == [{"max_rows": 7, "expand_docker": True, "lod_threshold": None}]

    def test_zero_rows_means_every_row_and_collapsed_means_always(
        self, calls: list[dict[str, Any]]
    ) -> None:
        invoke(
            "scan",
            SIMPLE_PLAN,
            "-f",
            "diagram",
            "--fail-on",
            "none",
            "--diagram-max-rows",
            "0",
            "--diagram-detail",
            "collapsed",
        )
        assert calls == [{"max_rows": None, "expand_docker": False, "lod_threshold": 0}]

    def test_max_rows_changes_the_real_diagram(self) -> None:
        full = invoke("scan", INSECURE_PLAN, "-f", "diagram", "--fail-on", "none").stdout
        short = invoke(
            "scan", INSECURE_PLAN, "-f", "diagram", "--fail-on", "none", "--diagram-max-rows", "1"
        ).stdout
        assert len(short) < len(full)

    def test_a_bad_detail_or_row_count_is_a_usage_error(self) -> None:
        bad_detail = invoke("scan", SIMPLE_PLAN, "-f", "diagram", "--diagram-detail", "some")
        assert bad_detail.exit_code == 2
        assert "Invalid value for '--diagram-detail'" in bad_detail.stderr
        bad_rows = invoke("scan", SIMPLE_PLAN, "-f", "diagram", "--diagram-max-rows", "-1")
        assert bad_rows.exit_code == 2

    @pytest.mark.parametrize(
        "flags",
        [["--diagram-max-rows", "5"], ["--diagram-expand-docker"], ["--diagram-detail", "full"]],
    )
    def test_they_refuse_to_be_ignored_by_another_format(self, flags: list[str]) -> None:
        result = invoke("scan", SIMPLE_PLAN, "-f", "json", "--fail-on", "none", *flags)
        assert result.exit_code == 2
        assert "--diagram-* options only apply to -f diagram" in result.stderr


# ── FR-09: the SDK before the key ──


@pytest.fixture
def no_sdk(monkeypatch: pytest.MonkeyPatch) -> None:
    """The anthropic SDK is not installed: its import fails and it cannot be found."""
    monkeypatch.setitem(sys.modules, "anthropic", None)


class TestLlmChecksTheSdkFirst:
    @pytest.mark.parametrize("key", [None, "sk-test"])
    def test_without_the_sdk_it_is_one_exit_2_line_with_or_without_a_key(
        self, no_sdk: None, monkeypatch: pytest.MonkeyPatch, key: str | None
    ) -> None:
        if key:
            monkeypatch.setenv("ANTHROPIC_API_KEY", key)
        result = invoke("scan", SIMPLE_PLAN, "--llm", "--fail-on", "none")
        assert result.exit_code == 2
        lines = result.stderr.strip().splitlines()
        assert len(lines) == 1, result.stderr
        assert "pip install 'threatcode[llm]'" in lines[0]
        assert "sending" not in result.stderr
        assert "enabled" not in result.stderr
        assert "API key" not in result.stderr

    def test_the_environment_variable_and_a_config_get_the_same_answer(
        self, no_sdk: None, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        monkeypatch.setenv("THREATCODE_LLM", "1")
        env = invoke("scan", SIMPLE_PLAN)
        monkeypatch.delenv("THREATCODE_LLM")
        config = tmp_path / "c.yml"
        config.write_text("llm:\n  enabled: true\n")
        from_config = invoke("scan", SIMPLE_PLAN, "-c", config)
        for result in (env, from_config):
            assert result.exit_code == 2
            assert "pip install 'threatcode[llm]'" in result.stderr

    def test_a_dry_run_needs_no_sdk(self, no_sdk: None) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--dry-run", "--fail-on", "none", "-f", "json")
        assert result.exit_code == 0, result.stderr
        assert "Dry run" in result.stderr
        assert "pip install" not in result.stderr

    def test_without_a_key_it_does_not_claim_to_send(self) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--llm", "--fail-on", "none")
        assert "No Anthropic API key" in result.stderr
        assert "sending a redacted graph" not in result.stderr
        assert result.exit_code == 0  # the rules still ran

    def test_without_the_flag_nothing_is_checked(self, no_sdk: None) -> None:
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none")
        assert result.exit_code == 0
        assert "pip install" not in result.stderr


# ── duplicate ids on the CLI path ──


class TestDuplicateIds:
    def test_a_repeated_id_is_warned_about(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from threatcode.models.report import ThreatReport

        monkeypatch.setattr(ThreatReport, "duplicate_ids", lambda self: ["R-1", "R-2"])
        result = invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json")
        assert "the report holds 2 threat id(s) more than once" in result.stderr
        assert "R-1, R-2" in result.stderr
        assert (
            "more than once"
            not in invoke("scan", SIMPLE_PLAN, "--fail-on", "none", "-f", "json", "-q").stderr
        )

    def test_a_clean_scan_says_nothing(self) -> None:
        result = invoke("scan", WEBAPP, "--fail-on", "none", "-f", "json")
        assert "more than once" not in result.stderr


# ── the closing line says incomplete ──


def skipped_helm_chart(tmp_path: Path) -> Path:
    import shutil

    chart = tmp_path / "chart"
    shutil.copytree(HELM_CHART, chart)
    (chart / "templates" / "bad.yaml").write_text("a: [1, 2\nb: : :\n")
    return chart


class TestTheClosingLineSaysIncomplete:
    def test_a_skipped_helm_template_makes_the_line_incomplete(self, tmp_path: Path) -> None:
        chart = skipped_helm_chart(tmp_path)
        result = invoke("scan", chart, "--fail-on", "none", "-f", "json")
        closing = [line for line in result.stderr.splitlines() if line.startswith("Scanned")]
        assert len(closing) == 1
        assert "incomplete: 1 Helm template skipped or approximated" in closing[0]

    def test_a_chart_that_rendered_fully_is_not_called_incomplete(self) -> None:
        result = invoke("scan", WEBAPP, "--fail-on", "none", "-f", "json")
        assert "Scanned" in result.stderr
        assert "incomplete" not in result.stderr

    def test_the_helm_approximation_alone_is_a_gap_but_not_incomplete(self) -> None:
        coverage = Coverage(gaps=[{"level": "warning", "code": "helm.fallback_render"}])
        assert _incomplete_phrase(coverage) == ""

    def test_an_error_level_gap_is_incomplete(self) -> None:
        coverage = Coverage(
            gaps=[
                {"level": "error", "code": "x.broken", "message": "m"},
                {"level": "error", "code": "x.broken", "message": "m"},
                {"level": "warning", "code": "x.other", "message": "m"},
            ]
        )
        assert _incomplete_phrase(coverage) == "1 error-level coverage gap"

    def test_all_causes_are_named_together(self) -> None:
        coverage = Coverage(
            errors=[{"file": "a", "code": "c", "message": "m"}],
            gaps=[
                {"level": "error", "code": "x.broken", "message": "m"},
                {"level": "warning", "code": "helm.render_warning", "message": "a"},
                {"level": "warning", "code": "helm.render_warning", "message": "b"},
            ],
        )
        assert _incomplete_phrase(coverage) == (
            "1 input error, 1 error-level coverage gap, 2 Helm templates skipped or approximated"
        )

    def test_nothing_wrong_is_empty(self) -> None:
        assert _incomplete_phrase(Coverage()) == ""
