"""The composite GitHub Action: static checks on its manifest and runs of its scan step.

The manifest is read with a YAML parser, so the checks hold whatever the formatting.
The scan step is a bash script; the behavior tests extract it, put a ``threatcode`` shim on PATH
and run it the way the runner does, with the inputs in the environment and ``GITHUB_OUTPUT``
pointing at a file.
That proves what the static checks cannot: a path with spaces reaches the CLI as one argument,
exit 2 fails the step at once with the message, exit 1 does not fail the scan step (the SARIF is
uploaded first and a later step enforces the gate), and the counts mean the same for every format.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import textwrap
from pathlib import Path
from typing import Any

import pytest
import yaml

REPO = Path(__file__).resolve().parent.parent
ACTION = REPO / ".github" / "actions" / "threatcode" / "action.yml"
WORKFLOWS = REPO / ".github" / "workflows"

FIXTURES = REPO / "tests" / "fixtures"
K8S_EXAMPLE = REPO / "examples" / "k8s-platform"
AWS_EXAMPLE = REPO / "examples" / "aws-webapp"

EXPECTED_INPUTS = {
    "path",
    "input-file",
    "format",
    "fail-on",
    "min-severity",
    "config-file",
    "extra-rules",
    "ingest",
    "baseline",
    "comment",
    "github-token",
    "upload",
    "version",
    "python-version",
}
EXPECTED_OUTPUTS = {"exit-code", "threat-count", "path-count", "report-file", "sarif-file"}
FULL_SHA = re.compile(r"^[0-9a-f]{40}$")
# The commit the manifest pinned before it was found not to exist (CodeQL action v3.28.13).
NONEXISTENT_PIN = "ea9e4e37992a54ee68a9571ad585ae0e9ce4e12b"
COMMENT_MARKER = "<!-- threatcode-report -->"


def load_action() -> dict[str, Any]:
    data = yaml.safe_load(ACTION.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    return data


def steps() -> list[dict[str, Any]]:
    result = load_action()["runs"]["steps"]
    assert isinstance(result, list)
    return result


def step_named(fragment: str) -> dict[str, Any]:
    matches = [s for s in steps() if fragment.lower() in str(s.get("name", "")).lower()]
    assert len(matches) == 1, f"expected exactly one step named like {fragment!r}: {matches}"
    return matches[0]


def step_index(fragment: str) -> int:
    return steps().index(step_named(fragment))


def run_scripts() -> list[tuple[str, str]]:
    return [(str(s["name"]), s["run"]) for s in steps() if "run" in s]


def scan_script() -> str:
    script = step_named("Run ThreatCode scan")["run"]
    assert isinstance(script, str)
    return script


class TestManifestShape:
    def test_it_is_a_composite_action(self) -> None:
        action = load_action()
        assert action["runs"]["using"] == "composite"
        assert action["name"] and action["description"]

    def test_the_inputs_are_exactly_the_documented_ones(self) -> None:
        assert set(load_action()["inputs"]) == EXPECTED_INPUTS

    def test_every_input_is_described(self) -> None:
        for name, spec in load_action()["inputs"].items():
            assert str(spec.get("description", "")).strip(), name

    def test_the_defaults_keep_adoption_safe(self) -> None:
        inputs = load_action()["inputs"]
        assert inputs["format"]["default"] == "sarif"
        # none keeps today's behavior: the action reports and never fails on findings.
        assert inputs["fail-on"]["default"] == "none"
        assert inputs["upload"]["default"] == "true"
        assert inputs["comment"]["default"] == "false"
        assert inputs["version"]["default"] == ""

    def test_the_outputs_exist_for_every_format(self) -> None:
        outputs = load_action()["outputs"]
        assert set(outputs) == EXPECTED_OUTPUTS
        for name in ("exit-code", "threat-count", "path-count", "report-file"):
            assert outputs[name]["value"] == "${{ steps.scan.outputs." + name + " }}"

    def test_the_scan_step_has_the_id_the_outputs_read(self) -> None:
        assert step_named("Run ThreatCode scan")["id"] == "scan"

    def test_the_file_input_was_renamed_without_breaking_old_workflows(self) -> None:
        inputs = load_action()["inputs"]
        assert "deprecated" in inputs["input-file"]["description"].lower()
        env = step_named("Run ThreatCode scan")["env"]
        assert "inputs.input-file" in env["TC_INPUT_FILE"]
        assert "inputs.path" in env["TC_PATH"]


class TestNothingCanBeSwallowed:
    def test_no_script_ends_a_command_with_or_true(self) -> None:
        for name, script in run_scripts():
            assert not re.search(r"\|\|\s*(true|:)\b", script), name
            assert not re.search(r"\|\|\s*exit\s+0", script), name

    def test_the_scan_command_is_not_followed_by_anything_that_hides_its_status(self) -> None:
        script = scan_script()
        assert "set +e" not in script or "rc=$?" in script
        assert re.search(r"2> \"\$stderr_file\"\n\s*rc=\$\?", script)
        assert 'echo "exit-code=$rc" >> "$GITHUB_OUTPUT"' in script

    def test_exit_two_or_more_fails_the_step_at_once_with_the_message(self) -> None:
        script = scan_script()
        assert 'if [ "$rc" -gt 1 ]' in script
        assert "::error title=ThreatCode failed" in script
        assert 'exit "$rc"' in script

    def test_stderr_is_shown_between_stop_commands(self) -> None:
        # File names from the scanned tree reach stderr; a line starting with two colons would
        # otherwise be run as a workflow command.
        script = scan_script()
        assert "::stop-commands::" in script
        assert "secrets.token_hex" in script

    def test_the_message_is_escaped_for_a_workflow_command(self) -> None:
        script = scan_script()
        assert "%25" in script and "%0A" in script and "%0D" in script


class TestInstall:
    def test_the_default_installs_the_code_at_the_actions_own_ref(self) -> None:
        script = step_named("Install ThreatCode")["run"]
        assert '"$GITHUB_ACTION_PATH/../../.."' in script

    def test_the_version_input_installs_that_exact_release(self) -> None:
        step = step_named("Install ThreatCode")
        assert "inputs.version" in step["env"]["TC_VERSION"]
        assert '"threatcode==$TC_VERSION"' in step["run"]

    def test_the_version_is_validated_before_pip_sees_it(self) -> None:
        script = step_named("Install ThreatCode")["run"]
        assert re.search(r"\*\[!0-9A-Za-z", script)
        assert script.index("[!0-9A-Za-z") < script.index("pip install")

    def test_no_script_installs_the_bare_package_name(self) -> None:
        # A bare name resolves to whatever PyPI serves: another project's package before the
        # first release, and a version unrelated to the action's ref after it.
        for name, script in run_scripts():
            for line in script.splitlines():
                if "pip install" not in line:
                    continue
                assert not re.search(
                    r"""pip install\b[^\n]*[\s"']threatcode(?![=\w/.-])""", line
                ), (
                    name,
                    line,
                )
                assert not re.search(r"pip install\s+threatcode\s*$", line), (name, line)

    def test_the_manifest_text_has_no_bare_install_anywhere(self) -> None:
        text = ACTION.read_text(encoding="utf-8")
        assert not re.search(r"pip install\s+-?[\w-]*\s*threatcode(\s|$|\")", text)
        assert "pip install threatcode" not in text.replace("pip install threatcode==", "")

    def test_it_runs_python_three_not_bare_python(self) -> None:
        for name, script in run_scripts():
            assert not re.search(r"(^|[\s(`;&|])python(\s|$)", script, re.MULTILINE), name


class TestInputsReachTheShellOnlyThroughTheEnvironment:
    def test_no_run_script_interpolates_an_expression(self) -> None:
        for name, script in run_scripts():
            assert "${{" not in script, f"{name} interpolates an expression into a script"

    def test_every_input_a_script_reads_arrives_through_env(self) -> None:
        scan = step_named("Run ThreatCode scan")["env"]
        sources = " ".join(str(v) for v in scan.values())
        for name in (
            "path",
            "input-file",
            "format",
            "fail-on",
            "min-severity",
            "config-file",
            "extra-rules",
            "ingest",
            "baseline",
            "comment",
        ):
            assert f"inputs.{name}" in sources, name

    def test_input_expressions_appear_only_in_env_with_if_and_the_pinned_steps(self) -> None:
        for step in steps():
            for key, value in step.items():
                if key in {"env", "with", "if", "name", "id", "uses", "shell", "run"}:
                    continue
                assert "inputs." not in str(value), (step.get("name"), key)

    def test_arguments_are_bash_arrays_so_paths_with_spaces_survive(self) -> None:
        script = scan_script()
        assert "shared=()" in script
        assert 'scan_paths+=("$line")' in script
        assert '"${scan_paths[@]}"' in script
        assert '"${shared[@]}"' in script
        assert not re.search(r"ARGS=|\$ARGS", script)

    def test_the_cli_is_called_with_the_flags_the_inputs_name(self) -> None:
        script = scan_script()
        for flag in ("--format", "--fail-on", "--min-severity", "--config", "--baseline"):
            assert flag in script, flag
        assert '--rules "$rule"' in script
        assert '--ingest "$ingest_file"' in script


class TestUploadAndGate:
    def test_the_upload_runs_even_when_the_gate_will_fail(self) -> None:
        condition = step_named("Upload SARIF")["if"]
        assert "always()" in condition
        assert "inputs.upload == 'true'" in condition
        assert "inputs.format == 'sarif'" in condition
        assert "hashFiles(" in condition and "!= ''" in condition

    def test_the_upload_is_pinned_to_a_commit_that_exists(self) -> None:
        uses = step_named("Upload SARIF")["uses"]
        ref = uses.split("@", 1)[1].split()[0]
        assert uses.startswith("github/codeql-action/upload-sarif@")
        assert FULL_SHA.match(ref), uses
        assert NONEXISTENT_PIN not in ACTION.read_text(encoding="utf-8")
        comment = [ln for ln in ACTION.read_text().splitlines() if ref in ln][0]
        assert re.search(r"# v3\.\d+\.\d+$", comment), comment

    def test_every_third_party_action_is_pinned_to_a_full_commit(self) -> None:
        for step in steps():
            uses = step.get("uses")
            if uses:
                assert FULL_SHA.match(uses.split("@", 1)[1].split()[0]), uses

    def test_the_gate_step_comes_after_the_upload_and_fails_on_exit_one(self) -> None:
        gate = step_named("Enforce the gate")
        assert step_index("Enforce the gate") > step_index("Upload SARIF")
        assert "always()" in gate["if"]
        assert "steps.scan.outputs.exit-code == '1'" in gate["if"]
        assert re.search(r"^\s*exit 1\s*$", gate["run"], re.MULTILINE)

    def test_the_gate_is_the_last_step(self) -> None:
        assert steps()[-1]["name"] == "Enforce the gate"


class TestPullRequestComment:
    def test_it_only_runs_for_a_pull_request_when_asked(self) -> None:
        condition = step_named("Comment on the pull request")["if"]
        assert "inputs.comment == 'true'" in condition
        assert "github.event_name == 'pull_request'" in condition

    def test_the_token_and_the_body_file_arrive_through_the_environment(self) -> None:
        step = step_named("Comment on the pull request")
        env = step["env"]
        assert env["GH_TOKEN"] == "${{ inputs.github-token }}"
        assert "steps.scan.outputs.comment-file" in env["TC_BODY_FILE"]
        assert "github.repository" in env["TC_REPO"]
        assert "pull_request.number" in env["TC_PR_NUMBER"]
        assert "${{" not in step["run"]

    def test_the_body_is_read_from_a_file_never_placed_on_the_command_line(self) -> None:
        script = step_named("Comment on the pull request")["run"]
        assert '-F "body=@$TC_BODY_FILE"' in script
        assert "--raw-field" not in script
        assert not re.search(r"-f\s+body=", script)
        assert "--method PATCH" in script and "--method POST" in script

    def test_it_finds_its_comment_by_the_marker(self) -> None:
        assert COMMENT_MARKER in step_named("Comment on the pull request")["run"]
        assert COMMENT_MARKER in scan_script()

    def test_forks_and_read_only_tokens_skip_with_a_notice(self) -> None:
        step = step_named("Comment on the pull request")
        assert "head.repo.full_name != github.repository" in step["env"]["TC_IS_FORK"]
        script = step["run"]
        assert '[ "$TC_IS_FORK" = "true" ]' in script
        assert script.count("::notice") >= 3
        assert re.search(r"^\s*exit 0\s*$", script, re.MULTILINE)

    def test_the_body_stays_under_githubs_limit(self) -> None:
        assert "limit = 60000" in scan_script()


class TestOtherWorkflowsUseTheAction:
    def test_ci_exercises_the_local_action(self) -> None:
        text = (WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        assert "uses: ./.github/actions/threatcode" in text

    def test_ci_never_uploads_from_the_self_test(self) -> None:
        ci = yaml.safe_load((WORKFLOWS / "ci.yml").read_text(encoding="utf-8"))
        job = ci["jobs"]["action"]
        local = [s for s in job["steps"] if s.get("uses") == "./.github/actions/threatcode"]
        assert len(local) >= 3
        for step in local:
            assert step["with"]["upload"] == "false", step.get("name")


def workflow(name: str) -> dict[str, Any]:
    data = yaml.safe_load((WORKFLOWS / name).read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    # YAML 1.1 reads the key `on` as the boolean True.
    if True in data:
        data["on"] = data.pop(True)
    return data


def all_run_text(wf: dict[str, Any]) -> str:
    return "\n".join(
        step["run"] for job in wf["jobs"].values() for step in job.get("steps", []) if "run" in step
    )


class TestCiWorkflow:
    def test_it_runs_on_every_pull_request_and_in_a_merge_queue(self) -> None:
        on = workflow("ci.yml")["on"]
        assert "pull_request" in on
        # A branch filter would leave a pull request onto a feature branch unchecked.
        assert not (on["pull_request"] or {}).get("branches")
        assert "merge_group" in on and "workflow_call" in on
        assert on["push"]["branches"] == ["main", "develop"]
        assert "schedule" in on and "workflow_dispatch" in on

    def test_the_matrix_covers_python_310_to_314_and_two_more_platforms(self) -> None:
        jobs = workflow("ci.yml")["jobs"]
        assert jobs["test"]["strategy"]["matrix"]["python-version"] == [
            "3.10",
            "3.11",
            "3.12",
            "3.13",
            "3.14",
        ]
        assert set(jobs["test-platforms"]["strategy"]["matrix"]["os"]) == {
            "macos-latest",
            "windows-latest",
        }

    def test_both_hcl2_ends_of_the_supported_range_run_the_suite(self) -> None:
        job = workflow("ci.yml")["jobs"]["hcl2"]
        specs = job["strategy"]["matrix"]["hcl2"]
        assert any("==4.3" in spec for spec in specs)
        assert any(">=8" in spec for spec in specs)
        pyproject = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        assert re.search(r'"python-hcl2>=4\.3,<9"', pyproject)

    def test_the_weekly_jobs_are_the_audit_and_the_mitre_drift_check_only(self) -> None:
        jobs = workflow("ci.yml")["jobs"]
        runs_on_schedule = {
            name
            for name, job in jobs.items()
            if "if" not in job or "schedule" in str(job["if"]).replace("!= 'schedule'", "")
        }
        assert runs_on_schedule == {"audit", "mitre-drift"}
        assert "gen_mitre_db.py" in all_run_text(workflow("ci.yml"))
        assert "--check" in jobs["mitre-drift"]["steps"][-1]["run"]

    def test_the_drift_check_cannot_block_a_pull_request(self) -> None:
        job = workflow("ci.yml")["jobs"]["mitre-drift"]
        assert "pull_request" not in str(job["if"])
        assert "github.workflow == 'CI'" in job["if"]

    def test_the_docs_are_built_with_warnings_as_errors(self) -> None:
        assert "mkdocs build --strict" in all_run_text(workflow("ci.yml"))

    def test_the_workflows_and_the_composite_action_are_linted(self) -> None:
        text = all_run_text(workflow("ci.yml"))
        assert "actionlint" in text and "shellcheck" in text
        assert ".github/actions/threatcode/action.yml" in text

    def test_the_coverage_artifact_is_a_file_an_upload_does_not_skip(self) -> None:
        steps_ = workflow("ci.yml")["jobs"]["test"]["steps"]
        upload = [s for s in steps_ if str(s.get("uses", "")).startswith("actions/upload-artifact")]
        assert len(upload) == 1
        assert upload[0]["with"]["path"] == "coverage.xml"
        assert upload[0]["with"]["if-no-files-found"] == "error"
        assert "--cov-report=xml" in all_run_text(workflow("ci.yml"))

    def test_every_action_in_every_workflow_is_pinned_to_a_commit(self) -> None:
        for path in WORKFLOWS.glob("*.yml"):
            for use in re.findall(r"uses:\s+(\S+)", path.read_text(encoding="utf-8")):
                if use.startswith("./"):
                    continue
                assert FULL_SHA.match(use.split("@", 1)[1]), f"{path.name}: {use}"


class TestPublishWorkflow:
    def test_a_release_cannot_be_published_from_a_commit_whose_ci_failed(self) -> None:
        jobs = workflow("publish.yml")["jobs"]
        assert jobs["ci"]["uses"] == "./.github/workflows/ci.yml"
        assert jobs["build"]["needs"] == "ci"
        assert jobs["pypi"]["needs"] == "build"
        assert jobs["testpypi"]["needs"] == "build"

    def test_the_built_version_is_what_the_tag_is_checked_against(self) -> None:
        text = all_run_text(workflow("publish.yml"))
        # The version is dynamic, so pyproject.toml has no version to read.
        assert "tomllib" not in text
        assert "METADATA" in text and '"$TAG" != "v$VERSION"' in text

    def test_the_artifacts_are_checked_and_smoke_tested_before_upload(self) -> None:
        text = all_run_text(workflow("publish.yml"))
        assert "twine check" in text
        assert "scripts/smoke_test_wheel.sh" in text

    def test_pypi_is_released_only_by_a_release_and_testpypi_only_by_hand(self) -> None:
        jobs = workflow("publish.yml")["jobs"]
        assert jobs["pypi"]["if"] == "github.event_name == 'release'"
        assert jobs["testpypi"]["if"] == "github.event_name == 'workflow_dispatch'"
        assert jobs["pypi"]["environment"]["name"] == "pypi"
        assert jobs["testpypi"]["environment"]["name"] == "testpypi"
        assert "repository-url" in jobs["testpypi"]["steps"][-1]["with"]
        assert "repository-url" not in jobs["pypi"]["steps"][-1].get("with", {})

    def test_only_the_upload_jobs_may_mint_an_oidc_token(self) -> None:
        wf = workflow("publish.yml")
        assert wf["permissions"] == {"contents": "read"}
        assert wf["jobs"]["pypi"]["permissions"] == {"id-token": "write"}
        assert "permissions" not in wf["jobs"]["build"]


class TestRepositoryAutomation:
    def test_dependabot_keeps_the_pinned_actions_and_the_python_dependencies_fresh(self) -> None:
        data = yaml.safe_load((REPO / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
        assert data["version"] == 2
        ecosystems = {u["package-ecosystem"]: u for u in data["updates"]}
        assert set(ecosystems) == {"github-actions", "pip"}
        assert "/.github/actions/threatcode" in ecosystems["github-actions"]["directories"]
        for update in ecosystems.values():
            assert update["schedule"]["interval"] == "weekly"

    def test_the_pre_commit_hook_scans_the_whole_repository_and_gates_on_high(self) -> None:
        hooks = yaml.safe_load((REPO / ".pre-commit-hooks.yaml").read_text(encoding="utf-8"))
        assert [h["id"] for h in hooks] == ["threatcode"]
        hook = hooks[0]
        assert hook["language"] == "python"
        # One graph across all files: a list of changed files would hide half of an attack path.
        assert hook["pass_filenames"] is False
        assert hook["entry"] == "threatcode scan . --fail-on high --format text"
        assert "terraform" in hook["types_or"] and "yaml" in hook["types_or"]

    def test_make_smoke_builds_and_installs_the_wheel(self) -> None:
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        assert re.search(r"^smoke:", makefile, re.MULTILINE)
        assert "scripts/smoke_test_wheel.sh" in makefile
        assert re.search(r"^ci:.*\bsmoke\b", makefile, re.MULTILINE)

    def test_make_mitre_check_runs_the_drift_script(self) -> None:
        makefile = (REPO / "Makefile").read_text(encoding="utf-8")
        assert re.search(r"^mitre-check:\n\t.*scripts/gen_mitre_db\.py --check", makefile, re.M)

    def test_the_package_declares_python_314(self) -> None:
        text = (REPO / "pyproject.toml").read_text(encoding="utf-8")
        assert "Programming Language :: Python :: 3.14" in text
        assert 'requires-python = ">=3.10"' in text


class TestSmokeScript:
    script = (REPO / "scripts" / "smoke_test_wheel.sh").read_text(encoding="utf-8")

    def test_it_compares_the_wheel_to_the_checkout_instead_of_counting(self) -> None:
        assert "diff " in self.script and "source_rule_files" in self.script
        assert "-lt 50" not in self.script and ">= 220" not in self.script
        assert "loaded_ids == source_ids" in self.script

    def test_it_proves_the_core_install_has_no_sdk_and_the_extra_installs_it(self) -> None:
        assert 'find_spec("anthropic") is None' in self.script
        assert "import anthropic  # noqa: F401" in self.script
        assert "--llm" in self.script and "threatcode\\[llm\\]" in self.script
        assert '"${WHEEL}[llm]"' in self.script

    def test_it_scans_the_worked_example_and_checks_the_version(self) -> None:
        assert "examples/aws-webapp" in self.script
        assert "threatcode, version $WHEEL_VERSION" in self.script

    def test_it_uses_python3_not_a_bare_python(self) -> None:
        assert "PYTHON=${PYTHON:-python3}" in self.script
        assert not re.search(r"^\s*python\s", self.script, re.MULTILINE)

    @pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
    def test_it_passes_shellcheck(self) -> None:
        proc = subprocess.run(
            ["shellcheck", str(REPO / "scripts" / "smoke_test_wheel.sh")],
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 0, proc.stdout


# --------------------------------------------------------------------------------------------
# Running the scan step
# --------------------------------------------------------------------------------------------

BASH = shutil.which("bash")
runs_bash = pytest.mark.skipif(
    BASH is None or sys.platform == "win32", reason="the scan step is a bash script"
)


class Runner:
    """Runs the scan step's script with a fake runner environment."""

    def __init__(self, tmp_path: Path) -> None:
        tmp_path.mkdir(parents=True, exist_ok=True)
        self.workspace = tmp_path / "workspace"
        self.workspace.mkdir()
        self.runner_temp = tmp_path / "runner temp"
        self.runner_temp.mkdir()
        self.output_file = tmp_path / "github_output"
        self.output_file.write_text("")
        shim_dir = tmp_path / "bin"
        shim_dir.mkdir()
        shim = shim_dir / "threatcode"
        shim.write_text(
            "#!/bin/sh\n"
            f"exec '{sys.executable}' -c "
            "'import sys; from threatcode.cli import cli; sys.argv[0] = \"threatcode\"; cli()' "
            '"$@"\n'
        )
        shim.chmod(shim.stat().st_mode | stat.S_IXUSR)
        python3 = shim_dir / "python3"
        python3.write_text(f"#!/bin/sh\nexec '{sys.executable}' \"$@\"\n")
        python3.chmod(python3.stat().st_mode | stat.S_IXUSR)
        self.shim_dir = shim_dir

    def run(self, **inputs: str) -> subprocess.CompletedProcess[str]:
        env = {
            "PATH": f"{self.shim_dir}{os.pathsep}{os.environ['PATH']}",
            "HOME": str(self.workspace),
            "GITHUB_OUTPUT": str(self.output_file),
            "RUNNER_TEMP": str(self.runner_temp),
            "PYTHONPATH": str(REPO / "src"),
            "NO_COLOR": "1",
            "TC_PATH": "",
            "TC_INPUT_FILE": "",
            "TC_FORMAT": "sarif",
            "TC_FAIL_ON": "none",
            "TC_MIN_SEVERITY": "",
            "TC_CONFIG_FILE": "",
            "TC_EXTRA_RULES": "",
            "TC_INGEST": "",
            "TC_BASELINE": "",
            "TC_COMMENT": "false",
            "TC_EVENT_NAME": "push",
        }
        env.update({f"TC_{k.upper()}": v for k, v in inputs.items()})
        assert BASH is not None
        return subprocess.run(
            [BASH, "-c", scan_script()],
            cwd=self.workspace,
            env=env,
            capture_output=True,
            text=True,
            timeout=300,
        )

    def outputs(self) -> dict[str, str]:
        result: dict[str, str] = {}
        for line in self.output_file.read_text().splitlines():
            key, _, value = line.partition("=")
            result[key] = value
        return result


@pytest.fixture
def runner(tmp_path: Path) -> Runner:
    return Runner(tmp_path)


@runs_bash
class TestTheScanStepRuns:
    def test_a_clean_scan_reports_zero_and_counts_the_findings(self, runner: Runner) -> None:
        proc = runner.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="json")
        assert proc.returncode == 0, proc.stderr
        out = runner.outputs()
        assert out["exit-code"] == "0"
        assert out["report-file"] == "threatcode-results.json"
        assert int(out["threat-count"]) > 0
        assert int(out["path-count"]) >= 0
        report = json.loads((runner.workspace / out["report-file"]).read_text())
        assert int(out["threat-count"]) == len(report["threats"])

    def test_the_sarif_file_is_advertised_only_for_sarif(self, runner: Runner) -> None:
        proc = runner.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="sarif")
        assert proc.returncode == 0, proc.stderr
        out = runner.outputs()
        assert out["sarif-file"] == "threatcode-results.sarif" == out["report-file"]
        assert json.loads((runner.workspace / out["sarif-file"]).read_text())["version"] == "2.1.0"

        second = Runner(runner.output_file.parent / "again")
        proc = second.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="markdown")
        assert proc.returncode == 0, proc.stderr
        assert "sarif-file" not in second.outputs()
        assert second.outputs()["report-file"] == "threatcode-results.md"

    @pytest.mark.parametrize("fmt", ["sarif", "json", "markdown", "text"])
    def test_the_counts_mean_the_same_for_every_format(self, runner: Runner, fmt: str) -> None:
        proc = runner.run(path=str(K8S_EXAMPLE), format=fmt)
        assert proc.returncode == 0, proc.stderr
        out = runner.outputs()
        reference = Runner(runner.output_file.parent / "reference")
        reference.run(path=str(K8S_EXAMPLE), format="json")
        expected = reference.outputs()
        assert out["threat-count"] == expected["threat-count"]
        assert out["path-count"] == expected["path-count"]
        assert int(out["threat-count"]) > 0
        assert (runner.workspace / out["report-file"]).stat().st_size > 0

    def test_findings_at_the_gate_do_not_fail_the_scan_step_but_set_exit_code_one(
        self, runner: Runner
    ) -> None:
        proc = runner.run(path=str(K8S_EXAMPLE), format="sarif", fail_on="high")
        # The step succeeds so the SARIF upload that follows it runs; the last step fails the job.
        assert proc.returncode == 0, proc.stderr
        out = runner.outputs()
        assert out["exit-code"] == "1"
        assert (runner.workspace / out["sarif-file"]).is_file()
        assert int(out["threat-count"]) > 0

    def test_fail_on_none_never_trips_on_findings(self, runner: Runner) -> None:
        proc = runner.run(path=str(K8S_EXAMPLE), format="json", fail_on="none")
        assert proc.returncode == 0
        assert runner.outputs()["exit-code"] == "0"

    def test_a_clean_threshold_leaves_exit_code_zero(self, runner: Runner) -> None:
        # The aws-webapp example carries a critical attack path, so it is not a clean input at any
        # threshold. A lone SNS topic has no finding and no path.
        clean = runner.workspace / "clean"
        clean.mkdir()
        (clean / "main.tf").write_text('resource "aws_sns_topic" "t" {\n  name = "t"\n}\n')
        proc = runner.run(path=str(clean), format="json", fail_on="high")
        assert proc.returncode == 0, proc.stderr
        assert runner.outputs()["exit-code"] == "0"

    def test_a_critical_attack_path_trips_a_critical_threshold(self, runner: Runner) -> None:
        proc = runner.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="json", fail_on="critical")
        assert proc.returncode == 0, proc.stderr
        assert runner.outputs()["exit-code"] == "1"

    def test_an_error_fails_the_step_at_once_with_the_message(self, runner: Runner) -> None:
        proc = runner.run(path=str(runner.workspace / "does-not-exist"), format="sarif")
        assert proc.returncode == 2
        out = runner.outputs()
        assert out["exit-code"] == "2"
        assert "report-file" not in out and "threat-count" not in out
        assert "::error title=ThreatCode failed (exit 2)::" in proc.stdout
        assert "path not found" in proc.stdout
        assert not (runner.workspace / "threatcode-results.sarif").exists()

    def test_a_scan_that_finds_nothing_to_model_is_an_error_not_a_clean_pass(
        self, runner: Runner
    ) -> None:
        empty = runner.workspace / "empty"
        empty.mkdir()
        proc = runner.run(path=str(empty), format="sarif")
        assert proc.returncode == 2
        assert runner.outputs()["exit-code"] == "2"

    def test_an_invalid_threshold_is_an_error(self, runner: Runner) -> None:
        proc = runner.run(path=str(K8S_EXAMPLE), format="json", fail_on="catastrophic")
        assert proc.returncode == 2
        assert runner.outputs()["exit-code"] == "2"

    def test_an_empty_path_is_an_error(self, runner: Runner) -> None:
        proc = runner.run(path="", format="json")
        assert proc.returncode == 2
        assert "path input is empty" in proc.stdout

    def test_the_old_input_name_still_works(self, runner: Runner) -> None:
        proc = runner.run(input_file=str(AWS_EXAMPLE / "tfplan.json"), format="json")
        assert proc.returncode == 0, proc.stderr
        assert int(runner.outputs()["threat-count"]) > 0

    def test_a_path_with_spaces_reaches_the_cli_as_one_argument(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        target = tmp_path / "my infra dir" / "plan files"
        shutil.copytree(AWS_EXAMPLE, target)
        proc = runner.run(path=str(target / "tfplan.json"), format="json")
        assert proc.returncode == 0, proc.stderr
        assert int(runner.outputs()["threat-count"]) > 0

        directory = Runner(tmp_path / "second")
        proc = directory.run(path=str(target), format="json")
        assert proc.returncode == 0, proc.stderr

    def test_several_paths_on_separate_lines_are_scanned_together(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        plan = AWS_EXAMPLE / "tfplan.json"
        manifest = FIXTURES / "kubernetes" / "insecure_deployment.yml"
        proc = runner.run(path=f"{plan}\n\n{manifest}\r\n", format="json")
        assert proc.returncode == 0, proc.stderr
        report = json.loads((runner.workspace / "threatcode-results.json").read_text())
        assert report["coverage"]["units_parsed"] == 2

    def test_an_extra_rule_file_with_spaces_in_its_path_is_loaded(
        self, runner: Runner, tmp_path: Path
    ) -> None:
        rules = tmp_path / "my rules" / "custom rules.yml"
        rules.parent.mkdir()
        rules.write_text(
            "rules:\n"
            "  - id: ACTION_TEST_BUCKET\n"
            "    title: Action test bucket\n"
            "    description: A rule that only the action test loads.\n"
            "    stride_category: information_disclosure\n"
            "    severity: low\n"
            "    confidence: definitive\n"
            "    resource_type: aws_s3_bucket\n"
            "    condition:\n"
            "      not:\n"
            "        derived.sse_algorithm:\n"
            '          matches_any: ["never-a-real-algorithm"]\n'
            "    mitigation: None needed.\n",
            encoding="utf-8",
        )
        proc = runner.run(
            path=str(AWS_EXAMPLE / "tfplan.json"), format="json", extra_rules=str(rules)
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        report = json.loads((runner.workspace / "threatcode-results.json").read_text())
        assert "ACTION_TEST_BUCKET" in {t.get("rule_id") for t in report["threats"]}

    def test_min_severity_changes_the_report_and_the_counts_together(self, runner: Runner) -> None:
        everything = Runner(runner.output_file.parent / "all")
        everything.run(path=str(K8S_EXAMPLE), format="markdown")
        proc = runner.run(path=str(K8S_EXAMPLE), format="markdown", min_severity="high")
        assert proc.returncode == 0, proc.stderr
        assert int(runner.outputs()["threat-count"]) < int(everything.outputs()["threat-count"])

    def test_a_baseline_that_is_not_there_is_an_error(self, runner: Runner) -> None:
        proc = runner.run(
            path=str(K8S_EXAMPLE), format="json", baseline=str(runner.workspace / "missing.json")
        )
        assert proc.returncode == 2

    def test_stderr_is_shown_between_stop_commands(self, runner: Runner) -> None:
        proc = runner.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="json")
        assert proc.returncode == 0
        lines = proc.stdout.splitlines()
        starts = [i for i, ln in enumerate(lines) if ln.startswith("::stop-commands::")]
        assert starts, proc.stdout
        token = lines[starts[0]].split("::")[-1]
        assert len(token) == 32
        assert f"::{token}::" in lines[starts[0] + 1 :]
        assert "Scanned" in proc.stderr

    def test_no_comment_body_is_written_unless_asked(self, runner: Runner) -> None:
        proc = runner.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="json")
        assert proc.returncode == 0
        assert "comment-file" not in runner.outputs()

        asked = Runner(runner.output_file.parent / "asked")
        proc = asked.run(path=str(AWS_EXAMPLE / "tfplan.json"), format="json", comment="true")
        assert proc.returncode == 0
        assert "comment-file" not in asked.outputs(), "only a pull_request event renders a body"

    def test_the_comment_body_starts_with_the_marker_and_holds_the_markdown(
        self, runner: Runner
    ) -> None:
        proc = runner.run(
            path=str(K8S_EXAMPLE), format="sarif", comment="true", event_name="pull_request"
        )
        assert proc.returncode == 0, proc.stderr
        body_file = Path(runner.outputs()["comment-file"])
        body = body_file.read_text(encoding="utf-8")
        assert body.startswith(COMMENT_MARKER + "\n\n")
        assert "# ThreatCode Threat Model Report" in body
        assert len(body) <= 60000

    def test_a_long_report_is_cut_below_githubs_limit_with_a_note(self, runner: Runner) -> None:
        many = runner.workspace / "many"
        many.mkdir()
        resources = "\n".join(
            f'resource "aws_s3_bucket" "b{i}" {{\n  bucket = "b-{i}"\n  acl = "public-read"\n}}\n'
            for i in range(400)
        )
        (many / "main.tf").write_text(resources, encoding="utf-8")
        proc = runner.run(
            path=str(many), format="markdown", comment="true", event_name="pull_request"
        )
        assert proc.returncode == 0, proc.stdout + proc.stderr
        body = Path(runner.outputs()["comment-file"]).read_text(encoding="utf-8")
        assert len(body) <= 60000
        assert body.startswith(COMMENT_MARKER)
        # The Markdown formatter caps itself at 60,000 characters and says what it left out, so
        # the report file is already within GitHub's limit.
        report = (runner.workspace / "threatcode-results.md").read_text(encoding="utf-8")
        assert len(report) <= 60000
        assert "more threats omitted" in report
        assert "more threats omitted" in body

    def test_the_comment_backstop_cuts_a_body_the_formatter_left_too_long(
        self, tmp_path: Path
    ) -> None:
        pattern = (
            r"python3 - \"\$markdown_file\" \"\$scratch/threatcode-comment.md\""
            r" <<'PY'\n(.*?)\n\s*PY\n"
        )
        match = re.search(pattern, scan_script(), re.S)
        assert match, "the comment backstop heredoc moved"
        code = textwrap.dedent(match.group(1))
        source = tmp_path / "in.md"
        source.write_text("x" * 70000, encoding="utf-8")
        out = tmp_path / "out.md"
        subprocess.run([sys.executable, "-c", code, str(source), str(out)], check=True)
        body = out.read_text(encoding="utf-8")
        assert len(body) <= 60000
        assert body.startswith(COMMENT_MARKER + "\n\n")
        assert body.endswith("The full report is the report-file output of the action step._\n")


@runs_bash
class TestTheGateStep:
    def test_the_gate_step_fails_with_a_message_naming_the_threshold(self, tmp_path: Path) -> None:
        script = step_named("Enforce the gate")["run"]
        assert BASH is not None
        proc = subprocess.run(
            [BASH, "-c", script],
            env={
                "PATH": os.environ["PATH"],
                "TC_FAIL_ON": "high",
                "TC_THREATS": "5",
                "TC_PATHS": "2",
            },
            capture_output=True,
            text=True,
        )
        assert proc.returncode == 1
        assert "'high'" in proc.stdout and "5 findings and 2 attack paths" in proc.stdout


class TestShellScriptsAreClean:
    @pytest.mark.skipif(shutil.which("shellcheck") is None, reason="shellcheck is not installed")
    def test_every_script_passes_shellcheck(self, tmp_path: Path) -> None:
        for index, (name, script) in enumerate(run_scripts()):
            path = tmp_path / f"step{index}.sh"
            path.write_text("#!/usr/bin/env bash\n" + script, encoding="utf-8")
            proc = subprocess.run(
                ["shellcheck", "-s", "bash", str(path)], capture_output=True, text=True
            )
            assert proc.returncode == 0, f"{name}\n{proc.stdout}"
