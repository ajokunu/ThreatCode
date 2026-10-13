"""Final quality gates: invariants of the repository that no single feature test can see.

Each gate fails with the list of offenders, and each has a self-test that feeds it a bad
example, so a gate that quietly stopped looking is itself a failure.

* No test carries a ``pending`` marker (the markers are for work that has not landed; the
  release is the point where there is no such work).
* Every ``tests/test_rules/uncovered/*.txt`` is empty and there is exactly one per rule file.
* No builtin rule maps to an ATT&CK technique that is missing, revoked or deprecated.
* Every resource type a builtin rule names has an explicit catalog category.
* No test function is assertion-free unless it is on the reviewed does-not-raise list.
* No test accepts a range of exit codes (``exit_code in (0, 1)``).
* ``pyproject.toml`` keeps the widened ruff selection for ``src``.
* The version in ``threatcode.__version__`` fits ``CHANGELOG.md``: not a released number while
  Unreleased has content, the newest released number once it is cut.
* No test opens a fixture through a path that depends on the working directory.
* No function, method or class in ``src`` is unreferenced, except the reviewed list.
"""

from __future__ import annotations

import ast
import json
import os
import re
import subprocess
import sys
import tempfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest

from tests.helpers.pending_report import REPORT_ENV
from tests.test_rules.harness import load_rules_by_group, read_uncovered
from threatcode.engine.mitre import (
    PATH_TECHNIQUES,
    TACTIC_DB,
    TECHNIQUE_DB,
    is_deprecated,
    is_revoked,
    normalize_technique,
)
from threatcode.engine.rules.loader import load_builtin_rules
from threatcode.ir.catalog import categorize_resource
from threatcode.ir.nodes import NodeCategory

REPO_ROOT = Path(__file__).resolve().parents[1]
TESTS_DIR = REPO_ROOT / "tests"
UNCOVERED_DIR = TESTS_DIR / "test_rules" / "uncovered"


# ---------------------------------------------------------------------------------------
# No pending markers
# ---------------------------------------------------------------------------------------


def pending_markers_in_suite() -> list[dict[str, str]]:
    """Collect the whole suite in a child process and return every pending marker it finds.

    A child process, because the markers must be read from a collection of every test file,
    not only from the files this session was asked to run.
    """
    with tempfile.TemporaryDirectory(prefix="threatcode-pending-") as directory:
        report = Path(directory) / "pending.json"
        done = subprocess.run(
            [
                sys.executable,
                "-m",
                "pytest",
                "--collect-only",
                "-q",
                "-p",
                "no:cacheprovider",
                "-p",
                "tests.helpers.pending_report",
                str(TESTS_DIR),
            ],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(REPO_ROOT),
            env={**os.environ, REPORT_ENV: str(report)},
        )
        if done.returncode != 0 or not report.is_file():
            raise AssertionError(
                f"collecting the suite failed (exit {done.returncode}):\n"
                f"{done.stdout[-1500:]}\n{done.stderr[-1500:]}"
            )
        found: list[dict[str, str]] = json.loads(report.read_text(encoding="utf-8"))
        return found


def test_no_test_carries_a_pending_marker() -> None:
    found = pending_markers_in_suite()
    lines = [f"{m['test']}  [{m['package']}] {m['reason']}" for m in found]
    assert not found, (
        f"{len(found)} test(s) still carry a pending marker. A marker names work that has not "
        "landed: deliver it and delete the marker (the test, or the pending block of its data "
        "file), or delete the test.\n  " + "\n  ".join(lines)
    )


def test_the_pending_gate_sees_a_marker(
    pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Collection finds a marker that is built from data, which a text search could not."""
    pytester.makeconftest('pytest_plugins = ["tests.helpers.pending"]')
    pytester.makepyfile(
        test_sample="""
        import pytest
        from tests.helpers.pending import pending

        ROWS = [pytest.param(1, marks=pending("WP-2-1", "references land"))]

        @pytest.mark.parametrize("n", ROWS)
        def test_row(n):
            assert n
        """
    )
    report = pytester.path / "report.json"
    monkeypatch.setenv(REPORT_ENV, str(report))
    monkeypatch.setenv("PYTHONPATH", os.pathsep.join([str(REPO_ROOT), str(REPO_ROOT / "src")]))
    result = pytester.runpytest_subprocess(
        "--collect-only", "-q", "-p", "tests.helpers.pending_report"
    )
    assert result.ret == 0, result.stdout.str() + result.stderr.str()
    found = json.loads(report.read_text(encoding="utf-8"))
    assert [(m["package"], m["reason"]) for m in found] == [("WP-2-1", "references land")]


# ---------------------------------------------------------------------------------------
# Rule example coverage
# ---------------------------------------------------------------------------------------


def test_every_uncovered_list_is_empty() -> None:
    nonempty = {group: ids for group, ids in read_uncovered(UNCOVERED_DIR).items() if ids}
    assert not nonempty, (
        "these rules have no example case (a failing and a passing snippet in the rule's group "
        "under tests/test_rules/cases):\n  "
        + "\n  ".join(f"{group}: {', '.join(ids)}" for group, ids in sorted(nonempty.items()))
    )


def test_there_is_one_uncovered_list_per_rule_file() -> None:
    lists = {path.stem for path in UNCOVERED_DIR.glob("*.txt")}
    groups = set(load_rules_by_group())
    assert lists == groups, (
        f"rule files without a list: {sorted(groups - lists)}; "
        f"lists without a rule file: {sorted(lists - groups)}"
    )


# ---------------------------------------------------------------------------------------
# ATT&CK mapping
# ---------------------------------------------------------------------------------------


def technique_problems(technique_id: str) -> list[str]:
    """Why an ATT&CK technique id should not be in a rule or a path step, if it should not."""
    if technique_id not in TECHNIQUE_DB:
        return ["is not in the ATT&CK tables"]
    problems = []
    if is_revoked(technique_id):
        problems.append(f"is revoked (use {normalize_technique(technique_id)})")
    if is_deprecated(technique_id):
        problems.append("is deprecated")
    return problems


def test_no_builtin_rule_uses_a_missing_revoked_or_deprecated_technique() -> None:
    offenders: list[str] = []
    for rule in load_builtin_rules():
        mitre = rule.metadata.get("mitre", {})
        for technique_id in mitre.get("techniques", []):
            offenders += [
                f"{rule.id}: {technique_id} {p}" for p in technique_problems(technique_id)
            ]
        for tactic_id in mitre.get("tactics", []):
            if tactic_id not in TACTIC_DB:
                offenders.append(f"{rule.id}: tactic {tactic_id} is not in the ATT&CK tables")
    assert not offenders, "\n  ".join(["builtin rules with a stale ATT&CK id:", *offenders])


def test_no_attack_path_step_uses_a_missing_revoked_or_deprecated_technique() -> None:
    offenders = [
        f"{kind}: {technique_id} {problem}"
        for kind, technique_id in PATH_TECHNIQUES.items()
        for problem in technique_problems(technique_id)
    ]
    assert not offenders, "\n  ".join(["attack path steps with a stale ATT&CK id:", *offenders])


def test_the_technique_gate_flags_a_revoked_and_an_unknown_id() -> None:
    revoked = next(t for t in TECHNIQUE_DB if is_revoked(t))
    assert any("revoked" in p for p in technique_problems(revoked))
    assert technique_problems("T9999.999") == ["is not in the ATT&CK tables"]
    current = next(t for t in TECHNIQUE_DB if not is_revoked(t) and not is_deprecated(t))
    assert technique_problems(current) == []


# ---------------------------------------------------------------------------------------
# Catalog categories
# ---------------------------------------------------------------------------------------


def test_every_resource_type_a_rule_names_has_a_catalog_category() -> None:
    unknown: dict[str, list[str]] = {}
    for rule in load_builtin_rules():
        for resource_type in rule.resource_types:
            # A trailing '*' is a prefix glob: the prefix itself has to be classified
            if categorize_resource(resource_type.rstrip("*")) is NodeCategory.UNKNOWN:
                unknown.setdefault(resource_type, []).append(rule.id)
    assert not unknown, (
        "resource types read by a rule but missing from threatcode/ir/catalog (the node would "
        "be UNKNOWN and land in the wrong zone):\n  "
        + "\n  ".join(f"{t}: {', '.join(ids)}" for t, ids in sorted(unknown.items()))
    )


def test_the_catalog_gate_sees_an_unclassified_type() -> None:
    assert categorize_resource("aws_s3_bucket") is not NodeCategory.UNKNOWN
    assert categorize_resource("aws_not_a_real_resource_type") is NodeCategory.UNKNOWN


# ---------------------------------------------------------------------------------------
# Assertion-free tests
# ---------------------------------------------------------------------------------------

_ASSERT_METHODS = ("fail", "raises", "warns", "deprecated_call", "assertRaises", "assertWarns")


def _called_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute):
        return func.attr
    return func.id if isinstance(func, ast.Name) else ""


def _raises_assertion_error(node: ast.Raise) -> bool:
    exc = node.exc
    if isinstance(exc, ast.Call):
        exc = exc.func
    return isinstance(exc, ast.Name) and exc.id == "AssertionError"


def has_a_check(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Whether a test function can fail on a wrong answer.

    An ``assert``; ``pytest.raises``, ``pytest.warns`` or ``pytest.fail``; a call of an
    ``assert*`` method (unittest and mock style); or a ``raise AssertionError`` in the function
    or a stub it defines.
    """
    for node in ast.walk(function):
        if isinstance(node, ast.Assert):
            return True
        if isinstance(node, ast.Raise) and _raises_assertion_error(node):
            return True
        if isinstance(node, ast.Call):
            name = _called_name(node)
            if name in _ASSERT_METHODS or name.startswith("assert"):
                return True
    return False


def _is_fixture(function: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for decorator in function.decorator_list:
        target = decorator.func if isinstance(decorator, ast.Call) else decorator
        name = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", "")
        if name == "fixture":
            return True
    return False


def collected_test_functions(
    tree: ast.Module,
) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
    """The functions pytest would collect: module level ``test*`` and ``Test*`` class methods."""

    def in_class(cls: ast.ClassDef) -> Iterator[ast.FunctionDef | ast.AsyncFunctionDef]:
        for item in cls.body:
            if isinstance(item, ast.ClassDef) and item.name.startswith("Test"):
                yield from in_class(item)
            elif (
                isinstance(item, ast.FunctionDef | ast.AsyncFunctionDef)
                and item.name.startswith("test")
                and not _is_fixture(item)
            ):
                yield item

    for node in tree.body:
        if isinstance(node, ast.ClassDef) and node.name.startswith("Test"):
            yield from in_class(node)
        elif (
            isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
            and node.name.startswith("test")
            and not _is_fixture(node)
        ):
            yield node


def assertion_free_tests(source: str) -> list[str]:
    """Names (``Class.name`` for methods) of the collected tests in ``source`` without a check."""
    tree = ast.parse(source)
    owners: dict[int, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef):
            for item in node.body:
                owners[id(item)] = node.name
    return [
        f"{owners[id(f)]}.{f.name}" if id(f) in owners else f.name
        for f in collected_test_functions(tree)
        if not has_a_check(f)
    ]


# Tests that are correct without an assertion of their own. Each one either states a
# does-not-raise contract (the call under test raises, and a raise fails the test) or hands the
# check to a helper that raises. A new entry needs a reason; an entry that no longer matches an
# assertion-free test is an error, so the list only shrinks.
DOES_NOT_RAISE = "the call under test raises when the contract is broken; success is the result"
HELPER_RAISES = "the check lives in a helper that raises"
NO_THROW_PROPERTY = "a property test whose contract is that the code never raises"
JSON_ROUND_TRIP = "json.dumps raises on anything that does not serialize; that is the contract"

ASSERTION_FREE_ALLOWED: dict[tuple[str, str], str] = {
    (
        "tests/test_diagnostics.py",
        "TestRegistry.test_register_code_is_idempotent_for_the_same_description",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrl.test_valid_https_url",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrl.test_allows_172_outside_private",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_http_localhost",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_http_127_0_0_1",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_http_ipv6_loopback",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_https_loopback",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_private_and_shared_addresses",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_hostname_on_private_network",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_llm_client.py",
        "TestValidateBaseUrlLocalNetwork.test_allows_https_public_address",
    ): DOES_NOT_RAISE,
    (
        "tests/test_engine/test_mitre.py",
        "TestBuiltinRuleTechniques.test_revoked_rule_techniques_are_reported_not_failed",
    ): "reports through warnings.warn by design; the hard gate is tests/test_meta.py",
    (
        "tests/test_engine/test_rule_loader.py",
        "TestConditionValidation.test_valid_arguments_pass",
    ): HELPER_RAISES,
    (
        "tests/test_engine/test_rule_loader.py",
        "TestConditionValidation.test_a_property_named_like_a_logical_operator_with_a_normal_check_is_fine",
    ): HELPER_RAISES,
    (
        "tests/test_engine/test_rule_loader.py",
        "TestConditionValidation.test_valid_property_paths",
    ): HELPER_RAISES,
    (
        "tests/test_engine/test_rule_loader.py",
        "TestConditionValidation.test_port_overlaps_is_a_key_that_takes_a_port_list",
    ): HELPER_RAISES,
    (
        "tests/test_engine/test_rule_loader.py",
        "TestDocumentationExamples.test_every_condition_example_validates",
    ): DOES_NOT_RAISE,
    (
        "tests/test_formatters/test_schema_conformance.py",
        "TestVendoredSchemas.test_the_navigator_schema_is_valid_draft_7",
    ): "jsonschema's check_schema raises on an invalid schema",
    (
        "tests/test_ingest/test_threats.py",
        "TestShape.test_every_threat_serializes",
    ): JSON_ROUND_TRIP,
    (
        "tests/test_parsers/test_cfn_properties.py",
        "TestBounds.test_values_below_the_depth_cap_are_unknown",
    ): JSON_ROUND_TRIP,
    (
        "tests/test_parsers/test_hcl_eval.py",
        "TestProperties.test_arbitrary_text_never_raises",
    ): NO_THROW_PROPERTY,
    (
        "tests/test_parsers/test_json_lines.py",
        "TestIndex.test_every_pointer_resolves_in_the_parsed_document",
    ): "indexing the document with a wrong pointer raises KeyError or IndexError",
    (
        "tests/test_parsers/test_parser_registry.py",
        "TestCloudFormationDetection.test_short_form_output_is_json_serializable",
    ): JSON_ROUND_TRIP,
    (
        "tests/test_parsers/test_terraform_plan.py",
        "TestHostileModules.test_malformed_sections_never_crash_the_parser",
    ): NO_THROW_PROPERTY,
    (
        "tests/test_quality/test_expected.py",
        "TestExpectationFiles.test_named_resources_exist_in_the_graph",
    ): "require_resources raises when a named resource is missing",
}


def test_every_test_function_checks_something() -> None:
    offenders: list[str] = []
    seen: set[tuple[str, str]] = set()
    for path in sorted(TESTS_DIR.rglob("test_*.py")):
        relative = path.relative_to(REPO_ROOT).as_posix()
        for name in assertion_free_tests(path.read_text(encoding="utf-8")):
            key = (relative, name)
            seen.add(key)
            if key not in ASSERTION_FREE_ALLOWED:
                offenders.append(f"{relative}::{name}")
    assert not offenders, (
        "test functions with no assert, pytest.raises, pytest.warns or pytest.fail. Assert on "
        "the returned value; a test that only calls the code passes when the code is wrong:\n  "
        + "\n  ".join(offenders)
    )
    stale = sorted(set(ASSERTION_FREE_ALLOWED) - seen)
    assert not stale, (
        "ASSERTION_FREE_ALLOWED lists tests that now assert or no longer exist; "
        "delete the entries:\n  " + "\n  ".join(f"{p}::{n}" for p, n in stale)
    )


def test_every_assertion_free_entry_has_a_reason() -> None:
    assert all(reason.strip() for reason in ASSERTION_FREE_ALLOWED.values())


def test_the_scanner_flags_a_test_that_only_calls_the_code() -> None:
    source = """
import pytest

def test_calls_only():
    run()

def test_asserts():
    assert run() == 1

class TestGroup:
    def test_method_calls_only(self):
        run()

    def test_method_raises(self):
        with pytest.raises(ValueError):
            run()

    def test_mock_style(self, mock):
        mock.assert_called_once()

    def helper_not_collected(self):
        run()

@pytest.fixture
def test_looking_fixture():
    return 1

def test_stub_guard(monkeypatch):
    def boom():
        raise AssertionError("must not run")
    monkeypatch.setattr("x.y", boom)
    run()
"""
    assert assertion_free_tests(source) == ["test_calls_only", "TestGroup.test_method_calls_only"]


# ---------------------------------------------------------------------------------------
# Exit codes are exact
# ---------------------------------------------------------------------------------------

_RANGE_OF_EXIT_CODES = re.compile(
    r"(?:exit_code|returncode)\s*(?:not\s+in|in|!=|>=|<=|>|<)\s*[\(\[\{\d]"
)


def test_no_test_accepts_a_range_of_exit_codes() -> None:
    offenders: list[str] = []
    for path in sorted(TESTS_DIR.rglob("*.py")):
        if path == Path(__file__).resolve():
            continue
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
            if _RANGE_OF_EXIT_CODES.search(line):
                offenders.append(
                    f"{path.relative_to(REPO_ROOT).as_posix()}:{number}: {line.strip()}"
                )
    assert not offenders, (
        "pin the exit code (0 clean, 1 findings, 2 usage or input error) instead of accepting "
        "a range, which passes for the wrong reason:\n  " + "\n  ".join(offenders)
    )


@pytest.mark.parametrize(
    "line",
    [
        "assert result.exit_code in (0, 1)",
        "assert result.exit_code not in [2]",
        "assert run.exit_code != 0",
        "assert proc.returncode >= 1",
    ],
)
def test_the_exit_code_gate_flags_a_range(line: str) -> None:
    assert _RANGE_OF_EXIT_CODES.search(line)


@pytest.mark.parametrize(
    "line", ["assert result.exit_code == 1", "assert run.exit_code is not None", "exit_code = 2"]
)
def test_the_exit_code_gate_accepts_an_exact_code(line: str) -> None:
    assert not _RANGE_OF_EXIT_CODES.search(line)


# ---------------------------------------------------------------------------------------
# Lint configuration
# ---------------------------------------------------------------------------------------

REQUIRED_SRC_RULES = {"E", "F", "I", "N", "W", "UP", "B", "BLE", "S", "ARG", "SIM", "C4", "C901"}


def _pyproject() -> dict[str, Any]:
    try:
        import tomllib
    except ModuleNotFoundError:  # Python 3.10
        import tomli as tomllib
    with (REPO_ROOT / "pyproject.toml").open("rb") as handle:
        data: dict[str, Any] = tomllib.load(handle)
    return data


def test_ruff_keeps_the_widened_selection_for_src() -> None:
    ruff = _pyproject()["tool"]["ruff"]
    lint = ruff["lint"]
    assert REQUIRED_SRC_RULES <= set(lint["select"]), sorted(
        REQUIRED_SRC_RULES - set(lint["select"])
    )
    assert lint["mccabe"]["max-complexity"] <= 15


def test_ruff_exempts_only_tests_and_scripts_from_the_widened_rules() -> None:
    ignores = _pyproject()["tool"]["ruff"]["lint"]["per-file-ignores"]
    widened = REQUIRED_SRC_RULES - {"E", "F", "I", "N", "W", "UP"}
    for pattern, codes in ignores.items():
        if pattern.startswith(("tests", "scripts")):
            continue
        assert pattern.startswith("src/threatcode/"), pattern
        assert set(codes) <= {"ARG001", "ARG002"}, (
            f"{pattern} ignores {codes}; only unused-argument rules may be ignored per file "
            "(the dispatch tables), anything else needs a noqa with a reason on the line"
        )
        assert not set(codes) & (widened - {"ARG"}), pattern


# ---------------------------------------------------------------------------------------
# Packaging and the commands that check it
# ---------------------------------------------------------------------------------------


def _requirement_names(requirements: list[str]) -> dict[str, str]:
    """Map each requirement's package name to the whole requirement line."""
    return {re.split(r"[<>=!~;\s\[]", line, maxsplit=1)[0].lower(): line for line in requirements}


def test_tomli_is_a_development_dependency_only() -> None:
    """src never reads TOML, so the runtime install must not pull a TOML parser in."""
    project = _pyproject()["project"]
    runtime = _requirement_names(project["dependencies"])
    dev = _requirement_names(project["optional-dependencies"]["dev"])
    assert "tomli" not in runtime, runtime["tomli"]
    assert "tomli" in dev and "python_version<'3.11'" in dev["tomli"].replace(" ", "")
    in_src = [
        path.relative_to(REPO_ROOT).as_posix()
        for path in (REPO_ROOT / "src").rglob("*.py")
        if re.search(r"^\s*(?:import|from) (?:tomli|tomllib)\b", path.read_text("utf-8"), re.M)
    ]
    assert not in_src, f"src reads TOML after all, so tomli is a runtime dependency: {in_src}"


def test_hcl_stays_supported_from_the_oldest_release_to_the_newest_major() -> None:
    requirements = _requirement_names(_pyproject()["project"]["dependencies"])
    assert requirements["python-hcl2"].replace(" ", "") == "python-hcl2>=4.3,<9"


def _make_target(makefile: str, name: str) -> str:
    """The recipe lines of the make target ``name``."""
    match = re.search(rf"^{re.escape(name)}:.*\n((?:\t.*\n?)*)", makefile, re.MULTILINE)
    assert match, f"the Makefile has no {name} target"
    return match.group(1)


def test_lint_runs_over_the_whole_repository_in_make_and_in_ci() -> None:
    """``scripts/`` has its own lint configuration, so a gate over src and tests skips it."""
    wanted = ("ruff check .", "ruff format --check .")
    recipe = _make_target((REPO_ROOT / "Makefile").read_text("utf-8"), "lint")
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    for command in wanted:
        assert re.search(rf"^\s*{re.escape(command)}\s*$", recipe, re.M), command
        assert re.search(rf"^\s*- run: {re.escape(command)}\s*$", ci, re.M), command
    for text in (recipe, ci):
        assert not re.search(r"ruff (?:check|format --check) src", text), text


def test_the_format_target_covers_what_lint_checks() -> None:
    recipe = _make_target((REPO_ROOT / "Makefile").read_text("utf-8"), "format")
    assert "ruff format ." in recipe and "ruff check --fix ." in recipe


def test_make_clean_removes_the_egg_info_under_src() -> None:
    """``*.egg-info`` in the recipe only matches the top level, where a src layout has none."""
    recipe = _make_target((REPO_ROOT / "Makefile").read_text("utf-8"), "clean")
    assert "src/*.egg-info" in recipe


def _manifest_files(manifest: str, root: Path) -> set[str]:
    """The files under ``root`` that the MANIFEST.in directives select, as POSIX paths.

    It reads the few directives this project uses (``include``, ``recursive-include``,
    ``global-exclude``) with the matching rules of ``fnmatch``, which is what setuptools applies.
    """
    import fnmatch

    every = [
        p.relative_to(root).as_posix()
        for top in sorted(root.iterdir())
        if top.name not in {".git", ".venv", "build", "dist", "node_modules", ".mypy_cache"}
        for p in ([top] if top.is_file() else top.rglob("*"))
        if p.is_file() and top.name != "src"
    ]
    chosen: set[str] = set()
    excluded: list[str] = []
    for raw in manifest.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        directive, *args = line.split()
        if directive == "include":
            chosen.update(a for a in args if a in every)
        elif directive == "recursive-include":
            directory, *patterns = args
            for path in every:
                if path.startswith(directory + "/") and any(
                    fnmatch.fnmatch(path.rsplit("/", 1)[-1], pattern) for pattern in patterns
                ):
                    chosen.add(path)
        elif directive == "global-exclude":
            excluded.extend(args)
        else:
            raise AssertionError(f"MANIFEST.in uses {directive!r}, which this gate does not read")
    return {
        path
        for path in chosen
        if not any(
            fnmatch.fnmatch(part, pattern) for pattern in excluded for part in path.split("/")
        )
    }


SDIST_MUST_CONTAIN = (
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "CONTRIBUTING.md",
    "tests/conftest.py",
    "tests/helpers/cli.py",
    "tests/fixtures/terraform/simple.tf",
    "docs/index.md",
    "examples/aws-webapp/tfplan.json",
    "scripts/gen_docs_counts.py",
    ".github/actions/threatcode/action.yml",
)


def test_the_source_distribution_carries_what_its_tests_read() -> None:
    """Tests that ship without their fixtures, docs and examples cannot run, so ship it all."""
    files = _manifest_files((REPO_ROOT / "MANIFEST.in").read_text("utf-8"), REPO_ROOT)
    missing = [name for name in SDIST_MUST_CONTAIN if name not in files]
    assert not missing, f"MANIFEST.in leaves these out of the sdist: {missing}"
    assert not [f for f in files if "__pycache__" in f or f.endswith((".pyc", ".pyo"))]
    fixtures = [f for f in files if f.startswith("tests/fixtures/")]
    assert len(fixtures) > 100, "the fixtures the tests read are in the sdist"


def test_the_manifest_gate_notices_a_missing_directory_and_a_compiled_file(
    tmp_path: Path,
) -> None:
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "a.py").write_text("x", encoding="utf-8")
    (tmp_path / "tests" / "a.pyc").write_text("x", encoding="utf-8")
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "i.md").write_text("x", encoding="utf-8")
    (tmp_path / "README.md").write_text("x", encoding="utf-8")
    only_docs = _manifest_files("recursive-include docs *\ninclude README.md\n", tmp_path)
    assert only_docs == {"docs/i.md", "README.md"}
    with_tests = _manifest_files("recursive-include tests *\nglobal-exclude *.pyc\n", tmp_path)
    assert with_tests == {"tests/a.py"}
    with pytest.raises(AssertionError, match="prune"):
        _manifest_files("prune tests\n", tmp_path)


def test_the_package_job_checks_the_source_distribution() -> None:
    ci = (REPO_ROOT / ".github" / "workflows" / "ci.yml").read_text("utf-8")
    package = ci[ci.index("\n  package:") :]
    assert "tar tzf" in package and "tests/conftest.py" in package


def test_the_dockerfile_tests_pass_from_another_working_directory(tmp_path: Path) -> None:
    """Fixtures are found from the test file, so the directory pytest starts in does not matter."""
    target = TESTS_DIR / "test_parsers" / "test_dockerfile.py"
    done = subprocess.run(
        [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", str(target)],
        cwd=tmp_path,
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert done.returncode == 0, done.stdout[-600:] + done.stderr[-300:]


# ---------------------------------------------------------------------------------------
# The version names this release
# ---------------------------------------------------------------------------------------


def released_versions(changelog: str) -> list[str]:
    """The versions ``changelog`` has a dated section for, newest first."""
    return re.findall(r"^## \[(\d+\.\d+\.\d+)\] - \d{4}-\d{2}-\d{2}$", changelog, re.MULTILINE)


def unreleased_section(changelog: str) -> str:
    """The text under ``## [Unreleased]``, up to the next version heading."""
    start = changelog.index("## [Unreleased]") + len("## [Unreleased]")
    end = changelog.find("\n## [", start)
    return changelog[start : end if end >= 0 else len(changelog)]


def version_problem(version: str, changelog: str) -> str:
    """Why ``version`` does not fit ``changelog``, or the empty string when it does.

    While the Unreleased section holds anything, the code is a line that is not out yet, so it must
    not carry a number that was released.
    When the section is empty, the release commit has moved it under a dated heading, and the
    version must be that heading's number.
    """
    released = released_versions(changelog)
    pending = re.search(r"^(?:### |- )", unreleased_section(changelog), re.MULTILINE)
    if pending:
        if version in released:
            return (
                f"__version__ {version} is already released but the changelog has unreleased "
                "changes; set the version of the line that the Unreleased section becomes"
            )
        return ""
    if not released or version != released[0]:
        return (
            f"the Unreleased section is empty, so __version__ {version} must be the newest "
            f"released version {released[0] if released else '(none)'}"
        )
    return ""


def test_the_version_names_this_release() -> None:
    """Otherwise ``threatcode --version`` and a report's ``version`` cannot tell this line from
    the release that is on PyPI, or from the one that is being cut."""
    from threatcode import __version__

    changelog = (REPO_ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "## [Unreleased]" in changelog
    assert version_problem(__version__, changelog) == ""


def test_the_version_gate_accepts_the_release_commit_and_refuses_a_stale_number() -> None:
    pending = "# Changelog\n\n## [Unreleased]\n\n### Added\n- a thing\n\n## [0.9.1] - 2026-10-03\n"
    assert version_problem("1.0.0", pending) == ""
    assert "already released" in version_problem("0.9.1", pending)
    # The release commit: the section moved under a dated heading, the version is that number.
    cut = "# Changelog\n\n## [Unreleased]\n\n## [1.0.0] - 2026-11-01\n\n## [0.9.1] - 2026-10-03\n"
    assert version_problem("1.0.0", cut) == ""
    assert "must be the newest released version 1.0.0" in version_problem("0.9.1", cut)
    assert "must be the newest released version 1.0.0" in version_problem("1.1.0", cut)


def test_the_released_versions_are_read_from_the_dated_headings_only() -> None:
    text = "## [Unreleased]\n\n## [1.2.3] - 2026-01-02\n\n## [1.2.2] - 2025-12-31\n"
    assert released_versions(text) == ["1.2.3", "1.2.2"]


# ---------------------------------------------------------------------------------------
# Fixture paths do not depend on the working directory
# ---------------------------------------------------------------------------------------

# Test files that still open a fixture as Path("tests/..."), which only works when pytest runs
# from the repository root. Each entry is a bug to fix; the list only shrinks.
CWD_RELATIVE_ALLOWED: dict[str, str] = {
    "tests/test_engine/test_docker_rules.py": "globs Path('tests/fixtures/docker')",
    "tests/test_parsers/test_kubernetes.py": "reads Path('tests/fixtures/kubernetes/...')",
}

_FILE_OPENERS = {"Path", "PurePath", "open", "PosixPath"}


def cwd_relative_fixture_paths(source: str) -> list[int]:
    """Line numbers where a file opener is given a literal path that starts at ``tests``."""
    lines: list[int] = []
    for node in ast.walk(ast.parse(source)):
        if not isinstance(node, ast.Call) or not node.args:
            continue
        func = node.func
        name = func.attr if isinstance(func, ast.Attribute) else getattr(func, "id", "")
        first = node.args[0]
        if (
            name in _FILE_OPENERS
            and isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and (first.value == "tests" or first.value.startswith("tests/"))
        ):
            lines.append(node.lineno)
    return lines


def test_no_test_opens_a_fixture_relative_to_the_working_directory() -> None:
    offenders: dict[str, list[int]] = {}
    for path in sorted(TESTS_DIR.rglob("*.py")):
        if path == Path(__file__).resolve():
            continue
        lines = cwd_relative_fixture_paths(path.read_text(encoding="utf-8"))
        if lines:
            offenders[path.relative_to(REPO_ROOT).as_posix()] = lines
    new = {f: lines for f, lines in offenders.items() if f not in CWD_RELATIVE_ALLOWED}
    assert not new, (
        "these tests open Path('tests/...'), which fails when pytest runs from another directory. "
        "Build the path from Path(__file__).parent or tests/conftest.py instead:\n  "
        + "\n  ".join(f"{f}: lines {lines}" for f, lines in sorted(new.items()))
    )
    fixed = sorted(set(CWD_RELATIVE_ALLOWED) - set(offenders))
    assert not fixed, f"fixed, so delete them from CWD_RELATIVE_ALLOWED: {fixed}"


def test_the_working_directory_gate_flags_a_relative_fixture_and_not_an_anchored_one() -> None:
    bad = 'from pathlib import Path\nx = Path("tests/fixtures/a.tf").read_text()\n'
    glob = 'import pathlib\nfiles = pathlib.Path("tests/fixtures").glob("*.tf")\n'
    opened = 'with open("tests/fixtures/a.tf") as f:\n    f.read()\n'
    good = (
        "from pathlib import Path\n"
        'x = (Path(__file__).parent / "tests/fixtures/a.tf").read_text()\n'
        'name = "tests/fixtures/a.tf"\n'
        'expected = {"input": "tests/fixtures/a.tf"}\n'
    )
    assert cwd_relative_fixture_paths(bad) == [2]
    assert cwd_relative_fixture_paths(glob) == [2]
    assert cwd_relative_fixture_paths(opened) == [1]
    assert cwd_relative_fixture_paths(good) == []


# ---------------------------------------------------------------------------------------
# Unreferenced code in src
# ---------------------------------------------------------------------------------------

SRC_DIR = REPO_ROOT / "src" / "threatcode"

# Definitions that nothing in src refers to. The first group has callers only in tests, so each
# is either dead code or a test helper that belongs under tests/; the second group is a name that
# is only reached by getattr. The list only shrinks: deleting a definition or giving it a caller
# means deleting its entry here.
UNREFERENCED_ALLOWED: dict[str, str] = {
    "Redactor.redact_text": "dead: no caller anywhere",
    "Redactor.mapping_size": "test only",
    "clear_builtin_cache": "test only",
    "evaluate_rule": "test only",
    "ports_overlap": "test only",
    "module_of": "test only",
    "principal_is_wildcard": "test only",
    "InfraGraph.duplicate_of": "test only",
    "InfraGraph.get_neighbors": "test only",
    "InfraGraph.get_edges_for_node": "test only",
    "InfraGraph.nodes_by_zone": "test only",
    "InfraGraph.reachability_subgraph": "test only",
    "AgentCapabilities.lethal_trifecta": "test only",
    "terraform_types": "test only",
    "cfn_types_for": "test only",
    "uses_sam": "test only",
    "extract_refs": "dead: no caller anywhere, in src or in tests",
    "evaluate_expression": "test only",
    "load_config": "public helper kept for callers that want the model without the resolver",
}

# Families that are looked up by name at run time (``getattr(self, "_do_" + name)``).
_DISPATCHED_PREFIXES = ("f_", "_do_")
# Methods a library calls on a subclass of its class: yaml.Dumper.ignore_aliases.
_LIBRARY_HOOKS = frozenset({"ignore_aliases"})


def unreferenced_definitions(sources: dict[str, str], other_text: str = "") -> list[str]:
    """Functions, methods and classes whose name occurs once in ``sources``: at its definition.

    A name counts as referenced when it appears anywhere else in any file, including a string
    (``__all__``, a dispatch table, a registry), or in ``other_text`` (the rule files).
    Dunder methods, decorated functions (validators, registered hooks, class methods; a plain
    property is still checked) and the
    dispatched families above are skipped, because something other than a call site reaches them.
    """
    words: dict[str, int] = {}
    for text in [*sources.values(), other_text]:
        for word in re.findall(r"[A-Za-z_][A-Za-z0-9_]*", text):
            words[word] = words.get(word, 0) + 1
    found: list[str] = []
    for text in sources.values():
        tree = ast.parse(text)
        for node in tree.body:
            if isinstance(node, ast.ClassDef):
                members: list[tuple[str, ast.AST]] = [(node.name, node)]
                members += [
                    (f"{node.name}.{m.name}", m)
                    for m in node.body
                    if isinstance(m, ast.FunctionDef | ast.AsyncFunctionDef)
                ]
            elif isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                members = [(node.name, node)]
            else:
                continue
            for qualified, member in members:
                name = qualified.rsplit(".", 1)[-1]
                decorators = getattr(member, "decorator_list", [])
                decorated = any(
                    not (isinstance(d, ast.Name) and d.id in {"property", "cached_property"})
                    for d in decorators
                )
                if (
                    (name.startswith("__") and name.endswith("__"))
                    or decorated
                    or name.startswith(_DISPATCHED_PREFIXES)
                    or name in _LIBRARY_HOOKS
                ):
                    continue
                if words.get(name, 0) <= 1:
                    found.append(qualified)
    return sorted(found)


def test_no_definition_in_src_is_unreferenced() -> None:
    sources = {
        p.relative_to(REPO_ROOT).as_posix(): p.read_text(encoding="utf-8")
        for p in sorted(SRC_DIR.rglob("*.py"))
    }
    rule_files = "\n".join(p.read_text(encoding="utf-8") for p in sorted(SRC_DIR.rglob("*.yml")))
    found = unreferenced_definitions(sources, rule_files)
    new = [f for f in found if f not in UNREFERENCED_ALLOWED]
    assert not new, (
        "defined in src and never referenced there (delete it, or move a test-only helper under "
        "tests/):\n  " + "\n  ".join(new)
    )
    fixed = sorted(set(UNREFERENCED_ALLOWED) - set(found))
    assert not fixed, (
        f"referenced or deleted now, so remove them from UNREFERENCED_ALLOWED: {fixed}"
    )


def test_the_unreferenced_gate_finds_a_definition_nothing_calls() -> None:
    sources = {
        "a.py": (
            "def used():\n    return 1\n\n"
            "def lonely():\n    return 2\n\n"
            "class Box:\n    def open(self):\n        return used()\n\n"
            "    def never(self):\n        return 0\n\n"
            "    @register\n    def decorated(self):\n        return 0\n\n"
            "    @property\n    def unread(self):\n        return 0\n\n"
            "    def __repr__(self):\n        return 'Box'\n"
        ),
        "b.py": "from a import Box\nBox().open()\n",
    }
    assert unreferenced_definitions(sources) == ["Box.never", "Box.unread", "lonely"]
