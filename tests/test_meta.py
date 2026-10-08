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
