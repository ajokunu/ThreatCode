"""Tests for threatcode.diagnostics."""

from __future__ import annotations

from collections.abc import Iterator

import pytest

from threatcode import diagnostics
from threatcode.diagnostics import DIAGNOSTIC_CODES, Diagnostic, register_code
from threatcode.parsers.base import ParsedOutput

SPEC_CODES = [
    "parse.failed",
    "parse.zero_resources",
    "cfn.skipped_resource",
    "cfn.unmapped_type",
    "cfn.nested_stack",
    "cfn.unresolved_intrinsic",
    "hcl.module_call_skipped",
    "hcl.unresolved_reference",
    "hcl.dynamic_block",
    "hcl.count_zero",
    "plan.data_source",
    "plan.unknown_values",
    "helm.fallback_render",
    "k8s.skipped_document",
    "mcp.unknown_entry",
    "mcp.unknown_capability",
    "graph.duplicate_address",
    "graph.dangling_declared_edge",
    "graph.edge_cap",
    "graph.ambiguous_reference",
    "graph.unit_superseded",
    "ingest.unattached",
    "ingest.duplicate",
]


@pytest.fixture
def scratch_codes() -> Iterator[None]:
    """Remove codes a test registers so the registry is the same afterwards."""
    before = set(diagnostics._CODES)
    yield
    for code in set(diagnostics._CODES) - before:
        del diagnostics._CODES[code]


class TestRegistry:
    @pytest.mark.parametrize("code", SPEC_CODES)
    def test_every_specified_code_is_registered_with_a_description(self, code: str) -> None:
        assert DIAGNOSTIC_CODES[code].strip()

    @pytest.mark.parametrize("code", SPEC_CODES)
    def test_every_specified_code_can_build_a_diagnostic(self, code: str) -> None:
        assert Diagnostic("info", code, "message").code == code

    def test_registry_view_is_read_only(self) -> None:
        with pytest.raises(TypeError):
            DIAGNOSTIC_CODES["sneaky.code"] = "x"  # type: ignore[index]

    def test_register_code_adds_a_code(self, scratch_codes: None) -> None:
        register_code("scan.example_gap", "An example coverage gap")
        assert DIAGNOSTIC_CODES["scan.example_gap"] == "An example coverage gap"
        assert Diagnostic("warning", "scan.example_gap", "m").code == "scan.example_gap"

    def test_register_code_is_idempotent_for_the_same_description(
        self, scratch_codes: None
    ) -> None:
        register_code("scan.example_gap", "An example coverage gap")
        register_code("scan.example_gap", "An example coverage gap")

    def test_register_code_rejects_a_conflicting_description(self, scratch_codes: None) -> None:
        register_code("scan.example_gap", "An example coverage gap")
        with pytest.raises(ValueError, match="already registered"):
            register_code("scan.example_gap", "Something else")

    def test_builtin_code_cannot_be_redefined(self) -> None:
        with pytest.raises(ValueError, match="already registered"):
            register_code("parse.failed", "Redefined")

    @pytest.mark.parametrize("code", ["nodot", "Upper.case", "a..b", ".a", "a.", "a b.c", ""])
    def test_register_code_rejects_a_malformed_code(self, code: str) -> None:
        with pytest.raises(ValueError, match="Invalid diagnostic code"):
            register_code(code, "description")

    def test_register_code_rejects_an_empty_description(self) -> None:
        with pytest.raises(ValueError, match="needs a description"):
            register_code("scan.blank_description", "  ")
        assert "scan.blank_description" not in DIAGNOSTIC_CODES


class TestDiagnostic:
    def test_unregistered_code_raises(self) -> None:
        with pytest.raises(ValueError, match="Unregistered diagnostic code 'made.up'"):
            Diagnostic("warning", "made.up", "message")

    def test_unknown_level_raises(self) -> None:
        with pytest.raises(ValueError, match="Invalid diagnostic level 'fatal'"):
            Diagnostic("fatal", "parse.failed", "message")  # type: ignore[arg-type]

    @pytest.mark.parametrize("level", ["info", "warning", "error"])
    def test_every_level_is_accepted(self, level: str) -> None:
        assert Diagnostic(level, "parse.failed", "m").level == level  # type: ignore[arg-type]

    def test_location_defaults_to_unset(self) -> None:
        d = Diagnostic("info", "parse.failed", "m")
        assert (d.file, d.line) == ("", None)

    def test_is_immutable(self) -> None:
        d = Diagnostic("info", "parse.failed", "m")
        with pytest.raises(AttributeError):
            d.message = "changed"  # type: ignore[misc]

    def test_to_dict_omits_unset_location(self) -> None:
        d = Diagnostic("warning", "parse.failed", "m")
        assert d.to_dict() == {"level": "warning", "code": "parse.failed", "message": "m"}

    def test_to_dict_includes_file_and_line_when_set(self) -> None:
        d = Diagnostic("error", "parse.failed", "m", file="a.tf", line=3)
        assert d.to_dict() == {
            "level": "error",
            "code": "parse.failed",
            "message": "m",
            "file": "a.tf",
            "line": 3,
        }


class TestParsedOutputChannel:
    def test_parsed_output_starts_with_no_diagnostics(self) -> None:
        assert ParsedOutput().diagnostics == []

    def test_parsed_outputs_do_not_share_the_list(self) -> None:
        first, second = ParsedOutput(), ParsedOutput()
        first.diagnostics.append(Diagnostic("info", "parse.failed", "m"))
        assert second.diagnostics == []
