"""Choosing a format from the output file name, and the deprecated ``matrix`` alias.

``-o results.sarif`` with no ``-f`` used to write the plain JSON report into a file that looks like
SARIF; the registry now says which format a file name means, and warns when a format is written
to a file named for another one.
"""

from __future__ import annotations

import logging
import os
from pathlib import Path

import pytest
from click.testing import CliRunner

from tests.helpers.scan import scan_files
from threatcode.cli import cli
from threatcode.formatters import (
    DEPRECATED_FORMATS,
    FORMATTERS,
    RenderOptions,
    deprecation_notice,
    extension_mismatch,
    format_for_extension,
    format_names,
    render,
    visible_format_names,
)
from threatcode.models.analysis import AnalysisResult

FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
PLAN = FIXTURES / "terraform" / "simple_s3.plan.json"


@pytest.fixture
def analysis() -> AnalysisResult:
    scan = scan_files([PLAN])
    return AnalysisResult(graph=scan.graph, report=scan.report)


class TestFormatForExtension:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("results.sarif", "sarif"),
            ("RESULTS.SARIF", "sarif"),
            ("out/report.md", "markdown"),
            ("flow.mmd", "mermaid"),
            ("map.svg", "diagram"),
            ("summary.txt", "text"),
            ("report.json", "json"),
            ("a.b/noext", None),
            ("noext", None),
            ("data.yaml", None),
            ("results.sarif.json", "json"),
            ("C:\\out\\results.sarif", "sarif"),
        ],
    )
    def test_the_extension_names_the_format(self, path: str, expected: str | None) -> None:
        assert format_for_extension(path) == expected

    def test_json_is_the_plain_report_not_a_json_flavor(self) -> None:
        assert format_for_extension("x.json") == "json"

    def test_a_path_object_works(self, tmp_path: Path) -> None:
        assert format_for_extension(tmp_path / "r.sarif") == "sarif"

    def test_the_alias_is_never_inferred(self) -> None:
        for spec_name in DEPRECATED_FORMATS:
            assert format_for_extension(f"x{FORMATTERS[spec_name].extension}") != spec_name

    def test_every_visible_format_with_its_own_extension_is_found_or_shares_json(self) -> None:
        for name in visible_format_names():
            inferred = format_for_extension(f"x{FORMATTERS[name].extension}")
            assert inferred == name or FORMATTERS[name].extension == ".json", name


class TestExtensionMismatch:
    def test_json_written_to_a_sarif_name_is_flagged(self) -> None:
        message = extension_mismatch("json", "results.sarif")
        assert "results.sarif" in message
        assert "-f sarif" in message

    def test_a_format_written_to_its_own_extension_is_fine(self) -> None:
        assert extension_mismatch("sarif", "results.sarif") == ""
        assert extension_mismatch("markdown", "r.md") == ""

    def test_the_json_flavors_may_use_a_json_name(self) -> None:
        assert extension_mismatch("navigator", "layer.json") == ""
        assert extension_mismatch("bitbucket", "report.json") == ""
        assert extension_mismatch("json", "report.json") == ""

    def test_a_name_with_no_meaning_is_never_flagged(self) -> None:
        assert extension_mismatch("json", "noext") == ""
        assert extension_mismatch("sarif", "out.dat") == ""

    def test_the_wrong_one_among_two_known_formats_is_flagged(self) -> None:
        assert extension_mismatch("sarif", "report.md")
        assert extension_mismatch("bitbucket", "x.sarif")

    def test_an_unknown_format_name_is_not_this_functions_business(self) -> None:
        assert extension_mismatch("yaml", "x.sarif") == ""


class TestDeprecatedAlias:
    def test_matrix_is_still_accepted_everywhere_names_are_validated(self) -> None:
        assert "matrix" in format_names()

    def test_matrix_is_left_out_of_what_is_advertised(self) -> None:
        assert "matrix" not in visible_format_names()
        assert visible_format_names() == [n for n in format_names() if n != "matrix"]

    def test_the_notice_names_the_replacement(self) -> None:
        assert deprecation_notice("matrix") == "-f matrix is deprecated, use -f navigator"
        assert deprecation_notice("navigator") == ""
        assert deprecation_notice("nonsense") == ""

    def test_rendering_matrix_warns_once_and_renders_the_navigator(
        self, analysis: AnalysisResult, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="threatcode"):
            old = render("matrix", analysis)
        warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
        assert warnings == ["-f matrix is deprecated, use -f navigator"]
        assert old == render("navigator", analysis)

    def test_rendering_a_current_format_does_not_warn(
        self, analysis: AnalysisResult, caplog: pytest.LogCaptureFixture
    ) -> None:
        with caplog.at_level(logging.WARNING, logger="threatcode"):
            for name in visible_format_names():
                render(name, analysis, RenderOptions())
        assert not [r for r in caplog.records if "deprecated" in r.getMessage()]


class TestCliShowsTheNotice:
    @pytest.fixture(autouse=True)
    def hermetic(
        self, tmp_path_factory: pytest.TempPathFactory, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        home = tmp_path_factory.mktemp("home")
        monkeypatch.setenv("HOME", str(home))
        monkeypatch.setenv("USERPROFILE", str(home))
        for name in list(os.environ):
            if name.startswith("THREATCODE_"):
                monkeypatch.delenv(name)

    def scan(self, *args: str, tmp_path: Path) -> tuple[int, str, str]:
        result = CliRunner().invoke(cli, ["scan", str(PLAN), "--fail-on", "none", *args])
        return result.exit_code, result.stdout, result.stderr

    def test_matrix_prints_the_notice_on_stderr_and_still_writes_the_layer(
        self, tmp_path: Path
    ) -> None:
        code, out, err = self.scan("-f", "matrix", "--no-timestamp", tmp_path=tmp_path)
        assert code == 0
        assert "-f matrix is deprecated, use -f navigator" in err
        assert '"domain": "enterprise-attack"' in out

    def test_navigator_prints_no_notice(self, tmp_path: Path) -> None:
        code, _out, err = self.scan("-f", "navigator", tmp_path=tmp_path)
        assert code == 0
        assert "deprecated" not in err
