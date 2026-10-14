"""A scan may name paths on different drives of Windows, where no directory holds them all.

A POSIX file system has one root, so the tests make two directories behave as two drives: a path
under ``elsewhere`` has no relative form to a path under ``here``, as ``ntpath.relpath`` has none
between ``C:\\`` and ``D:\\``.
On a Windows runner whose temporary directory is on another drive than the checkout, the last test
scans two real drives.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from threatcode import _paths, discovery
from threatcode.discovery import scan_root
from threatcode.pipeline import ScanResult, prepare_request, run_scan

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BUCKET = 'resource "aws_s3_bucket" "{name}" {{\n  bucket = "{name}"\n}}\n'


def scan(*paths: str | Path) -> ScanResult:
    return run_scan(prepare_request([str(p) for p in paths]).request)


def write(root: Path, relative: str, text: str) -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


@pytest.fixture
def drives(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """``here`` (the current directory) and ``elsewhere``, which has no relative form to it."""
    here = tmp_path / "here"
    elsewhere = tmp_path / "elsewhere"
    here.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(here)

    def drive_of(path: str | os.PathLike[str]) -> str:
        return "elsewhere" if Path(os.path.abspath(path)).is_relative_to(elsewhere) else "here"

    real_relative = _paths.relative_posix
    real_common = _paths.common_directory

    def relative(path: str, start: str, *, pathmod: object = os.path) -> str | None:
        if drive_of(path) != drive_of(start):
            return None
        return real_relative(path, start)

    def common(directories: list[str], **_: object) -> str | None:
        if len({drive_of(d) for d in directories}) > 1:
            return None
        return real_common(directories)

    monkeypatch.setattr(_paths, "relative_posix", relative)
    monkeypatch.setattr(discovery, "common_directory", common)
    return here, elsewhere


class TestTheRoot:
    def test_paths_on_different_drives_are_rooted_at_the_current_directory(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        assert scan_root([str(here), str(elsewhere)]) == here

    def test_standard_input_and_a_path_on_another_drive_are_rooted_at_the_current_directory(
        self, drives: tuple[Path, Path]
    ) -> None:
        _, elsewhere = drives
        assert scan_root([str(elsewhere), "-"]) == Path(os.getcwd())

    def test_paths_on_one_drive_keep_their_common_parent(self, drives: tuple[Path, Path]) -> None:
        here, _ = drives
        write(here, "a/main.tf", BUCKET.format(name="a"))
        write(here, "b/main.tf", BUCKET.format(name="b"))
        assert scan_root([str(here / "a"), str(here / "b")]) == here


class TestTheScan:
    def test_both_drives_are_scanned_and_the_other_one_keeps_its_absolute_form(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "main.tf", BUCKET.format(name="two"))
        result = scan(here, elsewhere)
        assert result.root == here
        assert result.graph.node_count == 2
        assert {t.location_file for t in result.report.threats} == {
            "main.tf",
            (elsewhere / "main.tf").as_posix(),
        }

    def test_the_report_names_both_inputs_without_the_machine_they_came_from(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "main.tf", BUCKET.format(name="two"))
        assert scan(here, elsewhere).report.input_file == "elsewhere, here"

    def test_two_resources_of_one_name_on_different_drives_stay_apart(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="same"))
        write(elsewhere, "main.tf", BUCKET.format(name="same"))
        result = scan(here, elsewhere)
        assert result.graph.node_count == 2

    def test_a_file_named_on_another_drive_is_found(self, drives: tuple[Path, Path]) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        other = write(elsewhere, "deep/dir/other.tf", BUCKET.format(name="two"))
        result = scan(here / "main.tf", other)
        assert result.graph.node_count == 2
        assert result.coverage.errors == []


def test_two_real_drives_can_be_scanned_together(tmp_path: Path) -> None:
    """The temporary directory and the checkout are on different drives of the Windows runner."""
    write(tmp_path, "main.tf", BUCKET.format(name="temporary"))
    result = scan(tmp_path, FIXTURES / "terraform" / "simple.tf")
    assert result.graph.node_count >= 2
    assert result.coverage.errors == []
    assert {Path(t.location_file).name for t in result.report.threats} >= {"main.tf", "simple.tf"}
