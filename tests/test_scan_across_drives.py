"""A scan may name paths on different drives of Windows, where no directory holds them all.

A POSIX file system has one root, so the tests make two directories behave as two drives: a path
under ``elsewhere`` is on drive ``D:`` and every other path on ``C:``, and ``ntpath`` gives no
relative form between the two.
The report names a file on ``D:`` by the drive and its place under the inputs on that drive
(``D/net/main.tf``), never by an absolute path, so the same tree has the same names and the same
fingerprints wherever it is checked out.
On a Windows runner whose temporary directory is on another drive than the checkout, the last test
scans two real drives.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from threatcode import _paths
from threatcode.discovery import scan_root
from threatcode.formatters import render
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


def locations(result: ScanResult) -> set[str]:
    return {t.location_file for t in result.report.threats}


@pytest.fixture
def drives(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path]:
    """``here`` (the current directory, drive ``C:``) and ``elsewhere`` (drive ``D:``)."""
    here = tmp_path / "here"
    elsewhere = tmp_path / "elsewhere"
    here.mkdir()
    elsewhere.mkdir()
    monkeypatch.chdir(here)

    def drive_of(path: str | os.PathLike[str], *, pathmod: object = os.path) -> str:
        return "D:" if Path(os.path.abspath(path)).is_relative_to(elsewhere) else "C:"

    monkeypatch.setattr(_paths, "drive_of", drive_of)
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
    def test_the_other_drive_is_named_by_its_letter_and_never_by_an_absolute_path(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "main.tf", BUCKET.format(name="two"))
        result = scan(here, elsewhere)
        assert result.root == here
        assert result.graph.node_count == 2
        assert locations(result) == {"main.tf", "D/main.tf"}

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
        assert len({t.fingerprint for t in result.report.threats}) == len(result.report.threats)

    def test_a_file_named_on_another_drive_is_named_from_its_own_directory(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        other = write(elsewhere, "deep/dir/other.tf", BUCKET.format(name="two"))
        result = scan(here / "main.tf", other)
        assert result.graph.node_count == 2
        assert result.coverage.errors == []
        assert locations(result) == {"main.tf", "D/other.tf"}

    def test_a_directory_on_another_drive_keeps_the_places_of_its_files(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "infra/net/main.tf", BUCKET.format(name="net"))
        write(elsewhere, "infra/db/main.tf", BUCKET.format(name="db"))
        result = scan(here, elsewhere / "infra")
        assert locations(result) == {"main.tf", "D/net/main.tf", "D/db/main.tf"}

    def test_two_inputs_on_the_other_drive_are_named_from_their_common_parent(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "shared/a/main.tf", BUCKET.format(name="a"))
        write(elsewhere, "shared/b/main.tf", BUCKET.format(name="b"))
        result = scan(here, elsewhere / "shared" / "a", elsewhere / "shared" / "b")
        assert locations(result) == {"main.tf", "D/a/main.tf", "D/b/main.tf"}

    def test_a_module_above_the_inputs_on_the_other_drive_is_named_from_the_top_of_the_drive(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "repo/modules/net/main.tf", BUCKET.format(name="net"))
        write(
            elsewhere,
            "repo/envs/prod/main.tf",
            'module "net" {\n  source = "../../modules/net"\n}\n',
        )
        result = scan(here, elsewhere / "repo" / "envs" / "prod")
        module = next(name for name in locations(result) if name.endswith("modules/net/main.tf"))
        assert module.startswith("D/")
        assert ":" not in module
        assert not module.startswith("/")


class TestTheNamesAreStable:
    """The directories above the inputs on the other drive are not part of a name."""

    def named(self, tree: Path) -> list[tuple[str, str, str, str]]:
        write(tree, "net/main.tf", BUCKET.format(name="net"))
        write(tree, "db/main.tf", BUCKET.format(name="db"))
        result = scan(Path.cwd(), tree)
        return sorted(
            (t.rule_id, t.resource_address, t.location_file, t.fingerprint)
            for t in result.report.threats
            if t.location_file.startswith("D/")
        )

    def test_a_tree_has_the_same_names_and_fingerprints_wherever_it_is_checked_out(
        self, drives: tuple[Path, Path]
    ) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="one"))
        first = self.named(elsewhere / "one")
        second = self.named(elsewhere / "work" / "a" / "deeper" / "two")
        assert first
        assert first == second
        assert all(len(item[3]) == 16 for item in first)

    def test_the_drive_letter_is_part_of_the_name(self, drives: tuple[Path, Path]) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="same"))
        write(elsewhere, "main.tf", BUCKET.format(name="same"))
        result = scan(here, elsewhere)
        by_file = {t.location_file: t.fingerprint for t in result.report.threats}
        assert set(by_file) == {"main.tf", "D/main.tf"}
        assert by_file["main.tf"] != by_file["D/main.tf"]

    def test_sarif_keeps_two_files_of_one_name_apart(self, drives: tuple[Path, Path]) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="same"))
        write(elsewhere, "main.tf", BUCKET.format(name="same"))
        sarif = json.loads(render("sarif", scan(here, elsewhere).analysis))
        uris = {
            location["physicalLocation"]["artifactLocation"]["uri"]
            for run in sarif["runs"]
            for item in run["results"]
            for location in item.get("locations", [])
        }
        assert uris == {"main.tf", "D/main.tf"}

    def test_sarif_says_the_other_drive_is_outside_the_repository_below_a_subdirectory(
        self, drives: tuple[Path, Path], monkeypatch: pytest.MonkeyPatch
    ) -> None:
        here, elsewhere = drives
        (here / ".git").mkdir()
        infra = here / "infra"
        write(infra, "main.tf", BUCKET.format(name="one"))
        write(elsewhere, "main.tf", BUCKET.format(name="two"))
        monkeypatch.chdir(infra)
        result = scan(infra, elsewhere)
        assert result.analysis.other_drives == ("D",)
        sarif = json.loads(render("sarif", result.analysis))
        run = sarif["runs"][0]
        uris = {
            item["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            for item in run["results"]
        }
        assert uris == {"infra/main.tf", "D/main.tf"}
        codes = {n["descriptor"]["id"] for n in run["invocations"][0]["toolExecutionNotifications"]}
        assert "sarif.paths.outside_repository" in codes

    def test_a_scan_of_one_drive_has_no_other_drive(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", BUCKET.format(name="one"))
        assert scan(tmp_path).analysis.other_drives == ()

    def test_bitbucket_keeps_two_files_of_one_name_apart(self, drives: tuple[Path, Path]) -> None:
        here, elsewhere = drives
        write(here, "main.tf", BUCKET.format(name="same"))
        write(elsewhere, "main.tf", BUCKET.format(name="same"))
        report = json.loads(render("bitbucket", scan(here, elsewhere).analysis))
        assert {item["path"] for item in report["annotations"]} == {"main.tf", "D/main.tf"}


def test_two_real_drives_can_be_scanned_together(tmp_path: Path) -> None:
    """The temporary directory and the checkout are on different drives of the Windows runner."""
    write(tmp_path, "main.tf", BUCKET.format(name="temporary"))
    result = scan(tmp_path, FIXTURES / "terraform" / "simple.tf")
    assert result.graph.node_count >= 2
    assert result.coverage.errors == []
    found = locations(result)
    assert {Path(name).name for name in found} >= {"main.tf", "simple.tf"}
    for name in found:
        assert not os.path.isabs(name), name
        assert ":" not in name, name
        assert "\\" not in name, name
