"""The path helpers answer as Windows does when they are given ``ntpath``."""

from __future__ import annotations

import ntpath
import os
import posixpath

import pytest

from threatcode._paths import (
    WINDOWS_DRIVE_PATH,
    common_directory,
    inside,
    is_windows_flavor,
    posix_separators,
    relative_posix,
)
from threatcode.diagnostics import Diagnostic
from threatcode.parsers.base import ParsedOutput, ParsedResource


class TestPosixSeparators:
    def test_a_windows_path_is_written_with_slashes(self) -> None:
        assert posix_separators("C:\\work\\repo\\main.tf", sep="\\") == "C:/work/repo/main.tf"

    def test_a_path_that_already_has_slashes_is_unchanged(self) -> None:
        assert posix_separators("C:/work/main.tf", sep="\\") == "C:/work/main.tf"
        assert posix_separators("", sep="\\") == ""

    def test_a_backslash_is_a_file_name_character_where_the_separator_is_a_slash(self) -> None:
        assert posix_separators("dir/a\\b.tf", sep="/") == "dir/a\\b.tf"

    def test_the_default_is_the_separator_of_this_platform(self) -> None:
        assert posix_separators(os.path.join("a", "b")) == "a/b"


class TestFlavor:
    def test_ntpath_is_windows_and_posixpath_is_not(self) -> None:
        assert is_windows_flavor(ntpath)
        assert not is_windows_flavor(posixpath)

    def test_a_drive_path_is_told_by_its_letter_and_slash(self) -> None:
        assert WINDOWS_DRIVE_PATH.match("C:/work")
        assert WINDOWS_DRIVE_PATH.match("d:/")
        assert not WINDOWS_DRIVE_PATH.match("C:work")
        assert not WINDOWS_DRIVE_PATH.match("/work")


class TestRelativePosix:
    @pytest.mark.parametrize(
        ("path", "start", "expected"),
        [
            ("C:\\work\\repo\\infra\\main.tf", "C:\\work\\repo", "infra/main.tf"),
            ("C:/work/repo/infra/main.tf", "C:\\work\\repo", "infra/main.tf"),
            ("c:\\Work\\Repo\\main.tf", "C:\\work\\repo", "main.tf"),
            ("C:\\work\\repo", "C:\\work\\repo", "."),
            ("C:\\work\\other\\main.tf", "C:\\work\\repo", "../other/main.tf"),
            ("C:\\main.tf", "C:\\work\\repo", "../../main.tf"),
        ],
    )
    def test_a_path_on_the_same_drive_has_a_relative_form(
        self, path: str, start: str, expected: str
    ) -> None:
        assert relative_posix(path, start, pathmod=ntpath) == expected

    def test_a_path_on_another_drive_has_none(self) -> None:
        assert relative_posix("C:\\Users\\me\\main.tf", "D:\\a\\repo", pathmod=ntpath) is None

    def test_a_posix_path_is_made_relative_too(self) -> None:
        assert relative_posix("/work/repo/a/b.tf", "/work/repo", pathmod=posixpath) == "a/b.tf"

    @pytest.mark.parametrize(
        ("relative", "expected"),
        [
            (".", True),
            ("a/b.tf", True),
            ("..data/x.tf", True),
            ("..", False),
            ("../x.tf", False),
            ("../../x.tf", False),
        ],
    )
    def test_a_relative_path_is_inside_unless_it_climbs(
        self, relative: str, expected: bool
    ) -> None:
        assert inside(relative) is expected


class TestCommonDirectory:
    def test_directories_on_one_drive_have_a_common_parent(self) -> None:
        found = common_directory(["C:\\work\\repo\\a", "C:\\work\\repo\\b"], pathmod=ntpath)
        assert found == "C:\\work\\repo"

    def test_directories_on_different_drives_have_none(self) -> None:
        assert common_directory(["C:\\Users\\me", "D:\\a\\repo"], pathmod=ntpath) is None

    def test_posix_directories_have_a_common_parent(self) -> None:
        assert common_directory(["/work/a", "/work/b"], pathmod=posixpath) == "/work"

    def test_a_mix_of_absolute_and_relative_paths_has_none(self) -> None:
        assert common_directory(["/work/a", "b"], pathmod=posixpath) is None


class TestWhatAParserReports:
    """A path in a parser's output has forward slashes, whatever the platform separator is."""

    @pytest.fixture
    def on_windows(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setattr(os, "sep", "\\")

    def test_a_resource_location_is_written_with_slashes_on_windows(self, on_windows: None) -> None:
        resource = ParsedResource("aws_vpc", "aws_vpc.main", "main", "aws")
        assert resource.source_location == ""
        located = ParsedResource(
            "aws_vpc", "aws_vpc.main", "main", "aws", source_location="D:\\a\\repo\\main.tf"
        )
        assert located.source_location == "D:/a/repo/main.tf"

    def test_a_resource_location_with_a_line_keeps_the_line_on_windows(
        self, on_windows: None
    ) -> None:
        located = ParsedResource(
            "aws_vpc", "aws_vpc.main", "main", "aws", source_location="D:\\a\\main.tf:7"
        )
        assert located.source_location == "D:/a/main.tf:7"

    def test_the_input_and_a_diagnostic_file_are_written_with_slashes_on_windows(
        self, on_windows: None
    ) -> None:
        output = ParsedOutput(source_path="D:\\a\\repo\\Chart.yaml")
        assert output.source_path == "D:/a/repo/Chart.yaml"
        diagnostic = Diagnostic("warning", "parse.failed", "bad", file="charts\\redis\\x.yaml")
        assert diagnostic.file == "charts/redis/x.yaml"

    def test_a_backslash_is_part_of_a_file_name_where_the_separator_is_a_slash(self) -> None:
        if os.sep != "/":
            pytest.skip("a backslash separates directories on this platform")
        located = ParsedResource(
            "aws_vpc", "aws_vpc.main", "main", "aws", source_location="dir/a\\b.tf"
        )
        assert located.source_location == "dir/a\\b.tf"
        assert Diagnostic("info", "parse.failed", "x", file="a\\b.tf").file == "a\\b.tf"

    def test_a_copy_of_a_resource_is_not_changed_again(self, on_windows: None) -> None:
        import dataclasses

        located = ParsedResource(
            "aws_vpc", "aws_vpc.main", "main", "aws", source_location="D:\\a\\main.tf"
        )
        copy = dataclasses.replace(located, name="other")
        assert copy.source_location == located.source_location == "D:/a/main.tf"
