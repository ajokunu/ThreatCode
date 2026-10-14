"""The path helpers answer as Windows does when they are given ``ntpath``."""

from __future__ import annotations

import ntpath
import os
import pathlib
import posixpath

import pytest

from threatcode._paths import (
    WINDOWS_DRIVE_PATH,
    ReportPaths,
    common_directory,
    drive_anchors,
    drive_label,
    drive_of,
    inside,
    is_absolute,
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

    def test_a_value_that_is_not_a_string_is_left_for_its_owner(self) -> None:
        assert posix_separators(None, sep="\\") is None  # type: ignore[arg-type]
        assert posix_separators(b"a\\b", sep="\\") == b"a\\b"  # type: ignore[arg-type]

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


class TestDriveOf:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("C:\\work", "C:"),
            ("c:/work", "C:"),
            ("d:", "D:"),
            ("\\\\host\\share\\x", "\\\\HOST\\SHARE"),
            ("\\work", ""),
            ("work\\x", ""),
        ],
    )
    def test_a_windows_path_is_on_the_drive_it_names_in_upper_case(
        self, path: str, expected: str
    ) -> None:
        assert drive_of(path, pathmod=ntpath) == expected

    def test_a_posix_path_has_no_drive(self) -> None:
        assert drive_of("/work/x", pathmod=posixpath) == ""
        assert drive_of("c:/work", pathmod=posixpath) == ""


class TestDriveLabel:
    @pytest.mark.parametrize(
        ("drive", "expected"),
        [
            ("C:", "C"),
            ("D:", "D"),
            ("\\\\HOST\\SHARE", "HOST/SHARE"),
            ("\\\\?\\C:", "C"),
            ("", "drive"),
        ],
    )
    def test_a_drive_is_one_or_two_path_segments(self, drive: str, expected: str) -> None:
        assert drive_label(drive) == expected


class TestDriveAnchors:
    def test_each_other_drive_gets_the_common_parent_of_its_inputs(self) -> None:
        found = drive_anchors(
            [
                "C:\\work\\app",
                "D:\\a\\repo\\infra",
                "d:\\a\\repo\\net",
                "E:\\x",
            ],
            "C:\\work",
            pathmod=ntpath,
        )
        assert [drive_of(a, pathmod=ntpath) for a in found] == ["D:", "E:"]
        assert found[0].lower() == "d:\\a\\repo"
        assert found[1] == "E:\\x"

    def test_the_drive_of_the_root_has_none(self) -> None:
        assert drive_anchors(["C:\\a", "C:\\b"], "C:\\", pathmod=ntpath) == []

    def test_a_platform_without_drives_has_none(self) -> None:
        assert drive_anchors(["/a", "/b/c"], "/", pathmod=posixpath) == []

    def test_a_single_input_is_its_own_anchor(self) -> None:
        assert drive_anchors(["D:\\infra"], "C:\\work", pathmod=ntpath) == ["D:\\infra"]


class TestReportPaths:
    ROOT = "C:\\work\\repo"
    ANCHORS = ("D:\\a\\infra", "\\\\host\\share\\mods")

    def paths(self, *anchors: str) -> ReportPaths:
        return ReportPaths(self.ROOT, anchors or self.ANCHORS, pathmod=ntpath)

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("C:\\work\\repo\\a\\b.tf", "a/b.tf"),
            ("c:\\WORK\\repo\\a\\b.tf", "a/b.tf"),
            ("C:\\work\\repo", "."),
            ("C:\\work\\other\\main.tf", "../other/main.tf"),
        ],
    )
    def test_a_path_on_the_drive_of_the_root_is_relative_to_it(
        self, path: str, expected: str
    ) -> None:
        assert self.paths().posix(path) == expected

    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("D:\\a\\infra\\main.tf", "D/main.tf"),
            ("D:/a/infra/net/main.tf", "D/net/main.tf"),
            ("d:\\A\\Infra\\net\\main.tf", "D/net/main.tf"),
            ("D:\\a\\infra", "D"),
            ("\\\\host\\share\\mods\\vpc\\main.tf", "HOST/SHARE/vpc/main.tf"),
        ],
    )
    def test_a_path_on_another_drive_is_named_by_the_drive_and_its_place_under_the_anchor(
        self, path: str, expected: str
    ) -> None:
        assert self.paths().posix(path) == expected

    def test_a_path_above_the_anchor_is_named_from_the_top_of_its_drive(self) -> None:
        found = self.paths().posix("D:\\a\\modules\\net\\main.tf")
        assert found == "D/a/modules/net/main.tf"

    def test_a_path_on_a_drive_no_input_is_on_is_named_from_the_top_of_its_drive(self) -> None:
        assert self.paths().posix("E:\\x\\main.tf") == "E/x/main.tf"
        assert self.paths().posix("E:\\") == "E"

    def test_the_same_tree_has_the_same_names_wherever_it_is_checked_out(self) -> None:
        one = ReportPaths("C:\\work\\repo", ["D:\\a\\repo\\infra"], pathmod=ntpath)
        other = ReportPaths("C:\\home\\me", ["D:\\code\\x\\infra"], pathmod=ntpath)
        assert one.posix("D:\\a\\repo\\infra\\net\\main.tf") == "D/net/main.tf"
        assert other.posix("D:\\code\\x\\infra\\net\\main.tf") == "D/net/main.tf"

    def test_files_of_one_name_on_two_drives_get_two_names(self) -> None:
        paths = ReportPaths("C:\\work", ["D:\\infra", "E:\\infra"], pathmod=ntpath)
        names = {
            paths.posix("C:\\work\\main.tf"),
            paths.posix("D:\\infra\\main.tf"),
            paths.posix("E:\\infra\\main.tf"),
        }
        assert names == {"main.tf", "D/main.tf", "E/main.tf"}

    @pytest.mark.parametrize(
        "path",
        [
            "C:\\work\\repo\\a.tf",
            "C:\\Users\\me\\a.tf",
            "D:\\a\\infra\\a.tf",
            "D:\\other\\a.tf",
            "E:\\a.tf",
            "\\\\host\\share\\mods\\a.tf",
            "\\\\other\\share\\a.tf",
        ],
    )
    def test_no_name_is_absolute_or_has_a_backslash_or_a_colon(self, path: str) -> None:
        found = self.paths().posix(path)
        assert not found.startswith("/")
        assert not WINDOWS_DRIVE_PATH.match(found)
        assert "\\" not in found
        assert ":" not in found

    def test_a_posix_machine_names_every_path_relative_to_the_root(self) -> None:
        paths = ReportPaths("/work/repo", pathmod=posixpath)
        assert paths.posix("/work/repo/a/b.tf") == "a/b.tf"
        assert paths.posix("/work/other/b.tf") == "../other/b.tf"
        assert paths.posix("/b.tf") == "../../b.tf"

    def test_holds_covers_the_root_and_the_anchors_but_not_what_is_above_them(self) -> None:
        paths = self.paths()
        assert paths.holds("C:\\work\\repo\\a\\b.tf")
        assert paths.holds("D:\\a\\infra\\net\\main.tf")
        assert paths.holds("d:\\a\\INFRA")
        assert not paths.holds("C:\\work\\other\\main.tf")
        assert not paths.holds("D:\\a\\modules\\main.tf")
        assert not paths.holds("E:\\main.tf")

    def test_the_other_drives_are_the_drives_of_the_anchors_and_of_every_name_given(self) -> None:
        paths = self.paths("D:\\a\\infra", "\\\\host\\share\\mods")
        assert paths.other_drives == ("D", "HOST/SHARE")
        paths.posix("E:\\x\\main.tf")
        assert paths.other_drives == ("D", "E", "HOST/SHARE")

    def test_a_root_alone_has_no_other_drive(self) -> None:
        paths = ReportPaths(self.ROOT, pathmod=ntpath)
        paths.posix("C:\\work\\other\\main.tf")
        assert paths.other_drives == ()

    def test_a_name_given_by_the_resolved_paths_is_listed_on_the_paths_it_came_from(self) -> None:
        paths = self.paths("D:\\a\\infra")
        paths.resolved.posix("F:\\x\\main.tf")
        assert "F" in paths.other_drives

    def test_a_path_may_be_a_path_object(self, tmp_path: pathlib.Path) -> None:
        assert ReportPaths(tmp_path).posix(tmp_path / "a" / "b.tf") == "a/b.tf"
        assert ReportPaths(tmp_path).holds(tmp_path / "a")

    def test_the_resolved_paths_follow_a_link_in_the_root(self, tmp_path: pathlib.Path) -> None:
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        try:
            link.symlink_to(real, target_is_directory=True)
        except OSError:
            pytest.skip("symbolic links are not available")
        paths = ReportPaths(link)
        assert not paths.holds(real / "m" / "main.tf")
        assert paths.resolved.holds(real / "m" / "main.tf")
        assert paths.resolved.root == os.path.realpath(link)


class TestIsAbsolute:
    @pytest.mark.parametrize(
        "path", ["C:\\work", "C:/work", "\\\\server\\share\\x", "/work", "\\work"]
    )
    def test_a_path_from_the_root_of_a_drive_is_absolute_on_windows(self, path: str) -> None:
        assert is_absolute(path, pathmod=ntpath)

    @pytest.mark.parametrize("path", ["work", "..\\work", "C:work", "", "./x"])
    def test_a_path_from_somewhere_else_is_not(self, path: str) -> None:
        assert not is_absolute(path, pathmod=ntpath)

    def test_a_posix_path_is_absolute_when_it_starts_with_a_slash(self) -> None:
        assert is_absolute("/work", pathmod=posixpath)
        assert not is_absolute("work/x", pathmod=posixpath)
        assert not is_absolute("\\work", pathmod=posixpath)


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
