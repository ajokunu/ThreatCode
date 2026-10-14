"""How a report names files on Windows, checked with ``ntpath`` so every platform can run it.

A Windows path has a drive letter and backslashes, and two paths on different drives have no
relative form.
The same code must give the answer Windows needs there and the answer a POSIX machine needs for
a path that came from a Windows report.
"""

from __future__ import annotations

import ntpath
import posixpath

import pytest

from threatcode.formatters import RepoPaths
from threatcode.formatters._utils import display_path, repo_path

CWD = "C:\\work\\repo"


class TestRepoPathOnWindows:
    @pytest.mark.parametrize(
        ("path", "expected"),
        [
            ("C:\\work\\repo\\tests\\x.tf", "tests/x.tf"),
            ("C:/work/repo/tests/x.tf", "tests/x.tf"),
            ("c:\\Work\\Repo\\tests\\x.tf", "tests/x.tf"),
            ("C:\\work\\repo\\x.tf", "x.tf"),
            ("C:\\work\\repo", "."),
        ],
    )
    def test_a_path_inside_the_current_directory_becomes_relative(
        self, path: str, expected: str
    ) -> None:
        assert repo_path(path, pathmod=ntpath, cwd=CWD) == expected

    @pytest.mark.parametrize(
        "path",
        ["C:\\Users\\me\\x.tf", "C:\\work\\other\\x.tf", "D:\\a\\repo\\x.tf", "C:\\x.tf"],
    )
    def test_a_path_outside_it_or_on_another_drive_is_reduced_to_its_name(self, path: str) -> None:
        assert repo_path(path, pathmod=ntpath, cwd=CWD) == "x.tf"

    def test_a_relative_path_gets_the_prefix_and_loses_its_backslashes(self) -> None:
        assert repo_path("modules\\vpc\\main.tf", "infra", pathmod=ntpath, cwd=CWD) == (
            "infra/modules/vpc/main.tf"
        )

    def test_a_drive_path_from_a_windows_report_is_not_a_place_on_a_posix_machine(self) -> None:
        assert repo_path("C:\\work\\repo\\tests\\x.tf", pathmod=posixpath, cwd="/work/repo") == (
            "x.tf"
        )

    def test_a_posix_path_inside_the_current_directory_is_relative_on_a_posix_machine(self) -> None:
        assert repo_path("/work/repo/tests/x.tf", pathmod=posixpath, cwd="/work/repo") == (
            "tests/x.tf"
        )


class TestRepoPathsOnWindows:
    @pytest.fixture
    def paths(self) -> RepoPaths:
        return RepoPaths(CWD + "\\infra", CWD, anchored=True, pathmod=ntpath)

    def test_an_absolute_path_inside_the_repository_is_made_relative(
        self, paths: RepoPaths
    ) -> None:
        assert paths.locate("C:\\work\\repo\\infra\\prod\\main.tf") == "infra/prod/main.tf"
        assert paths.locate("c:/work/repo/infra/main.tf") == "infra/main.tf"
        assert not paths.outside

    def test_a_path_relative_to_the_scan_root_is_placed_under_it(self, paths: RepoPaths) -> None:
        assert paths.locate("prod\\main.tf") == "infra/prod/main.tf"
        assert paths.locate("prod/main.tf") == "infra/prod/main.tf"

    def test_the_repository_root_is_a_dot(self, paths: RepoPaths) -> None:
        assert paths.locate("C:\\work\\repo") == "."

    @pytest.mark.parametrize("path", ["C:\\Users\\me\\vpc.tf", "D:\\a\\repo\\vpc.tf"])
    def test_a_path_elsewhere_is_reduced_to_its_name_and_counted(
        self, paths: RepoPaths, path: str
    ) -> None:
        assert paths.locate(path) == "vpc.tf"
        assert paths.outside == {path}

    def test_a_path_that_climbs_out_never_keeps_its_dots(self, paths: RepoPaths) -> None:
        located = paths.locate("..\\..\\..\\etc\\passwd")
        assert ".." not in located.split("/")
        assert paths.outside

    def test_the_uri_is_percent_encoded(self, paths: RepoPaths) -> None:
        assert paths.uri("C:\\work\\repo\\infra\\my dir\\main.tf") == "infra/my%20dir/main.tf"

    def test_a_drive_path_on_a_posix_machine_is_outside_the_repository(self) -> None:
        paths = RepoPaths("/work/repo/infra", "/work/repo", anchored=True, pathmod=posixpath)
        assert paths.locate("C:\\work\\repo\\infra\\main.tf") == "main.tf"
        assert paths.outside == {"C:\\work\\repo\\infra\\main.tf"}


class TestDisplayPathOnWindows:
    def test_a_relative_path_is_tidied_and_written_with_slashes(self) -> None:
        assert display_path("infra\\main.tf", cwd=CWD, pathmod=ntpath) == "infra/main.tf"
        assert display_path(".\\infra\\", cwd=CWD, pathmod=ntpath) == "infra"

    def test_an_absolute_path_inside_the_current_directory_becomes_relative(self) -> None:
        assert display_path(CWD + "\\infra\\main.tf", cwd=CWD, pathmod=ntpath) == "infra/main.tf"
        assert display_path(CWD, cwd=CWD, pathmod=ntpath) == "repo"

    def test_an_absolute_path_elsewhere_never_carries_its_parents(self) -> None:
        assert display_path("C:\\home\\me\\private\\stack", cwd=CWD, pathmod=ntpath) == "stack"
        assert display_path("D:\\other\\stack\\main.tf", cwd=CWD, pathmod=ntpath) == "main.tf"

    def test_a_path_on_another_drive_is_shown_from_the_scan_root_when_it_is_inside_it(self) -> None:
        root = "D:\\other"
        shown = display_path("D:\\other\\stack\\main.tf", cwd=CWD, root=root, pathmod=ntpath)
        assert shown == "stack/main.tf"

    def test_the_root_of_a_drive_is_named_by_the_drive(self) -> None:
        assert display_path("D:\\", cwd=CWD, pathmod=ntpath) == "D:"

    def test_the_root_of_a_posix_file_system_is_a_slash(self) -> None:
        assert display_path("/", cwd="/work/repo", pathmod=posixpath) == "/"
