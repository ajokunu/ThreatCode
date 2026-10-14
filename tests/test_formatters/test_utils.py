"""Tests for the helpers the formatters share: how a report names what it scanned."""

from __future__ import annotations

import os
from pathlib import Path

import pytest

from threatcode.formatters._utils import ELLIPSIS, display_path, input_summary


class TestDisplayPath:
    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("infra", "infra"),
            ("infra/", "infra"),
            ("./infra", "infra"),
            ("./infra/../infra/main.tf", "infra/main.tf"),
            ("examples/aws-webapp", "examples/aws-webapp"),
            ("deploy/app.yaml", "deploy/app.yaml"),
            ("../sibling/infra", "../sibling/infra"),
        ],
    )
    def test_a_relative_path_is_kept_as_typed_and_tidied(self, raw: str, expected: str) -> None:
        assert display_path(raw, cwd="/work/repo") == expected

    @pytest.mark.parametrize("raw", [".", "./", "", ".."])
    def test_the_current_directory_is_named_never_dot(self, raw: str) -> None:
        assert display_path(raw, cwd="/work/repo") == ("work" if raw == ".." else "repo")

    def test_an_absolute_path_inside_the_current_directory_becomes_relative(self) -> None:
        assert display_path("/work/repo/infra/main.tf", cwd="/work/repo") == "infra/main.tf"
        assert display_path("/work/repo", cwd="/work/repo") == "repo"
        assert display_path("/work/repo/", cwd="/work/repo") == "repo"

    def test_an_absolute_path_elsewhere_never_carries_its_parents(self) -> None:
        assert display_path("/home/someone/private/stack", cwd="/work/repo") == "stack"
        assert display_path("/home/someone/private/stack/main.tf", cwd="/work/repo") == "main.tf"

    def test_an_absolute_path_elsewhere_is_shown_from_the_scan_root_when_there_is_one(self) -> None:
        root = "/home/someone/private"
        assert display_path("/home/someone/private/a/main.tf", cwd="/work/repo", root=root) == (
            "a/main.tf"
        )
        assert display_path(root, cwd="/work/repo", root=root) == "private"
        assert display_path("/elsewhere/x.tf", cwd="/work/repo", root=root) == "x.tf"

    def test_the_filesystem_root_is_named_by_what_it_is_called(self) -> None:
        # a slash, and the drive on Windows (test_windows_paths has the Windows form)
        called = os.path.splitdrive(os.path.abspath("/"))[0] or "/"
        assert display_path("/", cwd="/work/repo") == called

    def test_the_default_is_the_real_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert display_path(".") == tmp_path.name
        assert display_path(str(tmp_path / "x" / "main.tf")) == "x/main.tf"


class TestInputSummary:
    def test_one_input_is_shown_as_it_is(self) -> None:
        assert input_summary("examples/aws-webapp") == "examples/aws-webapp"

    def test_two_short_inputs_are_both_named(self) -> None:
        assert input_summary("Dockerfile, infra") == "Dockerfile and infra"

    def test_more_inputs_are_the_first_and_a_count(self) -> None:
        assert input_summary("a.tf, b.tf, c.tf") == "a.tf and 2 more"

    def test_two_long_inputs_are_the_first_and_a_count(self) -> None:
        label = "deploy/production/eu-west-1/network, deploy/production/eu-west-1/compute"
        assert input_summary(label, limit=60) == ("deploy/production/eu-west-1/network and 1 more")

    def test_a_long_input_keeps_its_end(self) -> None:
        out = input_summary("a/very/deep/directory/structure/with/the-stack", limit=20)
        assert len(out) == 20 and out.startswith(ELLIPSIS) and out.endswith("the-stack")

    def test_no_input_is_nothing(self) -> None:
        assert input_summary("") == ""
