"""Tests for threatcode.discovery: units, pruning and the hardened walker."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest

from threatcode.discovery import (
    HCL_MODULE,
    HELM_CHART,
    STDIN_PATH,
    Discovery,
    ScanUnit,
    classify_name,
    discover,
    is_plan_name,
    scan_root,
)
from threatcode.exceptions import UsageError

TF = 'resource "aws_s3_bucket" "b" {\n  bucket = "b"\n}\n'
CHART = "apiVersion: v2\nname: demo\nversion: 0.1.0\n"


def write(root: Path, relative: str, text: str = "x\n") -> Path:
    path = root / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


def relpaths(found: Discovery) -> list[str]:
    return [unit.relpath for unit in found.units]


def kinds(found: Discovery) -> dict[str, str]:
    return {unit.relpath: unit.kind for unit in found.units}


class TestUnits:
    def test_a_directory_of_terraform_files_is_one_module_unit(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", TF)
        write(tmp_path, "network.tf", TF)
        write(tmp_path, "extra.tf.json", "{}")
        write(tmp_path, "tools.tofu", TF)
        found = discover([str(tmp_path)])
        assert len(found.units) == 1
        unit = found.units[0]
        assert unit.kind == HCL_MODULE
        assert unit.relpath == "."
        assert unit.path == tmp_path
        assert sorted(unit.files) == ["extra.tf.json", "main.tf", "network.tf", "tools.tofu"]
        assert found.files_discovered == 4

    def test_each_directory_with_terraform_files_is_its_own_module(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", TF)
        write(tmp_path, "modules/net/main.tf", TF)
        found = discover([str(tmp_path)])
        assert kinds(found) == {".": HCL_MODULE, "modules/net": HCL_MODULE}

    def test_a_chart_is_one_unit_and_owns_templates_charts_and_values(self, tmp_path: Path) -> None:
        write(tmp_path, "chart/Chart.yaml", CHART)
        write(tmp_path, "chart/values.yaml", "a: 1\n")
        write(tmp_path, "chart/values-prod.yaml", "a: 2\n")
        write(tmp_path, "chart/templates/deploy.yaml", "kind: Deployment\n")
        write(tmp_path, "chart/charts/sub/Chart.yaml", CHART)
        write(tmp_path, "chart/charts/sub/templates/x.yaml", "kind: Pod\n")
        found = discover([str(tmp_path)])
        assert kinds(found) == {"chart/Chart.yaml": HELM_CHART}
        assert found.files_discovered == 1

    def test_a_chart_does_not_hide_a_dockerfile_next_to_it(self, tmp_path: Path) -> None:
        write(tmp_path, "app/Chart.yaml", CHART)
        write(tmp_path, "app/Dockerfile", "FROM scratch\n")
        assert set(relpaths(discover([str(tmp_path)]))) == {"app/Chart.yaml", "app/Dockerfile"}

    def test_other_candidates_are_one_unit_each(self, tmp_path: Path) -> None:
        for name in [
            "plan.json",
            "stack.yml",
            "k8s/app.yaml",
            "t.template",
            "t.cfn",
            "Dockerfile",
            "api/Dockerfile.dev",
            "web.dockerfile",
            "Containerfile",
            ".mcp.json",
        ]:
            write(tmp_path, name)
        found = discover([str(tmp_path)])
        assert len(found.units) == 10
        assert {unit.kind for unit in found.units} == {"file"}

    def test_non_candidates_are_not_units(self, tmp_path: Path) -> None:
        for name in ["README.md", "main.py", "notes.txt", "values.tfvars", "Makefile"]:
            write(tmp_path, name)
        assert discover([str(tmp_path)]).units == []

    def test_units_are_sorted_by_relative_path_with_posix_separators(self, tmp_path: Path) -> None:
        write(tmp_path, "z/b.yaml")
        write(tmp_path, "a/c.json")
        write(tmp_path, "a/b.yml")
        assert relpaths(discover([str(tmp_path)])) == ["a/b.yml", "a/c.json", "z/b.yaml"]

    def test_discovery_is_repeatable(self, tmp_path: Path) -> None:
        for name in ["m/main.tf", "c/Chart.yaml", "a.json", "b/k.yaml"]:
            write(tmp_path, name, CHART if name.endswith("Chart.yaml") else "x\n")
        first = [(u.relpath, u.kind, u.files) for u in discover([str(tmp_path)]).units]
        second = [(u.relpath, u.kind, u.files) for u in discover([str(tmp_path)]).units]
        assert first == second


class TestClassification:
    @pytest.mark.parametrize(
        ("name", "candidate", "by_name"),
        [
            ("Dockerfile", True, True),
            ("Dockerfile.prod", True, True),
            ("Containerfile", True, True),
            ("Chart.yaml", True, True),
            (".mcp.json", True, True),
            ("claude_desktop_config.json", True, True),
            ("plan.json", True, True),
            ("tfplan.json", True, True),
            ("prod.tfplan.json", True, True),
            ("plan-prod.json", True, True),
            ("Plan.JSON", True, True),
            ("planning.json", True, False),
            ("plant.json", True, False),
            ("explain.json", True, False),
            ("package.json", True, False),
            ("deploy.yml", True, False),
            ("README.md", False, False),
            ("chart.yaml", True, False),
        ],
    )
    def test_classify_name(self, name: str, candidate: bool, by_name: bool) -> None:
        assert classify_name(name) == (candidate, by_name)


class TestPlanNames:
    @pytest.mark.parametrize(
        "name",
        [
            "plan.json",
            "tfplan.json",
            "a.tfplan.json",
            "plan-prod.json",
            "plan_2.json",
            "x_plan.json",
        ],
    )
    def test_the_usual_plan_names_are_recognised(self, name: str) -> None:
        assert is_plan_name(name)

    @pytest.mark.parametrize(
        "name",
        [
            "plan.yaml",
            "plan",
            "planning.json",
            "plant.json",
            "explain.json",
            "plan.json.bak",
            "tf.json",
        ],
    )
    def test_other_names_are_not(self, name: str) -> None:
        assert not is_plan_name(name)

    def test_a_plan_over_the_size_cap_stays_a_unit_so_the_failure_is_loud(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "plan.json", "x" * 200)
        found = discover([str(tmp_path)], max_file_bytes=100)
        assert relpaths(found) == ["plan.json"]
        assert found.units[0].by_name
        assert found.oversized == []


class TestPruning:
    @pytest.mark.parametrize(
        "directory",
        [
            ".git",
            "node_modules",
            ".terraform",
            "vendor",
            "__pycache__",
            ".venv",
            "venv",
            "dist",
            "build",
            ".tox",
            ".mypy_cache",
            ".github",
            ".circleci",
        ],
    )
    def test_skipped_and_dot_directories_are_pruned(self, tmp_path: Path, directory: str) -> None:
        write(tmp_path, "real.yaml")
        write(tmp_path, f"{directory}/hidden.yaml")
        write(tmp_path, f"{directory}/deep/main.tf", TF)
        assert relpaths(discover([str(tmp_path)])) == ["real.yaml"]

    @pytest.mark.parametrize("directory", [".cursor", ".vscode"])
    def test_mcp_config_dot_directories_are_entered(self, tmp_path: Path, directory: str) -> None:
        write(tmp_path, f"{directory}/mcp.json", "{}")
        write(tmp_path, f"{directory}/settings.json", "{}")
        assert f"{directory}/mcp.json" in relpaths(discover([str(tmp_path)]))

    def test_naming_a_pruned_directory_walks_it(self, tmp_path: Path) -> None:
        write(tmp_path, "node_modules/x.yaml")
        found = discover([str(tmp_path / "node_modules")])
        assert relpaths(found) == ["x.yaml"]


class TestSymlinksAndSpecialFiles:
    def test_file_and_directory_links_are_skipped_and_counted(self, tmp_path: Path) -> None:
        outside = tmp_path / "outside"
        write(outside, "secret.tf", TF)
        write(outside, "leak.yaml")
        root = tmp_path / "scan"
        write(root, "main.tf", TF)
        (root / "escape-file.yaml").symlink_to(outside / "leak.yaml")
        (root / "escape-dir").symlink_to(outside)
        found = discover([str(root)])
        assert relpaths(found) == ["."]
        assert found.units[0].files == ("main.tf",)
        assert found.symlinks_skipped == 2

    def test_link_cycles_cannot_loop(self, tmp_path: Path) -> None:
        root = tmp_path / "scan"
        write(root, "a.yaml")
        (root / "loop").symlink_to(".")
        (root / "cycle-a").symlink_to("cycle-b")
        (root / "cycle-b").symlink_to("cycle-a")
        found = discover([str(root)])
        assert relpaths(found) == ["a.yaml"]
        assert found.symlinks_skipped == 3

    def test_a_link_to_a_terraform_file_is_not_part_of_the_module(self, tmp_path: Path) -> None:
        real = write(tmp_path / "elsewhere", "other.tf", TF)
        root = tmp_path / "scan"
        write(root, "main.tf", TF)
        (root / "linked.tf").symlink_to(real)
        found = discover([str(root)])
        assert found.units[0].files == ("main.tf",)

    def test_a_broken_link_is_skipped_not_an_error(self, tmp_path: Path) -> None:
        write(tmp_path, "a.yaml")
        (tmp_path / "dangling.yaml").symlink_to(tmp_path / "missing.yaml")
        found = discover([str(tmp_path)])
        assert relpaths(found) == ["a.yaml"]
        assert found.symlinks_skipped == 1
        assert found.errors == []

    def test_a_symlink_named_directly_is_followed(self, tmp_path: Path) -> None:
        real = write(tmp_path / "real", "plan.json", "{}")
        link = tmp_path / "link.json"
        link.symlink_to(real)
        found = discover([str(link)])
        assert len(found.units) == 1
        assert found.units[0].explicit is True
        assert found.symlinks_skipped == 0

    def test_a_directory_symlink_named_directly_is_walked(self, tmp_path: Path) -> None:
        write(tmp_path / "real", "a.yaml")
        link = tmp_path / "linked"
        link.symlink_to(tmp_path / "real")
        assert relpaths(discover([str(link)])) == ["a.yaml"]

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
    def test_a_named_pipe_is_counted_and_never_opened(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", TF)
        os.mkfifo(tmp_path / "pipe.tf")
        os.mkfifo(tmp_path / "pipe.yaml")
        found = discover([str(tmp_path)])
        assert found.special_skipped == 2
        assert found.units[0].files == ("main.tf",)
        assert relpaths(found) == ["."]

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
    def test_a_named_pipe_given_directly_is_an_error_not_a_hang(self, tmp_path: Path) -> None:
        os.mkfifo(tmp_path / "pipe.tf")
        found = discover([str(tmp_path / "pipe.tf")])
        assert found.units == []
        assert [e["code"] for e in found.errors] == ["discovery.not_regular"]

    @pytest.mark.skipif(
        sys.platform == "win32", reason="no permission bit makes a directory unreadable on Windows"
    )
    def test_an_unreadable_subdirectory_is_recorded_and_the_rest_is_found(
        self, tmp_path: Path
    ) -> None:
        if os.geteuid() == 0:
            pytest.skip("root can read every directory")
        write(tmp_path, "a.yaml")
        locked = tmp_path / "locked"
        write(locked, "b.yaml")
        locked.chmod(0)
        try:
            found = discover([str(tmp_path)])
        finally:
            locked.chmod(0o700)
        assert relpaths(found) == ["a.yaml"]
        assert [e["code"] for e in found.errors] == ["discovery.unreadable"]
        assert "locked" in found.errors[0]["file"]


class TestSizeCap:
    def test_a_walked_generic_candidate_over_the_cap_is_set_aside(self, tmp_path: Path) -> None:
        write(tmp_path, "small.json", "{}")
        write(tmp_path, "huge.json", "x" * 200)
        found = discover([str(tmp_path)], max_file_bytes=100)
        assert relpaths(found) == ["small.json"]
        assert found.oversized == ["huge.json"]
        assert found.files_discovered == 2

    def test_a_file_identified_by_name_stays_a_unit_so_its_failure_is_loud(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "Dockerfile", "x" * 200)
        found = discover([str(tmp_path)], max_file_bytes=100)
        assert relpaths(found) == ["Dockerfile"]
        assert found.oversized == []


class TestNamedPaths:
    def test_a_missing_path_is_a_usage_error(self, tmp_path: Path) -> None:
        with pytest.raises(UsageError, match="path not found"):
            discover([str(tmp_path / "nope")])

    def test_no_paths_is_a_usage_error(self) -> None:
        with pytest.raises(UsageError, match="no input"):
            discover([])

    def test_a_named_terraform_file_is_parsed_alone(self, tmp_path: Path) -> None:
        write(tmp_path, "main.tf", TF)
        write(tmp_path, "other.tf", TF)
        found = discover([str(tmp_path / "main.tf")])
        assert len(found.units) == 1
        assert found.units[0].kind == "file"
        assert found.units[0].relpath == "main.tf"
        assert found.units[0].explicit and found.units[0].by_name

    def test_a_named_terraform_file_inside_a_named_directory_is_not_read_twice(
        self, tmp_path: Path
    ) -> None:
        write(tmp_path, "main.tf", TF)
        found = discover([str(tmp_path), str(tmp_path / "main.tf")])
        assert [u.kind for u in found.units] == [HCL_MODULE]

    def test_the_same_directory_named_twice_gives_each_unit_once(self, tmp_path: Path) -> None:
        write(tmp_path, "a.yaml")
        found = discover([str(tmp_path), str(tmp_path)])
        assert relpaths(found) == ["a.yaml"]

    def test_a_named_file_is_marked_explicit_even_when_also_walked(self, tmp_path: Path) -> None:
        file = write(tmp_path, "a.yaml")
        found = discover([str(tmp_path), str(file)])
        assert len(found.units) == 1
        assert found.units[0].explicit

    def test_a_named_chart_yaml_is_a_chart_unit(self, tmp_path: Path) -> None:
        chart = write(tmp_path, "c/Chart.yaml", CHART)
        found = discover([str(chart)])
        assert found.units[0].kind == HELM_CHART
        assert found.units[0].base_dir == chart.parent

    def test_relative_paths_are_resolved_against_the_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        write(tmp_path, "sub/a.yaml")
        monkeypatch.chdir(tmp_path)
        found = discover(["sub"])
        assert found.units[0].path == tmp_path / "sub" / "a.yaml"
        assert found.units[0].relpath == "a.yaml"


class TestScanRoot:
    def test_a_file_contributes_its_parent_directory(self, tmp_path: Path) -> None:
        file = write(tmp_path, "a/b/main.tf", TF)
        assert scan_root([str(file)]) == file.parent

    def test_a_directory_is_its_own_root(self, tmp_path: Path) -> None:
        (tmp_path / "infra").mkdir()
        assert scan_root([str(tmp_path / "infra")]) == tmp_path / "infra"

    def test_several_paths_have_their_common_parent_as_root(self, tmp_path: Path) -> None:
        a = write(tmp_path, "a/x.tf", TF)
        b = write(tmp_path, "b/y.tf", TF)
        assert scan_root([str(a), str(b)]) == tmp_path

    def test_stdin_means_the_current_directory(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.chdir(tmp_path)
        assert scan_root([STDIN_PATH]) == Path.cwd()

    def test_relpaths_follow_the_root(self, tmp_path: Path) -> None:
        a = write(tmp_path, "a/x.yaml")
        b = write(tmp_path, "b/y.yaml")
        found = discover([str(a), str(b)])
        assert found.root == tmp_path
        assert relpaths(found) == ["a/x.yaml", "b/y.yaml"]


class TestStdinUnit:
    def test_stdin_becomes_a_unit_named_for_format_detection(self, tmp_path: Path) -> None:
        saved = write(tmp_path / "tmp", "main.tf", TF)
        found = discover([STDIN_PATH], root=tmp_path, stdin_path=saved, stdin_name="main.tf")
        (unit,) = found.units
        assert unit.stdin and unit.explicit and unit.by_name
        assert unit.relpath == "main.tf"
        assert unit.path == saved

    def test_stdin_without_content_is_a_usage_error(self) -> None:
        with pytest.raises(UsageError, match="standard input"):
            discover([STDIN_PATH])


class TestScanUnit:
    def test_base_dir_and_base_rel_for_a_module_and_a_file(self, tmp_path: Path) -> None:
        module = ScanUnit(path=tmp_path / "net", relpath="net", kind=HCL_MODULE)
        file = ScanUnit(path=tmp_path / "net" / "a.yaml", relpath="net/a.yaml")
        assert module.base_dir == tmp_path / "net"
        assert module.base_rel.as_posix() == "net"
        assert file.base_dir == tmp_path / "net"
        assert file.base_rel.as_posix() == "net"

    def test_the_unit_is_parsed_slot_starts_empty(self, tmp_path: Path) -> None:
        assert ScanUnit(path=tmp_path, relpath=".").parsed is None
