"""Self-tests of the hostile-input generators and of the child-process budget machinery."""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest
import yaml

from tests.hostile import generators as gen
from tests.hostile.support import (
    DEFAULT_BUDGET_SECONDS,
    Outcome,
    cli_scan,
    run_python,
    scan_in_child,
)


class TestHelmGenerator:
    @pytest.mark.parametrize("shape", gen.HELM_SHAPES)
    def test_the_template_opens_an_action_and_never_closes_it(
        self, tmp_path: Path, shape: str
    ) -> None:
        chart_yaml = gen.unterminated_helm_chart(tmp_path, shape, units=2_000)
        template = (chart_yaml.parent / "templates" / "configmap.yaml").read_text(encoding="utf-8")
        assert "{{" in template
        assert "}}" not in template
        assert chart_yaml.name == "Chart.yaml"
        assert (chart_yaml.parent / "values.yaml").is_file()

    def test_the_units_parameter_scales_the_template(self) -> None:
        small = gen.helm_template_body("braces", 100)
        large = gen.helm_template_body("braces", 10_000)
        assert len(large) == 100 * len(small)

    def test_every_shape_has_a_default_size_and_the_defaults_are_large(self) -> None:
        assert set(gen.HELM_DEFAULT_UNITS) == set(gen.HELM_SHAPES)
        for shape in gen.HELM_SHAPES:
            assert len(gen.helm_template_body(shape, gen.HELM_DEFAULT_UNITS[shape])) >= 80_000

    def test_an_unknown_shape_is_rejected(self, tmp_path: Path) -> None:
        with pytest.raises(ValueError, match="unknown Helm shape"):
            gen.unterminated_helm_chart(tmp_path, "nope")

    def test_the_chart_is_valid_yaml_apart_from_the_template(self, tmp_path: Path) -> None:
        chart_yaml = gen.unterminated_helm_chart(tmp_path, "if_blocks", units=500)
        assert yaml.safe_load(chart_yaml.read_text(encoding="utf-8"))["name"] == "hostile"


class TestSymlinkGenerator:
    def test_links_point_out_of_the_scan_root_and_round_in_circles(self, tmp_path: Path) -> None:
        tree = gen.symlink_escape_tree(tmp_path)
        assert (tree.scan_root / "main.tf").is_file()
        assert not (tree.scan_root / "main.tf").is_symlink()
        escape_file = tree.scan_root / "escape-file.tf"
        assert escape_file.is_symlink()
        assert escape_file.resolve() == (tree.outside_dir / "secret.tf").resolve()
        assert (tree.scan_root / "escape-dir").resolve() == tree.outside_dir.resolve()
        assert (tree.scan_root / "loop-to-root").resolve() == tree.scan_root.resolve()
        cycle = tree.scan_root / "cycle-a"
        assert cycle.is_symlink()
        with pytest.raises(OSError):
            os.stat(cycle)  # following the cycle fails with ELOOP
        assert all(link.is_symlink() for link in tree.links)
        assert len(tree.links) == 5

    def test_the_outside_resource_is_named_so_a_leak_is_recognisable(self, tmp_path: Path) -> None:
        tree = gen.symlink_escape_tree(tmp_path)
        assert gen.OUTSIDE_RESOURCE in (tree.outside_dir / "secret.tf").read_text(encoding="utf-8")
        assert gen.OUTSIDE_RESOURCE not in (tree.scan_root / "main.tf").read_text(encoding="utf-8")


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
class TestFifoGenerator:
    def test_the_tree_holds_a_real_pipe_with_a_terraform_name(self, tmp_path: Path) -> None:
        root = gen.fifo_tree(tmp_path)
        assert gen.is_fifo(root / "pipe.tf")
        assert not gen.is_fifo(root / "main.tf")
        assert (root / "pipe.tf").name.endswith(".tf")

    def test_the_pipe_is_never_opened_by_the_generator_or_its_test(self, tmp_path: Path) -> None:
        """Opening it for reading would block this test process, so only lstat is used."""
        root = gen.fifo_tree(tmp_path)
        assert os.lstat(root / "pipe.tf").st_size == 0


class TestHugeLineGenerators:
    def test_plain_lines_have_the_requested_size_on_one_line(self, tmp_path: Path) -> None:
        path = gen.huge_line_dockerfile(tmp_path, size=100_000)
        lines = path.read_text(encoding="utf-8").splitlines()
        assert len(lines) == 2
        assert len(lines[1]) == len("RUN ") + 100_000

    def test_the_backtracking_line_has_no_pipe(self, tmp_path: Path) -> None:
        text = gen.backtracking_dockerfile(tmp_path, repeats=1_000).read_text(encoding="utf-8")
        assert text.count("curl x ") == 1_000
        assert "|" not in text

    def test_every_format_gets_one_long_line(self, tmp_path: Path) -> None:
        for make in (gen.huge_line_terraform, gen.huge_line_mcp, gen.huge_line_kubernetes):
            path = make(tmp_path, 50_000)
            longest = max(len(line) for line in path.read_text(encoding="utf-8").splitlines())
            assert longest >= 50_000, make.__name__


class TestNestingGenerators:
    def test_json_has_the_requested_depth_and_is_balanced(self, tmp_path: Path) -> None:
        text = gen.nested_json(tmp_path, depth=500).read_text(encoding="utf-8")
        assert gen.json_depth(text) == 500
        assert text.count("[") == text.count("]") == 500

    def test_the_json_depth_helper_ignores_brackets_inside_strings(self) -> None:
        assert gen.json_depth('{"a":"[[[[","b":[1,{"c":[]}]}') == 4
        assert gen.json_depth('{"a":"\\"[["}') == 1

    def test_yaml_flow_nesting_is_as_deep_as_requested(self, tmp_path: Path) -> None:
        text = gen.nested_yaml_flow(tmp_path, depth=300).read_text(encoding="utf-8")
        assert text.count("[") == 300

    def test_yaml_block_nesting_indents_one_more_space_per_line(self, tmp_path: Path) -> None:
        lines = gen.nested_yaml_block(tmp_path, depth=50).read_text(encoding="utf-8").splitlines()
        assert [len(line) - len(line.lstrip()) for line in lines] == list(range(50))


class TestAliasBomb:
    def test_the_document_loads_quickly_and_shares_one_object_per_level(self) -> None:
        doc = yaml.safe_load(gen.yaml_alias_bomb())
        assert doc["kind"] == "ConfigMap"
        data = doc["data"]
        assert data["l9"][0] is data["l9"][1]
        assert data["l9"][0] is data["l8"]

    def test_the_theoretical_expansion_is_exponential(self) -> None:
        assert gen.alias_bomb_expansion() == 9**10
        assert gen.alias_bomb_expansion(2, 3) == 27

    def test_a_small_bomb_really_expands_to_the_computed_size(self) -> None:
        doc = yaml.safe_load(gen.yaml_alias_bomb(levels=3, fanout=4))

        def leaves(node: object) -> int:
            return sum(leaves(c) for c in node) if isinstance(node, list) else 1

        assert leaves(doc["data"]["l3"]) == 4**4
        assert gen.alias_bomb_expansion(3, 4) == 4**4

    def test_the_default_document_stays_small_on_disk(self, tmp_path: Path) -> None:
        assert gen.write_alias_bomb(tmp_path).stat().st_size < 2_000

    def test_every_alias_is_defined_before_it_is_used(self) -> None:
        text = gen.yaml_alias_bomb()
        defined: set[str] = set()
        for line in text.splitlines():
            for anchor in re.findall(r"&(\w+)", line):
                defined.add(anchor)
            for alias in re.findall(r"\*(\w+)", line):
                assert alias in defined


class TestBudgetMachinery:
    def test_a_hang_is_reported_as_a_timeout_not_waited_for(self) -> None:
        outcome = run_python("import time; time.sleep(30)", budget=1.0)
        assert outcome.timed_out
        assert outcome.seconds < 5

    def test_a_finished_child_is_reported_with_its_exit_status(self) -> None:
        assert run_python("pass", budget=10.0).status == "ok"
        assert run_python("raise SystemExit(3)", budget=10.0).status == "error"

    def test_a_benign_input_is_scanned_cleanly_in_the_child(self, tmp_path: Path) -> None:
        path = tmp_path / "main.tf"
        path.write_text(gen._tf("fine"), encoding="utf-8")
        outcome = scan_in_child(path)
        assert outcome.clean and outcome.status == "ok"
        assert outcome.nodes == 1
        assert 0 < outcome.peak_mb < 1500
        assert outcome.seconds < DEFAULT_BUDGET_SECONDS

    def test_a_missing_file_is_a_clean_error_not_a_crash(self, tmp_path: Path) -> None:
        outcome = scan_in_child(tmp_path / "absent.tf")
        assert outcome.status == "error"
        assert outcome.exception == "FileNotFoundError"
        assert outcome.threatcode_error

    def test_an_unexpected_exception_type_is_not_counted_as_clean(self) -> None:
        crashed = Outcome("error", 0.1, exception="RecursionError", threatcode_error=False)
        assert not crashed.clean
        assert Outcome("error", 0.1, exception="ParseError", threatcode_error=True).clean
        assert not Outcome("timeout", 10.0).clean

    def test_the_cli_runner_reports_a_nonexistent_scan_target_with_an_exit_code(
        self, tmp_path: Path
    ) -> None:
        run = cli_scan(tmp_path / "does-not-exist", budget=30.0)
        assert run.exit_code == 2  # a path that does not exist is an input error
        assert sys.executable
