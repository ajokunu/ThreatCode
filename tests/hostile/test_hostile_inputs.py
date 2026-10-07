"""Hostile inputs against the parsers and the directory walker, each under a wall-clock budget.

Every scan runs in a child process (see ``support.py``), so a hang, a stack overflow or a leak
fails one test instead of taking the run down. Inputs the parsers already survive are regression
guards and run now. Inputs that stall or crash today are written now and pending on the package
that fixes them, each with a positive control so a pending test cannot pass by finding nothing.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from pathlib import Path

import pytest

from tests.helpers.pending import pending
from tests.hostile import generators as gen
from tests.hostile.support import (
    DEFAULT_BUDGET_SECONDS,
    DEFAULT_MEMORY_BUDGET_MB,
    cli_scan,
    scan_in_child,
)

# Two seconds of parsing is already far too long for a 5 MB file; ten is the hard budget.
FAST_SECONDS = 5.0


class TestSurvivedToday:
    """These inputs are handled in well under a second today; the tests keep it that way."""

    @pytest.mark.parametrize(
        "make",
        [
            gen.huge_line_dockerfile,
            gen.huge_line_terraform,
            gen.huge_line_mcp,
            gen.huge_line_kubernetes,
        ],
        ids=lambda f: f.__name__,
    )
    def test_a_multi_megabyte_line_is_scanned_within_budget(
        self, tmp_path: Path, make: Callable[..., Path]
    ) -> None:
        path = make(tmp_path)
        assert max(len(line) for line in path.read_text(encoding="utf-8").splitlines()) >= 3_000_000
        outcome = scan_in_child(path)
        assert outcome.status == "ok", f"{outcome.exception}: {outcome.message}"
        assert outcome.seconds < FAST_SECONDS
        assert outcome.peak_mb < DEFAULT_MEMORY_BUDGET_MB
        assert outcome.nodes >= 1

    def test_a_yaml_alias_bomb_is_not_expanded(self, tmp_path: Path) -> None:
        """Nine levels of nine aliases is 387 million strings if anything walks the document."""
        path = gen.write_alias_bomb(tmp_path)
        assert gen.alias_bomb_expansion() > 100_000_000
        outcome = scan_in_child(path)
        assert outcome.status == "ok", f"{outcome.exception}: {outcome.message}"
        assert outcome.seconds < FAST_SECONDS
        assert outcome.peak_mb < DEFAULT_MEMORY_BUDGET_MB
        assert outcome.nodes == 1

    def test_a_zero_byte_file_is_not_a_crash(self, tmp_path: Path) -> None:
        path = tmp_path / "empty.tf"
        path.write_text("", encoding="utf-8")
        outcome = scan_in_child(path)
        assert outcome.clean, f"{outcome.exception}: {outcome.message}"

    def test_a_binary_file_with_an_iac_name_does_not_hang_the_scan(self, tmp_path: Path) -> None:
        path = tmp_path / "main.tf"
        path.write_bytes(b"\x80\x81\x82" * 2000)  # not valid UTF-8, not a byte order mark
        outcome = scan_in_child(path)
        assert outcome.status in ("ok", "error")
        assert not outcome.timed_out
        assert outcome.seconds < FAST_SECONDS


class TestPendingParserFixes:
    def test_a_binary_file_ends_in_a_parse_error_that_names_the_cause(self, tmp_path: Path) -> None:
        path = tmp_path / "main.tf"
        path.write_bytes(b"\x80\x81\x82" * 2000)
        outcome = scan_in_child(path)
        assert outcome.status == "error"
        assert outcome.threatcode_error, f"raised {outcome.exception}, which the CLI cannot report"

    @pytest.mark.parametrize(
        "make",
        [gen.nested_json, gen.nested_yaml_flow, gen.nested_yaml_block],
        ids=lambda f: f.__name__,
    )
    def test_deeply_nested_documents_end_in_a_parse_error_not_a_stack_overflow(
        self, tmp_path: Path, make: Callable[..., Path]
    ) -> None:
        outcome = scan_in_child(make(tmp_path))
        assert not outcome.timed_out
        assert outcome.status == "error"
        assert outcome.threatcode_error, f"raised {outcome.exception}, which the CLI cannot report"

    def test_a_line_of_repeated_curl_commands_is_scanned_in_linear_time(
        self, tmp_path: Path
    ) -> None:
        path = gen.backtracking_dockerfile(tmp_path)
        outcome = scan_in_child(path, budget=DEFAULT_BUDGET_SECONDS)
        assert not outcome.timed_out, "the scan did not finish; the regex backtracks quadratically"
        assert outcome.status == "ok"
        assert outcome.seconds < FAST_SECONDS

    def test_a_smaller_backtracking_line_is_fine_today_so_the_threshold_is_real(
        self, tmp_path: Path
    ) -> None:
        path = gen.backtracking_dockerfile(tmp_path, repeats=2_000)
        outcome = scan_in_child(path)
        assert outcome.status == "ok"
        assert outcome.seconds < FAST_SECONDS


class TestPendingDirectoryWalker:
    """``threatcode scan DIR`` reads regular files and never follows a link out of the tree."""

    @pending("WP-2-8", "discovery walks with lstat, skips symlinks and counts them as skipped")
    def test_links_leading_out_of_the_tree_are_not_followed(self, tmp_path: Path) -> None:
        tree = gen.symlink_escape_tree(tmp_path)
        run = cli_scan(tree.scan_root)
        assert not run.timed_out, "the scan did not finish; a link cycle was followed"
        assert run.exit_code == 0, run.stderr[-300:]
        assert gen.INSIDE_RESOURCE in run.stdout, "positive control: the real file must be modeled"
        assert gen.OUTSIDE_RESOURCE not in run.stdout, "a file outside the scan root was read"

    @pending("WP-2-8", "discovery never follows a directory link, so a link cycle cannot loop")
    def test_link_cycles_end_the_scan_within_budget(self, tmp_path: Path) -> None:
        tree = gen.symlink_escape_tree(tmp_path)
        run = cli_scan(tree.scan_root, budget=DEFAULT_BUDGET_SECONDS)
        assert not run.timed_out
        assert run.seconds < FAST_SECONDS
        assert gen.INSIDE_RESOURCE in run.stdout, "positive control: the real file must be modeled"

    @pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="no named pipes on this platform")
    @pending("WP-2-8", "discovery reads only regular files, so a named pipe is never opened")
    def test_a_named_pipe_with_an_iac_name_is_not_opened(self, tmp_path: Path) -> None:
        root = gen.fifo_tree(tmp_path)
        run = cli_scan(root, budget=DEFAULT_BUDGET_SECONDS)
        assert not run.timed_out, "the scan blocked reading the named pipe"
        assert run.exit_code == 0, run.stderr[-300:]
        assert gen.INSIDE_RESOURCE in run.stdout, "positive control: the real file must be modeled"


class TestFlowDepthGuard:
    def test_an_apostrophe_in_a_plain_scalar_cannot_hide_the_nesting(self) -> None:
        from threatcode.exceptions import ParseError
        from threatcode.parsers._yaml import MAX_FLOW_DEPTH, load_yaml_documents

        text = "note: don't\nlist: " + "[" * (MAX_FLOW_DEPTH + 1) + "]" * (MAX_FLOW_DEPTH + 1)
        with pytest.raises(ParseError, match="nest deeper than"):
            load_yaml_documents(text, source="hostile.yaml")

    def test_ordinary_nesting_still_loads(self) -> None:
        from threatcode.parsers._yaml import load_yaml_documents

        assert load_yaml_documents("a: [1, {b: [2, [3]]}]") == [{"a": [1, {"b": [2, [3]]}]}]
