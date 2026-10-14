"""Tests for the terminal layout primitives: wrapping that never cuts a name."""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from threatcode.formatters.terminal_layout import (
    TIE,
    columns,
    flow,
    hanging,
    path_components,
    split_token,
    wrap,
    wrap_path,
)

ADDRESS = st.text(alphabet="abcxyz_.-:/[]0123456789", min_size=0, max_size=120)
WORDS = st.lists(st.text(alphabet="abcdefg_.-", min_size=1, max_size=40), max_size=30)


class TestSplitToken:
    def test_a_token_that_fits_is_returned_whole(self) -> None:
        assert split_token("aws_s3_bucket.logs", 40) == ["aws_s3_bucket.logs"]
        assert split_token("", 10) == [""]

    def test_an_address_breaks_after_a_dot_so_the_name_starts_a_line(self) -> None:
        assert split_token("aws_secretsmanager_secret.db_credentials", 26) == [
            "aws_secretsmanager_secret.",
            "db_credentials",
        ]

    def test_a_token_with_no_boundary_is_cut_at_the_width(self) -> None:
        assert split_token("x" * 25, 10) == ["x" * 10, "x" * 10, "x" * 5]

    def test_a_boundary_too_near_the_start_is_not_used(self) -> None:
        # Cutting after the first dot would leave a two character fragment
        assert split_token("ab.cdefghijklmnopqrst", 10) == ["ab.cdefghi", "jklmnopqrs", "t"]

    @given(ADDRESS, st.integers(min_value=1, max_value=60))
    @settings(max_examples=200)
    def test_the_pieces_hold_every_character_and_fit(self, token: str, width: int) -> None:
        pieces = split_token(token, width)
        assert "".join(pieces) == token
        assert all(len(piece) <= width for piece in pieces)


class TestALineReferenceStaysWithItsFile:
    def test_the_number_is_not_left_alone_when_the_cut_would_fall_after_the_colon(self) -> None:
        # The window ends on the colon, which is a boundary: cutting there would strand the 1
        assert split_token("0" * 19 + ":1", 20) == ["0" * 18, "0:1"]

    def test_a_boundary_before_the_reference_is_used_when_there_is_one(self) -> None:
        assert split_token("src/app/handler.py:12", 20) == ["src/app/handler.", "py:12"]

    def test_a_long_number_is_not_split_from_the_name_either(self) -> None:
        pieces = split_token("a" * 12 + ":123456", 15)
        assert pieces == ["a" * 11, "a:123456"]

    def test_a_reference_with_a_trailing_colon_stays_with_its_file(self) -> None:
        # ``file:line:`` is how a message about a line is introduced
        pieces = split_token("x" * 30 + ":12:", 10)
        assert "".join(pieces) == "x" * 30 + ":12:"
        assert pieces[-1].endswith(":12:") and len(pieces[-1]) > len(":12:")

    def test_a_token_without_a_reference_at_its_end_is_cut_as_before(self) -> None:
        assert split_token("x" * 12 + ":ab", 10) == ["x" * 10, "xx:ab"]
        # Digits inside a name, with more name after them, are not a reference
        assert split_token("x" * 8 + ":12:" + "y" * 8, 10) == ["x" * 8 + ":", "12:" + "y" * 7, "y"]

    def test_a_reference_wider_than_the_line_is_still_cut_and_keeps_its_characters(self) -> None:
        pieces = split_token("n:" + "9" * 12, 5)
        assert "".join(pieces) == "n:" + "9" * 12
        assert all(len(piece) <= 5 for piece in pieces)

    @given(
        st.text(alphabet="abcxyz_.-:/[]0123456789", min_size=1, max_size=100),
        st.integers(min_value=1, max_value=99999),
        st.integers(min_value=1, max_value=60),
    )
    @settings(max_examples=300)
    def test_the_last_piece_of_any_name_carries_its_number_and_some_of_the_name(
        self, name: str, line: int, width: int
    ) -> None:
        tail = f":{line}"
        pieces = split_token(name + tail, max(width, len(tail) + 1))
        assert "".join(pieces) == name + tail
        assert pieces[-1].endswith(tail) and len(pieces[-1]) > len(tail)


class TestPathComponents:
    def test_a_path_is_cut_after_each_slash(self) -> None:
        assert path_components("a/bb/ccc.tf:12") == ["a/", "bb/", "ccc.tf:12"]
        assert path_components("main.tf:1") == ["main.tf:1"]
        assert path_components("") == []

    def test_a_slash_at_the_end_does_not_leave_the_line_number_alone(self) -> None:
        assert path_components("dir/:7") == ["dir/:7"]

    def test_a_backslash_is_not_a_separator(self) -> None:
        # The terminal shows an escape as ``\x1b``; cutting after the backslash would split it
        assert path_components("a\\x1b[2J.tf:3") == ["a\\x1b[2J.tf:3"]


class TestWrapPath:
    def test_a_path_that_fits_is_one_line(self) -> None:
        assert wrap_path("modules/net/main.tf:120", 40) == ["modules/net/main.tf:120"]
        assert wrap_path("", 10) == [""]

    def test_as_many_components_share_a_line_as_fit(self) -> None:
        assert wrap_path("terraform/environments/production/main.tf:1234", 30) == [
            "terraform/environments/",
            "production/main.tf:1234",
        ]

    def test_the_file_name_is_not_cut_where_a_boundary_inside_it_would_have_fit(self) -> None:
        # ``split_token`` would break after the dot in ``handler.py``; a path breaks at the slash
        assert wrap_path("src/app/handler.py:12", 20) == ["src/app/", "handler.py:12"]

    def test_a_component_wider_than_the_line_is_the_only_thing_that_is_cut(self) -> None:
        pieces = wrap_path("d/" + "n" * 25 + ".tf:12345", 12)
        assert pieces[0] == "d/"
        assert pieces[-1].endswith(".tf:12345")
        assert all(len(piece) <= 12 for piece in pieces)

    @given(st.text(alphabet="abc_.-:/[]0123456789", max_size=120), st.integers(1, 60))
    @settings(max_examples=300)
    def test_the_pieces_hold_every_character_and_fit_and_break_only_after_a_slash_if_they_can(
        self, path: str, width: int
    ) -> None:
        pieces = wrap_path(path, width)
        assert "".join(pieces) == path
        assert all(len(piece) <= width for piece in pieces)
        if all(len(part) <= width for part in path_components(path)):
            assert all(piece.endswith("/") for piece in pieces[:-1])


class TestWrap:
    def test_an_empty_text_is_one_empty_line(self) -> None:
        assert wrap("", 10) == [""]
        assert wrap("   ", 10) == [""]

    def test_words_stay_whole(self) -> None:
        assert wrap("one two three four", 9) == ["one two", "three", "four"]

    def test_a_word_longer_than_a_line_is_split_not_dropped(self) -> None:
        lines = wrap("see aws_instance.some_long_name_here ok", 14)
        assert "".join(lines).replace(" ", "") == "seeaws_instance.some_long_name_hereok"
        assert all(len(line) <= 14 for line in lines)

    def test_the_first_line_can_have_its_own_width(self) -> None:
        assert wrap("aaaa bbbb cccc", 9, first_width=4) == ["aaaa", "bbbb cccc"]

    @given(WORDS, st.integers(min_value=1, max_value=50))
    @settings(max_examples=200)
    def test_no_line_is_wider_than_the_width_and_no_character_is_lost(
        self, words: list[str], width: int
    ) -> None:
        text = " ".join(words)
        lines = wrap(text, width)
        assert all(len(line) <= width for line in lines)
        assert "".join(lines).replace(" ", "") == text.replace(" ", "")


class TestHanging:
    def test_the_continuation_is_indented_as_far_as_the_prefix(self) -> None:
        assert hanging("one two three four", 14, first="Verdict: ") == [
            "Verdict: one",
            "         two",
            "         three",
            "         four",
        ]

    def test_an_explicit_rest_prefix_is_used(self) -> None:
        assert hanging("aa bb cc", 8, first="> ", rest="  ") == ["> aa bb", "  cc"]

    def test_a_first_line_with_no_prefix_gets_the_full_width(self) -> None:
        lines = hanging("a" * 8 + " " + "b" * 8, 17, rest="  ")
        assert lines == ["a" * 8 + " " + "b" * 8]

    @given(WORDS, st.integers(min_value=12, max_value=80), st.integers(min_value=0, max_value=8))
    @settings(max_examples=150)
    def test_the_prefixes_count_towards_the_width(
        self, words: list[str], width: int, indent: int
    ) -> None:
        lines = hanging(" ".join(words), width, first="P" * indent, rest=" " * indent)
        assert all(len(line) <= width for line in lines)


def text_of(lines: list[list[tuple[str, str]]]) -> list[str]:
    return ["".join(text for text, _ in line) for line in lines]


class TestFlow:
    def test_phrases_are_joined_with_the_separator(self) -> None:
        lines = flow([("2 high", "high"), ("1 low", "low")], 80, first="Verdict: ")
        assert text_of(lines) == ["Verdict: 2 high, 1 low"]

    def test_the_separator_stays_at_the_end_of_the_line_it_follows(self) -> None:
        lines = flow([("aaaa bbbb", ""), ("cccc dddd", "")], 10)
        assert text_of(lines) == ["aaaa bbbb,", "cccc dddd"]

    def test_a_phrase_that_wraps_keeps_its_style_on_both_lines(self) -> None:
        lines = flow([("alpha beta gamma delta", "high")], 12)
        styles = [{style for text, style in line if text.strip()} for line in lines]
        assert len(lines) == 2 and styles == [{"high"}, {"high"}]

    def test_a_separator_of_spaces_is_the_gap_between_phrases(self) -> None:
        assert text_of(flow([("a", ""), ("b", "")], 20, sep="  ")) == ["a  b"]

    def test_a_phrase_ending_in_a_colon_takes_no_separator(self) -> None:
        lines = flow([("step:", ""), ("HIGH R1", "high"), ("LOW R2", "low")], 80, sep=", ")
        assert text_of(lines) == ["step: HIGH R1, LOW R2"]

    def test_the_continuation_prefix_is_applied_and_counted(self) -> None:
        lines = flow([("aaaa bbbb cccc", "")], 9, first="* ", rest="  ")
        assert text_of(lines) == ["* aaaa", "  bbbb", "  cccc"]

    def test_a_word_longer_than_a_line_is_split_and_keeps_its_characters(self) -> None:
        lines = flow([("x" * 25, "")], 10)
        assert "".join(text_of(lines)) == "x" * 25
        assert all(len(line) <= 10 for line in text_of(lines))

    @given(WORDS, st.integers(min_value=10, max_value=60))
    @settings(max_examples=150)
    def test_no_line_is_wider_than_the_width(self, words: list[str], width: int) -> None:
        items = [(word, "") for word in words]
        lines = text_of(flow(items, width, first="V: ", rest="   "))
        assert all(len(line) <= width for line in lines)
        flat = re.sub(r"[\s,]", "", "".join(lines))
        assert flat == "V:" + re.sub(r"[\s,]", "", "".join(words))


class TestTie:
    def test_two_words_joined_by_the_tie_are_never_separated_and_print_as_a_space(self) -> None:
        text = f"aaaa HIGH{TIE}SOME_RULE bbbb"
        assert wrap(text, 14) == ["aaaa", "HIGH SOME_RULE", "bbbb"]

    def test_without_the_tie_the_same_words_split(self) -> None:
        assert wrap("aaaa HIGH SOME_RULE bbbb", 14) == ["aaaa HIGH", "SOME_RULE bbbb"]

    def test_a_tied_phrase_in_a_flow_moves_to_the_next_line_whole_and_keeps_its_style(self) -> None:
        items = [("step:", ""), (f"HIGH{TIE}SOME_RULE", "high"), ("LOW", "low")]
        lines = flow(items, 20, first="  ", rest="    ")
        assert text_of(lines) == ["  step:", "    HIGH SOME_RULE,", "    LOW"]
        assert ("HIGH SOME_RULE", "high") in lines[1]

    def test_the_tie_never_reaches_the_output(self) -> None:
        assert TIE not in "".join(wrap(f"a{TIE}b c{TIE}d", 3))
        assert TIE not in "".join(text_of(flow([(f"a{TIE}b", "")], 3)))

    def test_a_tied_word_longer_than_the_line_is_still_split_and_keeps_its_characters(self) -> None:
        lines = wrap(f"{'x' * 12}{TIE}{'y' * 12}", 10)
        assert "".join(lines).replace(" ", "") == "x" * 12 + "y" * 12
        assert all(len(line) <= 10 for line in lines)


class TestColumns:
    def test_cells_are_padded_to_their_columns_and_separated_by_the_gap(self) -> None:
        (line,) = columns([("ab", 4, ""), ("cd", 3, ""), ("ef", 2, "")])
        assert "".join(text for text, _ in line) == "ab    cd   ef"

    def test_the_last_cell_is_not_padded_and_trailing_empty_cells_leave_no_spaces(self) -> None:
        (line,) = columns([("ab", 4, ""), ("", 3, ""), ("", 2, "")])
        assert "".join(text for text, _ in line) == "ab"

    def test_an_empty_cell_in_the_middle_keeps_the_cells_after_it_in_their_column(self) -> None:
        (line,) = columns([("ab", 4, ""), ("", 3, ""), ("ef", 2, "")])
        assert "".join(text for text, _ in line) == "ab         ef"

    def test_a_cell_wider_than_its_column_wraps_in_it_and_the_others_stay_put(self) -> None:
        lines = columns([("one two three", 7, ""), ("X", 1, "")])
        assert text_of(lines) == ["one two  X", "three"]

    def test_a_row_is_as_tall_as_its_tallest_cell(self) -> None:
        lines = columns([("a", 3, ""), ("b c d", 1, "")])
        assert len(lines) == 3

    def test_a_cell_given_as_lines_is_taken_as_wrapped_already(self) -> None:
        lines = columns([(["src/", "main.tf:1"], 9, ""), ("X", 1, "")])
        assert text_of(lines) == ["src/       X", "main.tf:1"]

    def test_a_cell_given_as_no_lines_is_one_empty_line(self) -> None:
        assert text_of(columns([([], 4, ""), ("X", 1, "")])) == ["      X"]

    def test_the_lead_starts_every_line(self) -> None:
        lines = columns([("one two", 3, "")], lead="> ")
        assert text_of(lines) == ["> one", "> two"]

    def test_only_the_words_carry_the_style_not_the_padding(self) -> None:
        (line,) = columns([("ab", 5, "high"), ("cd", 2, "low")])
        assert line == [("ab", "high"), ("     ", ""), ("cd", "low")]

    @given(
        st.lists(
            st.tuples(
                st.text(alphabet="abc_.", max_size=30), st.integers(min_value=1, max_value=12)
            ),
            min_size=1,
            max_size=5,
        )
    )
    @settings(max_examples=150)
    def test_no_line_is_wider_than_the_columns_and_every_cell_keeps_its_characters(
        self, cells: list[tuple[str, int]]
    ) -> None:
        lines = text_of(columns([(text, width, "") for text, width in cells]))
        limit = sum(width for _, width in cells) + 2 * (len(cells) - 1)
        assert all(len(line) <= limit for line in lines)
        assert not any(line != line.rstrip() for line in lines)
        # Each cell, taken alone, is its pieces in order
        for text, width in cells:
            alone = text_of(columns([(text, width, "")]))
            assert "".join(alone) == text
            assert all(len(piece) <= width for piece in alone)
