"""Tests for the terminal layout primitives: wrapping that never cuts a name."""

from __future__ import annotations

import re

from hypothesis import given, settings
from hypothesis import strategies as st

from threatcode.formatters.terminal_layout import flow, hanging, split_token, wrap

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
