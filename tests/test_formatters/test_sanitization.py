"""Security regression tests for formatter output sanitization.

Text that comes from the scanned input (resource names, descriptions, model output) must stay
inert in every format: no Markdown structure, no mentions, no links, no HTML, no escape from a
Mermaid label.
"""

from __future__ import annotations

import re

import pytest

from threatcode.formatters._utils import (
    collapse_whitespace,
    md_code,
    md_inline,
    stride_label,
    technique_url,
    terminal_safe,
    truncate,
)
from threatcode.formatters.mermaid import mermaid_label

ZWJ = "‍"


class TestMdInline:
    def test_newlines_and_whitespace_collapse_to_one_line(self) -> None:
        assert md_inline("a\n\n\tb \r\n  c") == "a b c"
        assert "\n" not in md_inline("x y\x0bz\x00w")

    @pytest.mark.parametrize(
        "text",
        [
            "# heading",
            "###### deep",
            "- item",
            "+ item",
            "* item",
            "> quote",
            ">> nested",
            "| a | b |",
            "1. numbered",
            "12) numbered",
            "--- rule",
            "*** rule",
            "=== underline",
            "```fence",
            "~~~fence",
            "- > # 1. | mixed",
        ],
    )
    def test_block_markers_at_the_start_are_dropped(self, text: str) -> None:
        out = md_inline(text)
        assert not out.startswith(("#", "-", "+", ">", "|", "`", "~", "=", "*"))
        assert not re.match(r"^\d+[.)]", out)

    def test_the_text_after_a_marker_is_kept(self) -> None:
        assert md_inline("## Fake heading") == "Fake heading"
        assert md_inline("- injected list") == "injected list"

    def test_hashtags_and_negative_numbers_are_not_mistaken_for_markers(self) -> None:
        assert md_inline("#hashtag").startswith("#")
        assert md_inline("-1 is the default") == "-1 is the default"
        assert md_inline("3 buckets") == "3 buckets"

    @pytest.mark.parametrize("char", list("\\`*[]<|~&"))
    def test_inline_specials_are_backslash_escaped(self, char: str) -> None:
        assert md_inline(f"a{char}b") == f"a\\{char}b"

    def test_html_and_links_cannot_form(self) -> None:
        out = md_inline("<script>alert(1)</script> [link](http://evil.com) ![img](x)")
        assert "<script>" not in out.replace("\\<", "")
        assert "\\<script>" in out
        assert "[link]" not in out.replace("\\[", "").replace("\\]", "")
        assert "\\[link\\]" in out
        assert "![img]" not in out
        assert "](http://" not in out

    def test_underscores_inside_words_stay_readable_and_at_word_edges_are_escaped(self) -> None:
        assert md_inline("aws_s3_bucket and http_tokens") == "aws_s3_bucket and http_tokens"
        assert md_inline("_emphasis_ here") == "\\_emphasis\\_ here"
        assert md_inline("snake_ case") == "snake\\_ case"

    def test_mentions_are_code_spans(self) -> None:
        out = md_inline("CC @octocat and @org/security-team, (@x) and a@b.com")
        assert out == "CC `@octocat` and `@org/security-team`, (`@x`) and a@b.com"
        assert ZWJ not in out

    def test_issue_references_are_code_spans(self) -> None:
        out = md_inline("fixes #123 and org/repo#45, see #abc and C# and #")
        assert out == "fixes `#123` and org/repo`#45`, see #abc and C# and #"
        assert ZWJ not in out

    def test_bare_urls_are_code_spans_that_copy_exactly(self) -> None:
        out = md_inline("see https://evil.example/x and HTTP://E.example and ftp://f")
        assert out == "see `https://evil.example/x` and `HTTP://E.example` and `ftp://f`"
        assert ZWJ not in out

    def test_trailing_punctuation_stays_outside_the_span(self) -> None:
        out = md_inline("See http://a.example. Then (see http://a.example), or http://a.example!")
        assert out == (
            "See `http://a.example`. Then (see `http://a.example`), or `http://a.example`!"
        )

    def test_a_mention_inside_an_address_is_not_wrapped_twice(self) -> None:
        out = md_inline("https://example.com/@octocat#12 ok")
        assert out == "`https://example.com/@octocat#12` ok"

    def test_a_bare_scheme_without_an_address_is_plain_text(self) -> None:
        assert md_inline("http://") == "http://"

    def test_hostile_markup_next_to_a_span_is_still_escaped(self) -> None:
        out = md_inline("<script>@octocat</script> [x](http://e) *b* | ~")
        assert out == "\\<script>`@octocat`\\</script> \\[x\\](`http://e`) \\*b\\* \\| \\~"

    def test_private_use_characters_cannot_forge_a_span(self) -> None:
        assert md_inline("odd \ue0000\ue001 x") == "odd 0 x"

    def test_arrows_and_parentheses_stay_readable(self) -> None:
        assert md_inline("internet -> private (cpu, memory)") == "internet -> private (cpu, memory)"
        assert md_inline("a > b") == "a > b"

    def test_a_limit_truncates_the_plain_text_before_escaping(self) -> None:
        out = md_inline("a*" * 50, limit=10)
        assert out == "a\\*a\\*a\\*a..."

    def test_empty_input(self) -> None:
        assert md_inline("") == "" and md_inline("   \n ") == ""

    def test_the_result_is_stable_when_applied_to_safe_text(self) -> None:
        assert md_inline("plain words only") == "plain words only"


class TestMdCode:
    def test_the_text_is_not_escaped(self) -> None:
        text = 'module.net.aws_instance.web["a"][0]'
        assert md_code(text) == f"`{text}`"

    def test_the_fence_is_longer_than_any_backtick_run_inside(self) -> None:
        assert md_code("a`b") == "``a`b``"
        assert md_code("a``b") == "```a``b```"
        assert md_code("a`b``c```d") == "````a`b``c```d````"

    def test_a_backtick_at_an_edge_is_padded_with_spaces(self) -> None:
        assert md_code("`x`") == "`` `x` ``"
        assert md_code("`x") == "`` `x ``"

    def test_it_stays_on_one_line(self) -> None:
        assert md_code("a\nb\r\nc") == "`a b c`"

    def test_a_pipe_is_escaped_in_a_table_cell_only(self) -> None:
        assert md_code("a|b") == "`a|b`"
        assert md_code("a|b", table=True) == "`a\\|b`"

    def test_empty_text_gives_no_span(self) -> None:
        assert md_code("") == "" and md_code(" \n") == ""

    @pytest.mark.parametrize("text", ["a", "a`b", "``", "`", "x`" * 5, "`a`b`"])
    def test_a_code_span_parser_reads_back_the_text(self, text: str) -> None:
        span = md_code(text)
        match = re.fullmatch(r"(`+)(?: (.*) |(.*))\1", span, flags=re.DOTALL)
        assert match
        inner = match.group(2) if match.group(2) is not None else match.group(3)
        assert inner == text
        fence = match.group(1)
        assert fence not in re.sub(
            r"`+", lambda m: "" if len(m.group()) != len(fence) else "!", text
        )


class TestSmallHelpers:
    def test_collapse_whitespace(self) -> None:
        assert collapse_whitespace("  a \n b\t") == "a b"

    def test_truncate(self) -> None:
        assert truncate("abcdef", 10) == "abcdef"
        assert truncate("abcdefghij", 8) == "abcde..."
        assert truncate("abcdef", 3) == "abc"
        assert truncate("abc", 0) == ""

    def test_stride_labels_are_readable(self) -> None:
        assert stride_label("information_disclosure") == "Information Disclosure"
        assert stride_label("denial_of_service") == "Denial of Service"
        assert stride_label("elevation_of_privilege") == "Elevation of Privilege"
        assert stride_label("made_up_category") == "Made Up Category"

    def test_technique_urls(self) -> None:
        assert technique_url("T1530") == "https://attack.mitre.org/techniques/T1530/"
        assert technique_url("T1552.005") == "https://attack.mitre.org/techniques/T1552/005/"
        assert technique_url("javascript:alert(1)") == ""
        assert technique_url("T1530/../x") == ""


class TestMermaidLabels:
    @pytest.mark.parametrize("char", list(r'"<>&`[]{}|\;%#'))
    def test_every_syntax_character_becomes_an_entity_code(self, char: str) -> None:
        out = mermaid_label(f"a{char}b")
        assert re.fullmatch(r"a#\w+;b", out)

    def test_a_hash_is_encoded_once(self) -> None:
        assert mermaid_label("#quot;") == "#35;quot#59;"

    def test_a_breakout_attempt_is_inert(self) -> None:
        out = mermaid_label('a"]; click n1 call alert(1) <img src=x onerror=alert(1)> `x`\n%%{x}')
        plain = re.sub(r"#\w+;", "", out)
        assert not set('"<>`[]{}|\n;%\\') & set(plain)

    def test_the_label_is_capped_and_one_line(self) -> None:
        out = mermaid_label("word " * 100)
        assert len(out) <= 60 and "\n" not in out and out.endswith("...")


# The characters that must never reach a terminal as themselves
UNSAFE = re.compile(
    "[\x00-\x08\x0b-\x1f\x7f-\x9f\u061c\u200e\u200f\u2028\u2029\u202a-\u202e\u2066-\u2069]"
)


class TestTerminalSafe:
    HOSTILE = "evil\x1b[2J\x1b[Hpwned\x1b]0;TITLE\x07"

    def test_an_escape_sequence_is_printed_as_text_not_executed(self) -> None:
        out = terminal_safe(self.HOSTILE)
        assert out == "evil\\x1b[2J\\x1b[Hpwned\\x1b]0;TITLE\\x07"
        assert not UNSAFE.search(out)

    @pytest.mark.parametrize("code", [*range(0x00, 0x20), 0x7F, *range(0x80, 0xA0)])
    def test_no_c0_c1_or_delete_character_survives(self, code: int) -> None:
        for keep_lines in (False, True):
            out = terminal_safe(f"a{chr(code)}b", keep_lines=keep_lines)
            if chr(code) in "\t\n" and keep_lines:
                continue
            assert not UNSAFE.search(out), (hex(code), keep_lines)
            assert out.startswith("a") and out.endswith("b")

    def test_c1_controls_show_their_code(self) -> None:
        assert terminal_safe("a\x9bb\x9d") == "a\\x9bb\\x9d"

    @pytest.mark.parametrize("char", ["\u202e", "\u2066", "\u200f", "\u2028", "\u2029"])
    def test_bidirectional_and_separator_controls_show_their_code(self, char: str) -> None:
        out = terminal_safe(f"a{char}b")
        assert out == f"a\\u{ord(char):04x}b"

    def test_whitespace_collapses_to_one_line(self) -> None:
        assert terminal_safe("a\n\n\tb \r\n  c ") == "a b c"

    def test_keeping_lines_keeps_newlines_and_tabs_but_not_a_carriage_return(self) -> None:
        assert terminal_safe("a\tb\r\nc\rd", keep_lines=True) == "a\tb\nc d"

    def test_ordinary_text_including_non_ascii_is_untouched(self) -> None:
        text = 'aws_s3_bucket.donn\u00e9es["a"] -> \u65e5\u672c\u8a9e (private)'
        assert terminal_safe(text) == text

    def test_collapse_whitespace_also_drops_c1_controls_from_markdown(self) -> None:
        assert collapse_whitespace("a\x9bb\x9dc") == "a b c"
