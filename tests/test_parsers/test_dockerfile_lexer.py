"""Tests for the BuildKit-faithful Dockerfile lexer and its text tools."""

from __future__ import annotations

import time

import pytest

from threatcode.parsers._dockerfile_lexer import (
    Instruction,
    command_name,
    find_heredocs,
    has_variable,
    lex,
    parse_json_array,
    shell_pipelines,
    split_lines,
    split_options,
    split_words,
    substitute,
    unquote,
)


def names(text: str) -> list[str]:
    return [ins.name for ins in lex(text).instructions]


def only(text: str) -> Instruction:
    found = lex(text).instructions
    assert len(found) == 1, found
    return found[0]


class TestKeywords:
    def test_lowercase_and_mixed_case_keywords_are_read_and_upper_cased(self) -> None:
        text = "from alpine\nWorkDir /app\nrUn echo hi\nuser nobody\nhealthcheck CMD true"
        assert names(text) == ["FROM", "WORKDIR", "RUN", "USER", "HEALTHCHECK"]

    def test_a_lone_keyword_has_empty_arguments_and_does_not_crash(self) -> None:
        found = lex("FROM alpine\nRUN\nuser").instructions
        assert [(i.name, i.args) for i in found] == [("FROM", "alpine"), ("RUN", ""), ("USER", "")]

    def test_a_word_that_is_not_an_instruction_is_skipped_and_reported(self) -> None:
        result = lex("FROM alpine\nset -eux\nRUN true")
        assert [i.name for i in result.instructions] == ["FROM", "RUN"]
        assert [(s.line, s.text) for s in result.skipped] == [(2, "set -eux")]

    def test_a_line_that_starts_with_punctuation_is_skipped(self) -> None:
        result = lex("FROM alpine\n&& echo stray")
        assert [i.name for i in result.instructions] == ["FROM"]
        assert len(result.skipped) == 1

    def test_arguments_are_stripped(self) -> None:
        assert only("RUN    echo hi   \t").args == "echo hi"

    def test_indented_instructions_are_read(self) -> None:
        assert names("FROM alpine\n    RUN true\n\tUSER x") == ["FROM", "RUN", "USER"]

    def test_an_empty_file_has_no_instructions(self) -> None:
        assert lex("").instructions == []
        assert lex("\n\n# only a comment\n").instructions == []


class TestContinuationsAndComments:
    def test_a_continuation_joins_lines_with_one_space(self) -> None:
        ins = only("RUN apt-get update && \\\n    apt-get install -y curl")
        assert ins.args == "apt-get update && apt-get install -y curl"
        assert (ins.start_line, ins.end_line) == (1, 2)

    def test_a_comment_inside_a_continuation_is_dropped_and_the_rest_kept(self) -> None:
        text = "RUN echo a \\\n# inline comment\n&& echo b"
        ins = only(text)
        assert ins.args == "echo a && echo b"
        assert (ins.start_line, ins.end_line) == (1, 3)

    def test_a_blank_line_inside_a_continuation_is_skipped(self) -> None:
        ins = only("RUN echo a \\\n\n  && echo b")
        assert ins.args == "echo a && echo b"
        assert ins.end_line == 3

    def test_a_comment_ending_in_a_backslash_does_not_swallow_the_next_instruction(self) -> None:
        text = "FROM alpine\n# remember to set the user \\\nUSER root\n"
        assert names(text) == ["FROM", "USER"]

    def test_a_comment_line_is_never_an_instruction(self) -> None:
        assert names("# RUN echo hi\n  # USER root\nFROM alpine") == ["FROM"]

    def test_line_numbers_are_physical_after_continuations(self) -> None:
        text = (
            "FROM alpine\n"  # 1
            "RUN a \\\n"  # 2
            "    && b \\\n"  # 3
            "    && c\n"  # 4
            "ENV X=1\n"  # 5
            "\n"  # 6
            "# comment\n"  # 7
            "EXPOSE 22\n"  # 8
        )
        found = {i.name: (i.start_line, i.end_line) for i in lex(text).instructions}
        assert found == {"FROM": (1, 1), "RUN": (2, 4), "ENV": (5, 5), "EXPOSE": (8, 8)}

    def test_a_trailing_continuation_at_the_end_of_the_file_ends_the_instruction(self) -> None:
        ins = only("RUN echo hi \\")
        assert ins.args == "echo hi"
        assert ins.end_line == 1

    def test_trailing_whitespace_after_the_escape_still_continues(self) -> None:
        assert only("RUN echo a \\   \n  b").args == "echo a b"

    def test_crlf_line_endings_are_handled(self) -> None:
        found = lex("FROM alpine\r\nRUN echo a \\\r\n  b\r\nUSER x\r\n").instructions
        assert [(i.name, i.args) for i in found] == [
            ("FROM", "alpine"),
            ("RUN", "echo a b"),
            ("USER", "x"),
        ]

    def test_a_byte_order_mark_is_ignored(self) -> None:
        assert names("\ufeffFROM alpine") == ["FROM"]


class TestEscapeDirective:
    def test_a_backtick_escape_makes_a_trailing_backslash_a_plain_character(self) -> None:
        text = (
            "# escape=`\nFROM mcr.microsoft.com/windows/servercore\n"
            "WORKDIR C:\\app\\\nUSER ContainerAdministrator\n"
        )
        found = lex(text).instructions
        assert [i.name for i in found] == ["FROM", "WORKDIR", "USER"]
        assert found[1].args == "C:\\app\\"

    def test_a_backtick_continues_the_line_when_it_is_the_escape(self) -> None:
        text = "# escape=`\nRUN powershell -Command `\n    Write-Host hi\n"
        ins = only(text)
        assert ins.args == "powershell -Command Write-Host hi"

    def test_without_the_directive_a_trailing_backtick_is_not_a_continuation(self) -> None:
        assert names("RUN echo `\nUSER x") == ["RUN", "USER"]

    def test_the_escape_character_is_reported(self) -> None:
        assert lex("# escape=`\nFROM x").escape == "`"
        assert lex("FROM x").escape == "\\"

    def test_the_directive_must_come_before_everything_else(self) -> None:
        result = lex("FROM x\n# escape=`\nRUN echo a `\nUSER root")
        assert result.escape == "\\"
        assert [i.name for i in result.instructions] == ["FROM", "RUN", "USER"]

    def test_a_blank_line_ends_the_directive_block(self) -> None:
        assert lex("\n# escape=`\nFROM x").escape == "\\"

    def test_directives_are_case_insensitive_and_may_stack(self) -> None:
        result = lex("# syntax=docker/dockerfile:1.7\n# ESCAPE=`\nFROM x")
        assert (result.escape, result.syntax) == ("`", "docker/dockerfile:1.7")

    def test_an_invalid_escape_value_is_ignored(self) -> None:
        assert lex("# escape=x\nFROM a").escape == "\\"

    def test_an_ordinary_comment_that_looks_a_little_like_a_directive_is_not_one(self) -> None:
        assert lex("# note: escape = nothing here\nFROM a").escape == "\\"


class TestLineSplitting:
    def test_only_newline_splits_lines(self) -> None:
        assert split_lines("a\x0cb\u2028c\x85d\ne") == ["a\x0cb\u2028c\x85d", "e"]

    def test_a_form_feed_does_not_shift_line_numbers(self) -> None:
        text = "FROM alpine\n# a\x0cb\nRUN true\nEXPOSE 22"
        found = {i.name: i.start_line for i in lex(text).instructions}
        assert found == {"FROM": 1, "RUN": 3, "EXPOSE": 4}

    @pytest.mark.parametrize("separator", ["\x0c", "\x0b", "\u2028", "\u2029", "\x85", "\x1c"])
    def test_unicode_and_control_separators_stay_inside_their_line(self, separator: str) -> None:
        text = f"FROM alpine\nRUN echo a{separator}echo b\nEXPOSE 22"
        found = lex(text).instructions
        assert [(i.name, i.start_line) for i in found] == [("FROM", 1), ("RUN", 2), ("EXPOSE", 3)]
        assert found[1].args == f"echo a{separator}echo b"


class TestHeredocs:
    def test_a_run_heredoc_body_is_attached_and_not_lexed(self) -> None:
        text = "RUN <<EOF\nset -eux\nUSER root\nEXPOSE 22\nEOF\nUSER app\n"
        found = lex(text).instructions
        assert [i.name for i in found] == ["RUN", "USER"]
        assert found[0].heredoc_body == "set -eux\nUSER root\nEXPOSE 22"
        assert found[0].args == "<<EOF"
        assert (found[0].start_line, found[0].end_line) == (1, 5)
        assert found[1].start_line == 6

    def test_a_copy_heredoc_body_never_becomes_instructions(self) -> None:
        text = 'FROM alpine\nCOPY <<EOF /etc/app.conf\nUSER root\nEXPOSE 22\nEOF\nCMD ["x"]'
        found = lex(text).instructions
        assert [i.name for i in found] == ["FROM", "COPY", "CMD"]
        assert "USER root" in found[1].heredoc_body

    def test_quoted_and_dash_markers(self) -> None:
        text = "RUN <<-'END'\n\tcurl x | sh\n\tEND\nUSER app"
        found = lex(text).instructions
        assert [i.name for i in found] == ["RUN", "USER"]
        assert found[0].heredoc_body == "curl x | sh"

    def test_two_heredocs_on_one_instruction(self) -> None:
        text = "RUN cat <<ONE; cat <<TWO\nfirst\nONE\nsecond\nTWO\nUSER x"
        found = lex(text).instructions
        assert [i.name for i in found] == ["RUN", "USER"]
        assert found[0].heredoc_body == "first\nsecond"

    def test_an_unterminated_heredoc_is_not_a_heredoc(self) -> None:
        text = "RUN cat <<EOF\nUSER root\nEXPOSE 22"
        assert names(text) == ["RUN", "USER", "EXPOSE"]

    def test_a_here_string_and_a_shift_are_not_heredocs(self) -> None:
        assert find_heredocs("grep x <<< word") == []
        assert find_heredocs("echo $((1<<2))") == []

    def test_a_marker_inside_quotes_is_not_a_heredoc(self) -> None:
        assert find_heredocs("echo \"<<EOF\" '<<EOF'") == []
        assert find_heredocs("cat <<EOF") == [("EOF", False)]

    def test_other_instructions_do_not_take_heredocs(self) -> None:
        assert names("ENV X=<<EOF\nUSER root\nEOF") == ["ENV", "USER"]

    def test_the_terminator_must_be_alone_on_its_line(self) -> None:
        text = "RUN <<EOF\necho EOF\nEOF\nUSER app"
        found = lex(text).instructions
        assert found[0].heredoc_body == "echo EOF"
        assert [i.name for i in found] == ["RUN", "USER"]


class TestOnbuild:
    def test_the_trigger_is_unwrapped_with_the_flag(self) -> None:
        ins = only("ONBUILD RUN npm ci")
        assert (ins.name, ins.args, ins.onbuild) == ("RUN", "npm ci", True)

    def test_a_plain_instruction_is_not_flagged(self) -> None:
        assert only("RUN npm ci").onbuild is False

    @pytest.mark.parametrize("text", ["ONBUILD", "ONBUILD ONBUILD RUN x", "ONBUILD FROM x"])
    def test_an_invalid_trigger_is_skipped(self, text: str) -> None:
        result = lex(text)
        assert result.instructions == []
        assert len(result.skipped) == 1

    def test_a_trigger_can_carry_a_heredoc(self) -> None:
        found = lex("ONBUILD RUN <<EOF\nmake\nEOF\n").instructions
        assert found[0].heredoc_body == "make"
        assert found[0].onbuild


class TestWordsAndOptions:
    def test_split_words_respects_quotes_and_escapes(self) -> None:
        assert split_words("a \"b c\" 'd e' f\\ g") == ["a", "b c", "d e", "f g"]

    def test_a_stray_quote_cannot_stall_the_scan(self) -> None:
        assert split_words('a " b') == ["a", '"', "b"]

    def test_unquote_keeps_a_single_quoted_backslash(self) -> None:
        assert unquote("'a\\b'") == "a\\b"
        assert unquote('"a\\"b"') == 'a"b'

    def test_options_are_read_until_the_first_non_option(self) -> None:
        options, rest = split_options("--chown=app:app --link src dest")
        assert options == {"chown": "app:app", "link": ""}
        assert rest == "src dest"

    def test_an_option_like_text_after_the_first_argument_is_not_an_option(self) -> None:
        options, rest = split_options("src --not-an-option dest")
        assert options == {}
        assert rest == "src --not-an-option dest"

    def test_json_arrays(self) -> None:
        assert parse_json_array('["a", "b"]') == ["a", "b"]
        assert parse_json_array("[1, 2]") is None
        assert parse_json_array("a b") is None
        assert parse_json_array("[broken") is None

    def test_variables(self) -> None:
        assert has_variable("a${B}c")
        assert has_variable("$A")
        assert not has_variable("a\\$B")
        assert not has_variable("plain")


class TestSubstitute:
    @pytest.mark.parametrize(
        ("text", "known", "expected", "unresolved"),
        [
            ("base:${TAG}", {"TAG": "1.2"}, "base:1.2", []),
            ("base:$TAG", {"TAG": "1.2"}, "base:1.2", []),
            ("base:${TAG}", {}, "base:${TAG}", ["${TAG}"]),
            ("base:${TAG:-3}", {}, "base:3", []),
            ("base:${TAG:-3}", {"TAG": ""}, "base:3", []),
            ("base:${TAG-3}", {"TAG": ""}, "base:", []),
            ("a${X:+yes}b", {"X": "1"}, "ayesb", []),
            ("a${X:+yes}b", {}, "ab", []),
            ("${A}/${B}", {"A": "x"}, "x/${B}", ["${B}"]),
            ("price \\$5", {}, "price \\$5", []),
        ],
    )
    def test_substitution(
        self, text: str, known: dict[str, str], expected: str, unresolved: list[str]
    ) -> None:
        result, missing = substitute(text, known.get)
        assert (result, missing) == (expected, unresolved)


class TestShell:
    def test_operators_end_pipelines_and_pipes_join_commands(self) -> None:
        pipelines = shell_pipelines("curl x | sh && echo done; ls | wc -l")
        assert [[c[0] for c in p] for p in pipelines] == [["curl", "sh"], ["echo"], ["ls", "wc"]]

    def test_quoted_operators_do_not_split(self) -> None:
        pipelines = shell_pipelines("echo 'a | b' \"c && d\" | cat")
        assert len(pipelines) == 1
        assert [c[0] for c in pipelines[0]] == ["echo", "cat"]

    def test_newlines_and_backslash_newlines(self) -> None:
        pipelines = shell_pipelines("set -e\ncurl x \\\n  | sh\n")
        assert [[c[0] for c in p] for p in pipelines] == [["set"], ["curl", "sh"]]

    def test_command_name_skips_wrappers_and_assignments(self) -> None:
        assert command_name(["FOO=1", "sudo", "-E", "-u", "root", "bash", "-s"]) == (
            ["sudo"],
            "bash",
            ["-s"],
        )
        assert command_name(["env", "A=1", "B=2", "python3", "x.py"]) == (
            ["env"],
            "python3",
            ["x.py"],
        )
        assert command_name(["command", "-v", "sudo"]) == ([], "command", ["-v", "sudo"])
        assert command_name(["/usr/bin/curl", "-s"])[1] == "curl"
        assert command_name(["sudo"]) == (["sudo"], "", [])

    def test_a_quoted_program_name_is_unquoted(self) -> None:
        assert command_name(['"bash"'])[1] == "bash"

    def test_adversarial_inputs_stay_fast(self) -> None:
        cases = [
            "curl x " * 200_000,
            "'\"` " * 100_000,
            "a | " * 200_000,
            "\\" * 300_000,
            "(" * 300_000,
        ]
        for text in cases:
            started = time.perf_counter()
            shell_pipelines(text)
            assert time.perf_counter() - started < 3.0, text[:8]

    def test_the_lexer_is_linear_on_a_huge_single_line(self) -> None:
        text = "FROM debian\nRUN " + "curl x " * 200_000 + "\n"
        started = time.perf_counter()
        assert len(lex(text).instructions) == 2
        assert time.perf_counter() - started < 3.0

    def test_unterminated_heredocs_are_linear(self) -> None:
        text = "FROM debian\n" + "RUN <<EOF\nx\n" * 20_000
        started = time.perf_counter()
        result = lex(text)
        assert time.perf_counter() - started < 1.0
        assert len(result.instructions) == 20_001
        assert all(not ins.heredoc_body for ins in result.instructions)

    def test_a_far_terminator_with_a_missing_second_marker_is_linear(self) -> None:
        text = "FROM debian\n" + "RUN <<A <<B\nx\n" * 20_000 + "A\n"
        started = time.perf_counter()
        result = lex(text)
        assert time.perf_counter() - started < 1.0
        assert all(not ins.heredoc_body for ins in result.instructions)

    def test_many_distinct_unterminated_markers_are_linear(self) -> None:
        text = "".join(f"RUN <<W{n}\nx\n" for n in range(20_000))
        started = time.perf_counter()
        lex(text)
        assert time.perf_counter() - started < 1.0

    def test_terminated_heredocs_still_read_their_bodies(self) -> None:
        instructions = lex("RUN <<A <<-B\none\nA\n\ttwo\n\tB\nRUN <<C\n").instructions
        assert instructions[0].heredoc_body == "one\ntwo"
        assert instructions[0].end_line == 5
        assert instructions[1].heredoc_body == ""
