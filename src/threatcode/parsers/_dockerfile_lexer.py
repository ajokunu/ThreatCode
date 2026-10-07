"""A BuildKit-faithful Dockerfile lexer and the small text tools the Dockerfile parser needs.

The lexer reads physical lines the way BuildKit does:

* Lines are split on ``\\n`` only (never ``str.splitlines``, which also splits on form feeds
  and Unicode separators and shifts every later line number).
* ``# escape=`` and ``# syntax=`` directives count only in the comment lines at the top.
  The escape character is a backslash unless a directive makes it a backtick.
* Blank lines and comment lines are skipped everywhere, including inside a continuation.
  A comment that ends in the escape character does not continue onto the next line.
* A line whose last non-space character is the escape character continues onto the next
  physical line.
* Keywords are case-insensitive and reported upper-case. A lone keyword has empty arguments.
* ``RUN``, ``COPY`` and ``ADD`` accept heredocs (``<<EOF``, ``<<-EOF``, ``<<'EOF'``). The
  body lines up to the terminator belong to that instruction and never become instructions.
  A marker without a terminator is not a heredoc, so a stray ``<<`` cannot swallow the file.
* ``ONBUILD <INSTRUCTION>`` is unwrapped into the inner instruction with the ``onbuild`` flag.

Every instruction is reported at its first physical line, with the last line it spans.

The text tools below the lexer are the ones the parser shares: whitespace splitting that
respects quotes, leading ``--flag[=value]`` options, ``$VAR`` substitution and a shell
tokenizer that splits ``RUN`` text into pipelines of commands. All of them run in time linear
in the length of the text, because Dockerfiles in the wild contain single lines of megabytes.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

# Every instruction BuildKit knows. Anything else is not an instruction.
KEYWORDS: frozenset[str] = frozenset(
    {
        "FROM",
        "RUN",
        "CMD",
        "LABEL",
        "MAINTAINER",
        "EXPOSE",
        "ENV",
        "ADD",
        "COPY",
        "ENTRYPOINT",
        "VOLUME",
        "USER",
        "WORKDIR",
        "ARG",
        "ONBUILD",
        "STOPSIGNAL",
        "HEALTHCHECK",
        "SHELL",
    }
)

# Instructions that may carry heredocs.
HEREDOC_INSTRUCTIONS: frozenset[str] = frozenset({"RUN", "COPY", "ADD"})

# Triggers ONBUILD cannot carry.
_FORBIDDEN_TRIGGERS: frozenset[str] = frozenset({"ONBUILD", "FROM", "MAINTAINER"})

ONBUILD_FLAG = "onbuild"

_DIRECTIVES: frozenset[str] = frozenset({"escape", "syntax", "check"})
_DIRECTIVE_RE = re.compile(r"^\s*#\s*([A-Za-z]+)\s*=\s*(\S.*?)\s*$")
_KEYWORD_RE = re.compile(r"([A-Za-z]+)(?=\s|$)\s*(.*)$", re.DOTALL)

# Quoted strings are consumed first so a marker inside quotes is not a heredoc.
_HEREDOC_RE = re.compile(
    r"""
    "(?:[^"\\]|\\.)*"
    | '[^']*'
    | (?<!<)<<(?!<)(-?)(?:"([^"]+)"|'([^']+)'|([A-Za-z_][A-Za-z0-9_]*))
    """,
    re.VERBOSE | re.DOTALL,
)


@dataclass(frozen=True)
class Instruction:
    """One instruction.

    ``args`` is the logical argument text: continuation lines joined with a single space and
    comment lines dropped, without the heredoc body.
    ``flags`` holds ``"onbuild"`` for an instruction unwrapped from ``ONBUILD``.
    """

    name: str
    args: str
    start_line: int
    end_line: int
    heredoc_body: str = ""
    flags: frozenset[str] = frozenset()

    @property
    def onbuild(self) -> bool:
        return ONBUILD_FLAG in self.flags


@dataclass(frozen=True)
class SkippedLine:
    """A logical line that is not an instruction, with the reason."""

    line: int
    text: str
    reason: str


@dataclass
class LexResult:
    instructions: list[Instruction] = field(default_factory=list)
    skipped: list[SkippedLine] = field(default_factory=list)
    escape: str = "\\"
    syntax: str = ""


def split_lines(text: str) -> list[str]:
    """Split on newline only, dropping one trailing carriage return per line."""
    if text.startswith("﻿"):
        text = text[1:]
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def _read_directives(lines: list[str]) -> tuple[str, str]:
    escape, syntax = "\\", ""
    for line in lines:
        match = _DIRECTIVE_RE.match(line)
        if match is None or match.group(1).lower() not in _DIRECTIVES:
            break
        name, value = match.group(1).lower(), match.group(2)
        if name == "escape" and value in ("\\", "`"):
            escape = value
        elif name == "syntax":
            syntax = value
    return escape, syntax


def _is_skippable(line: str) -> bool:
    stripped = line.strip()
    return not stripped or stripped.startswith("#")


def find_heredocs(args: str) -> list[tuple[str, bool]]:
    """The heredoc markers in ``args`` as ``(terminator word, strips leading tabs)``."""
    found: list[tuple[str, bool]] = []
    for match in _HEREDOC_RE.finditer(args):
        word = match.group(2) or match.group(3) or match.group(4)
        if word:
            found.append((word, match.group(1) == "-"))
    return found


def _take_heredocs(
    lines: list[str], index: int, markers: list[tuple[str, bool]]
) -> tuple[str, int] | None:
    """Read the bodies after line ``index``; return the text and the last line used.

    Returns None when any marker has no terminator, so nothing is consumed.
    """
    bodies: list[str] = []
    cursor = index + 1
    for word, strip_tabs in markers:
        body: list[str] = []
        while cursor < len(lines):
            line = lines[cursor]
            candidate = line.lstrip("\t") if strip_tabs else line
            if candidate.rstrip() == word:
                break
            body.append(line.lstrip("\t") if strip_tabs else line)
            cursor += 1
        else:
            return None
        bodies.append("\n".join(body))
        cursor += 1  # the terminator line
    return "\n".join(bodies), cursor - 1


def lex(text: str) -> LexResult:
    """Lex Dockerfile text into instructions (see the module docstring for the rules)."""
    lines = split_lines(text)
    result = LexResult()
    result.escape, result.syntax = _read_directives(lines)
    escape = result.escape
    count = len(lines)
    i = 0
    while i < count:
        if _is_skippable(lines[i]):
            i += 1
            continue
        start = i
        end = i
        parts: list[str] = []
        line = lines[i].strip()
        while True:
            body = line.rstrip()
            if body.endswith(escape):
                parts.append(body[:-1].rstrip())
                i += 1
                while i < count and _is_skippable(lines[i]):
                    i += 1
                if i >= count:
                    break
                end = i
                line = lines[i].strip()
                continue
            parts.append(body)
            break
        i = end + 1
        logical = " ".join(part for part in parts if part)

        match = _KEYWORD_RE.match(logical)
        if match is None:
            result.skipped.append(
                SkippedLine(start + 1, logical[:60], "does not start with an instruction keyword")
            )
            continue
        name = match.group(1).upper()
        args = match.group(2).strip()
        flags: frozenset[str] = frozenset()
        if name not in KEYWORDS:
            result.skipped.append(
                SkippedLine(start + 1, logical[:60], f"{name} is not an instruction")
            )
            continue
        if name == "ONBUILD":
            inner = _KEYWORD_RE.match(args)
            inner_name = inner.group(1).upper() if inner else ""
            if inner is None or inner_name not in KEYWORDS or inner_name in _FORBIDDEN_TRIGGERS:
                result.skipped.append(
                    SkippedLine(
                        start + 1, logical[:60], "ONBUILD needs a valid trigger instruction"
                    )
                )
                continue
            name, args = inner_name, inner.group(2).strip()
            flags = frozenset({ONBUILD_FLAG})

        heredoc_body = ""
        if name in HEREDOC_INSTRUCTIONS:
            markers = find_heredocs(args)
            if markers:
                taken = _take_heredocs(lines, end, markers)
                if taken is not None:
                    heredoc_body, end = taken
                    i = end + 1
        result.instructions.append(
            Instruction(name, args, start + 1, end + 1, heredoc_body=heredoc_body, flags=flags)
        )
    return result


# ---------------------------------------------------------------------------
# Words, options, JSON arrays, substitution
# ---------------------------------------------------------------------------

# A shell-like word: runs of plain characters, quoted strings and escaped characters. A stray
# quote or backslash that opens nothing is a word of its own, so scanning cannot stall.
_WORD_RE = re.compile(r"""(?:"(?:[^"\\]|\\.)*"|'[^']*'|\\.|[^\s"'\\])+|["'\\]""", re.DOTALL)


def split_words_raw(text: str) -> list[str]:
    """Split on whitespace outside quotes, keeping the quotes in each word."""
    return _WORD_RE.findall(text)


def unquote(word: str) -> str:
    """Remove the quotes and escapes of one raw word."""
    if len(word) == 1 or ("'" not in word and '"' not in word and "\\" not in word):
        return word
    out: list[str] = []
    quote = ""
    i = 0
    while i < len(word):
        ch = word[i]
        if ch == "\\" and quote != "'" and i + 1 < len(word):
            out.append(word[i + 1])
            i += 2
            continue
        if ch in "'\"" and (not quote or quote == ch):
            quote = "" if quote else ch
            i += 1
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def split_words(text: str) -> list[str]:
    """Split on whitespace outside quotes and remove the quotes."""
    return [unquote(word) for word in split_words_raw(text)]


_OPTION_RE = re.compile(r"--([A-Za-z][A-Za-z0-9_-]*)(?:=(\S*))?(?:\s+|$)")


def split_options(args: str) -> tuple[dict[str, str], str]:
    """Split leading ``--flag[=value]`` tokens from the rest of an instruction's arguments.

    A flag without a value maps to the empty string. Later flags win over earlier ones.
    """
    options: dict[str, str] = {}
    pos = 0
    text = args.lstrip()
    while True:
        match = _OPTION_RE.match(text, pos)
        if match is None:
            break
        options[match.group(1).lower()] = unquote(match.group(2) or "")
        pos = match.end()
    return options, text[pos:].strip()


def parse_json_array(text: str) -> list[str] | None:
    """Return the strings of a JSON array argument (exec form), or None if it is not one."""
    stripped = text.strip()
    if not (stripped.startswith("[") and stripped.endswith("]")):
        return None
    try:
        value = json.loads(stripped)
    except ValueError:
        return None
    if isinstance(value, list) and all(isinstance(item, str) for item in value):
        return list(value)
    return None


_VAR_RE = re.compile(
    r"(?<!\\)\$(?:\{([A-Za-z_][A-Za-z0-9_]*)(?:(:?[-+])([^}]*))?\}|([A-Za-z_][A-Za-z0-9_]*))"
)


def has_variable(text: str) -> bool:
    """True when the text references a variable (``$NAME`` or ``${NAME...}``)."""
    return _VAR_RE.search(text) is not None


def substitute(text: str, lookup: Callable[[str], str | None]) -> tuple[str, list[str]]:
    """Replace ``$NAME`` and ``${NAME}`` (with ``:-``, ``-``, ``:+`` and ``+``) using ``lookup``.

    Returns the substituted text and the variable references that could not be resolved,
    which are left in the text exactly as written.
    """
    unresolved: list[str] = []

    def replace(match: re.Match[str]) -> str:
        name = match.group(1) or match.group(4)
        modifier, operand = match.group(2), match.group(3) or ""
        value = lookup(name)
        if modifier in ("-", ":-"):
            if value is None or (modifier == ":-" and value == ""):
                return operand
            return value
        if modifier in ("+", ":+"):
            if value is None or (modifier == ":+" and value == ""):
                return ""
            return operand
        if value is None:
            unresolved.append(match.group(0))
            return match.group(0)
        return value

    return _VAR_RE.sub(replace, text), unresolved


# ---------------------------------------------------------------------------
# Shell tokenizer
# ---------------------------------------------------------------------------

_SHELL_RE = re.compile(
    r"""
      (?P<space>[ \t]+)
    | (?P<cont>\\\n)
    | (?P<newline>\n)
    | (?P<redir>&>>?)
    | (?P<op>&&|\|\||\|&|\||;|&|\(|\))
    | (?P<word>(?:"(?:[^"\\]|\\.)*"|'[^']*'|\\.|[<>]&[0-9]*-?|[^\s|&;()"'\\])+|["'\\])
    """,
    re.VERBOSE | re.DOTALL,
)

_PIPES = frozenset({"|", "|&"})


def shell_pipelines(text: str) -> list[list[list[str]]]:
    """Split shell text into pipelines of commands of raw words.

    ``&&``, ``||``, ``;``, ``&``, parentheses and newlines end a pipeline; ``|`` joins the
    commands on either side into one. Quoted strings stay inside their word, and a
    backslash-newline joins lines. File-descriptor redirections (``2>&1``, ``>&2``, ``&>file``,
    ``>&-``) stay inside the command; only a bare ``&`` or ``&&`` ends it.
    """
    pipelines: list[list[list[str]]] = []
    pipeline: list[list[str]] = []
    command: list[str] = []

    def end_command() -> None:
        nonlocal command
        if command:
            pipeline.append(command)
            command = []

    def end_pipeline() -> None:
        nonlocal pipeline
        end_command()
        if pipeline:
            pipelines.append(pipeline)
            pipeline = []

    for match in _SHELL_RE.finditer(text):
        kind = match.lastgroup
        if kind in ("word", "redir"):
            command.append(match.group())
        elif kind == "op":
            if match.group() in _PIPES:
                end_command()
            else:
                end_pipeline()
        elif kind == "newline":
            end_pipeline()
    end_pipeline()
    return pipelines


_ASSIGNMENT_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
# Shell reserved words that can precede a command in command position.
_RESERVED_PREFIXES = frozenset({"if", "then", "else", "elif", "do", "while", "until", "!", "{"})
# Wrappers that run the next command; the value is the options that take an argument.
_WRAPPERS: Mapping[str, frozenset[str]] = {
    "sudo": frozenset({"-u", "-g", "-h", "-p", "-C", "-T", "-r", "-t", "-U", "-D"}),
    "doas": frozenset({"-u", "-C"}),
    "env": frozenset({"-u", "-C", "-S"}),
    "command": frozenset(),
    "exec": frozenset({"-a"}),
    "nohup": frozenset(),
    "time": frozenset(),
}


def command_name(raw_words: list[str]) -> tuple[list[str], str, list[str]]:
    """Find the program a command runs.

    Skips ``VAR=value`` prefixes, reserved words such as ``then`` and ``do``, and wrapper
    commands (``sudo``, ``env``, ``command``, ``exec``, ``nohup``, ``time``) with their options.
    Returns the wrappers that were skipped, the program's base name and the words after it.
    """
    words = [unquote(word) for word in raw_words]
    wrappers: list[str] = []
    i = 0
    while i < len(words):
        word = words[i]
        if _ASSIGNMENT_RE.match(word) or word in _RESERVED_PREFIXES:
            i += 1
            continue
        base = word.rsplit("/", 1)[-1]
        takes_argument = _WRAPPERS.get(base)
        if takes_argument is None:
            return wrappers, base, words[i + 1 :]
        if base == "command" and any(w in ("-v", "-V") for w in words[i + 1 : i + 3]):
            # `command -v sudo` looks a program up; it does not run it
            return wrappers, "command", words[i + 1 :]
        wrappers.append(base)
        i += 1
        while i < len(words) and words[i].startswith("-"):
            option = words[i]
            i += 1
            if option in takes_argument and i < len(words):
                i += 1
        if base == "env":
            while i < len(words) and _ASSIGNMENT_RE.match(words[i]):
                i += 1
    return wrappers, "", []
