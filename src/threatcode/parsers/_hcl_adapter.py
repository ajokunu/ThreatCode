"""One canonical view of Terraform source, whichever python-hcl2 reads it.

python-hcl2 changed its output between 4.x and 8.x.
Labels and string values keep their surrounding quotes in 8.x, a heredoc is reported with its
``<<EOT`` markers, objects carry ``__is_block__`` markers, ``jsonencode`` is printed as HCL
rather than as a Python literal, and the ``with_meta`` option no longer reports line numbers.
Everything that reads HCL goes through this module, so the parser sees the 4.x shape in both.

The canonical shape is a list of :class:`HclBlock` with these rules.

- Labels are plain text, without quotes.
- String values are in source form without their quotes: an expression is ``${...}``, a quoted
  string keeps its backslash escapes, a heredoc is its text with the indentation of ``<<-``
  removed and no trailing newline.
- A nested block is a list of dictionaries, one per occurrence, and no markers remain.
- Top-level blocks carry the 1-based first and last line of their source.
  The lines come from a brace-matching scan of the text for both versions, because 8.x reports
  none and one scan is easier to trust than two sources.
  Where the scan cannot pair its blocks with the parsed ones the lines are ``None``.

Terraform's JSON syntax (``main.tf.json``, written by CDK for Terraform) is converted to the
same blocks.

Three things keep real repositories readable and correct.

- A file that python-hcl2 rejects is tried once more with its layout normalized (see
  ``normalize_layout``).
  python-hcl2 4.x cannot read an object element whose value is an operator expression
  (``index = var.n == 0 ? 0 : 1`` followed by another element), a conditional that breaks its
  line before ``?`` inside nested parentheses, or a ``\\r\\n`` inside a block comment, and 8.x
  cannot read a traversal that continues on the next line.
  All of these are valid HCL, and the normalized text means the same thing.
  When the retry fails too, the error of the original text is reported, with its line numbers.
- python-hcl2 4.x drops the parentheses of a grouped expression: ``a && (b || c)`` comes back
  as ``a && b || c``, which changes what a ``count`` or a condition evaluates to.
  Before a 4.x parse every grouping ``(`` is renamed ``__tcg(`` (a function call, which 4.x keeps),
  and the marker is put back in the parsed strings.
  A call such as ``length(x)`` is not a group and is left alone.
- The same text is parsed once: a module directory is read as a unit of its own and again by
  every caller, and python-hcl2 8.x parses about 2.5 times slower than 4.x, so ``_parse`` keeps
  the parsed data of recent texts (see ``_ParseCache``).
"""

from __future__ import annotations

import importlib
import re
import threading
from bisect import bisect_right
from collections import OrderedDict, defaultdict
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Any

from threatcode.exceptions import ParseError
from threatcode.parsers._json_lines import json_line_index

# Block kinds read by the parser, with the number of labels each has
BLOCK_LABELS: dict[str, int] = {
    "resource": 2,
    "data": 2,
    "module": 1,
    "variable": 1,
    "output": 1,
    "provider": 1,
    "locals": 0,
    "terraform": 0,
}

_HEREDOC_HEADER = re.compile(r"<<(-?)[ \t]*([A-Za-z_][\w-]*)[ \t]*\r?\n")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_META_KEYS = frozenset({"__is_block__", "__start_line__", "__end_line__"})
_MAX_NESTING = 200


def _too_deep(name: str) -> str:
    return f"{name}: nested too deeply to read"


@contextmanager
def _bounded(name: str) -> Iterator[None]:
    """Input nested past ``_MAX_NESTING`` is a ``ParseError`` naming the file.

    The walks below raise ``RecursionError`` when they are cut off, and python-hcl2 4.x and
    8.x differ in where that surfaces, so both end up here as the same error.
    """
    try:
        yield
    except RecursionError as exc:
        raise ParseError(_too_deep(name)) from exc


@dataclass(frozen=True)
class HclBlock:
    """One top-level block: ``resource "aws_s3_bucket" "logs" { ... }`` and its relatives."""

    kind: str
    labels: tuple[str, ...]
    body: dict[str, Any]
    start_line: int | None = None
    end_line: int | None = None


@dataclass
class HclDocument:
    """The blocks of one file, in the order python-hcl2 groups them."""

    blocks: list[HclBlock] = field(default_factory=list)


# --- reading python-hcl2 ---------------------------------------------------------------


def _hcl2() -> Any:
    """The python-hcl2 module, typed loosely because its API differs between 4.x and 8.x."""
    return importlib.import_module("hcl2")


def _is_modern() -> bool:
    return hasattr(_hcl2(), "SerializationOptions")


def _hcl2_loads(text: str) -> dict[str, Any]:
    hcl2 = _hcl2()
    if hasattr(hcl2, "SerializationOptions"):
        options = hcl2.SerializationOptions(
            with_comments=False, explicit_blocks=False, preserve_heredocs=True
        )
        return dict(hcl2.loads(text, serialization_options=options))
    return dict(hcl2.loads(text))


def describe_error(exc: Exception, name: str) -> str:
    """One-line message with the file and line, without the parser's token dump."""
    line = getattr(exc, "line", None)
    column = getattr(exc, "column", None)
    if isinstance(line, int) and line > 0:
        where = f"line {line}"
        if isinstance(column, int) and column > 0:
            where += f", column {column}"
        return f"Invalid HCL in {name}, {where}: syntax error"
    detail = str(exc).strip().splitlines()[0] if str(exc).strip() else type(exc).__name__
    if "Token(" in detail or "Expected one of" in detail:
        detail = "syntax error"  # the parser's token dump helps nobody
    return f"Invalid HCL in {name}: {detail}"


def _load_data(text: str) -> dict[str, Any]:
    return _canonical(_hcl2_loads(text), 0) if _is_modern() else _hcl2_loads(text)


# The text the pure Python layout rewrite is run on, at most: past this it costs more than it is
# worth, and a file this size is not hand-written Terraform
_MAX_NORMALIZED_CHARS = 4_000_000
# Said after a 4.x failure, because 4.x rejects some valid HCL and the line it names may be before
# the real problem
_UPGRADE_HINT = " (python-hcl2 4.x cannot read some valid HCL: pip install -U 'python-hcl2>=8')"
# The marker that keeps a grouping parenthesis through python-hcl2 4.x
_GROUP_MARK = "__tcg"


def _layouts() -> list[tuple[bool, bool] | None]:
    """The ``(flatten, mark)`` layouts to try in order, ``None`` being the text as written.

    4.x gets its groups marked on the first try, because it reads everything else the same, then
    the full rewrite, then the text as written (which reads, but loses the parentheses).
    8.x reads the text as written, then with the line breaks inside brackets joined.
    """
    if _is_modern():
        return [None, (True, False)]
    return [(False, True), (True, True), None]


def _parse(text: str, name: str) -> dict[str, Any]:
    try:
        _hcl2()
    except ImportError as exc:
        raise ParseError("python-hcl2 required: pip install python-hcl2") from exc
    key = (text, _hcl2_loads)
    cached = _PARSE_CACHE.get(key)
    if cached is not None:
        return cached
    data = _read_layouts(text, name)
    _PARSE_CACHE.put(key, data, len(text))
    return data


def _read_layouts(text: str, name: str) -> dict[str, Any]:
    """Parse ``text``, trying each layout until one reads; the error is the text's own."""
    original: Exception = ValueError("unreadable")
    tried = {text}
    for layout in _layouts():
        candidate = text
        if layout is not None:
            if len(text) > _MAX_NORMALIZED_CHARS:
                continue
            try:
                rewritten = normalize_layout(text, flatten=layout[0], mark=layout[1])
            except Exception:  # noqa: BLE001 - the rewrite is a convenience, never a new failure
                rewritten = None
            if rewritten is None or rewritten in tried:
                continue
            tried.add(rewritten)
            candidate = rewritten
        try:
            data = _load_data(candidate)
        except RecursionError as exc:
            raise ParseError(_too_deep(name)) from exc
        except Exception as exc:  # noqa: BLE001 - python-hcl2 raises its own error types
            if layout is None:
                original = exc
            continue
        return _restore_groups(data, 0) if layout is not None and layout[1] else data
    message = describe_error(original, name)
    if not _is_modern():
        message += _UPGRADE_HINT
    raise ParseError(message) from original


def _restore_groups(value: Any, depth: int) -> Any:
    """Put the grouping parentheses back where ``_GROUP_MARK`` carried them through 4.x."""
    if depth > _MAX_NESTING:
        raise RecursionError("HCL value nested too deeply")
    if isinstance(value, str):
        return value.replace(f"{_GROUP_MARK}(", "(") if _GROUP_MARK in value else value
    if isinstance(value, dict):
        return {
            _restore_groups(k, depth + 1): _restore_groups(v, depth + 1) for k, v in value.items()
        }
    if isinstance(value, list):
        return [_restore_groups(v, depth + 1) for v in value]
    return value


# --- a bounded cache of parsed texts ---------------------------------------------------------


class _ParseCache:
    """The parsed data of recently seen texts, bounded by the characters of text it holds.

    The data is shared between callers and nothing may change it: ``load`` and
    ``load_attributes`` copy it into new containers (``_strip_meta``), and the strings, numbers
    and booleans inside are immutable.
    The key holds the python-hcl2 entry point too, so replacing it (a test, a different major)
    never serves data parsed by another one.
    """

    def __init__(self, max_chars: int) -> None:
        self._max_chars = max_chars
        self._entries: OrderedDict[
            tuple[str, Callable[[str], dict[str, Any]]], tuple[dict[str, Any], int]
        ]
        self._entries = OrderedDict()
        self._chars = 0
        self._lock = threading.Lock()

    def get(self, key: tuple[str, Callable[[str], dict[str, Any]]]) -> dict[str, Any] | None:
        with self._lock:
            entry = self._entries.get(key)
            if entry is None:
                return None
            self._entries.move_to_end(key)
            return entry[0]

    def put(
        self, key: tuple[str, Callable[[str], dict[str, Any]]], data: dict[str, Any], size: int
    ) -> None:
        if size > self._max_chars:
            return
        with self._lock:
            if key in self._entries:
                return
            self._entries[key] = (data, size)
            self._chars += size
            while self._chars > self._max_chars:
                _, (_, evicted) = self._entries.popitem(last=False)
                self._chars -= evicted

    def clear(self) -> None:
        with self._lock:
            self._entries.clear()
            self._chars = 0


# Eight million characters of source: enough for a large repository's modules to stay parsed
# for the length of one scan, small enough that the data (a few times the size of the text) is
# never a memory concern
_PARSE_CACHE = _ParseCache(8_000_000)


# --- layout normalization: the retry for grammar gaps ---------------------------------------

_WORD = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_CARRIAGE_RETURNS = re.compile(r"\r+\n")
_NUMBER = re.compile(r"[0-9]+(?:\.[0-9]+)?(?:[eE][+-]?[0-9]+)?")
_TWO_CHAR_OPERATORS = frozenset({"==", "!=", "<=", ">=", "&&", "||", "=>", "::"})
_COMPARISONS = frozenset({"==", "!=", "<=", ">=", "&&", "||", "<", ">"})
# `-` and `*` also mean a negative number and a splat, so they only count after an operand
_ARITHMETIC = frozenset({"+", "-", "*", "/", "%"})
# Words that end an expression's value position the way an operator does (``for x in {a = 1}``)
_KEYWORDS = frozenset({"in", "if", "else", "for"})
_MAX_FRAMES = 200
# The frames in which a line break is whitespace; in a block or an object it ends an element
_FLAT_KINDS = frozenset({"paren", "bracket", "for_object"})

# What the previous significant token was: it decides whether `{` opens a block or an object and
# whether `-` is a subtraction
_VALUE, _OPERATOR, _START = "value", "operator", "start"


@dataclass
class _Frame:
    """One open ``{``, ``(`` or ``[`` and, for an object, the element being read."""

    kind: str  # "block", "object", "for_object", "paren" or "bracket"
    expect_key: bool = True
    value_start: int = -1
    value_end: int = -1
    has_operator: bool = False
    has_heredoc: bool = False


class _Layout:
    """One pass over the text that collects the edits ``normalize_layout`` applies."""

    def __init__(self, text: str, flatten: bool, mark: bool) -> None:
        self.text = text
        self.flatten = flatten
        self.mark = mark
        self.edits: list[tuple[int, int, str]] = []
        self.stack: list[_Frame] = [_Frame("block")]
        self.previous = _START
        # True when the previous token was a name: a `(` right after it is a call, not a group
        self.after_name = False
        self.keep_newline = False

    # -- bookkeeping ---------------------------------------------------------------------

    @property
    def top(self) -> _Frame:
        return self.stack[-1]

    def token(self, start: int, end: int, category: str) -> None:
        """Record a significant token: what follows it and where an object value starts and ends."""
        self.previous = category
        self.after_name = False
        frame = self.top
        if frame.kind == "object" and not frame.expect_key:
            if frame.value_start < 0:
                frame.value_start = start
            frame.value_end = end

    def finish_element(self, frame: _Frame) -> None:
        """End the object element in progress, wrapping an operator expression in parentheses."""
        if (
            self.flatten
            and frame.kind == "object"
            and not frame.expect_key
            and frame.has_operator
            and not frame.has_heredoc
            and frame.value_start >= 0
        ):
            self.edits.append((frame.value_start, frame.value_start, "("))
            self.edits.append((frame.value_end, frame.value_end, ")"))
        frame.expect_key = True
        frame.value_start = frame.value_end = -1
        frame.has_operator = frame.has_heredoc = False

    def operator(self, symbol: str) -> None:
        frame = self.top
        if frame.kind != "object" or frame.expect_key:
            return
        if (
            symbol == "?"
            or symbol in _COMPARISONS
            or (symbol in _ARITHMETIC and self.previous == _VALUE)
        ):
            frame.has_operator = True

    # -- the walk ------------------------------------------------------------------------

    def run(self) -> str | None:
        text, n, i = self.text, len(self.text), 0
        while i < n:
            ch = text[i]
            if ch in " \t":
                i += 1
            elif ch in "\r\n":
                self.newline(i)
                i += 1
            elif ch == "#" or text.startswith("//", i):
                end = text.find("\n", i)
                end = n if end == -1 else end
                self.blank(i, end)
                i = end
            elif text.startswith("/*", i):
                end = text.find("*/", i + 2)
                end = n if end == -1 else end + 2
                self.blank(i, end)
                i = end
            elif ch == '"':
                end = _skip_quoted(text, i)
                self.token(i, end, _VALUE)
                i = end
            elif text.startswith("<<", i) and (header := _HEREDOC_HEADER.match(text, i)):
                end = _skip_heredoc(text, header.end(), header.group(2))
                self.token(i, end, _VALUE)
                self.top.has_heredoc = True
                self.keep_newline = True
                i = end
            else:
                i = self.punctuation_or_word(i)
                if i < 0 or len(self.stack) > _MAX_FRAMES:
                    return None
        if len(self.stack) != 1:
            return None
        return self.apply()

    def newline(self, at: int) -> None:
        frame = self.top
        if frame.kind in _FLAT_KINDS:
            if self.keep_newline:
                self.keep_newline = False
            elif self.flatten:
                self.edits.append((at, at + 1, " "))
        elif frame.kind == "object":
            self.finish_element(frame)
            self.keep_newline = False
        else:
            self.keep_newline = False

    def blank(self, start: int, end: int) -> None:
        """A comment inside parentheses or brackets goes, so the line breaks beside it can."""
        if self.flatten and self.top.kind in _FLAT_KINDS and end > start:
            self.edits.append((start, end, " " * (end - start)))

    def punctuation_or_word(self, i: int) -> int:
        """Handle the token at ``i``; the index after it, or -1 when the brackets do not match."""
        text = self.text
        ch = text[i]
        pair = text[i : i + 2]
        if ch == "{":
            self.open_brace(i)
            return i + 1
        if ch == "(":
            self.open_paren(i)
            return i + 1
        if ch == "[":
            self.token(i, i + 1, _OPERATOR)
            self.stack.append(_Frame("bracket"))
            self.previous = _OPERATOR
            return i + 1
        if ch in "})]":
            return self.close(i)
        if pair in _TWO_CHAR_OPERATORS:
            self.operator(pair)
            self.token(i, i + 2, _OPERATOR)
            return i + 2
        if ch in "=:":
            frame = self.top
            if frame.kind == "object" and frame.expect_key:
                frame.expect_key = False
            self.previous = _OPERATOR
            self.after_name = False
            return i + 1
        if ch == ",":
            self.finish_element(self.top)
            self.previous = _OPERATOR
            self.after_name = False
            return i + 1
        word = _WORD.match(text, i)
        if word is not None:
            is_keyword = word.group(0) in _KEYWORDS
            self.token(i, word.end(), _OPERATOR if is_keyword else _VALUE)
            self.after_name = not is_keyword
            return word.end()
        number = _NUMBER.match(text, i)
        if number is not None:
            self.token(i, number.end(), _VALUE)
            return number.end()
        if ch == ".":
            # a traversal: `a.b`, `a.*.b`; what follows is a name, not an operand
            self.token(i, i + 1, _OPERATOR)
            return i + 1
        # `?` `<` `>` `+` `-` `*` `/` `%` `!` `&` `|` and anything else a single character long
        self.operator(ch)
        self.token(i, i + 1, _OPERATOR)
        return i + 1

    def open_paren(self, at: int) -> None:
        """`(` after a name is a call; anywhere else it groups, and 4.x loses a group."""
        grouping = not self.after_name
        key = self.top.kind == "object" and self.top.expect_key
        if self.mark and grouping and not key:
            # the space keeps `if(` and `in(` from running into the name
            self.edits.append((at, at + 1, f" {_GROUP_MARK}("))
        self.token(at, at + 1, _OPERATOR)
        self.stack.append(_Frame("paren"))
        self.previous = _OPERATOR

    def open_brace(self, at: int) -> None:
        """`{` after a name or a quoted label opens a block; anywhere else it opens an object."""
        if self.top.kind == "block" and self.previous == _VALUE:
            kind = "block"
        else:
            following = _skip_trivia(self.text, at + 1)
            word = _WORD.match(self.text, following)
            kind = "for_object" if word is not None and word.group(0) == "for" else "object"
        self.token(at, at + 1, _OPERATOR)
        self.stack.append(_Frame(kind))
        self.previous = _START

    def close(self, at: int) -> int:
        frame = self.top
        wanted = {"}": ("block", "object", "for_object"), ")": ("paren",), "]": ("bracket",)}
        if len(self.stack) == 1 or frame.kind not in wanted[self.text[at]]:
            return -1
        self.finish_element(frame)
        self.stack.pop()
        self.token(at, at + 1, _VALUE)
        return at + 1

    def apply(self) -> str:
        pieces: list[str] = []
        position = 0
        for start, end, replacement in sorted(self.edits, key=lambda edit: (edit[0], edit[1])):
            pieces.append(self.text[position:start])
            pieces.append(replacement)
            position = end
        pieces.append(self.text[position:])
        return "".join(pieces)


def normalize_layout(text: str, *, flatten: bool = True, mark: bool = False) -> str | None:
    """The same HCL written another way, for what python-hcl2 cannot read or keep.

    ``flatten`` makes the layout rewrites, none of which changes what the text means.

    - Inside parentheses, brackets and the braces of a ``for`` expression a line break is
      whitespace in HCL, so it becomes a space (a comment there is dropped first, or it would
      swallow the next line), which turns a conditional or a traversal that wraps over several
      lines into one line.
      A line break inside an object constructor, or after a heredoc, stays: it separates elements.
    - The value of an object element that is an operator expression
      (``index = var.n == 0 ? 0 : 1``) is wrapped in parentheses, which python-hcl2 4.x needs
      when another element follows.
    - ``\\r\\n`` becomes ``\\n`` (the number of lines does not change), because python-hcl2 4.x
      cannot read a ``\\r\\n`` inside a block comment and a checkout with ``core.autocrlf``
      makes every file of a repository so.

    ``mark`` renames every grouping ``(`` to ``__tcg(`` (see the module docstring).

    Strings (with their interpolations), comments and heredocs are never looked into.
    Returns None when the brackets do not match, so there is nothing safe to rewrite.
    """
    if _GROUP_MARK in text:
        mark = False  # a text that already uses the name cannot be told apart afterwards
    return _Layout(_CARRIAGE_RETURNS.sub("\n", text) if flatten else text, flatten, mark).run()


# --- the 8.x spelling of strings ---------------------------------------------------------


def _unquote_key(key: str) -> str:
    if len(key) >= 2 and key[0] == '"' and key[-1] == '"':
        return key[1:-1]
    return key


def _heredoc_text(content: str) -> str | None:
    """The text of a heredoc given as ``<<EOT\\n...\\nEOT``; None when it is not one."""
    match = _HEREDOC_HEADER.match(content)
    if match is None:
        return None
    marker = match.group(2)
    lines = content[match.end() :].split("\n")
    if lines and lines[-1].strip() == marker:
        lines.pop()
    if match.group(1):
        indents = [len(ln) - len(ln.lstrip(" \t")) for ln in lines if ln.strip()]
        strip = min(indents) if indents else 0
        lines = [ln[strip:] if ln.strip() else ln.lstrip(" \t") for ln in lines]
    return "\n".join(lines)


def _canonical_string(value: str) -> str:
    if len(value) >= 2 and value[0] == '"' and value[-1] == '"':
        inner = value[1:-1]
        heredoc = _heredoc_text(inner)
        return inner if heredoc is None else heredoc
    return value


def _canonical(value: Any, depth: int) -> Any:
    """Convert the 8.x shape of a value to the 4.x shape."""
    if depth > _MAX_NESTING:
        raise RecursionError("HCL value nested too deeply")
    if isinstance(value, dict):
        return {
            _unquote_key(str(k)): _canonical(v, depth + 1)
            for k, v in value.items()
            if k not in _META_KEYS
        }
    if isinstance(value, list):
        return [_canonical(v, depth + 1) for v in value]
    if isinstance(value, str):
        return _canonical_string(value)
    return value


def _strip_meta(value: Any, depth: int = 0) -> Any:
    """Drop the markers python-hcl2 may add to block bodies."""
    if depth > _MAX_NESTING:
        raise RecursionError("HCL value nested too deeply")
    if isinstance(value, dict):
        return {k: _strip_meta(v, depth + 1) for k, v in value.items() if k not in _META_KEYS}
    if isinstance(value, list):
        return [_strip_meta(v, depth + 1) for v in value]
    return value


# --- block spans: a brace-matching scan ----------------------------------------------------


@dataclass(frozen=True)
class _Span:
    kind: str
    labels: tuple[str, ...]
    start_line: int
    end_line: int


def _skip_trivia(text: str, i: int) -> int:
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in " \t\r\n":
            i += 1
        elif ch == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
        else:
            break
    return i


# Interpolations nested inside strings nested inside interpolations: deeper than this is
# taken as running to the end of the text
_MAX_NESTING_DEPTH = 64


def _skip_interpolation(text: str, i: int, depth: int = 0) -> int:
    """Index after the ``}`` that closes the interpolation whose ``{`` is at ``i``."""
    if depth > _MAX_NESTING_DEPTH:
        return len(text)
    nesting = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i = _skip_quoted(text, i, depth + 1)
            continue
        if ch == "{":
            nesting += 1
        elif ch == "}":
            nesting -= 1
            if nesting == 0:
                return i + 1
        i += 1
    return n


def _skip_quoted(text: str, i: int, depth: int = 0) -> int:
    """Index after the double-quoted string that starts at ``i``."""
    if depth > _MAX_NESTING_DEPTH:
        return len(text)
    i += 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
        elif ch == '"':
            return i + 1
        elif text.startswith(("$${", "%%{"), i):
            i += 3
        elif text.startswith(("${", "%{"), i):
            i = _skip_interpolation(text, i + 1, depth + 1)
        else:
            i += 1
    return n


def _skip_heredoc(text: str, i: int, marker: str) -> int:
    """Index of the end of the line that closes a heredoc whose body starts at ``i``."""
    n = len(text)
    while i < n:
        end = text.find("\n", i)
        stop = n if end == -1 else end
        if text[i:stop].strip() == marker:
            return stop
        i = stop + 1
    return n


def _skip_body(text: str, i: int) -> int:
    """Index just after the ``}`` that closes the ``{`` at ``i``."""
    depth = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == '"':
            i = _skip_quoted(text, i)
            continue
        if ch == "#" or text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        if text.startswith("/*", i):
            end = text.find("*/", i + 2)
            i = n if end == -1 else end + 2
            continue
        if text.startswith("<<", i):
            header = _HEREDOC_HEADER.match(text, i)
            if header is not None:
                i = _skip_heredoc(text, header.end(), header.group(2))
                continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return i + 1
        i += 1
    return n


def scan_blocks(text: str) -> list[_Span]:
    """Find the top-level blocks of ``text`` and the lines they span.

    This is not a parser: it only needs to find where each block starts and where its braces
    close, skipping strings, comments and heredocs. A top-level attribute (as in a ``.tfvars``
    file) is skipped to the end of its line.
    """
    starts = [0]
    starts.extend(m.end() for m in re.finditer("\n", text))

    def line_of(pos: int) -> int:
        return bisect_right(starts, pos)

    spans: list[_Span] = []
    i, n = 0, len(text)
    while True:
        i = _skip_trivia(text, i)
        if i >= n:
            break
        match = _IDENT.match(text, i)
        if match is None:
            end = text.find("\n", i)
            i = n if end == -1 else end
            continue
        kind, start, i = match.group(0), i, match.end()
        labels: list[str] = []
        while i < n:
            while i < n and text[i] in " \t":
                i += 1
            if i < n and text[i] == '"':
                end = _skip_quoted(text, i)
                labels.append(text[i + 1 : end - 1])
                i = end
                continue
            label = _IDENT.match(text, i)
            if label is not None and text[i : i + 1] != "{":
                labels.append(label.group(0))
                i = label.end()
                continue
            break
        if i < n and text[i] == "{":
            end = _skip_body(text, i)
            spans.append(_Span(kind, tuple(labels), line_of(start), line_of(max(end - 1, start))))
            i = end
        else:
            end = text.find("\n", i)
            i = n if end == -1 else end
    return spans


# --- building blocks ------------------------------------------------------------------------


def _body(value: Any) -> dict[str, Any] | None:
    if isinstance(value, list) and len(value) == 1:
        value = value[0]
    return _strip_meta(value) if isinstance(value, dict) else None


def _bodies(value: Any) -> list[dict[str, Any]]:
    """Every body of one label path: JSON syntax allows an object or a list of objects."""
    items = value if isinstance(value, list) else [value]
    return [_strip_meta(item) for item in items if isinstance(item, dict)]


def _entries(value: Any) -> list[dict[str, Any]]:
    items = value if isinstance(value, list) else [value]
    return [item for item in items if isinstance(item, dict)]


def _hcl_blocks(data: dict[str, Any]) -> list[tuple[str, tuple[str, ...], dict[str, Any]]]:
    found: list[tuple[str, tuple[str, ...], dict[str, Any]]] = []
    for kind, content in data.items():
        count = BLOCK_LABELS.get(kind)
        if count is None:
            continue
        for entry in _entries(content):
            if count == 0:
                found.append((kind, (), _strip_meta(entry)))
            elif count == 1:
                for label, body in entry.items():
                    parsed = _body(body)
                    if parsed is not None:
                        found.append((kind, (label,), parsed))
            else:
                for first, seconds in entry.items():
                    if not isinstance(seconds, dict):
                        continue
                    for second, body in seconds.items():
                        parsed = _body(body)
                        if parsed is not None:
                            found.append((kind, (first, second), parsed))
    return found


def load(text: str, name: str = "<input>") -> HclDocument:
    """Parse Terraform source into canonical blocks.

    Raises:
        ParseError: python-hcl2 is missing, the text is not valid HCL or it is nested too deeply.
    """
    data = _parse(text, name)
    spans: dict[tuple[str, tuple[str, ...]], list[_Span]] = defaultdict(list)
    for span in scan_blocks(text):
        spans[(span.kind, span.labels)].append(span)
    seen: dict[tuple[str, tuple[str, ...]], int] = defaultdict(int)
    document = HclDocument()
    with _bounded(name):
        blocks = _hcl_blocks(data)
    for kind, labels, body in blocks:
        key = (kind, labels)
        position = seen[key]
        seen[key] += 1
        candidates = spans.get(key, [])
        found = candidates[position] if position < len(candidates) else None
        document.blocks.append(
            HclBlock(
                kind,
                labels,
                body,
                found.start_line if found else None,
                found.end_line if found else None,
            )
        )
    return document


def load_attributes(text: str, name: str = "<input>") -> dict[str, Any]:
    """Parse a file that only assigns values, such as ``terraform.tfvars``."""
    data = _parse(text, name)
    with _bounded(name):
        return {key: _strip_meta(value) for key, value in data.items() if key not in _META_KEYS}


def load_json_syntax(
    data: dict[str, Any], text: str | None = None, name: str = "<input>"
) -> HclDocument:
    """Convert Terraform's JSON syntax to the canonical blocks.

    ``text`` is the source the dictionary was read from. With it, a block's first line is
    taken from the key's line in the file; the last line is not known.
    ``name`` is only used to say which file was nested too deeply (``ParseError``).
    """
    with _bounded(name):
        return _json_syntax_document(data, text)


def _json_syntax_document(data: dict[str, Any], text: str | None) -> HclDocument:
    lines = json_line_index(text) if text else {}

    def line_for(*tokens: str) -> int | None:
        pointer = "".join("/" + t.replace("~", "~0").replace("/", "~1") for t in tokens)
        return lines.get(pointer)

    document = HclDocument()
    for kind, content in data.items():
        count = BLOCK_LABELS.get(kind)
        if count is None:
            continue
        for position, entry in enumerate(_entries(content)):
            prefix = (kind,) if isinstance(content, dict) else (kind, str(position))
            if count == 0:
                document.blocks.append(
                    HclBlock(kind, (), _strip_meta(entry), line_for(*prefix), None)
                )
            elif count == 1:
                for label, body in entry.items():
                    for parsed in _bodies(body):
                        document.blocks.append(
                            HclBlock(kind, (label,), parsed, line_for(*prefix, label), None)
                        )
            else:
                for first, seconds in entry.items():
                    if not isinstance(seconds, dict):
                        continue
                    for second, body in seconds.items():
                        for parsed in _bodies(body):
                            document.blocks.append(
                                HclBlock(
                                    kind,
                                    (first, second),
                                    parsed,
                                    line_for(*prefix, first, second),
                                    None,
                                )
                            )
    return document
