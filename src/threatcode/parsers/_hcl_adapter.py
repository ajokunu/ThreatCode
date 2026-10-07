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
"""

from __future__ import annotations

import importlib
import re
from bisect import bisect_right
from collections import defaultdict
from collections.abc import Iterator
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


def _parse(text: str, name: str) -> dict[str, Any]:
    try:
        _hcl2()
    except ImportError as exc:
        raise ParseError("python-hcl2 required: pip install python-hcl2") from exc
    try:
        return _canonical(_hcl2_loads(text), 0) if _is_modern() else _hcl2_loads(text)
    except RecursionError as exc:
        raise ParseError(_too_deep(name)) from exc
    except Exception as exc:
        raise ParseError(describe_error(exc, name)) from exc


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
