"""Line numbers for JSON documents, for source locations in findings.

``json.loads`` throws the position of every value away. ``json_line_index`` re-reads the
text once and records the line where each object key and array item starts, keyed by RFC
6901 JSON pointer, so the plan, CloudFormation JSON and MCP parsers can point a finding at
the line that causes it.
"""

from __future__ import annotations

import json
import re

# A JSON string literal, scanned in linear time (no nested quantifiers).
_STRING_RE = re.compile(r'"[^"\\]*(?:\\.[^"\\]*)*"', re.DOTALL)
# A number, true, false or null: everything up to the next structural character.
_SCALAR_RE = re.compile(r'[^\s,:\[\]{}"]+')


class _Frame:
    """An open object or array while scanning."""

    __slots__ = ("count", "is_object", "key", "pointer")

    def __init__(self, pointer: str, is_object: bool) -> None:
        self.pointer = pointer
        self.is_object = is_object
        self.key: str | None = None  # object: key read, value not finished yet
        self.count = 0  # array: items seen so far


def _escape(token: str) -> str:
    return token.replace("~", "~0").replace("/", "~1")


def _decode_key(literal: str) -> str:
    if "\\" not in literal:
        return literal[1:-1]
    try:
        decoded = json.loads(literal)
    except ValueError:
        return literal[1:-1]
    return decoded if isinstance(decoded, str) else literal[1:-1]


def json_line_index(text: str) -> dict[str, int]:
    """Map JSON pointers to the 1-based line where each key or item starts.

    The root value is recorded under ``""``. An object member is recorded at the line of
    its key and an array item at the line of its first token. A key that appears twice
    keeps the line of its last occurrence, which is the value ``json.loads`` returns.

    The scan is a single pass with an explicit stack, so deeply nested input cannot hit
    the recursion limit. The text is expected to be valid JSON, but malformed input never
    raises: the scan stops at the first token it cannot place and returns what it found.
    """
    index: dict[str, int] = {}
    stack: list[_Frame] = []
    line = 1
    pos = 1 if text.startswith("﻿") else 0
    length = len(text)

    def begin_value() -> str | None:
        """Pointer for a value starting here, or None when the structure is broken."""
        if not stack:
            if "" in index:
                return None
            index[""] = line
            return ""
        top = stack[-1]
        if top.is_object:
            if top.key is None:
                return None
            return f"{top.pointer}/{_escape(top.key)}"
        pointer = f"{top.pointer}/{top.count}"
        top.count += 1
        index[pointer] = line
        return pointer

    def finish_value() -> None:
        if stack and stack[-1].is_object:
            stack[-1].key = None

    while pos < length:
        char = text[pos]
        if char == "\n":
            line += 1
            pos += 1
        elif char in " \t\r,:":
            pos += 1
        elif char == '"':
            match = _STRING_RE.match(text, pos)
            if match is None:
                break
            literal = match.group(0)
            top = stack[-1] if stack else None
            if top is not None and top.is_object and top.key is None:
                top.key = _decode_key(literal)
                index[f"{top.pointer}/{_escape(top.key)}"] = line
            else:
                if begin_value() is None:
                    break
                finish_value()
            line += literal.count("\n")
            pos = match.end()
        elif char in "{[":
            pointer = begin_value()
            if pointer is None:
                break
            stack.append(_Frame(pointer, char == "{"))
            pos += 1
        elif char in "}]":
            if not stack:
                break
            stack.pop()
            finish_value()
            pos += 1
        else:
            match = _SCALAR_RE.match(text, pos)
            if match is None:
                break
            if begin_value() is None:
                break
            finish_value()
            pos = match.end()
    return index
