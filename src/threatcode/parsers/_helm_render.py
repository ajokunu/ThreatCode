"""A bounded, side-effect free Helm renderer for when the ``helm`` binary is not available.

``helm template`` is the accurate way to render a chart, and the parser uses it when it can.
This module is the fallback. It reads ``Chart.yaml`` and ``values.yaml``, walks ``templates/``
and ``charts/`` and evaluates the Go template subset that real charts use: ``.Values``,
``.Chart`` and ``.Release`` lookups, ``if`` / ``else if`` / ``else``, ``with``, ``range``,
variables, ``define`` / ``include`` / ``template``, ``toYaml`` with ``indent`` and ``nindent``,
and the Sprig functions that charts lean on (``default``, ``quote``, ``trunc``, ``printf``,
``trimSuffix`` and others).

Two kinds of value cannot be known and are handled separately:

* A lookup into ``.Values`` that has no entry (``MISSING``). A real ``helm template`` of the
  chart with its default values sees ``nil`` there, so a condition on it is false, ``with`` and
  ``range`` skip their body, and ``default`` takes its fallback. Printed, it becomes a token.
* A value the renderer cannot compute (``UNKNOWN``), such as ``randAlphaNum``, ``.Files`` or a
  function it does not know. A condition on it is true, so the resource is not hidden.

Both print as a token ``placeholder-<template>-<document>-<n>``: ``<template>`` is the template
path, ``<document>`` counts the YAML documents emitted so far in that template and ``<n>``
numbers the distinct expressions inside the document. The same expression gives the same token
within one document, and two documents or two templates never share one, so two resources named
from different values never get the same address.

Bounds, because a chart is input from a repository somebody else controls:

* the template scanner is one left-to-right pass built on ``str.find``, so a template that opens
  ``{{`` and never closes it costs linear time; the unterminated text is copied through with its
  ``{{`` pairs defused,
* a template over ``MAX_TEMPLATE_BYTES`` is skipped, a line over ``MAX_LINE_CHARS`` is
  replaced by a comment, an action over ``MAX_ACTION_CHARS`` is not evaluated,
* evaluation has a step budget, an output budget and a wall-clock budget per chart, and
  ``include`` and ``tpl`` have a depth limit,
* regular expressions written by the chart are never run, and symbolic links are never followed.
"""

from __future__ import annotations

import base64
import bisect
import copy
import hashlib
import json
import logging
import os
import re
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from threatcode.exceptions import ParseError
from threatcode.parsers._k8s_security import PLACEHOLDER_PREFIX
from threatcode.parsers._text import decode_input
from threatcode.parsers._yaml import load_yaml_documents

logger = logging.getLogger(__name__)

# The release a render pretends to be: the same name the helm binary path uses, so both paths
# give a resource the same address
RELEASE_NAME = "release"
RELEASE_NAMESPACE = "default"

MAX_TEMPLATE_BYTES = 2 * 1024 * 1024
MAX_VALUES_BYTES = 2 * 1024 * 1024
MAX_LINE_CHARS = 64 * 1024
MAX_ACTION_CHARS = 8 * 1024
MAX_TEMPLATE_FILES = 5_000
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
MAX_STEPS = 2_000_000
MAX_RANGE_ITEMS = 5_000
MAX_NEST = 50
MAX_INCLUDE_DEPTH = 24
MAX_SUBCHART_DEPTH = 4
MAX_CHARTS = 40
MAX_VALUE_NODES = 100_000
MAX_VALUE_DEPTH = 64
DEFAULT_TIME_BUDGET_SECONDS = 20.0

_WHITESPACE = " \t\r\n"


# ---------------------------------------------------------------------------------------
# Values the renderer cannot know
# ---------------------------------------------------------------------------------------


class _Hole:
    """A value that is not known; see the module docstring for the two kinds."""

    __slots__ = ("name", "truthy")

    def __init__(self, name: str, truthy: bool) -> None:
        self.name = name
        self.truthy = truthy

    def __repr__(self) -> str:
        return f"<{self.name}>"

    def __bool__(self) -> bool:
        return self.truthy


UNKNOWN = _Hole("unknown", True)
MISSING = _Hole("missing", False)


def is_hole(value: object) -> bool:
    return isinstance(value, _Hole)


class ValuesDict(dict[str, Any]):
    """A mapping that came from a values file: a key it does not have is ``MISSING``.

    A mapping a template builds with ``dict`` is a plain dict, where a missing key is nil.
    """


class RenderAbortError(Exception):
    """The chart used up a budget; what has been rendered so far is kept."""


class _TemplateError(Exception):
    """A template cannot be parsed or evaluated; the file falls back to a flat scan."""


# ---------------------------------------------------------------------------------------
# Scanning a template into text and actions
# ---------------------------------------------------------------------------------------

_SPECIAL = re.compile(r'["`}]')
_STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
_DEFINITION_KEYWORDS = ("if", "else", "end", "range", "with", "define", "template", "block")
_KEYWORD = re.compile(
    r"(if|else|end|range|with|define|template|block|break|continue)(?![A-Za-z0-9_])"
)


@dataclass(slots=True)
class Token:
    kind: str  # "text" or "action"
    text: str
    line: int


def _find_action_end(source: str, start: int) -> int:
    """Index of the ``}}`` that closes the action whose body starts at ``start``, or -1.

    Quoted strings and raw strings may hold ``}}``. Every iteration advances, and
    ``_SPECIAL.search`` jumps over plain characters, so the scan is linear.
    """
    position = start
    while True:
        found = _SPECIAL.search(source, position)
        if found is None:
            return -1
        index = found.start()
        char = found.group()
        if char == "}":
            if source.startswith("}}", index):
                return index
            position = index + 1
        elif char == '"':
            string = _STRING.match(source, index)
            if string is None:
                return -1
            position = string.end()
        else:
            closing = source.find("`", index + 1)
            if closing < 0:
                return -1
            position = closing + 1


def _comment_end(source: str, body_start: int) -> int | None:
    """For a ``{{/* ... */}}`` comment, the index of its ``}}``; None when it is not one."""
    index = body_start
    if source.startswith("-", index) and source[index + 1 : index + 2] in tuple(_WHITESPACE):
        index += 1
    while index < len(source) and source[index] in _WHITESPACE:
        index += 1
    if not source.startswith("/*", index):
        return None
    closing = source.find("*/", index + 2)
    if closing < 0:
        return -1
    end = source.find("}}", closing + 2)
    return end if end >= 0 else -1


def tokenize(source: str) -> list[Token]:
    """Split a template into text and action tokens in one left-to-right pass.

    ``{{-`` removes the whitespace before the action and ``-}}`` the whitespace after it,
    as Go's ``text/template`` does. An action that is never closed ends the scan: everything
    from its ``{{`` on is kept as text with each ``{{`` replaced by ``((`` so the leftover
    cannot be read as YAML flow collections nested thousands of levels deep.
    """
    tokens: list[Token] = []
    position = 0
    line = 1
    trim_next = False
    length = len(source)

    def add_text(text: str, text_line: int, trim_left: bool, trim_right: bool) -> None:
        if trim_left:
            text = text.lstrip(_WHITESPACE)
        if trim_right:
            text = text.rstrip(_WHITESPACE)
        if text:
            tokens.append(Token("text", text, text_line))

    while position < length:
        start = source.find("{{", position)
        if start < 0:
            add_text(source[position:], line, trim_next, False)
            break
        body_start = start + 2
        comment_end = _comment_end(source, body_start)
        end = _find_action_end(source, body_start) if comment_end is None else comment_end
        if end < 0:
            add_text(source[position:start], line, trim_next, False)
            line += source.count("\n", position, start)
            tokens.append(Token("text", source[start:].replace("{{", "(("), line))
            break
        body = source[body_start:end]
        trim_left = len(body) >= 2 and body[0] == "-" and body[1] in _WHITESPACE
        trim_right = len(body) >= 2 and body[-1] == "-" and body[-2] in _WHITESPACE
        if trim_left:
            body = body[1:]
        if trim_right:
            body = body[:-1]
        add_text(source[position:start], line, trim_next, trim_left)
        action_line = line + source.count("\n", position, start)
        tokens.append(Token("action", body.strip(), action_line))
        line = action_line + source.count("\n", start, end + 2)
        position = end + 2
        trim_next = trim_right
    return tokens


# ---------------------------------------------------------------------------------------
# Expressions
# ---------------------------------------------------------------------------------------


@dataclass(slots=True)
class Lit:
    value: Any


@dataclass(slots=True)
class DotRef:
    chain: tuple[str, ...]


@dataclass(slots=True)
class VarRef:
    name: str
    chain: tuple[str, ...]


@dataclass(slots=True)
class Func:
    name: str


@dataclass(slots=True)
class Sub:
    pipeline: Pipeline
    chain: tuple[str, ...]


Term = Lit | DotRef | VarRef | Func | Sub


@dataclass(slots=True)
class Command:
    terms: list[Term]


@dataclass(slots=True)
class Pipeline:
    commands: list[Command]
    # Variable names and whether the action declares (:=) or assigns (=); None for no variable
    variables: tuple[str, ...] = ()
    declare: bool = True


_LEXEME = re.compile(
    r"""
    (?P<space>\s+)
  | (?P<string>"(?:[^"\\]|\\.)*")
  | (?P<raw>`[^`]*`)
  | (?P<char>'(?:[^'\\]|\\.)')
  | (?P<assign>:=|=)
  | (?P<pipe>\|)
  | (?P<open>\()
  | (?P<close>\))
  | (?P<comma>,)
  | (?P<var>\$[A-Za-z0-9_]*)
  | (?P<field>\.[A-Za-z_][A-Za-z0-9_]*)
  | (?P<dot>\.)
  | (?P<number>[+-]?\d+(?:\.\d+)?)
  | (?P<ident>[A-Za-z_][A-Za-z0-9_]*)
    """,
    re.VERBOSE,
)

_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'", "a": "\a", "b": "\b"}


def _unquote(literal: str) -> str:
    inner = literal[1:-1]
    if "\\" not in inner:
        return inner
    out: list[str] = []
    index = 0
    while index < len(inner):
        char = inner[index]
        if char == "\\" and index + 1 < len(inner):
            out.append(_ESCAPES.get(inner[index + 1], inner[index + 1]))
            index += 2
        else:
            out.append(char)
            index += 1
    return "".join(out)


@dataclass(slots=True)
class _Lexeme:
    kind: str
    text: str
    start: int
    end: int


def _lex(body: str) -> list[_Lexeme]:
    lexemes: list[_Lexeme] = []
    position = 0
    while position < len(body):
        match = _LEXEME.match(body, position)
        if match is None:
            raise _TemplateError(f"cannot read expression at {body[position : position + 20]!r}")
        kind = match.lastgroup or ""
        if kind != "space":
            lexemes.append(_Lexeme(kind, match.group(), match.start(), match.end()))
        position = match.end()
    return lexemes


class _ExpressionParser:
    def __init__(self, lexemes: list[_Lexeme]) -> None:
        self.lexemes = lexemes
        self.position = 0

    def peek(self) -> _Lexeme | None:
        return self.lexemes[self.position] if self.position < len(self.lexemes) else None

    def next(self) -> _Lexeme:
        lexeme = self.peek()
        if lexeme is None:
            raise _TemplateError("unexpected end of expression")
        self.position += 1
        return lexeme

    def parse(self) -> Pipeline:
        pipeline = self.pipeline(depth=0)
        if self.peek() is not None:
            raise _TemplateError(f"unexpected {self.peek().text!r}")  # type: ignore[union-attr]
        return pipeline

    def pipeline(self, depth: int) -> Pipeline:
        if depth > 30:
            raise _TemplateError("expression nested too deeply")
        variables: tuple[str, ...] = ()
        declare = True
        names = self._declaration()
        if names is not None:
            variables, declare = names
        commands = [self.command(depth)]
        while self.peek() is not None and self.peek().kind == "pipe":  # type: ignore[union-attr]
            self.next()
            commands.append(self.command(depth))
        return Pipeline(commands, variables, declare)

    def _declaration(self) -> tuple[tuple[str, ...], bool] | None:
        """Read ``$x :=``, ``$x =`` or ``$i, $e :=`` when the expression starts with one."""
        index = self.position
        names: list[str] = []
        while index < len(self.lexemes) and self.lexemes[index].kind == "var":
            names.append(self.lexemes[index].text)
            index += 1
            if index < len(self.lexemes) and self.lexemes[index].kind == "comma":
                index += 1
                continue
            break
        if names and index < len(self.lexemes) and self.lexemes[index].kind == "assign":
            declare = self.lexemes[index].text == ":="
            self.position = index + 1
            return tuple(names), declare
        return None

    def command(self, depth: int) -> Command:
        terms: list[Term] = []
        while True:
            lexeme = self.peek()
            if lexeme is None or lexeme.kind in ("pipe", "close"):
                break
            terms.append(self.term(depth))
        if not terms:
            raise _TemplateError("empty command")
        return Command(terms)

    def _chain(self, after: int) -> tuple[str, ...]:
        """Field names that follow a term with no whitespace in between."""
        chain: list[str] = []
        while True:
            lexeme = self.peek()
            if lexeme is None or lexeme.kind != "field" or lexeme.start != after:
                break
            chain.append(lexeme.text[1:])
            after = lexeme.end
            self.position += 1
        return tuple(chain)

    def term(self, depth: int) -> Term:
        lexeme = self.next()
        kind = lexeme.kind
        if kind == "string":
            return Lit(_unquote(lexeme.text))
        if kind == "raw":
            return Lit(lexeme.text[1:-1])
        if kind == "char":
            return Lit(_unquote(lexeme.text))
        if kind == "number":
            text = lexeme.text
            return Lit(float(text) if "." in text else int(text))
        if kind == "dot":
            return DotRef(())
        if kind == "field":
            return DotRef((lexeme.text[1:], *self._chain(lexeme.end)))
        if kind == "var":
            return VarRef(lexeme.text, self._chain(lexeme.end))
        if kind == "open":
            inner = self.pipeline(depth + 1)
            closing = self.next()
            if closing.kind != "close":
                raise _TemplateError("missing closing parenthesis")
            return Sub(inner, self._chain(closing.end))
        if kind == "ident":
            if lexeme.text == "true":
                return Lit(True)
            if lexeme.text == "false":
                return Lit(False)
            if lexeme.text == "nil":
                return Lit(None)
            return Func(lexeme.text)
        raise _TemplateError(f"unexpected {lexeme.text!r}")


def parse_expression(body: str) -> Pipeline:
    if len(body) > MAX_ACTION_CHARS:
        raise _TemplateError("action is too long to evaluate")
    return _ExpressionParser(_lex(body)).parse()


# ---------------------------------------------------------------------------------------
# The template tree
# ---------------------------------------------------------------------------------------


@dataclass(slots=True)
class TextNode:
    text: str
    line: int


@dataclass(slots=True)
class ActionNode:
    pipeline: Pipeline
    source: str
    line: int


@dataclass(slots=True)
class IfNode:
    branches: list[tuple[Pipeline, list[Node]]]
    otherwise: list[Node]
    line: int


@dataclass(slots=True)
class WithNode:
    pipeline: Pipeline
    body: list[Node]
    otherwise: list[Node]
    line: int


@dataclass(slots=True)
class RangeNode:
    pipeline: Pipeline
    body: list[Node]
    otherwise: list[Node]
    line: int


@dataclass(slots=True)
class TemplateNode:
    name: str
    pipeline: Pipeline | None
    line: int


@dataclass(slots=True)
class LoopControl:
    kind: str  # "break" or "continue"


Node = TextNode | ActionNode | IfNode | WithNode | RangeNode | TemplateNode | LoopControl


@dataclass(slots=True)
class _Frame:
    kind: str  # if, with, range, define, block
    line: int
    pipeline: Pipeline | None = None
    name: str = ""
    argument: Pipeline | None = None
    # if: the branches closed by an else-if or else; the open branch is `body` under `condition`
    branches: list[tuple[Pipeline, list[Node]]] = field(default_factory=list)
    condition: Pipeline | None = None
    body: list[Node] = field(default_factory=list)
    otherwise: list[Node] = field(default_factory=list)
    in_else: bool = False

    @property
    def target(self) -> list[Node]:
        """Where the nodes that follow go: the else branch once an else has been seen."""
        return self.otherwise if self.in_else else self.body


def _keyword_of(body: str) -> tuple[str, str] | None:
    found = _KEYWORD.match(body)
    if found is None:
        return None
    return found.group(1), body[found.end() :].strip()


def _quoted_name(text: str) -> tuple[str, str]:
    """Split ``"name" rest`` into the unquoted name and the rest."""
    match = re.match(r'\s*("(?:[^"\\]|\\.)*"|`[^`]*`)\s*(.*)\Z', text, re.DOTALL)
    if match is None:
        raise _TemplateError("a template name must be a quoted string")
    literal = match.group(1)
    name = literal[1:-1] if literal[0] == "`" else _unquote(literal)
    return name, match.group(2).strip()


@dataclass
class ParsedTemplate:
    nodes: list[Node]
    defines: dict[str, list[Node]]


def parse_template(tokens: Sequence[Token]) -> ParsedTemplate:
    """Build the node tree of a template; raises ``_TemplateError`` when it is malformed."""
    root: list[Node] = []
    defines: dict[str, list[Node]] = {}
    stack: list[_Frame] = []

    def current() -> list[Node]:
        return stack[-1].target if stack else root

    for token in tokens:
        if token.kind == "text":
            current().append(TextNode(token.text, token.line))
            continue
        body = token.text
        if not body or body.startswith("/*"):
            continue
        keyword = _keyword_of(body)
        if keyword is None:
            pipeline = parse_expression(body)
            current().append(ActionNode(pipeline, " ".join(body.split()), token.line))
            continue
        word, rest = keyword
        if word in ("if", "with", "range"):
            if len(stack) >= MAX_NEST:
                raise _TemplateError("template blocks are nested too deeply")
            expression = parse_expression(rest)
            stack.append(_Frame(word, token.line, pipeline=expression, condition=expression))
        elif word in ("define", "block"):
            if word == "define" and stack:
                raise _TemplateError("define is only allowed at the top level")
            if len(stack) >= MAX_NEST:
                raise _TemplateError("template blocks are nested too deeply")
            name, argument = _quoted_name(rest)
            stack.append(
                _Frame(
                    word,
                    token.line,
                    name=name,
                    argument=parse_expression(argument) if argument else None,
                )
            )
        elif word == "else":
            _else(stack, rest)
        elif word == "end":
            _end(stack, root, defines)
        elif word == "template":
            name, argument = _quoted_name(rest)
            current().append(
                TemplateNode(name, parse_expression(argument) if argument else None, token.line)
            )
        else:  # break, continue
            current().append(LoopControl(word))
    if stack:
        raise _TemplateError(f"{stack[-1].kind} at line {stack[-1].line} is never closed")
    return ParsedTemplate(root, defines)


def _else(stack: list[_Frame], rest: str) -> None:
    if not stack or stack[-1].kind not in ("if", "with", "range") or stack[-1].in_else:
        raise _TemplateError("else outside an if, with or range")
    frame = stack[-1]
    if rest:
        # only `else if CONDITION` is supported
        if frame.kind != "if" or not rest.startswith("if") or rest[2:3].isalnum():
            raise _TemplateError("unsupported else clause")
        assert frame.condition is not None
        frame.branches.append((frame.condition, frame.body))
        frame.condition = parse_expression(rest[2:].strip())
        frame.body = []
        return
    if frame.kind == "if":
        assert frame.condition is not None
        frame.branches.append((frame.condition, frame.body))
        frame.condition = None
        frame.body = []
    frame.in_else = True


def _end(stack: list[_Frame], root: list[Node], defines: dict[str, list[Node]]) -> None:
    if not stack:
        raise _TemplateError("end without a block to close")
    frame = stack.pop()
    parent = stack[-1].target if stack else root
    node: Node
    if frame.kind == "if":
        branches = list(frame.branches)
        if frame.condition is not None:
            branches.append((frame.condition, frame.body))
        node = IfNode(branches, frame.otherwise, frame.line)
    elif frame.kind == "with":
        assert frame.pipeline is not None
        node = WithNode(frame.pipeline, frame.body, frame.otherwise, frame.line)
    elif frame.kind == "range":
        assert frame.pipeline is not None
        node = RangeNode(frame.pipeline, frame.body, frame.otherwise, frame.line)
    elif frame.kind == "define":
        defines[frame.name] = frame.body
        return
    else:  # block: a define that is also called in place
        defines[frame.name] = frame.body
        node = TemplateNode(frame.name, frame.argument, frame.line)
    parent.append(node)


# ---------------------------------------------------------------------------------------
# Values: conversion, truthiness and printing
# ---------------------------------------------------------------------------------------


class _NoArgument:
    """Marks 'nothing was piped in'; a pipe can carry any value, including None."""


_NOARG = _NoArgument()


def to_values(value: Any, budget: list[int] | None = None, depth: int = 0) -> Any:
    """Copy a loaded YAML value with every mapping as a ``ValuesDict``.

    The walk counts every visit, so a document built from aliases that expand exponentially
    stops at ``MAX_VALUE_NODES`` instead of running away. Raises ``_TemplateError``.
    """
    remaining = budget if budget is not None else [MAX_VALUE_NODES]
    remaining[0] -= 1
    if remaining[0] < 0:
        raise _TemplateError("values hold too many nodes")
    if depth > MAX_VALUE_DEPTH:
        raise _TemplateError("values are nested too deeply")
    if isinstance(value, dict):
        return ValuesDict(
            {str(key): to_values(item, remaining, depth + 1) for key, item in value.items()}
        )
    if isinstance(value, list):
        return [to_values(item, remaining, depth + 1) for item in value]
    return value


def is_empty(value: Any) -> bool:
    """Go template truthiness, inverted: false, 0, nil, "" and empty collections are empty."""
    if value is None or value is MISSING:
        return True
    if isinstance(value, bool):
        return not value
    if isinstance(value, (int, float)):
        return value == 0
    if isinstance(value, (str, list, dict, tuple)):
        return len(value) == 0
    return False


def _condition(value: Any) -> bool:
    """Whether an ``if`` or ``with`` takes its body: an unknown value does, so nothing hides."""
    if value is UNKNOWN:
        return True
    return not is_empty(value)


def _format_number(value: int | float) -> str:
    if isinstance(value, float) and value.is_integer() and abs(value) < 1e21:
        return str(int(value))
    return str(value)


def _kind(value: Any) -> str:
    if value is None:
        return "invalid"
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float64"
    if isinstance(value, str):
        return "string"
    if isinstance(value, dict):
        return "map"
    if isinstance(value, (list, tuple)):
        return "slice"
    return "invalid"


class _YamlDumper(yaml.SafeDumper):
    """Dumps without anchors or aliases, and accepts the ``ValuesDict`` subclass."""

    def ignore_aliases(self, data: Any) -> bool:
        return True


_YamlDumper.add_multi_representer(dict, yaml.SafeDumper.represent_dict)


def _bounded(value: Any) -> bool:
    """Whether a value is small and shallow enough to dump or walk (it is not an alias bomb)."""
    remaining = MAX_VALUE_NODES
    stack: list[tuple[Any, int]] = [(value, 0)]
    while stack:
        item, depth = stack.pop()
        remaining -= 1
        if remaining < 0 or depth > MAX_VALUE_DEPTH:
            return False
        if isinstance(item, dict):
            stack.extend((child, depth + 1) for child in item.values())
        elif isinstance(item, (list, tuple)):
            stack.extend((child, depth + 1) for child in item)
    return True


# ---------------------------------------------------------------------------------------
# Execution
# ---------------------------------------------------------------------------------------

_MAX_MARKS = 200_000
_SEPARATOR = re.compile(r"---(?:[ \t].*)?\Z")


class _BreakError(Exception):
    pass


class _ContinueError(Exception):
    pass


@dataclass
class _Env:
    """What every template of one chart tree shares: definitions and the three budgets."""

    defines: dict[str, list[Node]]
    deadline: float
    steps: int = 0
    output: int = 0
    since_check: int = 0

    def charge(self, amount: int = 1) -> None:
        self.steps += amount
        self.since_check += amount
        if self.steps > MAX_STEPS:
            raise RenderAbortError(f"the chart needs more than {MAX_STEPS} evaluation steps")
        if self.since_check >= 256:
            self.since_check = 0
            if time.monotonic() > self.deadline:
                raise RenderAbortError("the chart used up its time budget")

    def charge_output(self, size: int) -> None:
        self.output += size
        if self.output > MAX_OUTPUT_BYTES:
            raise RenderAbortError(f"the chart renders more than {MAX_OUTPUT_BYTES} bytes")


class Executor:
    """Runs the node tree of one template and collects its text."""

    def __init__(self, env: _Env, slug: str, *, track_lines: bool = False) -> None:
        self.env = env
        self.slug = slug
        self.track_lines = track_lines
        self.out: list[str] = []
        self.size = 0
        self.marks: list[tuple[int, int]] = []
        self.capturing = 0
        self.depth = 0
        self.source = ""
        self.document = 0
        self.document_has_content = False
        self._tokens: dict[tuple[int, str], int] = {}
        self._token_counts: dict[int, int] = {}

    # -- output ----------------------------------------------------------------------

    def text(self) -> str:
        return "".join(self.out)

    def emit(self, text: str, line: int, *, literal: bool) -> None:
        if not text:
            return
        self.env.charge_output(len(text))
        if self.track_lines and not self.capturing and len(self.marks) < _MAX_MARKS:
            self.marks.append((self.size, line))
            if literal and "\n" in text:
                offset, current = self.size, line
                for part in text.split("\n")[:-1]:
                    offset += len(part) + 1
                    current += 1
                    self.marks.append((offset, current))
        self.out.append(text)
        self.size += len(text)
        if self.capturing:
            return
        if literal:
            self._track_documents(text)
        elif text.strip():
            self.document_has_content = True

    def _track_documents(self, text: str) -> None:
        for raw in text.split("\n"):
            stripped = raw.strip()
            if _SEPARATOR.match(stripped):
                if self.document_has_content:
                    self.document += 1
                    self.document_has_content = False
            elif stripped and not stripped.startswith("#"):
                self.document_has_content = True

    def token(self) -> str:
        """The placeholder for the unknown value the current expression prints."""
        key = (self.document, self.source)
        number = self._tokens.get(key)
        if number is None:
            number = self._token_counts.get(self.document, 0) + 1
            self._token_counts[self.document] = number
            self._tokens[key] = number
        return f"{PLACEHOLDER_PREFIX}{self.slug}-{self.document}-{number}"

    def printable(self, value: Any) -> str:
        """The text a value prints as; an unknown value prints as its placeholder token."""
        if is_hole(value):
            return self.token()
        if value is None:
            return ""
        if isinstance(value, bool):
            return "true" if value else "false"
        if isinstance(value, (int, float)):
            return _format_number(value)
        if isinstance(value, str):
            return value
        if isinstance(value, (list, tuple)):
            return "[" + " ".join(self.printable(item) for item in value[:1000]) + "]"
        if isinstance(value, dict):
            pairs = sorted(value.items(), key=lambda pair: str(pair[0]))[:1000]
            return "map[" + " ".join(f"{k}:{self.printable(v)}" for k, v in pairs) + "]"
        return str(value)

    def resolved(self, value: Any, depth: int = 0) -> Any:
        """A copy of a value with every unknown inside it replaced by its placeholder token."""
        if is_hole(value):
            return self.token()
        if depth > MAX_VALUE_DEPTH:
            return self.token()
        if isinstance(value, dict):
            return {str(k): self.resolved(v, depth + 1) for k, v in value.items()}
        if isinstance(value, (list, tuple)):
            return [self.resolved(v, depth + 1) for v in value]
        return value

    # -- nodes -----------------------------------------------------------------------

    def run(self, nodes: Sequence[Node], dot: Any) -> None:
        """Execute a template with ``dot`` as both ``.`` and ``$``."""
        self.execute(nodes, dot, [{"$": dot}])

    def execute(self, nodes: Sequence[Node], dot: Any, scopes: list[dict[str, Any]]) -> None:
        for node in nodes:
            self.env.charge()
            if isinstance(node, TextNode):
                self.emit(node.text, node.line, literal=True)
            elif isinstance(node, ActionNode):
                self._action(node, dot, scopes)
            elif isinstance(node, IfNode):
                self._if(node, dot, scopes)
            elif isinstance(node, WithNode):
                self._with(node, dot, scopes)
            elif isinstance(node, RangeNode):
                self._range(node, dot, scopes)
            elif isinstance(node, TemplateNode):
                self._template(node, dot, scopes)
            elif node.kind == "break":
                raise _BreakError
            else:
                raise _ContinueError

    def _block(self, nodes: Sequence[Node], dot: Any, scopes: list[dict[str, Any]]) -> None:
        scopes.append({})
        try:
            self.execute(nodes, dot, scopes)
        finally:
            scopes.pop()

    def _action(self, node: ActionNode, dot: Any, scopes: list[dict[str, Any]]) -> None:
        self.source = node.source
        value = self.evaluate(node.pipeline, dot, scopes)
        variables = node.pipeline.variables
        if variables:
            self._assign(variables[0], value, scopes, node.pipeline.declare)
            return
        self.emit(self.printable(value), node.line, literal=False)

    @staticmethod
    def _assign(name: str, value: Any, scopes: list[dict[str, Any]], declare: bool) -> None:
        if not declare:
            for scope in reversed(scopes):
                if name in scope:
                    scope[name] = value
                    return
        scopes[-1][name] = value

    def _if(self, node: IfNode, dot: Any, scopes: list[dict[str, Any]]) -> None:
        for condition, body in node.branches:
            self.source = ""
            if _condition(self.evaluate(condition, dot, scopes)):
                self._block(body, dot, scopes)
                return
        if node.otherwise:
            self._block(node.otherwise, dot, scopes)

    def _with(self, node: WithNode, dot: Any, scopes: list[dict[str, Any]]) -> None:
        value = self.evaluate(node.pipeline, dot, scopes)
        if _condition(value):
            scopes.append({})
            try:
                if node.pipeline.variables:
                    scopes[-1][node.pipeline.variables[0]] = value
                self.execute(node.body, value, scopes)
            finally:
                scopes.pop()
        elif node.otherwise:
            self._block(node.otherwise, dot, scopes)

    def _range(self, node: RangeNode, dot: Any, scopes: list[dict[str, Any]]) -> None:
        collection = self.evaluate(node.pipeline, dot, scopes)
        items: list[tuple[Any, Any]]
        if collection is UNKNOWN:
            items = [(UNKNOWN, UNKNOWN)]
        elif isinstance(collection, dict):
            items = [(key, collection[key]) for key in sorted(collection, key=str)]
        elif isinstance(collection, (list, tuple)):
            items = list(enumerate(collection))
        elif isinstance(collection, int) and not isinstance(collection, bool):
            items = [(n, n) for n in range(max(0, min(collection, MAX_RANGE_ITEMS)))]
        else:
            items = []
        if not items:
            if node.otherwise:
                self._block(node.otherwise, dot, scopes)
            return
        names = node.pipeline.variables
        for key, item in items[:MAX_RANGE_ITEMS]:
            self.env.charge()
            scopes.append({})
            try:
                if len(names) == 1:
                    scopes[-1][names[0]] = item
                elif len(names) >= 2:
                    scopes[-1][names[0]] = key
                    scopes[-1][names[1]] = item
                self.execute(node.body, item, scopes)
            except _BreakError:
                break
            except _ContinueError:
                continue
            finally:
                scopes.pop()

    def _template(self, node: TemplateNode, dot: Any, scopes: list[dict[str, Any]]) -> None:
        argument: Any = None
        if node.pipeline is not None:
            argument = self.evaluate(node.pipeline, dot, scopes)
        nodes = self.env.defines.get(node.name)
        if nodes is None:
            self.source = f"template {node.name}"
            self.emit(self.printable(UNKNOWN), node.line, literal=False)
            return
        self.call_define(nodes, argument, emit_line=node.line)

    def call_define(self, nodes: list[Node], argument: Any, emit_line: int | None = None) -> str:
        """Run a defined template with ``argument`` as dot; returns the text it produced.

        With ``emit_line`` the text is also written to the output, as ``{{ template }}`` does.
        """
        if self.depth >= MAX_INCLUDE_DEPTH:
            raise RenderAbortError("templates include each other too deeply")
        saved = (self.out, self.size, self.source)
        self.out, self.size = [], 0
        self.capturing += 1
        self.depth += 1
        try:
            self.execute(nodes, argument, [{"$": argument}])
            text = "".join(self.out)
        finally:
            self.depth -= 1
            self.capturing -= 1
            self.out, self.size, self.source = saved
        if emit_line is not None:
            self.emit(text, emit_line, literal=False)
        return text

    # -- expressions -----------------------------------------------------------------

    def evaluate(self, pipeline: Pipeline, dot: Any, scopes: list[dict[str, Any]]) -> Any:
        value: Any = _NOARG
        for command in pipeline.commands:
            value = self._command(command, dot, scopes, value)
        return value

    def _command(self, command: Command, dot: Any, scopes: list[dict[str, Any]], piped: Any) -> Any:
        self.env.charge()
        head, rest = command.terms[0], command.terms[1:]
        if isinstance(head, Func):
            if head.name in ("and", "or"):
                return self._short_circuit(head.name, rest, dot, scopes, piped)
            arguments = [self._term(term, dot, scopes) for term in rest]
            if piped is not _NOARG:
                arguments.append(piped)
            return self.call(head.name, arguments)
        if rest and isinstance(head, (DotRef, VarRef)) and head.chain:
            # A method call such as .Capabilities.APIVersions.Has "apps/v1"
            owner = self._term(type(head)(*self._without_last(head)), dot, scopes)
            if head.chain[-1] == "Has" and owner is not MISSING:
                return True
            return UNKNOWN
        value = self._term(head, dot, scopes)
        return value

    @staticmethod
    def _without_last(term: DotRef | VarRef) -> tuple[Any, ...]:
        if isinstance(term, DotRef):
            return (term.chain[:-1],)
        return (term.name, term.chain[:-1])

    def _short_circuit(
        self, name: str, terms: list[Term], dot: Any, scopes: list[dict[str, Any]], piped: Any
    ) -> Any:
        value: Any = None
        for term in terms:
            value = self._term(term, dot, scopes)
            if value is UNKNOWN:
                return UNKNOWN
            if name == "and" and is_empty(value):
                return value
            if name == "or" and not is_empty(value):
                return value
        if piped is not _NOARG:
            if piped is UNKNOWN:
                return UNKNOWN
            if (name == "and" and is_empty(piped)) or (name == "or" and not is_empty(piped)):
                return piped
            value = piped
        return value

    def _term(self, term: Term, dot: Any, scopes: list[dict[str, Any]]) -> Any:
        if isinstance(term, Lit):
            return term.value
        if isinstance(term, DotRef):
            return self._fields(dot, term.chain)
        if isinstance(term, VarRef):
            return self._fields(self._variable(term.name, scopes), term.chain)
        if isinstance(term, Func):
            return self.call(term.name, [])
        value = self.evaluate(term.pipeline, dot, scopes)
        return self._fields(value, term.chain)

    @staticmethod
    def _variable(name: str, scopes: list[dict[str, Any]]) -> Any:
        for scope in reversed(scopes):
            if name in scope:
                return scope[name]
        return UNKNOWN

    @staticmethod
    def _fields(value: Any, chain: tuple[str, ...]) -> Any:
        for name in chain:
            if value is UNKNOWN:
                return UNKNOWN
            if isinstance(value, ValuesDict):
                value = value[name] if name in value else MISSING
            elif isinstance(value, dict):
                value = value.get(name)
            else:
                return MISSING
        return value

    def call(self, name: str, arguments: list[Any]) -> Any:
        self.env.charge()
        function = FUNCTIONS.get(name)
        if function is None:
            return UNKNOWN
        try:
            return function(self, *arguments)
        except (RenderAbortError, _BreakError, _ContinueError):
            raise
        except RecursionError:
            raise RenderAbortError("the template is nested too deeply") from None
        except (TypeError, ValueError, KeyError, IndexError, AttributeError, ArithmeticError):
            return UNKNOWN


# ---------------------------------------------------------------------------------------
# Functions
# ---------------------------------------------------------------------------------------

Function = Callable[..., Any]
FUNCTIONS: dict[str, Function] = {}


def _register(*names: str, strict: bool = True) -> Callable[[Function], Function]:
    """Register a template function.

    A strict function returns UNKNOWN when any argument is not known, which is right for
    everything that computes a value from its arguments. The few that give a hole a meaning
    of their own (``default``, ``empty``, ``eq``, ``quote``, ``indent``, ``include``) are not
    strict.
    """

    def decorate(function: Function) -> Function:
        implementation = function
        if strict:

            def guarded(ex: Executor, *args: Any) -> Any:
                if any(is_hole(arg) for arg in args):
                    return UNKNOWN
                return function(ex, *args)

            implementation = guarded
        for name in names:
            FUNCTIONS[name] = implementation
        return function

    return decorate


def _nil(value: Any) -> Any:
    """A missing lookup is nil to the functions that compare and default."""
    return None if value is MISSING else value


def _int(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)):
        return int(value)
    if isinstance(value, str):
        try:
            return int(float(value.strip()))
        except ValueError:
            return 0
    return 0


def _string(ex: Executor, value: Any) -> str:
    return ex.printable(value)


# -- logic and comparison ---------------------------------------------------------------


@_register("default", strict=False)
def f_default(ex: Executor, fallback: Any, value: Any = None) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    return fallback if is_empty(value) else value


@_register("empty", strict=False)
def f_empty(ex: Executor, value: Any = None) -> Any:
    return UNKNOWN if value is UNKNOWN else is_empty(value)


@_register("not", strict=False)
def f_not(ex: Executor, value: Any = None) -> Any:
    return UNKNOWN if value is UNKNOWN else is_empty(value)


@_register("coalesce", strict=False)
def f_coalesce(ex: Executor, *values: Any) -> Any:
    for value in values:
        if value is UNKNOWN:
            return UNKNOWN
        if not is_empty(value):
            return value
    return None


@_register("ternary", strict=False)
def f_ternary(ex: Executor, when_true: Any, when_false: Any, condition: Any = None) -> Any:
    if condition is UNKNOWN:
        return UNKNOWN
    return when_false if is_empty(condition) else when_true


def _same(left: Any, right: Any) -> bool:
    if isinstance(left, bool) != isinstance(right, bool):
        return False
    return bool(left == right)


@_register("eq", strict=False)
def f_eq(ex: Executor, first: Any, *others: Any) -> Any:
    if first is UNKNOWN or any(other is UNKNOWN for other in others):
        return UNKNOWN
    return any(_same(_nil(first), _nil(other)) for other in others)


@_register("ne", strict=False)
def f_ne(ex: Executor, left: Any, right: Any) -> Any:
    if left is UNKNOWN or right is UNKNOWN:
        return UNKNOWN
    return not _same(_nil(left), _nil(right))


def _order(left: Any, right: Any) -> tuple[Any, Any] | None:
    left, right = _nil(left), _nil(right)
    numeric = (int, float)
    if isinstance(left, numeric) and isinstance(right, numeric):
        return left, right
    if isinstance(left, str) and isinstance(right, str):
        return left, right
    return None


def _comparison(operator: Callable[[Any, Any], bool]) -> Function:
    def compare(ex: Executor, left: Any, right: Any) -> Any:
        if left is UNKNOWN or right is UNKNOWN:
            return UNKNOWN
        pair = _order(left, right)
        return UNKNOWN if pair is None else operator(*pair)

    return compare


FUNCTIONS["lt"] = _comparison(lambda a, b: a < b)
FUNCTIONS["le"] = _comparison(lambda a, b: a <= b)
FUNCTIONS["gt"] = _comparison(lambda a, b: a > b)
FUNCTIONS["ge"] = _comparison(lambda a, b: a >= b)


@_register("required", strict=False)
def f_required(ex: Executor, message: Any, value: Any = None) -> Any:
    if is_hole(value) or is_empty(value):
        return UNKNOWN
    return value


@_register("fail", "mustFail", strict=False)
def f_fail(ex: Executor, *_: Any) -> Any:
    return UNKNOWN


@_register("kindIs", strict=False)
def f_kind_is(ex: Executor, kind: Any, value: Any = None) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    return _kind(_nil(value)) == kind


@_register("typeIs", strict=False)
def f_type_is(ex: Executor, kind: Any, value: Any = None) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    return _kind(_nil(value)) == kind


@_register("kindOf", "typeOf", strict=False)
def f_kind_of(ex: Executor, value: Any = None) -> Any:
    return UNKNOWN if value is UNKNOWN else _kind(_nil(value))


@_register("semverCompare", "semver", strict=False)
def f_semver_compare(ex: Executor, *_: Any) -> Any:
    # Charts use it to pick an API version for a newer cluster; the newer branch is the real one
    return True


@_register("hasKey", strict=False)
def f_has_key(ex: Executor, mapping: Any, key: Any = None) -> Any:
    if mapping is UNKNOWN or key is UNKNOWN:
        return UNKNOWN
    return isinstance(mapping, dict) and key in mapping


@_register("len", strict=False)
def f_len(ex: Executor, value: Any = None) -> Any:
    if value is UNKNOWN:
        return UNKNOWN
    value = _nil(value)
    return 0 if value is None else len(value)


# -- templates --------------------------------------------------------------------------


@_register("include", "mustInclude", strict=False)
def f_include(ex: Executor, name: Any, context: Any = None) -> Any:
    if is_hole(name) or not isinstance(name, str):
        return UNKNOWN
    nodes = ex.env.defines.get(name)
    if nodes is None:
        return UNKNOWN
    return ex.call_define(nodes, context)


@_register("tpl", strict=False)
def f_tpl(ex: Executor, template: Any, context: Any = None) -> Any:
    if template is UNKNOWN:
        return UNKNOWN
    template = _nil(template)
    if not isinstance(template, str):
        return template
    if "{{" not in template:
        return template
    if len(template) > MAX_ACTION_CHARS:
        return UNKNOWN
    try:
        parsed = parse_template(tokenize(template))
    except _TemplateError:
        return UNKNOWN
    inner = dict(ex.env.defines)
    inner.update(parsed.defines)
    saved_defines = ex.env.defines
    ex.env.defines = inner
    try:
        return ex.call_define(parsed.nodes, context)
    finally:
        ex.env.defines = saved_defines


@_register("lookup", strict=False)
def f_lookup(ex: Executor, *_: Any) -> Any:
    # `helm template` has no cluster: lookup returns an empty mapping
    return {}


# -- strings ----------------------------------------------------------------------------


@_register("quote", strict=False)
def f_quote(ex: Executor, *values: Any) -> Any:
    quoted = []
    for value in values:
        if value is None:
            continue
        quoted.append(json.dumps(_string(ex, value), ensure_ascii=False))
    return " ".join(quoted)


@_register("squote", strict=False)
def f_squote(ex: Executor, *values: Any) -> Any:
    return " ".join(f"'{_string(ex, value)}'" for value in values if value is not None)


def _indent(amount: int, text: str) -> str:
    padding = " " * max(0, min(amount, 1000))
    return padding + text.replace("\n", "\n" + padding)


@_register("indent", strict=False)
def f_indent(ex: Executor, amount: Any, text: Any = "") -> Any:
    if is_hole(amount):
        return UNKNOWN
    return _indent(_int(amount), _string(ex, _nil(text)) if is_hole(text) else str(text))


@_register("nindent", strict=False)
def f_nindent(ex: Executor, amount: Any, text: Any = "") -> Any:
    if is_hole(amount):
        return UNKNOWN
    return "\n" + _indent(_int(amount), _string(ex, text) if is_hole(text) else str(text))


@_register("upper")
def f_upper(ex: Executor, text: Any) -> Any:
    return str(text).upper()


@_register("lower")
def f_lower(ex: Executor, text: Any) -> Any:
    return str(text).lower()


@_register("title")
def f_title(ex: Executor, text: Any) -> Any:
    return str(text).title()


@_register("untitle")
def f_untitle(ex: Executor, text: Any) -> Any:
    value = str(text)
    return value[:1].lower() + value[1:]


@_register("trim")
def f_trim(ex: Executor, text: Any) -> Any:
    return str(text).strip()


@_register("trimAll")
def f_trim_all(ex: Executor, cutset: Any, text: Any) -> Any:
    return str(text).strip(str(cutset))


@_register("trimPrefix")
def f_trim_prefix(ex: Executor, prefix: Any, text: Any) -> Any:
    return str(text).removeprefix(str(prefix))


@_register("trimSuffix")
def f_trim_suffix(ex: Executor, suffix: Any, text: Any) -> Any:
    return str(text).removesuffix(str(suffix))


@_register("trunc")
def f_trunc(ex: Executor, length: Any, text: Any) -> Any:
    value, count = str(text), _int(length)
    if count >= 0:
        return value[:count]
    return value[count:]


@_register("substr")
def f_substr(ex: Executor, start: Any, end: Any, text: Any) -> Any:
    value = str(text)
    first, last = _int(start), _int(end)
    return value[first : last if last >= 0 else len(value)]


@_register("replace")
def f_replace(ex: Executor, old: Any, new: Any, text: Any) -> Any:
    return str(text).replace(str(old), str(new))


@_register("contains")
def f_contains(ex: Executor, needle: Any, text: Any) -> Any:
    return str(needle) in str(text)


@_register("hasPrefix")
def f_has_prefix(ex: Executor, prefix: Any, text: Any) -> Any:
    return str(text).startswith(str(prefix))


@_register("hasSuffix")
def f_has_suffix(ex: Executor, suffix: Any, text: Any) -> Any:
    return str(text).endswith(str(suffix))


@_register("repeat")
def f_repeat(ex: Executor, count: Any, text: Any) -> Any:
    return str(text) * max(0, min(_int(count), 1000))


@_register("nospace")
def f_nospace(ex: Executor, text: Any) -> Any:
    return "".join(str(text).split())


@_register("abbrev")
def f_abbrev(ex: Executor, width: Any, text: Any) -> Any:
    value, limit = str(text), _int(width)
    return value if len(value) <= limit else value[: max(0, limit - 3)] + "..."


@_register("cat")
def f_cat(ex: Executor, *values: Any) -> Any:
    return " ".join(ex.printable(v) for v in values if v is not None)


@_register("print")
def f_print(ex: Executor, *values: Any) -> Any:
    return "".join(ex.printable(v) for v in values)


@_register("println")
def f_println(ex: Executor, *values: Any) -> Any:
    return " ".join(ex.printable(v) for v in values) + "\n"


_PRINTF = re.compile(
    r"%(?P<flags>[-+# 0]*)(?P<width>\d+)?(?:\.(?P<precision>\d+))?(?P<verb>[a-zA-Z%])"
)


@_register("printf")
def f_printf(ex: Executor, template: Any, *values: Any) -> Any:
    arguments = list(values)

    def substitute(match: re.Match[str]) -> str:
        verb = match.group("verb")
        if verb == "%":
            return "%"
        value = arguments.pop(0)
        width = int(match.group("width") or 0)
        flags = match.group("flags")
        if verb in ("s", "v"):
            text = ex.printable(value)
        elif verb == "q":
            text = json.dumps(ex.printable(value), ensure_ascii=False)
        elif verb == "d":
            text = str(_int(value))
        elif verb == "t":
            text = "true" if value is True else "false"
        elif verb == "f":
            precision = int(match.group("precision") or 6)
            text = f"{float(value):.{precision}f}"
        else:
            raise ValueError(f"unsupported printf verb %{verb}")
        if "-" in flags:
            return text.ljust(width)
        return text.rjust(width, "0" if "0" in flags and verb in ("d", "f") else " ")

    return _PRINTF.sub(substitute, str(template))


@_register("b64enc")
def f_b64enc(ex: Executor, text: Any) -> Any:
    return base64.b64encode(str(text).encode()).decode()


@_register("b64dec")
def f_b64dec(ex: Executor, text: Any) -> Any:
    return base64.b64decode(str(text), validate=True).decode()


@_register("sha256sum")
def f_sha256(ex: Executor, text: Any) -> Any:
    return hashlib.sha256(str(text).encode()).hexdigest()


@_register("sha1sum")
def f_sha1(ex: Executor, text: Any) -> Any:
    return hashlib.sha1(str(text).encode(), usedforsecurity=False).hexdigest()


@_register("toString")
def f_to_string(ex: Executor, value: Any) -> Any:
    return ex.printable(value)


@_register("toStrings")
def f_to_strings(ex: Executor, values: Any) -> Any:
    return [ex.printable(v) for v in values]


def _words(text: str) -> list[str]:
    return [w for w in re.split(r"[^A-Za-z0-9]+|(?<=[a-z0-9])(?=[A-Z])", text) if w]


@_register("kebabcase")
def f_kebabcase(ex: Executor, text: Any) -> Any:
    return "-".join(w.lower() for w in _words(str(text)))


@_register("snakecase")
def f_snakecase(ex: Executor, text: Any) -> Any:
    return "_".join(w.lower() for w in _words(str(text)))


@_register("camelcase")
def f_camelcase(ex: Executor, text: Any) -> Any:
    return "".join(w.capitalize() for w in _words(str(text)))


@_register("split")
def f_split(ex: Executor, separator: Any, text: Any) -> Any:
    parts = str(text).split(str(separator))
    return {f"_{n}": part for n, part in enumerate(parts)}


@_register("splitList")
def f_split_list(ex: Executor, separator: Any, text: Any) -> Any:
    return str(text).split(str(separator))


@_register("join")
def f_join(ex: Executor, separator: Any, values: Any) -> Any:
    return str(separator).join(ex.printable(v) for v in values)


# -- numbers ----------------------------------------------------------------------------


@_register("int", "int64", "atoi")
def f_int(ex: Executor, value: Any) -> Any:
    return _int(value)


@_register("float64")
def f_float(ex: Executor, value: Any) -> Any:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


@_register("add")
def f_add(ex: Executor, *values: Any) -> Any:
    return sum(_int(v) for v in values)


@_register("add1")
def f_add1(ex: Executor, value: Any) -> Any:
    return _int(value) + 1


@_register("sub")
def f_sub(ex: Executor, left: Any, right: Any) -> Any:
    return _int(left) - _int(right)


@_register("mul")
def f_mul(ex: Executor, *values: Any) -> Any:
    result = 1
    for value in values:
        result *= _int(value)
    return result


@_register("div")
def f_div(ex: Executor, left: Any, right: Any) -> Any:
    return _int(left) // _int(right)


@_register("mod")
def f_mod(ex: Executor, left: Any, right: Any) -> Any:
    return _int(left) % _int(right)


@_register("max")
def f_max(ex: Executor, *values: Any) -> Any:
    return max(_int(v) for v in values)


@_register("min")
def f_min(ex: Executor, *values: Any) -> Any:
    return min(_int(v) for v in values)


# -- collections ------------------------------------------------------------------------


@_register("list", "tuple", strict=False)
def f_list(ex: Executor, *values: Any) -> Any:
    return list(values)


@_register("dict", strict=False)
def f_dict(ex: Executor, *pairs: Any) -> Any:
    result: dict[str, Any] = {}
    for index in range(0, len(pairs) - 1, 2):
        key = pairs[index]
        if isinstance(key, str):
            result[key] = pairs[index + 1]
    return result


@_register("get")
def f_get(ex: Executor, mapping: Any, key: Any) -> Any:
    value = mapping.get(key, "") if isinstance(mapping, dict) else ""
    return value


@_register("set")
def f_set(ex: Executor, mapping: Any, key: Any, value: Any) -> Any:
    mapping[str(key)] = value
    return mapping


@_register("unset")
def f_unset(ex: Executor, mapping: Any, key: Any) -> Any:
    mapping.pop(str(key), None)
    return mapping


@_register("keys")
def f_keys(ex: Executor, *mappings: Any) -> Any:
    return sorted({key for mapping in mappings for key in mapping})


@_register("values")
def f_values(ex: Executor, mapping: Any) -> Any:
    return [mapping[key] for key in sorted(mapping, key=str)]


@_register("pick")
def f_pick(ex: Executor, mapping: Any, *keys: Any) -> Any:
    return {key: mapping[key] for key in keys if key in mapping}


@_register("omit")
def f_omit(ex: Executor, mapping: Any, *keys: Any) -> Any:
    return {key: value for key, value in mapping.items() if key not in keys}


def _merge_into(destination: dict[str, Any], source: Mapping[str, Any], depth: int = 0) -> None:
    if depth > MAX_VALUE_DEPTH:
        raise RecursionError
    for key, value in source.items():
        if isinstance(value, dict) and isinstance(destination.get(key), dict):
            _merge_into(destination[key], value, depth + 1)
        else:
            destination[key] = copy.deepcopy(value)


@_register("merge", "mustMerge")
def f_merge(ex: Executor, destination: Any, *sources: Any) -> Any:
    for source in sources:
        for key, value in source.items():
            if key not in destination:
                destination[key] = copy.deepcopy(value)
            elif isinstance(value, dict) and isinstance(destination[key], dict):
                _merge_keep(destination[key], value)
    return destination


def _merge_keep(destination: dict[str, Any], source: Mapping[str, Any], depth: int = 0) -> None:
    """Merge without overwriting: the destination wins where both have a value."""
    if depth > MAX_VALUE_DEPTH:
        raise RecursionError
    for key, value in source.items():
        if key not in destination or is_empty(destination[key]):
            destination[key] = copy.deepcopy(value)
        elif isinstance(value, dict) and isinstance(destination[key], dict):
            _merge_keep(destination[key], value, depth + 1)


@_register("mergeOverwrite", "mustMergeOverwrite")
def f_merge_overwrite(ex: Executor, destination: Any, *sources: Any) -> Any:
    for source in sources:
        _merge_into(destination, source)
    return destination


@_register("deepCopy", "mustDeepCopy")
def f_deep_copy(ex: Executor, value: Any) -> Any:
    return copy.deepcopy(value)


@_register("index", strict=False)
def f_index(ex: Executor, collection: Any, *keys: Any) -> Any:
    value = collection
    for key in keys:
        if value is UNKNOWN or key is UNKNOWN:
            return UNKNOWN
        if isinstance(value, ValuesDict):
            value = value[key] if key in value else MISSING
        elif isinstance(value, dict):
            value = value.get(key)
        elif isinstance(value, (list, tuple)):
            value = value[_int(key)]
        else:
            return MISSING
    return value


@_register("first", "mustFirst")
def f_first(ex: Executor, values: Any) -> Any:
    return values[0] if values else None


@_register("last", "mustLast")
def f_last(ex: Executor, values: Any) -> Any:
    return values[-1] if values else None


@_register("rest", "mustRest")
def f_rest(ex: Executor, values: Any) -> Any:
    return list(values[1:])


@_register("initial", "mustInitial")
def f_initial(ex: Executor, values: Any) -> Any:
    return list(values[:-1])


@_register("append", "mustAppend")
def f_append(ex: Executor, values: Any, item: Any) -> Any:
    return [*values, item]


@_register("prepend", "mustPrepend")
def f_prepend(ex: Executor, values: Any, item: Any) -> Any:
    return [item, *values]


@_register("concat")
def f_concat(ex: Executor, *lists: Any) -> Any:
    return [item for values in lists for item in values]


@_register("uniq", "mustUniq")
def f_uniq(ex: Executor, values: Any) -> Any:
    seen: list[Any] = []
    for item in values:
        if item not in seen:
            seen.append(item)
    return seen


@_register("without", "mustWithout")
def f_without(ex: Executor, values: Any, *excluded: Any) -> Any:
    return [item for item in values if item not in excluded]


@_register("has", "mustHas")
def f_has(ex: Executor, item: Any, values: Any) -> Any:
    return item in values


@_register("sortAlpha")
def f_sort_alpha(ex: Executor, values: Any) -> Any:
    return sorted(values, key=str)


@_register("reverse", "mustReverse")
def f_reverse(ex: Executor, values: Any) -> Any:
    return list(reversed(values))


# -- serialization ----------------------------------------------------------------------


def dump_yaml(ex: Executor, value: Any) -> str | _Hole:
    """What ``toYaml`` prints: block style, keys sorted, no trailing newline."""
    if value is UNKNOWN or value is MISSING:
        return UNKNOWN
    if not _bounded(value):
        return UNKNOWN
    cleaned = ex.resolved(value)
    text = yaml.dump(
        cleaned,
        Dumper=_YamlDumper,
        default_flow_style=False,
        sort_keys=True,
        allow_unicode=True,
        width=1_000_000,
    )
    if text.endswith("\n...\n"):
        text = text[: -len("\n...\n")] + "\n"
    return text.rstrip("\n")


@_register("toYaml", "mustToYaml", strict=False)
def f_to_yaml(ex: Executor, value: Any = None) -> Any:
    return dump_yaml(ex, _nil(value) if value is MISSING else value)


@_register("toJson", "mustToJson", strict=False)
def f_to_json(ex: Executor, value: Any = None) -> Any:
    if is_hole(value) or not _bounded(value):
        return UNKNOWN
    return json.dumps(ex.resolved(value), sort_keys=True, ensure_ascii=False)


@_register("toPrettyJson", "mustToPrettyJson", strict=False)
def f_to_pretty_json(ex: Executor, value: Any = None) -> Any:
    if is_hole(value) or not _bounded(value):
        return UNKNOWN
    return json.dumps(ex.resolved(value), sort_keys=True, ensure_ascii=False, indent=2)


@_register("fromYaml", "mustFromYaml")
def f_from_yaml(ex: Executor, text: Any) -> Any:
    if len(str(text)) > MAX_ACTION_CHARS * 8:
        return UNKNOWN
    try:
        documents = load_yaml_documents(str(text))
    except ParseError as exc:
        return {"Error": str(exc)}
    return to_values(documents[0]) if documents else {}


@_register("fromJson", "mustFromJson")
def f_from_json(ex: Executor, text: Any) -> Any:
    if len(str(text)) > MAX_ACTION_CHARS * 8:
        return UNKNOWN
    try:
        return to_values(json.loads(str(text)))
    except (ValueError, RecursionError):
        return {}


# ---------------------------------------------------------------------------------------
# Loading a chart from disk
# ---------------------------------------------------------------------------------------

_MANIFEST_SUFFIXES = (".yaml", ".yml")


@dataclass
class _Template:
    path: str  # relative to the root chart, with forward slashes
    text: str
    parsed: ParsedTemplate | None = None
    tokens: list[Token] = field(default_factory=list)
    error: str = ""


@dataclass
class _Chart:
    directory: Path
    relative: str  # "" for the root chart, "charts/redis" for a subchart
    name: str
    meta: dict[str, Any]
    values: ValuesDict
    manifests: list[_Template] = field(default_factory=list)
    helpers: list[_Template] = field(default_factory=list)
    subcharts: list[_Chart] = field(default_factory=list)


@dataclass
class RenderedFile:
    """The text one template rendered to, with a map from output lines back to template lines."""

    path: str  # relative to the root chart, for example templates/rbac/role.yaml
    text: str
    marks: list[tuple[int, int]] = field(default_factory=list)
    approximated: bool = False
    _line_starts: list[int] = field(default_factory=list, repr=False)
    _mark_offsets: list[int] = field(default_factory=list, repr=False)

    def template_line(self, rendered_line: int) -> int | None:
        """The template line that produced a 1-based line of the rendered text, if known."""
        if not self.marks or rendered_line < 1:
            return None
        if not self._line_starts:
            self._line_starts = [0]
            self._line_starts.extend(m.end() for m in re.finditer("\n", self.text))
            self._mark_offsets = [offset for offset, _ in self.marks]
        if rendered_line > len(self._line_starts):
            return None
        index = bisect.bisect_right(self._mark_offsets, self._line_starts[rendered_line - 1]) - 1
        return self.marks[index][1] if index >= 0 else None


@dataclass
class ChartRender:
    files: list[RenderedFile] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    aborted: bool = False


def _read_text(path: Path, label: str, warnings: list[str]) -> str | None:
    """Read a regular file as text, or None with a warning; links and huge files are refused."""
    try:
        info = path.lstat()
    except OSError:
        return None
    if info.st_mode & 0o170000 != 0o100000:  # not a regular file: a link, pipe or device
        warnings.append(f"{label} is not a regular file, so it was not read")
        return None
    if info.st_size > MAX_TEMPLATE_BYTES:
        warnings.append(
            f"{label} is {info.st_size} bytes, over the {MAX_TEMPLATE_BYTES} byte limit, "
            "so it was skipped"
        )
        return None
    try:
        text = decode_input(path, allow_empty=True)
    except (ParseError, OSError) as exc:
        warnings.append(f"{label} could not be read: {exc}")
        return None
    return _cap_lines(text, label, warnings)


def _cap_lines(text: str, label: str, warnings: list[str]) -> str:
    """Replace every line over ``MAX_LINE_CHARS`` characters with a comment."""
    if len(text) <= MAX_LINE_CHARS:
        return text
    lines = text.split("\n")
    changed = False
    for number, line in enumerate(lines):
        if len(line) > MAX_LINE_CHARS:
            lines[number] = f"# line {number + 1} skipped: longer than {MAX_LINE_CHARS} characters"
            changed = True
            warnings.append(
                f"{label} line {number + 1} is longer than {MAX_LINE_CHARS} characters "
                "and was skipped"
            )
    return "\n".join(lines) if changed else text


def _load_mapping(path: Path, label: str, warnings: list[str]) -> dict[str, Any]:
    text = _read_text(path, label, warnings)
    if not text or not text.strip():
        return {}
    try:
        documents = load_yaml_documents(text, source=path.name)
    except ParseError as exc:
        warnings.append(f"{label} is not valid YAML: {exc}")
        return {}
    first = documents[0] if documents else {}
    return first if isinstance(first, dict) else {}


def _load_values(path: Path, warnings: list[str]) -> ValuesDict:
    raw = _load_mapping(path, "values.yaml", warnings)
    try:
        converted = to_values(raw)
    except _TemplateError as exc:
        warnings.append(f"values.yaml was ignored: {exc}")
        return ValuesDict()
    return converted if isinstance(converted, ValuesDict) else ValuesDict()


def _gather_templates(
    chart_dir: Path, relative: str, warnings: list[str]
) -> tuple[list[_Template], list[_Template]]:
    """Template files of a chart: the manifests to render and the helpers kept for defines.

    Walks ``templates/`` and its subdirectories without following links, in sorted order.
    ``NOTES.txt`` and ``templates/tests/`` are not manifests, and a file whose name starts with
    an underscore or ends in ``.tpl`` only supplies definitions.
    """
    root = chart_dir / "templates"
    if root.is_symlink() or not root.is_dir():
        return [], []
    manifests: list[_Template] = []
    helpers: list[_Template] = []
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        directory = Path(dirpath)
        dirnames[:] = sorted(
            name
            for name in dirnames
            if not (directory / name).is_symlink() and not (directory == root and name == "tests")
        )
        for name in sorted(filenames):
            path = directory / name
            if name == "NOTES.txt" or path.is_symlink():
                continue
            is_helper = name.startswith("_") or name.endswith(".tpl")
            if not is_helper and not name.endswith(_MANIFEST_SUFFIXES):
                continue
            seen += 1
            if seen > MAX_TEMPLATE_FILES:
                warnings.append(
                    f"more than {MAX_TEMPLATE_FILES} template files; the rest were skipped"
                )
                return manifests, helpers
            posix = (Path(relative) / path.relative_to(chart_dir)).as_posix().lstrip("./")
            text = _read_text(path, posix, warnings)
            if text is None:
                continue
            (helpers if is_helper else manifests).append(_Template(posix, text))
    return sorted(manifests, key=lambda t: t.path), sorted(helpers, key=lambda t: t.path)


def _go_name(key: str) -> str:
    return {"apiVersion": "APIVersion", "kubeVersion": "KubeVersion"}.get(
        key, key[:1].upper() + key[1:]
    )


def _chart_context(meta: Mapping[str, Any]) -> ValuesDict:
    """``.Chart``: the Chart.yaml fields under their Go names (``name`` becomes ``Name``)."""
    context = ValuesDict()
    for key, value in meta.items():
        if isinstance(key, str):
            context[_go_name(key)] = (
                str(value) if key in ("version", "appVersion", "name") else to_values(value)
            )
    return context


def _lookup_path(values: Mapping[str, Any], path: str) -> Any:
    node: Any = values
    for part in path.split("."):
        if not isinstance(node, Mapping) or part not in node:
            return None
        node = node[part]
    return node


def _dependency_enabled(dependency: Mapping[str, Any], parent_values: Mapping[str, Any]) -> bool:
    """Helm drops a subchart when the first existing ``condition`` path is false."""
    condition = dependency.get("condition")
    if isinstance(condition, str):
        for path in condition.split(","):
            value = _lookup_path(parent_values, path.strip())
            if isinstance(value, bool):
                return value
    return True


def _scoped_values(
    defaults: ValuesDict, parent_values: Mapping[str, Any], scope: str
) -> ValuesDict:
    """A subchart's values: its defaults, overridden by the parent's entry named after it."""
    merged = ValuesDict(copy.deepcopy(defaults))
    override = parent_values.get(scope)
    if isinstance(override, dict):
        _merge_into(merged, override)
    parent_global = parent_values.get("global")
    if isinstance(parent_global, dict):
        shared = merged.get("global")
        if not isinstance(shared, dict):
            shared = ValuesDict()
            merged["global"] = shared
        _merge_into(shared, parent_global)
    return merged


def _load_chart(
    directory: Path,
    relative: str,
    meta: Mapping[str, Any] | None,
    parent_values: Mapping[str, Any] | None,
    dependency: Mapping[str, Any] | None,
    depth: int,
    warnings: list[str],
    loaded: list[int],
) -> _Chart | None:
    loaded[0] += 1
    if loaded[0] > MAX_CHARTS:
        warnings.append(f"more than {MAX_CHARTS} charts; {relative or directory.name} was skipped")
        return None
    chart_meta = (
        dict(meta)
        if meta is not None
        else _load_mapping(directory / "Chart.yaml", "Chart.yaml", warnings)
    )
    raw_name = chart_meta.get("name")
    name = raw_name if isinstance(raw_name, str) and raw_name else directory.name
    defaults = _load_values(directory / "values.yaml", warnings)
    if parent_values is None:
        values = defaults
    else:
        alias = dependency.get("alias") if dependency else None
        values = _scoped_values(defaults, parent_values, alias if isinstance(alias, str) else name)
    chart = _Chart(directory, relative, name, chart_meta, values)
    chart.manifests, chart.helpers = _gather_templates(directory, relative, warnings)
    if depth < MAX_SUBCHART_DEPTH:
        _load_subcharts(chart, depth, warnings, loaded)
    elif (directory / "charts").is_dir():
        warnings.append(f"subcharts of {name} are nested too deeply and were skipped")
    return chart


def _load_subcharts(chart: _Chart, depth: int, warnings: list[str], loaded: list[int]) -> None:
    charts_dir = chart.directory / "charts"
    if charts_dir.is_symlink() or not charts_dir.is_dir():
        return
    dependencies = {
        dep["name"]: dep
        for dep in chart.meta.get("dependencies") or []
        if isinstance(dep, dict) and isinstance(dep.get("name"), str)
    }
    try:
        entries = sorted(charts_dir.iterdir(), key=lambda p: p.name)
    except OSError:
        return
    for entry in entries:
        if entry.is_symlink():
            continue
        if entry.is_file() and entry.name.endswith((".tgz", ".tar.gz")):
            warnings.append(f"subchart archive charts/{entry.name} cannot be rendered without helm")
            continue
        if not entry.is_dir() or not (entry / "Chart.yaml").is_file():
            continue
        sub_meta = _load_mapping(entry / "Chart.yaml", f"charts/{entry.name}/Chart.yaml", warnings)
        sub_name = sub_meta.get("name") if isinstance(sub_meta.get("name"), str) else entry.name
        dependency = dependencies.get(sub_name)
        if dependency is not None and not _dependency_enabled(dependency, chart.values):
            warnings.append(f"subchart {sub_name} is disabled by its condition")
            continue
        relative = (Path(chart.relative) / "charts" / entry.name).as_posix().lstrip("./")
        sub = _load_chart(
            entry, relative, sub_meta, chart.values, dependency, depth + 1, warnings, loaded
        )
        if sub is not None:
            chart.subcharts.append(sub)


def _walk(chart: _Chart) -> list[_Chart]:
    """The chart and its subcharts, parents before their children."""
    ordered = [chart]
    for sub in chart.subcharts:
        ordered.extend(_walk(sub))
    return ordered


# ---------------------------------------------------------------------------------------
# Rendering a chart
# ---------------------------------------------------------------------------------------


def _slug(path: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", path.lower()).strip("-") or "template"


def _root_context(chart: _Chart, template_path: str) -> ValuesDict:
    base = f"{chart.name}/{Path(template_path).parent.as_posix()}"
    return ValuesDict(
        Values=chart.values,
        Chart=_chart_context(chart.meta),
        Release=ValuesDict(
            Name=RELEASE_NAME,
            Namespace=RELEASE_NAMESPACE,
            Service="Helm",
            IsInstall=True,
            IsUpgrade=False,
            Revision=1,
        ),
        Capabilities=ValuesDict(
            KubeVersion=ValuesDict(Version="v1.30.0", GitVersion="v1.30.0", Major="1", Minor="30"),
            APIVersions=ValuesDict(),
            HelmVersion=ValuesDict(Version="v3.15.0"),
        ),
        Template=ValuesDict(Name=f"{chart.name}/{template_path}", BasePath=base),
        Files=UNKNOWN,
    )


def _parse_all(charts: Sequence[_Chart], env: _Env, warnings: list[str]) -> None:
    """Tokenize and parse every template, then collect the definitions of all of them.

    Charts are visited deepest first so a parent chart's definition replaces a subchart's of
    the same name, as it does in Helm.
    """
    for chart in reversed(charts):
        for template in [*chart.helpers, *chart.manifests]:
            template.tokens = tokenize(template.text)
            try:
                template.parsed = parse_template(template.tokens)
            except _TemplateError as exc:
                template.error = str(exc)
                warnings.append(f"{template.path} could not be parsed ({exc}); it is approximated")
                continue
            env.defines.update(template.parsed.defines)


def _render_template(chart: _Chart, template: _Template, env: _Env) -> RenderedFile:
    slug = _slug(template.path)
    relative_in_chart = template.path
    if chart.relative:
        relative_in_chart = template.path[len(chart.relative) :].lstrip("/")
    context = _root_context(chart, relative_in_chart)
    if template.parsed is not None:
        executor = Executor(env, slug, track_lines=True)
        try:
            executor.run(template.parsed.nodes, context)
        except (_BreakError, _ContinueError):
            pass  # a stray break or continue outside a range: approximate the file instead
        else:
            return RenderedFile(template.path, executor.text(), executor.marks)
    flat = Executor(env, slug, track_lines=True)
    for token in template.tokens:
        if token.kind == "text":
            flat.emit(token.text, token.line, literal=True)
            continue
        body = token.text
        if not body or body.startswith("/*") or _keyword_of(body) is not None:
            continue
        flat.source = " ".join(body.split())
        flat.emit(flat.printable(UNKNOWN), token.line, literal=False)
    return RenderedFile(template.path, flat.text(), flat.marks, approximated=True)


def render_chart(
    chart_dir: Path,
    *,
    chart_meta: Mapping[str, Any] | None = None,
    time_budget: float = DEFAULT_TIME_BUDGET_SECONDS,
) -> ChartRender:
    """Render a chart and its subcharts with their default values.

    ``chart_meta`` is the already loaded ``Chart.yaml`` of the root chart. The result lists
    the text of each template that produced any, plus a warning for everything that was
    skipped, approximated or cut short by a budget.
    """
    result = ChartRender()
    root = _load_chart(chart_dir, "", chart_meta, None, None, 0, result.warnings, [0])
    if root is None:
        return result
    charts = _walk(root)
    env = _Env(defines={}, deadline=time.monotonic() + time_budget)
    try:
        _parse_all(charts, env, result.warnings)
    except RecursionError:
        result.warnings.append("a template is nested too deeply to parse")
        result.aborted = True
        return result
    for chart in charts:
        for template in chart.manifests:
            if time.monotonic() > env.deadline:
                result.warnings.append(
                    "the chart used up its time budget; later templates were skipped"
                )
                result.aborted = True
                return result
            try:
                rendered = _render_template(chart, template, env)
            except RenderAbortError as exc:
                result.warnings.append(f"{template.path} stopped rendering: {exc}")
                result.aborted = True
                return result
            except RecursionError:
                result.warnings.append(f"{template.path} is nested too deeply and was skipped")
                continue
            if rendered.text.strip():
                result.files.append(rendered)
    return result


def find_document_line(text: str, kind: str, occurrence: int = 0) -> int | None:
    """The 1-based line where the ``occurrence``-th document of ``kind`` starts, if it is found.

    The helm binary reports which template a document came from but not the line. A document
    is located by its ``kind: <kind>`` line, and by the ``apiVersion:`` line directly above it
    when there is one, which is where manifests conventionally start.
    """
    pattern = re.compile(r"\s*kind:\s*['\"]?" + re.escape(kind) + r"['\"]?\s*(?:#.*)?\Z")
    lines = text.split("\n")
    seen = 0
    for number, line in enumerate(lines, start=1):
        if pattern.match(line):
            if seen == occurrence:
                above = lines[number - 2] if number >= 2 else ""
                return number - 1 if above.lstrip().startswith("apiVersion:") else number
            seen += 1
    return None


def read_template(path: Path) -> str | None:
    """Read one template for line lookup, under the same limits as rendering."""
    return _read_text(path, path.name, [])
