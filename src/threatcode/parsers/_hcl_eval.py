"""A safe evaluator for the Terraform expressions python-hcl2 leaves as text.

python-hcl2 returns every expression as the string ``${...}``.
This module reads that text with its own small tokenizer and parser and evaluates what can be
known without running Terraform.
It never calls ``eval``, never reads a file and never calls a provider.

What evaluates

- literals, quoted strings and templates, lists and objects;
- ``var.x`` from a module context (tfvars, the variable default, a module input) and ``local.x``;
- arithmetic, comparison, ``!``, ``&&``, ``||`` and ternaries over known values, with
  three-valued short circuits (``false && unknown`` is ``false``);
- a few pure functions: ``jsonencode``, ``merge``, ``concat``, ``length``, ``lookup``, ``element``,
  ``join``, ``lower``, ``upper``, ``tostring``, ``tonumber``, ``tobool``, ``tolist``, ``toset``,
  ``tomap``, ``flatten``, ``distinct``, ``keys``, ``values`` and ``coalesce``.

Everything else evaluates to :class:`~threatcode.values.Unknown`.
That includes every attribute of a resource (``aws_kms_key.logs.arn`` carries that reference),
a variable with no value, a ``for`` expression and every function not listed above.
An ``Unknown`` is a value that exists but cannot be known here, so a rule treats it as
unknown instead of absent.

Limits keep a hostile file cheap to read: an expression longer than ``MAX_EXPRESSION_LENGTH``
or nested deeper than ``MAX_DEPTH`` is ``Unknown``, and so is a local that refers to itself.

References are found separately by ``string_references``, token by token, so a reference
inside a function call, a conditional or a ``for`` expression is found even though the value
is unknown.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, NamedTuple

from threatcode.parsers._hcl_values import (
    as_json_text,
    canonical_json,
    decode_escapes,
    normalize_text,
    skip_braces,
    unpythonize_template,
)
from threatcode.values import UNKNOWN_TEXT, Unknown, is_unknown

MAX_EXPRESSION_LENGTH = 20_000
MAX_DEPTH = 48
MAX_TOKENS = 5_000
_MAX_CACHE = 4_096
_MAX_REFERENCE_LENGTH = 200
# The name `self` and the other roots that never name a declared resource
NON_RESOURCE_ROOTS = frozenset({"var", "local", "each", "count", "self", "path", "terraform"})
_KEYWORDS = frozenset({"true", "false", "null", "for", "in", "if", "else", "endif", "endfor"})


class ExpressionError(Exception):
    """The text is not an expression this module can read."""


class _Missing:
    """Marker for a value that is not available (not the same as an Unknown)."""

    def __repr__(self) -> str:
        return "NOT_BOUND"


NOT_BOUND: Any = _Missing()


def _unknown(reference: str = "") -> Unknown:
    return Unknown(reference[:_MAX_REFERENCE_LENGTH])


# --- tokens ------------------------------------------------------------------------------


class Part(NamedTuple):
    """A piece of a template: literal text, a ``${}`` expression or a ``%{}`` directive."""

    kind: str
    text: str


class Token(NamedTuple):
    kind: str  # "ident", "num", "str", "op" or "eof"
    value: Any
    pos: int


_NUMBER = re.compile(r"\d+(?:\.\d+)?(?:[eE][+-]?\d+)?")
_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_OPS2 = ("=>", "==", "!=", "<=", ">=", "&&", "||", "::")
_OPS1 = frozenset("+-*/%<>!?:,.()[]{}=")


def _split_template(text: str, i: int, quote: str | None, decode: bool) -> tuple[list[Part], int]:
    """Split template text into parts, from ``i`` to the closing ``quote`` or the end.

    ``$${`` and ``%%{`` are literal. With ``decode`` the escapes of the literal parts are
    decoded, which is right inside a quoted string and wrong for a top-level string that may
    be a heredoc. Returns the parts and the index after the closing quote.
    """
    parts: list[Part] = []
    literal: list[str] = []
    n = len(text)

    def flush() -> None:
        if literal:
            chunk = "".join(literal)
            parts.append(Part("lit", decode_escapes(chunk) if decode else chunk))
            literal.clear()

    while i < n:
        ch = text[i]
        if quote is not None and ch == "\\" and i + 1 < n:
            literal.append(text[i : i + 2])
            i += 2
        elif quote is not None and ch == quote:
            flush()
            return parts, i + 1
        elif text.startswith("$${", i):
            literal.append("${")
            i += 3
        elif text.startswith("%%{", i):
            literal.append("%{")
            i += 3
        elif text.startswith(("${", "%{"), i):
            flush()
            end = skip_braces(text, i + 1)
            inner = text[i + 2 : end - 1] if text[end - 1 : end] == "}" else text[i + 2 : end]
            parts.append(Part("expr" if ch == "$" else "dir", inner.strip("~ \t\r\n")))
            i = end
        else:
            literal.append(ch)
            i += 1
    if quote is not None:
        raise ExpressionError("unterminated string")
    flush()
    return parts, i


def _lex(text: str) -> list[Token]:
    if len(text) > MAX_EXPRESSION_LENGTH:
        raise ExpressionError("expression too long")
    tokens: list[Token] = []
    i, n = 0, len(text)
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
        elif ch in "\"'":
            parts, end = _split_template(text, i + 1, ch, True)
            tokens.append(Token("str", tuple(parts), i))
            i = end
        elif ch in "0123456789":
            match = _NUMBER.match(text, i)
            if match is None:
                raise ExpressionError("bad number")
            raw = match.group(0)
            number: int | float = float(raw) if any(c in raw for c in ".eE") else int(raw)
            tokens.append(Token("num", number, i))
            i = match.end()
        elif ch == "_" or ("a" <= ch <= "z") or ("A" <= ch <= "Z"):
            match = _IDENT.match(text, i)
            if match is None:
                raise ExpressionError("bad identifier")
            tokens.append(Token("ident", match.group(0), i))
            i = match.end()
        elif text.startswith("...", i):
            tokens.append(Token("op", "...", i))
            i += 3
        elif text[i : i + 2] in _OPS2:
            tokens.append(Token("op", text[i : i + 2], i))
            i += 2
        elif ch in _OPS1:
            tokens.append(Token("op", ch, i))
            i += 1
        else:
            raise ExpressionError(f"unexpected character {ch!r}")
        if len(tokens) > MAX_TOKENS:
            raise ExpressionError("expression too large")
    tokens.append(Token("eof", None, n))
    return tokens


# --- syntax tree -------------------------------------------------------------------------


@dataclass(frozen=True, slots=True)
class Lit:
    value: Any


@dataclass(frozen=True, slots=True)
class Tpl:
    parts: tuple[Any, ...]  # str, an expression node, or a Directive
    directive: bool


@dataclass(frozen=True, slots=True)
class Name:
    ident: str


@dataclass(frozen=True, slots=True)
class Attr:
    base: Any
    name: str


@dataclass(frozen=True, slots=True)
class Idx:
    base: Any
    index: Any


@dataclass(frozen=True, slots=True)
class Splat:
    base: Any
    steps: tuple[tuple[str, Any], ...]


@dataclass(frozen=True, slots=True)
class Call:
    name: str
    args: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class Tup:
    items: tuple[Any, ...]


@dataclass(frozen=True, slots=True)
class Obj:
    items: tuple[tuple[Any, Any], ...]


@dataclass(frozen=True, slots=True)
class Opaque:
    """An expression that is parsed but never evaluated, such as a ``for`` expression."""

    kind: str


@dataclass(frozen=True, slots=True)
class Unary:
    op: str
    operand: Any


@dataclass(frozen=True, slots=True)
class Binary:
    op: str
    left: Any
    right: Any


@dataclass(frozen=True, slots=True)
class Cond:
    test: Any
    yes: Any
    no: Any


_PRECEDENCE = {
    "||": 1,
    "&&": 2,
    "==": 3,
    "!=": 3,
    "<": 4,
    "<=": 4,
    ">": 4,
    ">=": 4,
    "+": 5,
    "-": 5,
    "*": 6,
    "/": 6,
    "%": 6,
}


class _Parser:
    def __init__(self, tokens: list[Token], depth: int = 0) -> None:
        self.tokens = tokens
        self.i = 0
        self.depth = depth

    # token helpers
    def peek(self, offset: int = 0) -> Token:
        return self.tokens[min(self.i + offset, len(self.tokens) - 1)]

    def next(self) -> Token:
        token = self.peek()
        if token.kind != "eof":
            self.i += 1
        return token

    def is_op(self, value: str, offset: int = 0) -> bool:
        token = self.peek(offset)
        return token.kind == "op" and token.value == value

    def accept(self, value: str) -> bool:
        if self.is_op(value):
            self.i += 1
            return True
        return False

    def expect(self, value: str) -> None:
        if not self.accept(value):
            raise ExpressionError(f"expected {value!r}")

    # grammar
    def parse(self) -> Any:
        node = self.expr()
        if self.peek().kind != "eof":
            raise ExpressionError("unexpected trailing tokens")
        return node

    def expr(self) -> Any:
        self.depth += 1
        if self.depth > MAX_DEPTH:
            raise ExpressionError("expression nested too deeply")
        try:
            return self.conditional()
        finally:
            self.depth -= 1

    def conditional(self) -> Any:
        test = self.binary(1)
        if self.accept("?"):
            yes = self.expr()
            self.expect(":")
            no = self.expr()
            return Cond(test, yes, no)
        return test

    def binary(self, minimum: int) -> Any:
        left = self.unary()
        while True:
            token = self.peek()
            precedence = _PRECEDENCE.get(token.value) if token.kind == "op" else None
            if precedence is None or precedence < minimum:
                return left
            self.i += 1
            right = self.binary(precedence + 1)
            left = Binary(token.value, left, right)

    def unary(self) -> Any:
        token = self.peek()
        if token.kind == "op" and token.value in ("-", "!"):
            self.i += 1
            self.depth += 1
            if self.depth > MAX_DEPTH:
                raise ExpressionError("expression nested too deeply")
            try:
                return Unary(token.value, self.unary())
            finally:
                self.depth -= 1
        return self.postfix()

    def postfix(self) -> Any:
        node = self.primary()
        while True:
            if self.is_op("."):
                follower = self.peek(1)
                if follower.kind == "ident":
                    self.i += 2
                    node = Attr(node, follower.value)
                elif follower.kind == "num" and isinstance(follower.value, int):
                    self.i += 2
                    node = Idx(node, Lit(follower.value))
                elif follower.kind == "op" and follower.value == "*":
                    self.i += 2
                    node = Splat(node, self.splat_steps())
                else:
                    raise ExpressionError("expected a name after '.'")
            elif self.is_op("["):
                if self.is_op("*", 1) and self.is_op("]", 2):
                    self.i += 3
                    node = Splat(node, self.splat_steps())
                else:
                    self.i += 1
                    index = self.expr()
                    self.expect("]")
                    node = Idx(node, index)
            else:
                return node

    def splat_steps(self) -> tuple[tuple[str, Any], ...]:
        steps: list[tuple[str, Any]] = []
        while True:
            if self.is_op(".") and self.peek(1).kind == "ident":
                steps.append(("attr", self.peek(1).value))
                self.i += 2
            elif self.is_op("[") and not self.is_op("*", 1):
                self.i += 1
                steps.append(("idx", self.expr()))
                self.expect("]")
            else:
                return tuple(steps)

    def template(self, parts: tuple[Part, ...]) -> Any:
        if not parts:
            return Lit("")
        if all(part.kind == "lit" for part in parts):
            return Lit("".join(part.text for part in parts))
        nodes: list[Any] = []
        directive = False
        for part in parts:
            if part.kind == "lit":
                nodes.append(part.text)
            elif part.kind == "dir":
                directive = True
                nodes.append(part)
            else:
                sub = _Parser(_lex(part.text), self.depth + 1)
                if sub.depth > MAX_DEPTH:
                    raise ExpressionError("expression nested too deeply")
                nodes.append(sub.parse())
        return Tpl(tuple(nodes), directive)

    def primary(self) -> Any:
        token = self.next()
        if token.kind == "num":
            return Lit(token.value)
        if token.kind == "str":
            return self.template(token.value)
        if token.kind == "ident":
            word = token.value
            if self.is_op("("):
                return self.call(word)
            if word == "true":
                return Lit(True)
            if word == "false":
                return Lit(False)
            if word == "null":
                return Lit(None)
            return Name(word)
        if token.kind == "op":
            if token.value == "(":
                node = self.expr()
                self.expect(")")
                return node
            if token.value == "[":
                return self.tuple_or_for()
            if token.value == "{":
                return self.object_or_for()
        raise ExpressionError("unexpected token")

    def call(self, name: str) -> Any:
        self.expect("(")
        args: list[Any] = []
        expanded = False
        while not self.is_op(")"):
            args.append(self.expr())
            if self.accept("..."):
                expanded = True
            if not self.accept(","):
                break
        self.expect(")")
        return Opaque("expanded call") if expanded else Call(name, tuple(args))

    def for_expression(self, close: str) -> Any:
        self.i += 1  # the 'for'
        if self.next().kind != "ident":
            raise ExpressionError("expected an iterator name")
        if self.accept(","):
            if self.next().kind != "ident":
                raise ExpressionError("expected an iterator name")
        follower = self.next()
        if follower.kind != "ident" or follower.value != "in":
            raise ExpressionError("expected 'in'")
        self.expr()
        self.expect(":")
        self.expr()
        if self.accept("=>"):
            self.expr()
            self.accept("...")
        if self.peek().kind == "ident" and self.peek().value == "if":
            self.i += 1
            self.expr()
        self.expect(close)
        return Opaque("for expression")

    def tuple_or_for(self) -> Any:
        if self.peek().kind == "ident" and self.peek().value == "for":
            return self.for_expression("]")
        items: list[Any] = []
        while not self.is_op("]"):
            items.append(self.expr())
            if not self.accept(","):
                break
        self.expect("]")
        return Tup(tuple(items))

    def object_key(self) -> Any:
        token = self.next()
        if token.kind == "ident":
            return Lit(token.value)
        if token.kind == "num":
            return Lit(str(token.value))
        if token.kind == "str":
            return self.template(token.value)
        if token.kind == "op" and token.value == "(":
            key = self.expr()
            self.expect(")")
            return key
        raise ExpressionError("expected an object key")

    def object_or_for(self) -> Any:
        if self.peek().kind == "ident" and self.peek().value == "for":
            return self.for_expression("}")
        items: list[tuple[Any, Any]] = []
        while not self.is_op("}"):
            key = self.object_key()
            if not (self.accept("=") or self.accept(":")):
                raise ExpressionError("expected '=' or ':' after an object key")
            items.append((key, self.expr()))
            self.accept(",")
        self.expect("}")
        return Obj(tuple(items))


_PARSE_CACHE: dict[tuple[str, bool], Any] = {}


def _cached(key: tuple[str, bool], build: Callable[[], Any]) -> Any:
    if key in _PARSE_CACHE:
        return _PARSE_CACHE[key]
    try:
        node: Any = build()
    except ExpressionError as exc:
        node = exc
    except RecursionError:
        node = ExpressionError("expression nested too deeply")
    if len(_PARSE_CACHE) >= _MAX_CACHE:
        _PARSE_CACHE.clear()
    _PARSE_CACHE[key] = node
    return node


def parse_expression(text: str) -> Any:
    """Parse expression text (no ``${}``) to a syntax tree.

    Raises:
        ExpressionError: The text is not an expression this module can read.
    """
    node = _cached((text, False), lambda: _Parser(_lex(text)).parse())
    if isinstance(node, ExpressionError):
        raise node
    return node


def parse_template(text: str) -> Any:
    """Parse the text of a string value that may hold ``${}`` parts."""

    def build() -> Any:
        parts, _ = _split_template(text, 0, None, False)
        return _Parser([], 0).template(tuple(parts))

    node = _cached((text, True), build)
    if isinstance(node, ExpressionError):
        raise node
    return node


# --- context -----------------------------------------------------------------------------


class Context:
    """Where values come from. This base knows nothing, so everything is Unknown."""

    def variable(self, name: str) -> Any:
        return _unknown(f"var.{name}")

    def local(self, name: str) -> Any:
        return _unknown(f"local.{name}")

    def iterator(self, name: str) -> Any:
        """The value bound to a ``dynamic`` block iterator, or NOT_BOUND."""
        return NOT_BOUND

    def declares(self, root: str, name: str) -> bool:
        """Whether ``root.name`` is a resource declared in the module being read."""
        return False

    def declares_data(self, kind: str, name: str) -> bool:
        return False

    def data_value(self, kind: str, name: str, attribute: str) -> Any:
        """The value of a data source attribute, or NOT_BOUND when it cannot be known."""
        return NOT_BOUND

    def module_output(self, module: str, output: str) -> Any:
        return _unknown(f"module.{module}.{output}")

    def reference(self, chain: str) -> str:
        """The reference string for a declared resource, qualified for the current module."""
        return chain

    def variable_references(self, name: str) -> list[str]:
        return []

    def local_references(self, name: str) -> list[str]:
        return []

    def module_references(self, module: str, output: str) -> list[str]:
        return []


EMPTY_CONTEXT = Context()


class IteratorContext(Context):
    """A context that also binds one ``dynamic`` block iterator."""

    def __init__(self, base: Context, name: str, key: Any, value: Any) -> None:
        self._base = base
        self._name = name
        self._bound = {"key": key, "value": value}

    def iterator(self, name: str) -> Any:
        if name == self._name:
            return self._bound
        return self._base.iterator(name)

    def variable(self, name: str) -> Any:
        return self._base.variable(name)

    def local(self, name: str) -> Any:
        return self._base.local(name)

    def declares(self, root: str, name: str) -> bool:
        return self._base.declares(root, name)

    def declares_data(self, kind: str, name: str) -> bool:
        return self._base.declares_data(kind, name)

    def data_value(self, kind: str, name: str, attribute: str) -> Any:
        return self._base.data_value(kind, name, attribute)

    def module_output(self, module: str, output: str) -> Any:
        return self._base.module_output(module, output)

    def reference(self, chain: str) -> str:
        return self._base.reference(chain)

    def variable_references(self, name: str) -> list[str]:
        return self._base.variable_references(name)

    def local_references(self, name: str) -> list[str]:
        return self._base.local_references(name)

    def module_references(self, module: str, output: str) -> list[str]:
        return self._base.module_references(module, output)


# --- evaluation --------------------------------------------------------------------------


def _is_number(value: Any) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _flatten_chain(node: Any) -> tuple[Any, list[tuple[str, Any]]]:
    """Split ``a.b[0].c`` into its root node and the steps applied to it."""
    steps: list[tuple[str, Any]] = []
    while isinstance(node, (Attr, Idx)):
        if isinstance(node, Attr):
            steps.append(("attr", node.name))
        else:
            steps.append(("idx", node.index))
        node = node.base
    steps.reverse()
    return node, steps


def _step(value: Any, kind: str, key: Any) -> Any:
    """Apply one attribute or index step to a value."""
    if is_unknown(value):
        if kind == "attr" and value.reference:
            return _unknown(f"{value.reference}.{key}")
        return value
    if is_unknown(key):
        return _unknown()
    if isinstance(value, dict):
        name = key if isinstance(key, str) else str(key)
        if name in value:
            return value[name]
        return _unknown()
    if isinstance(value, (list, tuple)):
        if _is_number(key) and float(key).is_integer():
            index = int(key)
            if -len(value) <= index < len(value):
                return value[index]
        if isinstance(key, str) and key.lstrip("-").isdigit():
            index = int(key)
            if -len(value) <= index < len(value):
                return value[index]
        return _unknown()
    return _unknown()


def _chain_text(root: str, steps: list[tuple[str, Any]]) -> str:
    return ".".join([root, *(str(key) for kind, key in steps if kind == "attr")])


def _eval_name_chain(root: str, steps: list[tuple[str, Any]], ctx: Context, depth: int) -> Any:
    """Evaluate a traversal whose root is a bare name."""
    bound = ctx.iterator(root)
    if bound is not NOT_BOUND:
        value = bound
        for kind, key in steps:
            value = _step(value, kind, _eval_step_key(kind, key, ctx, depth))
        return value
    if root in ("var", "local"):
        if not steps or steps[0][0] != "attr":
            return _unknown(root)
        name = str(steps[0][1])
        value = ctx.variable(name) if root == "var" else ctx.local(name)
        for kind, key in steps[1:]:
            value = _step(value, kind, _eval_step_key(kind, key, ctx, depth))
        return value
    if root in NON_RESOURCE_ROOTS:
        return _unknown(_chain_text(root, steps))
    if root == "data":
        names = [str(key) for kind, key in steps if kind == "attr"]
        if len(names) >= 3:
            value = ctx.data_value(names[0], names[1], names[2])
            if value is not NOT_BOUND:
                return value
        return _unknown(_chain_text(root, steps))
    if root == "module":
        names = [str(key) for kind, key in steps if kind == "attr"]
        if len(names) >= 2:
            value = ctx.module_output(names[0], names[1])
            for kind, key in steps[2:]:
                value = _step(value, kind, _eval_step_key(kind, key, ctx, depth))
            return value
        return _unknown(_chain_text(root, steps))
    text = _chain_text(root, steps)
    names = [str(key) for kind, key in steps if kind == "attr"]
    if names and ctx.declares(root, names[0]):
        return _unknown(ctx.reference(text))
    return _unknown(text)


def _eval_step_key(kind: str, key: Any, ctx: Context, depth: int) -> Any:
    return key if kind == "attr" else _eval(key, ctx, depth + 1, False)


def _stringify(value: Any) -> str | None:
    """The text a value takes inside a template, or None when it has none."""
    if is_unknown(value) or value is None:
        return None
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float):
        return str(int(value)) if value.is_integer() else repr(value)
    if isinstance(value, str):
        return value
    return None


def _eval_template(node: Tpl, ctx: Context, depth: int, lenient: bool) -> Any:
    if node.directive and not lenient:
        return _unknown()
    if len(node.parts) == 1 and not isinstance(node.parts[0], (str, Part)):
        return _eval(node.parts[0], ctx, depth + 1, lenient)
    out: list[str] = []
    first_unknown: Unknown | None = None
    for part in node.parts:
        if isinstance(part, str):
            out.append(part)
            continue
        if isinstance(part, Part):  # a directive, only reached in lenient mode
            out.append(UNKNOWN_TEXT)
            continue
        value = _eval(part, ctx, depth + 1, lenient)
        text = _stringify(value)
        if text is None:
            if first_unknown is None:
                first_unknown = value if is_unknown(value) else _unknown()
            if not lenient:
                return first_unknown
            text = UNKNOWN_TEXT
        out.append(text)
    return "".join(out)


def _tri_bool(value: Any) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and not is_unknown(value) and value in ("true", "false"):
        return value == "true"
    return None


def _eval_binary(node: Binary, ctx: Context, depth: int, lenient: bool) -> Any:
    left = _eval(node.left, ctx, depth + 1, lenient)
    if node.op in ("&&", "||"):
        short = node.op == "||"
        left_bool = _tri_bool(left)
        if left_bool is short:
            return short
        right = _eval(node.right, ctx, depth + 1, lenient)
        right_bool = _tri_bool(right)
        if right_bool is short:
            return short
        if left_bool is None or right_bool is None:
            return _unknown()
        return not short
    right = _eval(node.right, ctx, depth + 1, lenient)
    if is_unknown(left) or is_unknown(right):
        return _unknown()
    op = node.op
    if op in ("==", "!="):
        same = _equal(left, right)
        return same if op == "==" else not same
    if not (_is_number(left) and _is_number(right)):
        return _unknown()
    try:
        if op == "+":
            return left + right
        if op == "-":
            return left - right
        if op == "*":
            return left * right
        if op == "/":
            result = left / right
            return int(result) if float(result).is_integer() else result
        if op == "%":
            return left % right
        if op == "<":
            return left < right
        if op == "<=":
            return left <= right
        if op == ">":
            return left > right
        if op == ">=":
            return left >= right
    except (ZeroDivisionError, OverflowError, ValueError):
        return _unknown()
    return _unknown()


def _equal(left: Any, right: Any) -> bool:
    if isinstance(left, bool) or isinstance(right, bool):
        return isinstance(left, bool) and isinstance(right, bool) and left == right
    if _is_number(left) and _is_number(right):
        return bool(left == right)
    if isinstance(left, (list, tuple)) and isinstance(right, (list, tuple)):
        return len(left) == len(right) and all(_equal(a, b) for a, b in zip(left, right))
    if isinstance(left, dict) and isinstance(right, dict):
        return left.keys() == right.keys() and all(_equal(left[k], right[k]) for k in left)
    if is_unknown(left) or is_unknown(right):
        return False
    return type(left) is type(right) and bool(left == right)


def _jsonable(value: Any, depth: int = 0) -> Any:
    """Make a value JSON-serialisable the way Terraform's ``jsonencode`` would."""
    if depth > MAX_DEPTH:
        return _unknown()
    if isinstance(value, dict):
        return {str(k): _jsonable(v, depth + 1) for k, v in value.items()}
    if isinstance(value, (list, tuple, set, frozenset)):
        items = sorted(value, key=str) if isinstance(value, (set, frozenset)) else value
        return [_jsonable(v, depth + 1) for v in items]
    if isinstance(value, float) and value.is_integer():
        return int(value)
    return value


def _fn_jsonencode(args: list[Any]) -> Any:
    if len(args) != 1 or is_unknown(args[0]):
        return _unknown()
    return canonical_json(_jsonable(args[0]))


def _fn_merge(args: list[Any]) -> Any:
    merged: dict[str, Any] = {}
    for arg in args:
        if arg is None:
            continue
        if not isinstance(arg, dict):
            return _unknown()
        merged.update(arg)
    return merged


def _fn_concat(args: list[Any]) -> Any:
    out: list[Any] = []
    for arg in args:
        if not isinstance(arg, (list, tuple)):
            return _unknown()
        out.extend(arg)
    return out


def _fn_length(args: list[Any]) -> Any:
    if len(args) == 1 and isinstance(args[0], (list, tuple, dict, str)):
        return len(args[0])
    return _unknown()


def _fn_lookup(args: list[Any]) -> Any:
    if len(args) in (2, 3) and isinstance(args[0], dict) and isinstance(args[1], str):
        if args[1] in args[0]:
            return args[0][args[1]]
        if len(args) == 3:
            return args[2]
    return _unknown()


def _fn_element(args: list[Any]) -> Any:
    if len(args) == 2 and isinstance(args[0], (list, tuple)) and args[0] and _is_number(args[1]):
        return args[0][int(args[1]) % len(args[0])]
    return _unknown()


def _fn_join(args: list[Any]) -> Any:
    if len(args) == 2 and isinstance(args[0], str) and isinstance(args[1], (list, tuple)):
        texts = [_stringify(item) for item in args[1]]
        if all(text is not None for text in texts):
            return args[0].join(t for t in texts if t is not None)
    return _unknown()


def _fn_case(upper: bool) -> Callable[[list[Any]], Any]:
    def convert(args: list[Any]) -> Any:
        if len(args) == 1 and isinstance(args[0], str):
            return args[0].upper() if upper else args[0].lower()
        return _unknown()

    return convert


def _fn_tostring(args: list[Any]) -> Any:
    if len(args) == 1:
        text = _stringify(args[0])
        if text is not None:
            return text
    return _unknown()


def _fn_tonumber(args: list[Any]) -> Any:
    if len(args) != 1:
        return _unknown()
    value = args[0]
    if _is_number(value):
        return value
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            try:
                return float(value)
            except ValueError:
                return _unknown()
    return _unknown()


def _fn_tobool(args: list[Any]) -> Any:
    if len(args) == 1:
        flag = _tri_bool(args[0])
        if flag is not None:
            return flag
    return _unknown()


def _fn_tolist(args: list[Any]) -> Any:
    if len(args) == 1 and isinstance(args[0], (list, tuple, set, frozenset)):
        return list(args[0])
    return _unknown()


def _fn_toset(args: list[Any]) -> Any:
    if len(args) == 1 and isinstance(args[0], (list, tuple, set, frozenset)):
        seen: list[Any] = []
        for item in args[0]:
            if not any(_equal(item, other) for other in seen):
                seen.append(item)
        return seen
    return _unknown()


def _fn_tomap(args: list[Any]) -> Any:
    if len(args) == 1 and isinstance(args[0], dict):
        return dict(args[0])
    return _unknown()


def _fn_flatten(args: list[Any]) -> Any:
    if len(args) != 1 or not isinstance(args[0], (list, tuple)):
        return _unknown()
    out: list[Any] = []
    pending = list(args[0])
    while pending:
        item = pending.pop(0)
        if isinstance(item, (list, tuple)):
            pending[0:0] = list(item)
        else:
            out.append(item)
    return out


def _fn_keys(args: list[Any]) -> Any:
    if len(args) == 1 and isinstance(args[0], dict):
        return sorted(args[0])
    return _unknown()


def _fn_values(args: list[Any]) -> Any:
    if len(args) == 1 and isinstance(args[0], dict):
        return [args[0][k] for k in sorted(args[0])]
    return _unknown()


def _fn_coalesce(args: list[Any]) -> Any:
    for arg in args:
        if is_unknown(arg):
            return _unknown()
        if arg is not None and arg != "":
            return arg
    return _unknown()


_FUNCTIONS: dict[str, Callable[[list[Any]], Any]] = {
    "jsonencode": _fn_jsonencode,
    "merge": _fn_merge,
    "concat": _fn_concat,
    "length": _fn_length,
    "lookup": _fn_lookup,
    "element": _fn_element,
    "join": _fn_join,
    "lower": _fn_case(False),
    "upper": _fn_case(True),
    "tostring": _fn_tostring,
    "tonumber": _fn_tonumber,
    "tobool": _fn_tobool,
    "tolist": _fn_tolist,
    "toset": _fn_toset,
    "tomap": _fn_tomap,
    "flatten": _fn_flatten,
    "distinct": _fn_toset,
    "keys": _fn_keys,
    "values": _fn_values,
    "coalesce": _fn_coalesce,
}
# Functions that handle an Unknown argument themselves
_UNKNOWN_TOLERANT = frozenset({"jsonencode", "coalesce"})


def _eval_call(node: Call, ctx: Context, depth: int, lenient: bool) -> Any:
    function = _FUNCTIONS.get(node.name)
    if function is None:
        return _unknown()
    inner_lenient = lenient or node.name == "jsonencode"
    args = [_eval(arg, ctx, depth + 1, inner_lenient) for arg in node.args]
    if node.name not in _UNKNOWN_TOLERANT and any(is_unknown(a) for a in args):
        return _unknown()
    try:
        return function(args)
    except (TypeError, ValueError, KeyError, IndexError, OverflowError, AttributeError):
        return _unknown()


def _eval_key(node: Any, ctx: Context, depth: int, lenient: bool) -> Any:
    value = _eval(node, ctx, depth + 1, lenient)
    if is_unknown(value):
        return value
    text = _stringify(value)
    return _unknown() if text is None else text


def _eval(node: Any, ctx: Context, depth: int, lenient: bool) -> Any:
    if depth > MAX_DEPTH:
        return _unknown()
    if isinstance(node, Lit):
        return node.value
    if isinstance(node, Tpl):
        return _eval_template(node, ctx, depth, lenient)
    if isinstance(node, (Attr, Idx)):
        root, steps = _flatten_chain(node)
        if isinstance(root, Name):
            return _eval_name_chain(root.ident, steps, ctx, depth)
        value = _eval(root, ctx, depth + 1, lenient)
        for kind, key in steps:
            value = _step(value, kind, _eval_step_key(kind, key, ctx, depth))
        return value
    if isinstance(node, Name):
        return _eval_name_chain(node.ident, [], ctx, depth)
    if isinstance(node, Cond):
        test = _eval(node.test, ctx, depth + 1, lenient)
        flag = _tri_bool(test)
        if flag is None:
            return _unknown()
        return _eval(node.yes if flag else node.no, ctx, depth + 1, lenient)
    if isinstance(node, Binary):
        return _eval_binary(node, ctx, depth, lenient)
    if isinstance(node, Unary):
        operand = _eval(node.operand, ctx, depth + 1, lenient)
        if is_unknown(operand):
            return _unknown()
        if node.op == "!":
            flag = _tri_bool(operand)
            return _unknown() if flag is None else not flag
        return -operand if _is_number(operand) else _unknown()
    if isinstance(node, Call):
        return _eval_call(node, ctx, depth, lenient)
    if isinstance(node, Tup):
        return [_eval(item, ctx, depth + 1, lenient) for item in node.items]
    if isinstance(node, Obj):
        result: dict[str, Any] = {}
        for key_node, value_node in node.items:
            key = _eval_key(key_node, ctx, depth, lenient)
            if is_unknown(key):
                return _unknown()
            result[str(key)] = _eval(value_node, ctx, depth + 1, lenient)
        return result
    if isinstance(node, Splat):
        base = _eval(node.base, ctx, depth + 1, lenient)
        if not isinstance(base, (list, tuple)):
            return _unknown()
        out: list[Any] = []
        for element in base:
            value = element
            for kind, key in node.steps:
                value = _step(value, kind, _eval_step_key(kind, key, ctx, depth))
            out.append(value)
        return out
    return _unknown()


def evaluate_expression(text: str, ctx: Context = EMPTY_CONTEXT) -> Any:
    """Evaluate expression text such as ``var.public ? 1 : 0``; Unknown when it cannot be known."""
    try:
        node = parse_expression(text)
    except ExpressionError:
        return _unknown(text)
    value = _eval(node, ctx, 0, False)
    if is_unknown(value) and not value.reference:
        return _unknown(text)
    return value


def evaluate_string(text: str, ctx: Context = EMPTY_CONTEXT) -> Any:
    """Evaluate a string value as python-hcl2 reports it.

    Text with no ``${}`` is a literal, kept as written except that JSON becomes canonical JSON.
    A template whose parts are all known is the joined text, and a lone ``${expr}`` keeps the
    type of ``expr``. A template with a part that is not known is Unknown, except that a
    template that is itself a JSON document is rendered with ``(known after apply)`` in place
    of each part it could not resolve, so its literal text stays readable by rules.
    """
    if "${" not in text and "%{" not in text:
        return normalize_text(text)
    text = unpythonize_template(text)
    try:
        node = parse_template(text)
    except ExpressionError:
        return _unknown(text)
    if isinstance(node, Lit):
        return normalize_text(str(node.value))
    value = _eval(node, ctx, 0, False)
    if is_unknown(value):
        if text.lstrip().startswith(("{", "[")) and isinstance(node, Tpl):
            lenient = _eval(node, ctx, 0, True)
            rendered = as_json_text(lenient) if isinstance(lenient, str) else None
            if rendered is not None:
                return rendered
        return value if value.reference else _unknown(text)
    if isinstance(value, str):
        return normalize_text(value)
    return value


def evaluate_value(raw: Any, ctx: Context = EMPTY_CONTEXT, depth: int = 0) -> Any:
    """Evaluate a value as python-hcl2 reports it: strings, numbers, lists and objects."""
    if depth > MAX_DEPTH * 4:
        return _unknown()
    if isinstance(raw, str):
        return evaluate_string(raw, ctx)
    if isinstance(raw, dict):
        return {key: evaluate_value(value, ctx, depth + 1) for key, value in raw.items()}
    if isinstance(raw, list):
        return [evaluate_value(item, ctx, depth + 1) for item in raw]
    return raw


# --- references --------------------------------------------------------------------------


def _close_bracket(tokens: list[Token], start: int) -> int:
    """Index of the token that closes the bracket opened at ``start``."""
    depth = 0
    for index in range(start, len(tokens)):
        token = tokens[index]
        if token.kind == "op" and token.value in "([{":
            depth += 1
        elif token.kind == "op" and token.value in ")]}":
            depth -= 1
            if depth == 0:
                return index
    return len(tokens) - 1


def _scan_references(
    tokens: list[Token], ctx: Context, bound: frozenset[str], out: list[str], depth: int
) -> None:
    if depth > MAX_DEPTH:
        return
    frames: list[frozenset[str]] = [bound]
    i, n = 0, len(tokens)
    while i < n:
        token = tokens[i]
        if token.kind == "str":
            for part in token.value:
                if part.kind != "lit":
                    _scan_text(part.text, ctx, frames[-1], out, depth + 1)
            i += 1
            continue
        if token.kind == "op":
            if token.value in "([{":
                names = frames[-1]
                follower = tokens[i + 1] if i + 1 < n else None
                if (
                    token.value in "[{"
                    and follower is not None
                    and follower.kind == "ident"
                    and follower.value == "for"
                ):
                    j = i + 2
                    found: set[str] = set()
                    while j < n and not (tokens[j].kind == "ident" and tokens[j].value == "in"):
                        if tokens[j].kind == "ident":
                            found.add(tokens[j].value)
                        j += 1
                    names = names | frozenset(found)
                    i = j
                frames.append(names)
            elif token.value in ")]}" and len(frames) > 1:
                frames.pop()
            i += 1
            continue
        if token.kind != "ident":
            i += 1
            continue
        previous = tokens[i - 1] if i else None
        follower = tokens[i + 1] if i + 1 < n else None
        if (
            token.value in _KEYWORDS
            or token.value in frames[-1]
            or (previous is not None and previous.kind == "op" and previous.value in (".", "::"))
            or (follower is not None and follower.kind == "op" and follower.value in ("(", "::"))
        ):
            i += 1
            continue
        segments, i = _read_chain(tokens, i, frames[-1], ctx, out, depth)
        _emit_chain(segments, ctx, out)


def _read_chain(
    tokens: list[Token], start: int, bound: frozenset[str], ctx: Context, out: list[str], depth: int
) -> tuple[list[str], int]:
    segments = [tokens[start].value]
    i, n = start + 1, len(tokens)
    while i < n:
        token = tokens[i]
        if token.kind == "op" and token.value == "." and i + 1 < n:
            follower = tokens[i + 1]
            if follower.kind == "ident":
                segments.append(follower.value)
                i += 2
                continue
            if follower.kind == "num" or (follower.kind == "op" and follower.value == "*"):
                i += 2
                continue
            break
        if token.kind == "op" and token.value == "[":
            close = _close_bracket(tokens, i)
            _scan_references(tokens[i + 1 : close], ctx, bound, out, depth + 1)
            i = close + 1
            continue
        break
    return segments, i


def _emit_chain(segments: list[str], ctx: Context, out: list[str]) -> None:
    root = segments[0]
    if root in ("each", "count", "self", "path", "terraform"):
        return
    if root == "var":
        if len(segments) > 1:
            out.extend(ctx.variable_references(segments[1]))
    elif root == "local":
        if len(segments) > 1:
            out.extend(ctx.local_references(segments[1]))
    elif root == "data":
        if len(segments) >= 3 and ctx.declares_data(segments[1], segments[2]):
            out.append(ctx.reference(".".join(segments)))
    elif root == "module":
        if len(segments) >= 3:
            out.extend(ctx.module_references(segments[1], segments[2]))
    elif len(segments) >= 2 and ctx.declares(root, segments[1]):
        out.append(ctx.reference(".".join(segments)))


def _scan_text(
    expression: str, ctx: Context, bound: frozenset[str], out: list[str], depth: int
) -> None:
    try:
        tokens = _lex(expression)
    except ExpressionError:
        return
    _scan_references(tokens, ctx, bound, out, depth)


def string_references(text: str, ctx: Context = EMPTY_CONTEXT) -> list[str]:
    """References to declared resources and data sources inside the ``${}`` parts of ``text``.

    Indexes and splats are dropped, so ``aws_subnet.private[count.index].id`` is
    ``aws_subnet.private.id`` and names every instance. ``var.`` and ``local.`` references
    contribute what the variable or local itself refers to, and ``module.<name>.<output>``
    contributes what a followed module's output refers to. Text without ``${`` has none.
    """
    if "${" not in text and "%{" not in text:
        return []
    out: list[str] = []
    try:
        parts, _ = _split_template(unpythonize_template(text), 0, None, False)
    except ExpressionError:
        return []
    for part in parts:
        if part.kind != "lit":
            _scan_text(part.text, ctx, frozenset(), out, 0)
    return list(dict.fromkeys(out))
