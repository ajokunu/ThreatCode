"""Value normalisation for Terraform HCL: JSON text, escapes and Python-flavoured expressions.

python-hcl2 hands the parser strings that are not what Terraform would see.
This module turns them into stable values, independent of the python-hcl2 version.

- A policy written as a heredoc, as ``jsonencode({...})`` or as an escaped literal
  (``"{\\"Action\\": \\"*\\"}"``) all become the same compact JSON text, with sorted keys
  as Terraform's own ``jsonencode`` writes them, so a rule that reads the text sees one shape.
- python-hcl2 4.x prints Python literals inside ``${...}`` expressions (``True``, ``None``,
  single-quoted dictionaries).
  ``unpythonize_template`` restores ``true``, ``false`` and ``null`` in expression text
  and never touches the inside of a quoted string.
- ``normalize_value`` runs the whole pipeline over one value without any module context.
  Every variable, local and resource reference in it is an :class:`~threatcode.values.Unknown`.
  The parser itself evaluates with a module context through ``_hcl_eval.evaluate_value``.

The decoding of escapes in top-level strings is deliberately limited.
python-hcl2 4.x prints a quoted string in its source form (backslashes kept) and a heredoc
as raw text, and the two cannot be told apart afterwards.
Only text that is JSON once unescaped is decoded, so a heredoc with a literal backslash is
never mangled.
"""

from __future__ import annotations

import json
import re
from typing import Any

from threatcode.values import UNKNOWN_TEXT

# JSON documents longer than this are kept as written rather than re-serialised
MAX_JSON_TEXT = 2_000_000

_IDENT = re.compile(r"[A-Za-z_][A-Za-z0-9_-]*")
_PYTHON_LITERALS = {"True": "true", "False": "false", "None": "null"}
_SIMPLE_ESCAPES = {
    '"': '"',
    "\\": "\\",
    "/": "/",
    "n": "\n",
    "r": "\r",
    "t": "\t",
    "b": "\b",
    "f": "\f",
}


def canonical_json(value: Any) -> str:
    """Compact JSON with sorted keys, which is how Terraform's ``jsonencode`` prints.

    An ``Unknown`` is a ``str`` and is written as its ``(known after apply)`` text.
    """
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def decode_escapes(text: str) -> str:
    """Decode the escapes of an HCL or JSON string: quotes, backslash, ``\\n``, ``\\uXXXX``.

    An escape it does not know is kept as written, so the function never raises.
    """
    if "\\" not in text:
        return text
    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        ch = text[i]
        if ch != "\\" or i + 1 >= n:
            out.append(ch)
            i += 1
            continue
        nxt = text[i + 1]
        if nxt in _SIMPLE_ESCAPES:
            out.append(_SIMPLE_ESCAPES[nxt])
            i += 2
        elif nxt == "'":
            out.append("'")
            i += 2
        elif nxt in ("u", "U", "x"):
            width = {"u": 4, "U": 8, "x": 2}[nxt]
            digits = text[i + 2 : i + 2 + width]
            if len(digits) == width and all(c in "0123456789abcdefABCDEF" for c in digits):
                try:
                    out.append(chr(int(digits, 16)))
                    i += 2 + width
                    continue
                except (ValueError, OverflowError):
                    pass
            out.append(ch)
            i += 1
        else:
            out.append(ch)
            i += 1
    return "".join(out)


def _load_container(text: str) -> dict[str, Any] | list[Any] | None:
    try:
        decoded = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return decoded if isinstance(decoded, (dict, list)) else None


def as_json_text(text: str) -> str | None:
    """Canonical JSON for ``text`` when it holds a JSON object or array, else None.

    Text that parses only after its backslash escapes are decoded (an escaped literal such as
    ``{\\"Action\\": \\"*\\"}``) is decoded first.
    """
    stripped = text.strip()
    if not stripped or stripped[0] not in "{[" or len(stripped) > MAX_JSON_TEXT:
        return None
    decoded = _load_container(stripped)
    if decoded is None and "\\" in stripped:
        decoded = _load_container(decode_escapes(stripped))
    return None if decoded is None else canonical_json(decoded)


def normalize_text(text: str) -> str:
    """Return ``text``, or its canonical JSON when it holds a JSON object or array.

    JSON is re-serialised compactly with sorted keys, and an escaped literal is decoded first.
    Anything else, including a string that merely starts with a brace, is returned unchanged.
    """
    rendered = as_json_text(text)
    return text if rendered is None else rendered


# --- expression text -----------------------------------------------------------------


# Strings nested inside interpolations nested inside strings: deeper than this is taken
# as running to the end of the text, so hostile input cannot exhaust the Python stack
_MAX_NESTING = 64


def _skip_string(text: str, i: int, depth: int = 0) -> int:
    """Index just after the quoted string that starts at ``i``, honouring ``${}`` nesting."""
    if depth > _MAX_NESTING:
        return len(text)
    quote = text[i]
    i += 1
    n = len(text)
    while i < n:
        ch = text[i]
        if ch == "\\":
            i += 2
            continue
        if ch == quote:
            return i + 1
        if ch in "$%" and text.startswith("{", i + 1) and not text.startswith(ch + ch, i - 1):
            i = skip_braces(text, i + 1, depth + 1)
            continue
        i += 1
    return n


def skip_braces(text: str, i: int, depth: int = 0) -> int:
    """Index just after the ``}`` that closes the ``{`` at ``i``; strings are skipped whole."""
    if depth > _MAX_NESTING:
        return len(text)
    nesting = 0
    n = len(text)
    while i < n:
        ch = text[i]
        if ch in "\"'":
            i = _skip_string(text, i, depth + 1)
            continue
        if ch == "{":
            nesting += 1
        elif ch == "}":
            nesting -= 1
            if nesting == 0:
                return i + 1
        i += 1
    return n


def find_interpolations(text: str) -> list[tuple[int, int]]:
    """Spans ``(start, end)`` of every ``${...}`` in ``text``, including the delimiters.

    ``$${`` is an escaped literal and is not a span.
    A ``${`` inside another interpolation is part of the outer span.
    """
    spans: list[tuple[int, int]] = []
    i, n = 0, len(text)
    while i < n:
        if text.startswith("$${", i):
            i += 3
            continue
        if text.startswith("${", i):
            end = skip_braces(text, i + 1)
            spans.append((i, end))
            i = end
            continue
        i += 1
    return spans


def unpythonize_expression(expression: str) -> str:
    """Rewrite ``True``, ``False`` and ``None`` as HCL literals, outside quoted strings."""
    if not any(word in expression for word in _PYTHON_LITERALS):
        return expression
    out: list[str] = []
    i, n = 0, len(expression)
    while i < n:
        ch = expression[i]
        if ch in "\"'":
            end = _skip_string(expression, i)
            out.append(expression[i:end])
            i = end
        else:
            match = _IDENT.match(expression, i)
            if match is None:
                out.append(ch)
                i += 1
                continue
            word = match.group(0)
            previous = expression[i - 1] if i else ""
            replacement = _PYTHON_LITERALS.get(word)
            out.append(replacement if replacement and previous != "." else word)
            i = match.end()
    return "".join(out)


def unpythonize_template(text: str) -> str:
    """Restore HCL literals inside every ``${...}`` of ``text`` and leave the rest alone."""
    if "${" not in text or not any(word in text for word in _PYTHON_LITERALS):
        return text
    out: list[str] = []
    last = 0
    for start, end in find_interpolations(text):
        closed = end - 1 > start + 1 and text[end - 1] == "}"
        inner = text[start + 2 : end - 1] if closed else text[start + 2 : end]
        out.append(text[last:start])
        out.append("${" + unpythonize_expression(inner) + ("}" if closed else ""))
        last = end
    out.append(text[last:])
    return "".join(out)


def normalize_value(value: Any) -> Any:
    """Normalise one value read from HCL, with no module context.

    Strings that hold JSON become canonical JSON text, ``${jsonencode(...)}`` is rendered, and
    an expression that cannot be known without a module (a variable, a local, a resource
    attribute) becomes an :class:`~threatcode.values.Unknown`.
    Lists and objects are normalised element by element.
    """
    from threatcode.parsers._hcl_eval import EMPTY_CONTEXT, evaluate_value

    return evaluate_value(value, EMPTY_CONTEXT)


__all__ = [
    "UNKNOWN_TEXT",
    "as_json_text",
    "canonical_json",
    "decode_escapes",
    "find_interpolations",
    "normalize_text",
    "normalize_value",
    "skip_braces",
    "unpythonize_expression",
    "unpythonize_template",
]
