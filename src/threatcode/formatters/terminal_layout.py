"""Layout primitives for the terminal report: wrapping that never cuts a name.

A security report is read for its names: a resource address, a rule id, a file and a line.
A name that is cut in the middle (``aws_in...ce.app[0]``) cannot be told from another one, cannot
be pasted into a suppressions file and hides the part that distinguishes it.
So the terminal report never shortens a name.
When a cell is wider than its column the text is wrapped onto further lines, at a word boundary
when there is one and at a punctuation boundary of an address (``.``, ``/``, ``_``, ``-``, ``:``,
``[``) when there is not.
A token with no boundary at all is broken at the column width, which is the only case where a
name is split, and then it is split into pieces that together hold every character.
A line reference (``main.tf:484``) is never separated from the file it belongs to: the piece that
carries the number always carries at least one character of the name before it.
A path in a column of its own (``wrap_path``) is wrapped after its ``/`` only, so a directory or
a file name is not cut in the middle when it fits.

Everything here is pure: text in, lines out.
Nothing touches a terminal, so a layout can be checked against any width.
"""

from __future__ import annotations

import re
from collections.abc import Sequence

__all__ = [
    "TIE",
    "Cell",
    "Item",
    "Run",
    "columns",
    "flow",
    "hanging",
    "path_components",
    "split_token",
    "wrap",
    "wrap_path",
]

# A run of text and the severity name that colors it ("" for plain text).
Run = tuple[str, str]
# A phrase of a flowing line and its style; the words of a phrase may wrap, the phrase is one unit
# of meaning.
Item = tuple[str, str]

# A cell of a row of columns: its text, the width of its column and its style.
# The text is wrapped inside the column; a sequence of strings is a cell that is already wrapped,
# one line each, which is how a path is laid out (``wrap_path``).
Cell = tuple[str | Sequence[str], int, str]

# Joins two words that must not be separated by a line break (``HIGH`` and the rule id after it).
# It is a C1 control: ``terminal_safe`` prints one that comes from the scanned input as a visible
# ``\x9c``, so no name can carry a tie, and ``str.split`` does not take it for a space.
# Every function here prints it as a plain space, and it is never written to a terminal as itself.
TIE = "\x9c"

# Where an identifier may be broken: after one of these.
_SOFT_BREAK_AFTER = ".:/_-[,"
# A piece is never shorter than this share of the width unless the token is shorter, so a long
# address is not shredded into fragments of one or two characters.
_MIN_PIECE_SHARE = 0.4
# A line reference at the end of a name: ``:484``, or ``:484:`` when a message follows it.
_LINE_TAIL = re.compile(r":\d+:?$")
# Where a path is cut: after each ``/`` and nowhere else.
_AFTER_SEPARATOR = re.compile(r"(?<=/)")


def split_token(token: str, width: int) -> list[str]:
    """``token`` broken into pieces of at most ``width`` characters, at a boundary when possible.

    The pieces joined give back ``token``.
    A token that fits is returned whole.
    A line reference at the end (``:484``) is kept with at least one character of the name before
    it, so the number is never left alone at the start of a line.
    """
    width = max(width, 1)
    pieces: list[str] = []
    rest = token
    while len(rest) > width:
        limit = width
        tail = _LINE_TAIL.search(rest)
        if tail and tail.start() >= 2:
            # The cut stays before the last character of the name, so that character travels on
            # with the reference
            limit = min(width, tail.start() - 1)
        window = rest[:limit]
        floor = max(int(width * _MIN_PIECE_SHARE), 1)
        cut = max(window.rfind(c) for c in _SOFT_BREAK_AFTER) + 1
        if cut < floor:
            cut = limit
        pieces.append(rest[:cut])
        rest = rest[cut:]
    if rest or not pieces:
        pieces.append(rest)
    return pieces


def path_components(path: str) -> list[str]:
    """``path`` cut after each ``/``: ``a/b/c.tf:12`` is ``a/``, ``b/`` and ``c.tf:12``.

    The components joined give back ``path``; the last one carries the file and its line.
    A line reference is never a component of its own, even after a trailing ``/``.
    """
    parts = [part for part in _AFTER_SEPARATOR.split(path) if part]
    if len(parts) > 1 and _LINE_TAIL.fullmatch(parts[-1]):
        parts[-2:] = [parts[-2] + parts[-1]]
    return parts


def wrap_path(path: str, width: int) -> list[str]:
    """``path`` wrapped to lines of at most ``width`` characters, cut only after a ``/``.

    As many components as fit share a line, so ``terraform/environments/`` is one piece and the
    file with its line number (``main.tf:484``) starts the next.
    A component wider than ``width`` is the only thing that is cut, with ``split_token``.
    The pieces joined give back ``path``; an empty path is one empty line.
    """
    width = max(width, 1)
    lines: list[str] = []
    current = ""
    for part in path_components(path):
        if len(current) + len(part) <= width:
            current += part
            continue
        if current:
            lines.append(current)
            current = ""
        if len(part) <= width:
            current = part
        else:
            *whole, current = split_token(part, width)
            lines.extend(whole)
    lines.append(current)
    return lines


def wrap(text: str, width: int, *, first_width: int | None = None) -> list[str]:
    """``text`` wrapped to lines of at most ``width`` characters; an empty text is one empty line.

    ``first_width`` is the room of the first line when it differs from the others.
    Words stay whole when they fit on a line; a longer one goes through ``split_token``.
    """
    width = max(width, 1)
    first = max(first_width, 1) if first_width is not None else width
    piece_width = min(width, first)
    lines: list[str] = []
    current = ""
    for word in text.split():
        for index, piece in enumerate(split_token(word, piece_width)):
            room = first if not lines else width
            if current and index == 0 and len(current) + 1 + len(piece) <= room:
                current = f"{current} {piece}"
                continue
            if current:
                lines.append(current)
            current = piece
    lines.append(current)
    return [line.replace(TIE, " ") for line in lines]


def hanging(text: str, width: int, *, first: str = "", rest: str | None = None) -> list[str]:
    """``text`` wrapped to ``width``; ``first`` starts the first line and ``rest`` the others.

    ``rest`` defaults to as many spaces as ``first`` is long, which is a hanging indent.
    The prefixes count towards the width, so no line is wider than ``width``.
    """
    lead = rest if rest is not None else " " * len(first)
    lines = wrap(text, max(width - len(lead), 1), first_width=max(width - len(first), 1))
    return [(first if index == 0 else lead) + line for index, line in enumerate(lines)]


def flow(
    items: Sequence[Item],
    width: int,
    *,
    sep: str = ", ",
    first: str = "",
    rest: str | None = None,
) -> list[list[Run]]:
    """Styled phrases wrapped to ``width``: lines of ``(text, style)`` runs.

    The phrases are joined with ``sep`` and wrapped like ``hanging``.
    A phrase is broken only at its own spaces, and a word longer than a line is split with
    ``split_token``, so a colored phrase that wraps stays colored on both lines.
    The separator stays at the end of the line it follows, never at the start of the next one,
    and a separator made only of spaces (``"  "``) is the gap between two phrases.
    A phrase that ends in a colon or a semicolon takes no separator: it introduces what follows.
    The prefixes count towards the width.
    """
    lead = rest if rest is not None else " " * len(first)
    first_room = max(width - len(first), 1)
    rest_room = max(width - len(lead), 1)
    room = min(first_room, rest_room)
    tail = sep.rstrip()
    gap_between = len(sep) - len(tail)

    # (runs, spaces before it, style of those spaces); a piece of a broken word follows its
    # predecessor with no space
    tokens: list[tuple[list[Run], int, str]] = []
    for position, (text, style) in enumerate(items):
        words = text.split()
        ends_with_sep = bool(tail) and position < len(items) - 1 and not text_ends_intro(text)
        for index, word in enumerate(words):
            last_word = index == len(words) - 1
            # The separator is part of the last piece, so that piece leaves room for it
            limit = max(room - len(tail), 1) if (last_word and ends_with_sep) else room
            pieces = split_token(word, limit)
            for piece_index, piece in enumerate(pieces):
                runs: list[Run] = [(piece.replace(TIE, " "), style)]
                if last_word and piece_index == len(pieces) - 1 and ends_with_sep:
                    runs.append((tail, ""))
                if piece_index:
                    before, space_style = 0, style
                elif index:
                    # Inside a phrase the spaces take its style, so a colored phrase is one run
                    before, space_style = 1, style
                else:
                    before, space_style = (gap_between if position else 0), ""
                    if position and text_ends_intro(items[position - 1][0]):
                        before = 1
                tokens.append((runs, before, space_style))

    lines: list[list[Run]] = []
    current: list[Run] = []
    used = 0
    for runs, before, space_style in tokens:
        size = sum(len(text) for text, _ in runs)
        gap = before if current else 0
        if current and used + gap + size > (first_room if not lines else rest_room):
            lines.append(current)
            current, used, gap = [], 0, 0
        if gap:
            current.append((" " * gap, space_style))
        current.extend(runs)
        used += gap + size
    lines.append(current)
    return [
        _merged(([(first if index == 0 else lead, "")] if (first or lead) else []) + line)
        for index, line in enumerate(lines)
    ]


def columns(cells: Sequence[Cell], *, gap: int = 2, lead: str = "") -> list[list[Run]]:
    """Cells side by side, each wrapped inside its own column: the lines of one table row.

    A cell wider than its column wraps onto further lines of that column only, so the cells to
    its right stay where they are, and a row is as tall as its tallest cell.
    Cells are padded to their width, apart from the trailing empty ones, so a line never ends in
    spaces; padding and ``gap`` are plain text and only the words carry the style of the cell.
    ``lead`` starts every line, which is how a row is indented.
    The pieces of a cell hold every character of it, as in ``wrap``.
    A cell given as a sequence of lines is taken as wrapped already; each line must fit its column.
    """
    pieces = [
        wrap(text, width) if isinstance(text, str) else list(text) or [""]
        for text, width, _style in cells
    ]
    height = max((len(p) for p in pieces), default=1)
    lines: list[list[Run]] = []
    for index in range(height):
        shown = [p[index] if index < len(p) else "" for p in pieces]
        last = max((i for i, text in enumerate(shown) if text), default=-1)
        line: list[Run] = [(lead, "")] if lead else []
        for i, text in enumerate(shown[: last + 1]):
            _text, width, style = cells[i]
            line.append((text, style))
            pad = width - len(text) + gap if i < last else 0
            if pad:
                line.append((" " * pad, ""))
        lines.append(_merged(line))
    return lines


def _merged(line: list[Run]) -> list[Run]:
    """``line`` with neighbouring runs of one style joined, so a colored phrase is one run."""
    merged: list[Run] = []
    for text, style in line:
        if merged and merged[-1][1] == style:
            merged[-1] = (merged[-1][0] + text, style)
        else:
            merged.append((text, style))
    return merged


def text_ends_intro(text: str) -> bool:
    """Whether ``text`` introduces what follows it (ends in a colon or a semicolon)."""
    return text.endswith((":", ";"))
