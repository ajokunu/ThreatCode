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

Everything here is pure: text in, lines out.
Nothing touches a terminal, so a layout can be checked against any width.
"""

from __future__ import annotations

from collections.abc import Sequence

__all__ = [
    "Item",
    "Run",
    "flow",
    "hanging",
    "split_token",
    "wrap",
]

# A run of text and the severity name that colors it ("" for plain text).
Run = tuple[str, str]
# A phrase of a flowing line and its style; the words of a phrase may wrap, the phrase is one unit
# of meaning.
Item = tuple[str, str]

# Where an identifier may be broken: after one of these.
_SOFT_BREAK_AFTER = ".:/_-[,"
# A piece is never shorter than this share of the width unless the token is shorter, so a long
# address is not shredded into fragments of one or two characters.
_MIN_PIECE_SHARE = 0.4


def split_token(token: str, width: int) -> list[str]:
    """``token`` broken into pieces of at most ``width`` characters, at a boundary when possible.

    The pieces joined give back ``token``.
    A token that fits is returned whole.
    """
    width = max(width, 1)
    pieces: list[str] = []
    rest = token
    while len(rest) > width:
        window = rest[:width]
        floor = max(int(width * _MIN_PIECE_SHARE), 1)
        cut = max(window.rfind(c) for c in _SOFT_BREAK_AFTER) + 1
        if cut < floor:
            cut = width
        pieces.append(rest[:cut])
        rest = rest[cut:]
    if rest or not pieces:
        pieces.append(rest)
    return pieces


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
    return lines


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

    # (runs, spaces before it); a piece of a broken word follows its predecessor with none
    tokens: list[tuple[list[Run], int]] = []
    for position, (text, style) in enumerate(items):
        words = text.split()
        ends_with_sep = bool(tail) and position < len(items) - 1 and not text_ends_intro(text)
        for index, word in enumerate(words):
            last_word = index == len(words) - 1
            # The separator is part of the last piece, so that piece leaves room for it
            limit = max(room - len(tail), 1) if (last_word and ends_with_sep) else room
            pieces = split_token(word, limit)
            for piece_index, piece in enumerate(pieces):
                runs: list[Run] = [(piece, style)]
                if last_word and piece_index == len(pieces) - 1 and ends_with_sep:
                    runs.append((tail, ""))
                if piece_index:
                    before = 0
                elif index:
                    before = 1
                else:
                    before = gap_between if position else 0
                    if position and text_ends_intro(items[position - 1][0]):
                        before = 1
                tokens.append((runs, before))

    lines: list[list[Run]] = []
    current: list[Run] = []
    used = 0
    for runs, before in tokens:
        size = sum(len(text) for text, _ in runs)
        gap = before if current else 0
        if current and used + gap + size > (first_room if not lines else rest_room):
            lines.append(current)
            current, used, gap = [], 0, 0
        if gap:
            current.append((" " * gap, ""))
        current.extend(runs)
        used += gap + size
    lines.append(current)
    return [
        ([(first if index == 0 else lead, "")] if (first or lead) else []) + line
        for index, line in enumerate(lines)
    ]


def text_ends_intro(text: str) -> bool:
    """Whether ``text`` introduces what follows it (ends in a colon or a semicolon)."""
    return text.endswith((":", ";"))
