"""What the terminal says about the parts of the input a scan did not analyse.

The text report and the messages on standard error describe the same coverage gaps, so the
rules for showing them live here once: a gap that was reported twice is shown once, and a file
that produced hundreds of the same gap is one line with a count.

Nothing here prints; it returns data and lines for the callers to print.
Every string that comes from the scanned input is made safe for a terminal on its way out.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from threatcode.formatters._utils import terminal_safe

__all__ = [
    "GapLine",
    "error_text",
    "gap_lines",
    "gap_summary",
    "unique_gaps",
]

# A file with more than this many gaps of one code is one line with a count.
AGGREGATE_ABOVE = 3


def error_text(error: Mapping[str, Any]) -> str:
    """An input error as ``file: message``, safe for a terminal.

    The file is left out when it is the scan root (``.``) or when the message already names it,
    as a parser's does (``Invalid HCL in main.tf, line 2``), so it is not said twice.
    """
    file = terminal_safe(str(error.get("file", "")))
    message = terminal_safe(str(error.get("message", "")))
    if not file or file == "." or file in message:
        return message
    return f"{file}: {message}"


def _key(gap: Mapping[str, Any]) -> tuple[str, str, str, str]:
    return (
        str(gap.get("code", "")),
        str(gap.get("file", "")),
        str(gap.get("line", "")),
        str(gap.get("message", "")),
    )


def unique_gaps(gaps: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """``gaps`` without repeats, in the order they were first reported.

    Two gaps are the same when their code, file, line and message are.
    A parser that meets the same unresolved reference on every pass, or two diagnostics that
    describe one cause, would otherwise be counted and printed more than once.
    """
    seen: set[tuple[str, str, str, str]] = set()
    unique: list[dict[str, Any]] = []
    for gap in gaps:
        key = _key(gap)
        if key not in seen:
            seen.add(key)
            unique.append(dict(gap))
    return unique


@dataclass(frozen=True)
class GapLine:
    """One line of the gap listing: a gap, or the many gaps of one code in one file."""

    code: str
    file: str
    line: str
    message: str
    count: int = 1

    def names_its_file(self) -> bool:
        """Whether the message itself begins with the file, as ``Chart.yaml was rendered ...``.

        Such a line is not given the file twice (``Chart.yaml: Chart.yaml was rendered``).
        A gap with a line keeps its ``file:line`` whatever the message says, because that is the
        part an editor can jump to.
        """
        if not self.file or self.line or self.count > 1:
            return False
        return self.message.startswith(self.file) and self.message[len(self.file) :][:1] in (
            " ",
            ":",
        )

    def text(self) -> str:
        """``[code] file:line: message``, or ``[code] file: 252 times, first at line 12: ...``."""
        place = f" {self.file}" if self.file else ""
        if self.count > 1:
            first = f", first at line {self.line}" if self.line else ""
            return f"[{self.code}]{place}: {self.count} times{first}: {self.message}"
        if self.names_its_file():
            return f"[{self.code}] {self.message}"
        where = f":{self.line}" if self.file and self.line else ""
        return f"[{self.code}]{place}{where}: {self.message}"


def gap_lines(gaps: Sequence[Mapping[str, Any]]) -> list[GapLine]:
    """The gaps as lines to print: no repeats, and a file's many gaps of one code as one line.

    The gaps keep the order of their first report.
    The message of an aggregated line is the first one, which is a sample of the rest; the JSON
    report lists them all.
    """
    unique = unique_gaps(gaps)
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for gap in unique:
        groups.setdefault((str(gap.get("code", "")), str(gap.get("file", ""))), []).append(gap)
    lines: list[GapLine] = []
    emitted: set[tuple[str, str]] = set()
    for gap in unique:
        group_key = (str(gap.get("code", "")), str(gap.get("file", "")))
        members = groups[group_key]
        if len(members) > AGGREGATE_ABOVE:
            if group_key in emitted:
                continue
            emitted.add(group_key)
            first = members[0]
            lines.append(_line(first, len(members)))
        else:
            lines.append(_line(gap, 1))
    return lines


def _line(gap: Mapping[str, Any], count: int) -> GapLine:
    message = str(gap.get("message", "")).splitlines()[0] if gap.get("message") else ""
    return GapLine(
        code=terminal_safe(str(gap.get("code", ""))),
        file=terminal_safe(str(gap.get("file", ""))),
        line=terminal_safe(str(gap.get("line") or "")),
        message=terminal_safe(message),
        count=count,
    )


def gap_summary(gaps: Sequence[Mapping[str, Any]], *, limit: int = 4) -> str:
    """``12 gaps (hcl.module_call_skipped x9, helm.fallback_render x3)``: the gaps by code.

    Codes are listed most frequent first; more than ``limit`` of them end with ``and N more``.
    """
    unique = unique_gaps(gaps)
    counts = Counter(terminal_safe(str(g.get("code", ""))) for g in unique)
    ordered = sorted(counts.items(), key=lambda item: (-item[1], item[0]))
    shown = [f"{code} x{n}" for code, n in ordered[:limit]]
    if len(ordered) > limit:
        shown.append(f"{len(ordered) - limit} more codes")
    noun = "gap" if len(unique) == 1 else "gaps"
    return f"{len(unique)} {noun} ({', '.join(shown)})" if shown else f"{len(unique)} {noun}"
