"""Plain-text report for a terminal.

The report is built to be understood in ten seconds.
It shows, in order: the header (what was scanned and how many findings), a verdict line
(``Verdict: 3 critical, 14 high, 2 attack paths from the internet to data stores, worst
critical``), the attack paths with the findings that enable each hop, the findings most severe
first, and a coverage summary that always says what was not analysed, what was hidden and what
was set aside.

Nothing the report prints is ever cut in the middle of a name.
A resource address, a rule id, a file and a line are the keys a reader copies into a
suppressions file or an editor, so a cell that is wider than its column wraps onto a further line
instead of ending in ``...``, and two findings that differ only in a part of their title never
print as the same row.
The width is the terminal's (``COLUMNS``, then the terminal, else 100); a narrow terminal gets
a narrower layout, never a broken one.

Each finding is a block of lines in a fixed order (``terminal_table`` has the layout).
The first has the severity, the resource, the rule and the attack paths the finding enables
(``P1`` is the first path listed above); the second is the finding; the third, dim, is where it is
in the file, its ATT&CK techniques and its STRIDE category, in columns that line up from one
finding to the next under a header that names them.
The RULE is the key a suppression is written with, so it is printed in full; findings that share a
root cause on one resource are one entry whose other rules are listed on a line of their own.
A severity marked ``^`` was raised by context from the one its rule assigns (``v`` lowered), and
the legend under the findings says so.
A scan that left part of a Helm chart out says ``incomplete`` in the verdict, with the count of
templates it could not analyse (``terminal_verdict``).

Colors are used only when ``RenderOptions.color`` is set (the CLI sets it for a terminal) and
``NO_COLOR`` is not, so redirected output and CI logs stay plain.
Every string from the scanned input is made safe for a terminal first: an escape sequence in a
resource name is printed as ``\\x1b``, never executed.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Mapping, Sequence
from typing import TYPE_CHECKING, Any

import click

from threatcode.formatters import RenderOptions
from threatcode.formatters._utils import (
    input_summary,
    plural,
    rule_label,
    set_aside_phrase,
    terminal_safe,
)
from threatcode.formatters.terminal_coverage import error_text, gap_lines, unique_gaps
from threatcode.formatters.terminal_layout import TIE, Run, flow, hanging, wrap
from threatcode.formatters.terminal_table import findings_lines
from threatcode.formatters.terminal_verdict import verdict_items
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult

__all__ = ["format_text", "plural", "terminal_width"]

_STYLES: dict[str, dict[str, Any]] = {
    "critical": {"fg": "red", "bold": True},
    "high": {"fg": "red"},
    "medium": {"fg": "yellow"},
    "low": {"fg": "cyan"},
    "info": {"dim": True},
}
# Errors and gaps beyond this many are summarised, not listed; the JSON report has them all.
_LISTED_LIMIT = 10
_DEFAULT_WIDTH = 100
# Below this nothing useful fits on a line; the layout still works, the lines just wrap a lot.
_MIN_WIDTH = 40
_GAP = 2
_SEVERITY_WIDTH = 8
_MAX_PATHS = 10
# Files no parser recognised are named in the coverage block up to this many.
_NAMED_FILES = 5
_MAX_ENABLERS = 3
_PATH_INDENT = 4
# The scanned inputs are named in at least this many characters in the header.
_MIN_LABEL = 40


def terminal_width(options: RenderOptions | None = None) -> int:
    """The width to lay the report out for.

    An explicit ``RenderOptions.width`` wins, then ``COLUMNS``, then the terminal when standard
    output is one, and 100 columns otherwise so a redirected report does not depend on where it
    was made.
    """
    if options is not None and options.width > 0:
        return max(options.width, _MIN_WIDTH)
    columns = os.environ.get("COLUMNS", "")
    if columns.isdigit() and int(columns) > 0:
        return max(int(columns), _MIN_WIDTH)
    try:
        if sys.stdout.isatty():
            return max(shutil.get_terminal_size((_DEFAULT_WIDTH, 24)).columns, _MIN_WIDTH)
    except (AttributeError, ValueError):
        pass
    return _DEFAULT_WIDTH


class _Painter:
    def __init__(self, enabled: bool) -> None:
        self.enabled = enabled

    def __call__(self, text: str, style: str) -> str:
        if not self.enabled or not style or not text.strip():
            return text
        return click.style(text, **_STYLES[style])

    def runs(self, runs: Sequence[Run]) -> str:
        return "".join(self(text, style) for text, style in runs)


def format_text(analysis: AnalysisResult, options: RenderOptions | None = None) -> str:
    """Render the report of ``analysis`` as plain text."""
    report = analysis.report
    use_color = bool((options or RenderOptions()).color) and not os.environ.get("NO_COLOR")
    paint = _Painter(use_color)
    width = terminal_width(options)

    paths = _ordered_paths(report)
    by_id = {t.id: t for t in report.threats}
    enabling = _enabling(report, paths)

    lines: list[str] = _header(report, width)
    lines.append("")
    lines.extend(_verdict(report, paint, width))

    if paths:
        lines.append("")
        lines.extend(_attack_path_lines(paths, by_id, paint, width))

    if report.threats:
        lines.append("")
        lines.extend(findings_lines(report, enabling, paint, width, analysis.graph))

    lines.append("")
    lines.extend(_coverage_lines(report, width))
    lines.extend(_llm_lines(report, width))
    return "\n".join(lines) + "\n"


# ── header and verdict ────────────────────────────────────────────────


def _header(report: ThreatReport, width: int) -> list[str]:
    cov = report.coverage
    shown = len(report.threats)
    if cov.hidden_findings:
        findings = f"{shown} of {shown + cov.hidden_findings} findings shown"
    else:
        findings = plural(shown, "finding")
    counts = f": {plural(report.scanned_resources, 'resource')}, {findings}"
    prefix = "ThreatCode scan"
    # The inputs take the room the counts leave, so the header is one line
    room = max(width - len(prefix) - len(" of ") - len(counts), _MIN_LABEL)
    label = terminal_safe(input_summary(report.input_file, limit=room))
    target = f" of {label}" if label else ""
    return hanging(f"{prefix}{target}{counts}", width, rest="  ")


def _verdict(report: ThreatReport, paint: _Painter, width: int) -> list[str]:
    rows = flow(verdict_items(report), width, first="Verdict: ", rest=" " * 9)
    return [paint.runs(row) for row in rows]


# ── attack paths ──────────────────────────────────────────────────────


def _ordered_paths(report: ThreatReport) -> list[AttackPath]:
    return sorted(report.attack_paths, key=lambda p: (-p.severity.rank, -p.score, p.id))


def _enabling(report: ThreatReport, paths: Sequence[AttackPath]) -> dict[str, list[int]]:
    """For each finding id, the numbers (1 is the first path listed) of the paths it enables."""
    numbers = {path.id: number for number, path in enumerate(paths, start=1)}
    found: dict[str, set[int]] = {}
    for number, path in enumerate(paths, start=1):
        for hop in path.hops:
            for threat_id in hop.enabled_by:
                found.setdefault(threat_id, set()).add(number)
    for threat in report.threats:
        for path_id in threat.path_ids:
            if path_id in numbers:
                found.setdefault(threat.id, set()).add(numbers[path_id])
    return {threat_id: sorted(values) for threat_id, values in found.items()}


def _attack_path_lines(
    paths: Sequence[AttackPath], by_id: Mapping[str, Threat], paint: _Painter, width: int
) -> list[str]:
    lines = [f"Attack paths ({len(paths)})"]
    for number, path in enumerate(paths[:_MAX_PATHS], start=1):
        if number > 1:
            lines.append("")
        lines.extend(_one_path(number, path, by_id, paint, width))
    if len(paths) > _MAX_PATHS:
        lines.extend(
            hanging(
                f"... and {len(paths) - _MAX_PATHS} more, P{_MAX_PATHS + 1} to P{len(paths)} "
                "(see attack_paths in the JSON report)",
                width,
                first="  ",
                rest="    ",
            )
        )
    return lines


def _one_path(
    number: int, path: AttackPath, by_id: Mapping[str, Threat], paint: _Painter, width: int
) -> list[str]:
    severity = path.severity.value
    lead = f"P{number}".ljust(_PATH_INDENT)
    body = f"{terminal_safe(path.entry)} -> {terminal_safe(path.target)}"
    margin = _PATH_INDENT + _SEVERITY_WIDTH + _GAP
    lines = [
        "".join(text for text, _ in row) for row in flow([(body, "")], width, first=" " * margin)
    ]
    first = lead + paint(severity.upper().ljust(_SEVERITY_WIDTH), severity) + " " * _GAP
    out = [first + lines[0][margin:], *lines[1:]]

    indent = " " * _PATH_INDENT
    out.extend(hanging(_why(path, by_id), width, first=indent))
    out.extend(_chain(path, width, indent))
    out.extend(_enabler_lines(path, by_id, paint, width, indent))
    out.extend(hanging(f"ignore id: {terminal_safe(path.id)}", width, first=indent))
    return out


def _why(path: AttackPath, by_id: Mapping[str, Threat]) -> str:
    """Why the path matters, in one sentence: what it ends at, how long it is, what enables it.

    The engine's own rationale is in the JSON report; it repeats the entry and the target that
    the header already shows and quotes the title of the worst finding, which can run to several
    lines, so the terminal gets the facts a reader needs from it.
    """
    hops = max(len(path.hops) - 1, 0)
    facts = [*([terminal_safe(path.target_kind)] if path.target_kind else []), plural(hops, "hop")]
    if path.score:
        facts.append(f"score {path.score:.1f}")
    text = ", ".join(facts)
    ids = list(dict.fromkeys(i for hop in path.hops for i in hop.enabled_by))
    if ids:
        known = sorted(
            (by_id[i] for i in ids if i in by_id),
            key=lambda t: (-threat_severity(t).rank, rule_label(t), t.id),
        )
        text += f"; {plural(len(ids), 'finding')} enable{'s' if len(ids) == 1 else ''} it"
        if known:
            worst = known[0]
            # The severity and the rule it belongs to never end up on two lines
            text += (
                f", the worst being {threat_severity(worst).value.upper()}{TIE}"
                f"{terminal_safe(rule_label(worst))}"
            )
    if path.alternatives:
        text += (
            f"; plus {plural(path.alternatives, 'equivalent route')} through other instances "
            "of the same resources"
        )
    return text + "."


def _chain(path: AttackPath, width: int, indent: str) -> list[str]:
    """The route as ``a > b > c``, broken before an arrow so a continuation line starts with one."""
    room = max(width - len(indent), 1)
    lines: list[str] = []
    current = ""
    for index, hop in enumerate(path.hops):
        node = terminal_safe(hop.node_id)
        token = node if index == 0 else f"> {node}"
        if current and len(current) + 1 + len(token) > room:
            lines.append(current)
            current = token
        else:
            current = f"{current} {token}" if current else token
    if current:
        lines.append(current)
    out: list[str] = []
    for line in lines:
        out.extend(indent + piece for piece in wrap(line, room))
    return out


def _via_text(via: Mapping[str, Any]) -> str:
    """`` on tcp/443`` from the protocol and ports an edge was found to carry, or ``""``."""
    protocol = via.get("protocol")
    ports = via.get("ports", via.get("port"))
    if isinstance(ports, (str, int)) and not isinstance(ports, bool):
        ports = [ports]
    shown = (
        ",".join(terminal_safe(str(p)) for p in ports) if isinstance(ports, (list, tuple)) else ""
    )
    name = terminal_safe(protocol) if isinstance(protocol, str) else ""
    if shown and name:
        return f" on {name}/{shown}"
    if shown:
        return f" on port {shown}"
    return f" over {name}" if name else ""


def _enabler_lines(
    path: AttackPath, by_id: Mapping[str, Threat], paint: _Painter, width: int, indent: str
) -> list[str]:
    """One line per step that findings make possible: the step, then the worst findings."""
    out: list[str] = []
    for index, hop in enumerate(path.hops):
        if not hop.enabled_by:
            continue
        step = terminal_safe(hop.node_id)
        if index + 1 < len(path.hops):
            step += f" -> {terminal_safe(path.hops[index + 1].node_id)}"
        step += _via_text(hop.via)
        known = sorted(
            (by_id[i] for i in dict.fromkeys(hop.enabled_by) if i in by_id),
            key=lambda t: (-threat_severity(t).rank, rule_label(t), t.id),
        )
        unseen = len(set(hop.enabled_by)) - len(known)
        items: list[tuple[str, str]] = [(f"{step}:", "")]
        for threat in known[:_MAX_ENABLERS]:
            severity = threat_severity(threat).value
            items.append((f"{severity.upper()}{TIE}{terminal_safe(rule_label(threat))}", severity))
        more = max(len(known) - _MAX_ENABLERS, 0)
        if more:
            items.append((f"+{more} more", ""))
        if unseen:
            items.append((f"+{unseen} not shown", ""))
        rows = flow(items, width, first=indent + "  ", rest=indent + "    ")
        if not out:
            out.append(f"{indent}enabled by:")
        out.extend(paint.runs(row) for row in rows)
    return out


# ── coverage ──────────────────────────────────────────────────────────


def _coverage_lines(report: ThreatReport, width: int) -> list[str]:
    cov = report.coverage
    named = [terminal_safe(path) for path in cov.not_iac_paths[:_NAMED_FILES]]
    head = (
        f"Coverage: {plural(cov.files_discovered, 'file')} discovered, "
        f"{plural(cov.units_parsed, 'unit')} parsed"
    )
    # The names say how many there are when they are all named
    if cov.not_iac_count and (len(named) < cov.not_iac_count or not named):
        head += f", {cov.not_iac_count} not infrastructure"
    lines = hanging(head, width, rest="  ")
    lines.extend(_not_infrastructure_lines(cov.not_iac_count, named, width))
    skipped = []
    if cov.symlinks_skipped:
        skipped.append(plural(cov.symlinks_skipped, "symlink"))
    if cov.special_files_skipped:
        skipped.append(plural(cov.special_files_skipped, "special file"))
    if skipped:
        lines.extend(
            hanging(f"Skipped: {', '.join(skipped)} (never opened)", width, first="  ", rest="    ")
        )
    if cov.hidden_findings or cov.hidden_paths:
        hidden = set_aside_phrase(cov.hidden_findings, cov.hidden_paths)
        lines.extend(
            hanging(
                f"Hidden: {hidden} below {terminal_safe(cov.min_severity)} (--min-severity)",
                width,
                first="  ",
                rest="    ",
            )
        )
    lines.extend(_set_aside_lines(report, width))
    if cov.errors:
        lines.append(f"  Errors ({len(cov.errors)}):")
        for err in cov.errors[:_LISTED_LIMIT]:
            lines.extend(hanging(error_text(err), width, first="    ", rest="      "))
        _more(lines, len(cov.errors), "coverage.errors")
    gaps = gap_lines(cov.gaps)
    if gaps:
        unique = len(unique_gaps(cov.gaps))
        repeats = len(cov.gaps) - unique
        merged = f", {plural(repeats, 'repeat')} merged" if repeats else ""
        lines.append(f"  Gaps ({unique}{merged}):")
        for gap in gaps[:_LISTED_LIMIT]:
            lines.extend(hanging(gap.text(), width, first="    ", rest="      "))
        _more(lines, len(gaps), "coverage.gaps")
    if cov.rule_errors:
        lines.append(f"  Rule errors: {plural(cov.rule_errors, 'rule evaluation')} failed")
    if not (cov.errors or cov.gaps or cov.rule_errors):
        lines.extend(
            hanging(
                "No input errors or coverage gaps were recorded.", width, first="  ", rest="    "
            )
        )
    return lines


def _not_infrastructure_lines(count: int, named: Sequence[str], width: int) -> list[str]:
    """The files no parser recognised, by name: a count alone cannot be acted on.

    The report holds the first twenty paths; the first few are named and the rest counted.
    """
    if not named:
        return []
    left = count - len(named)
    tail = f" and {plural(left, 'more file')}" if left > 0 else ""
    return hanging(f"Not infrastructure: {', '.join(named)}{tail}", width, first="  ", rest="    ")


def _set_aside_lines(report: ThreatReport, width: int) -> list[str]:
    cov = report.coverage
    parts = []
    if cov.suppressed:
        phrase = set_aside_phrase(cov.suppressed - cov.suppressed_paths, cov.suppressed_paths)
        parts.append(f"{phrase} suppressed")
    if cov.baselined:
        phrase = set_aside_phrase(cov.baselined - cov.baselined_paths, cov.baselined_paths)
        parts.append(f"{phrase} baselined")
    if not parts:
        return []
    return hanging(f"Set aside: {', '.join(parts)}", width, first="  ", rest="    ")


def _llm_lines(report: ThreatReport, width: int) -> list[str]:
    llm = report.llm
    if not llm:
        return []
    status = terminal_safe(str(llm.get("status", "")))
    where = "/".join(terminal_safe(str(llm[k])) for k in ("provider", "model") if llm.get(k))
    where = f" ({where})" if where else ""
    if status == "ran":
        count = int(llm.get("threat_count", 0) or 0)
        text = f"LLM: ran{where}, {plural(count, 'advisory finding')} (never fail the gate)"
        lines = hanging(text, width, rest="  ")
        unattributed = int(llm.get("unattributed_count", 0) or 0)
        if unattributed:
            noun = plural(unattributed, "model finding")
            lines.extend(
                hanging(
                    f"LLM: {noun} named no resource in the scan and "
                    f"{'was' if unattributed == 1 else 'were'} set aside "
                    "(see llm.unattributed in the JSON report)",
                    width,
                    rest="  ",
                )
            )
        return lines
    if status == "failed":
        error = terminal_safe(str(llm.get("error", "")))
        text = f"LLM: failed{where}: {error}. Only rule-based findings are shown."
        return hanging(text, width, rest="  ")
    return []


def _more(lines: list[str], total: int, where: str) -> None:
    if total > _LISTED_LIMIT:
        lines.append(f"    ... and {total - _LISTED_LIMIT} more (see {where} in the JSON report)")
