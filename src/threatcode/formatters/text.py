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

Each finding takes two lines.
The first has the severity, the resource, the rule and the attack paths the finding enables
(``P1`` is the first path listed above); the second has the finding, then where it is in the
file and its ATT&CK techniques.
The RULE is the key a suppression is written with, so it is printed in full; findings that share a
root cause on one resource are one entry whose other rules are listed on a line of their own.
A severity marked ``^`` was raised by context from the one its rule assigns (``v`` lowered), and
the legend under the findings says so.

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
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

import click

from threatcode.formatters import RenderOptions
from threatcode.formatters._utils import (
    input_summary,
    plural,
    rule_label,
    set_aside_phrase,
    stride_label,
    terminal_safe,
    threat_source,
    verdict_items,
)
from threatcode.formatters.terminal_coverage import error_text, gap_lines, unique_gaps
from threatcode.formatters.terminal_layout import Run, flow, hanging, wrap
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Threat, ThreatSource

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
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
# Where the second line of a finding starts: under its resource.
_INDENT = _SEVERITY_WIDTH + _GAP
# A resource column narrower than this wraps an ordinary address on every row.
_MIN_RESOURCE = 20
_MAX_PATHS = 10
_MAX_ENABLERS = 3
_MAX_TECHNIQUES = 3
_PATH_INDENT = 4
# The scanned inputs are named in at least this many characters in the header.
_MIN_LABEL = 40
# STRIDE categories as the terminal shows them: short enough to share a line with the finding.
_STRIDE_SHORT = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Info disclosure",
    "denial_of_service": "DoS",
    "elevation_of_privilege": "EoP",
}


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
        lines.extend(_findings(report, enabling, paint, width, analysis.graph))

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
        facts.append(f"score {path.score:g}")
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
            text += (
                f", the worst being {threat_severity(worst).value.upper()} "
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
            items.append((f"{severity.upper()} {terminal_safe(rule_label(threat))}", severity))
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


# ── findings ──────────────────────────────────────────────────────────


@dataclass
class _Row:
    """One entry of the findings table: a finding, or the findings of one root cause."""

    severity: str
    marker: str
    resource: str
    rules: list[str]
    title: str
    paths: list[int]
    location: str
    techniques: list[str]
    stride: str
    members: int = 1
    cause: str = ""

    def path_text(self) -> str:
        """``P1``, ``P1,P2`` or ``P1,P2+3``: the attack paths this entry enables."""
        shown = ",".join(f"P{n}" for n in self.paths[:2])
        return shown + (f"+{len(self.paths) - 2}" if len(self.paths) > 2 else "")


def _sort_key(
    threat: Threat, enabling: Mapping[str, Sequence[int]]
) -> tuple[int, int, str, str, str]:
    on_a_path = 0 if enabling.get(threat.id) else 1
    return (
        -threat_severity(threat).rank,
        on_a_path,
        threat.resource_address,
        rule_label(threat),
        threat.id,
    )


def _location(threat: Threat, graph: InfraGraph | None = None) -> str:
    file, line, _end = threat_source(threat, graph)
    if not file:
        return ""
    file = terminal_safe(file)
    return f"{file}:{line}" if line else file


def _techniques(members: Sequence[Threat]) -> list[str]:
    seen: dict[str, None] = {}
    for member in members:
        for technique in member.mitre_techniques:
            seen.setdefault(terminal_safe(technique), None)
    return list(seen)


def _marker(threat: Threat) -> str:
    """``^`` when context raised the severity above the rule's own, ``v`` when it lowered it."""
    effective = threat.effective_severity
    if effective is None or effective == threat.severity:
        return ""
    return "^" if effective.rank > threat.severity.rank else "v"


def _flow_words(metadata: Mapping[str, Any]) -> str:
    """``tcp/8080``, ``https/443`` or ``port 22``: the protocol and ports of a boundary flow."""
    flow_data = metadata.get("flow")
    if not isinstance(flow_data, Mapping):
        return ""
    protocols = [str(p) for p in flow_data.get("protocols") or []]
    ports = ",".join(str(p) for p in flow_data.get("ports") or [])
    if protocols and ports:
        return f"{protocols[0]}/{ports}"
    if ports:
        return f"port {ports}"
    return protocols[0] if protocols else ""


def _boundary_title(threat: Threat) -> str:
    """A trust boundary finding named by what distinguishes it: the zones and the other end.

    The engine's title leads with the resource that the RESOURCE column already shows and puts
    the other end of the flow last, so every crossing from one resource reads alike.
    """
    meta = threat.metadata
    source, target = meta.get("source_address"), meta.get("target_address")
    szone, tzone = meta.get("source_zone"), meta.get("target_zone")
    if not (
        isinstance(source, str)
        and isinstance(target, str)
        and isinstance(szone, str)
        and isinstance(tzone, str)
        and source
        and target
    ):
        return terminal_safe(threat.title)
    if threat.resource_address == target or source == "internet":
        direction = f"from {'the internet' if source == 'internet' else source}"
    else:
        direction = f"to {target}"
    text = f"Trust boundary crossing, {szone} > {tzone}: {direction}"
    words = _flow_words(meta)
    if words:
        text += f" ({words})"
    flow_data = meta.get("flow")
    if isinstance(flow_data, Mapping):
        if flow_data.get("encrypted") is False:
            text += ", unencrypted"
        if flow_data.get("authenticated") is False:
            text += ", unauthenticated"
    return terminal_safe(text)


def _rows(
    threats: Sequence[Threat],
    enabling: Mapping[str, Sequence[int]],
    graph: InfraGraph | None = None,
) -> list[_Row]:
    """One row per finding; findings with one root cause on one resource share a row."""
    groups: dict[tuple[str, str], list[Threat]] = {}
    ordered: list[list[Threat]] = []
    for threat in sorted(threats, key=lambda t: _sort_key(t, enabling)):
        if threat.root_cause:
            key = (threat.resource_address, threat.root_cause)
            if key in groups:
                groups[key].append(threat)
                continue
            groups[key] = [threat]
            ordered.append(groups[key])
        else:
            ordered.append([threat])
    rows: list[_Row] = []
    for members in ordered:
        first = members[0]
        title = (
            _boundary_title(first)
            if first.source is ThreatSource.BOUNDARY
            else terminal_safe(first.title)
        ) or "-"
        cause = ""
        if len(members) > 1:
            cause = terminal_safe(first.root_cause.replace("_", " ").replace("-", " "))
            title += f" (+{len(members) - 1} related: {cause})"
        rules = list(dict.fromkeys(terminal_safe(rule_label(m)) for m in members))
        paths = sorted({n for m in members for n in enabling.get(m.id, ())})
        rows.append(
            _Row(
                severity=threat_severity(first).value,
                marker=_marker(first),
                resource=terminal_safe(first.resource_address) or "-",
                rules=rules,
                title=title,
                paths=paths,
                location=_location(first, graph),
                techniques=_techniques(members),
                stride=terminal_safe(
                    _STRIDE_SHORT.get(first.stride_category) or stride_label(first.stride_category)
                ),
                members=len(members),
                cause=cause,
            )
        )
    return rows


def _technique_text(techniques: Sequence[str]) -> str:
    shown = ",".join(techniques[:_MAX_TECHNIQUES])
    more = len(techniques) - _MAX_TECHNIQUES
    return f"{shown} +{more}" if more > 0 else shown


@dataclass(frozen=True)
class _Layout:
    resource: int
    rule: int
    path: int
    inline_rule: bool


def _layout(rows: Sequence[_Row], width: int) -> _Layout:
    """How wide the resource and rule columns are.

    The rule id is a key and gets the width of the longest one, so it never wraps; the resource is
    the identity of the finding and gets the rest of the line, and what does not fit wraps.
    When the longest rule id and a readable resource do not fit side by side the rule moves to
    a line of its own, which is how a narrow terminal is served.
    """
    path = max([len(r.path_text()) for r in rows] + [0])
    path = max(path, len("PATHS")) if path else 0
    room = width - _INDENT - (_GAP + path if path else 0)
    rule = max(len(r.rules[0]) for r in rows)
    resource_natural = max(len(r.resource) for r in rows)
    if room < _MIN_RESOURCE + _GAP + rule:
        return _Layout(resource=max(width - _INDENT, 1), rule=0, path=path, inline_rule=False)
    resource = min(resource_natural, room - _GAP - rule)
    return _Layout(resource=resource, rule=rule, path=path, inline_rule=True)


def _findings(
    report: ThreatReport,
    enabling: Mapping[str, Sequence[int]],
    paint: _Painter,
    width: int,
    graph: InfraGraph | None,
) -> list[str]:
    rows = _rows(report.threats, enabling, graph)
    layout = _layout(rows, width)
    total = len(report.threats)
    hidden = report.coverage.hidden_findings
    counts = f"{total} of {total + hidden} shown" if hidden else str(total)
    if len(rows) < total:
        counts += f", {plural(len(rows), 'row')} after grouping"
    out = [f"Findings ({counts})"]
    out.extend(_table_head(rows, layout, width))
    for row in rows:
        out.extend(_render_row(row, layout, paint, width))
    out.extend(_legend(rows, width))
    return out


def _detail_heads(rows: Sequence[_Row]) -> list[str]:
    heads = ["FINDING"]
    if any(r.location for r in rows):
        heads.append("LOCATION")
    if any(r.techniques for r in rows):
        heads.append("ATT&CK")
    if any(r.stride for r in rows):
        heads.append("STRIDE")
    return heads


def _table_head(rows: Sequence[_Row], layout: _Layout, width: int) -> list[str]:
    indent = " " * _INDENT
    heads = [(head, "") for head in _detail_heads(rows)]
    detail = [
        "".join(text for text, _ in row) for row in flow(heads, width, sep="  ", first=indent)
    ]
    first = "SEVERITY".ljust(_SEVERITY_WIDTH) + " " * _GAP + "RESOURCE"
    if layout.inline_rule:
        first = first.ljust(_INDENT + layout.resource) + " " * _GAP + "RULE"
        if layout.path:
            first = first.ljust(_INDENT + layout.resource + _GAP + layout.rule) + " " * _GAP
            first += "PATHS"
        return [first.rstrip(), *detail]
    tail = "RULE" + (" " * _GAP + "PATHS" if layout.path else "")
    return [first, indent + tail, *detail]


def _render_row(row: _Row, layout: _Layout, paint: _Painter, width: int) -> list[str]:
    indent = " " * _INDENT
    label = f"{row.severity.upper()}{row.marker}".ljust(_SEVERITY_WIDTH)
    resource = wrap(row.resource, layout.resource)
    out: list[str] = []
    if layout.inline_rule:
        rule = wrap(row.rules[0], layout.rule)
        path = [row.path_text()]
        for index in range(max(len(resource), len(rule))):
            res = resource[index] if index < len(resource) else ""
            rul = rule[index] if index < len(rule) else ""
            cells = [
                (paint(label, row.severity) if index == 0 else " " * _SEVERITY_WIDTH),
                " " * _GAP,
                res.ljust(layout.resource),
                " " * _GAP,
                rul.ljust(layout.rule),
            ]
            if layout.path:
                cells.extend([" " * _GAP, path[0] if index == 0 else ""])
            out.append("".join(cells).rstrip())
    else:
        for index, piece in enumerate(resource):
            lead = paint(label, row.severity) if index == 0 else " " * _SEVERITY_WIDTH
            out.append((lead + " " * _GAP + piece).rstrip())
        tail = row.rules[0] + (f"  {row.path_text()}" if row.paths else "")
        out.extend(hanging(tail, width, first=indent))

    detail: list[tuple[str, str]] = [(row.title, "")]
    for text in (row.location, _technique_text(row.techniques), row.stride):
        if text:
            detail.append((text, "info"))
    out.extend(paint.runs(r).rstrip() for r in flow(detail, width, sep="  ", first=indent))
    if len(row.rules) > 1:
        out.extend(
            hanging(f"also {', '.join(row.rules[1:])}", width, first=indent, rest=indent + "     ")
        )
    return out


def _legend(rows: Sequence[_Row], width: int) -> list[str]:
    notes: list[str] = []
    if any(r.marker == "^" for r in rows):
        notes.append("^ severity raised from the rule's own by context")
    if any(r.marker == "v" for r in rows):
        notes.append("v lowered by context")
    if any(r.paths for r in rows):
        notes.append("P1, P2: the attack paths above that the finding enables")
    if not notes:
        return []
    return hanging("Key: " + "; ".join(notes), width, first="", rest="     ")


# ── coverage ──────────────────────────────────────────────────────────


def _coverage_lines(report: ThreatReport, width: int) -> list[str]:
    cov = report.coverage
    head = (
        f"Coverage: {plural(cov.files_discovered, 'file')} discovered, "
        f"{plural(cov.units_parsed, 'unit')} parsed"
    )
    if cov.not_iac_count:
        head += f", {cov.not_iac_count} not infrastructure"
    lines = hanging(head, width, rest="  ")
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
