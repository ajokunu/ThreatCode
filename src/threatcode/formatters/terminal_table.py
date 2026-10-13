"""The findings table of the terminal report.

Each finding is a small block of lines that always reads in the same order:

.. code-block:: text

    SEVERITY  RESOURCE              RULE              PATHS
              FINDING
              LOCATION         ATT&CK      STRIDE
    HIGH^     aws_instance.app[0]  EC2_IMDSV1        P1,P2+1
              EC2 instance metadata service allows IMDSv1
              tfplan.json:484  T1552.005   EoP

The first line is the identity: the severity, the resource, the rule (the key a suppression is
written with, always printed whole) and the attack paths the finding enables.
The second line is the finding itself, wrapped with a hanging indent when it is long.
The third line is what a reader looks up, in columns that line up from one finding to the next
and are named by the header in the same order: where it is in the file, the ATT&CK techniques
and the STRIDE category.
When the resource and the rule do not fit on one line side by side, the whole table puts the rule
on a line of its own under the resource, so a resource address is never wrapped when it can be
kept whole.
A table never mixes the two: the layout is decided once for all rows, from their widest cells.

Nothing is shortened with dots.
A cell wider than its column wraps onto further lines of that column (``terminal_layout``).

Everything here is pure: rows in, lines out.
Every string from the scanned input is made safe for a terminal on its way in.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol

from threatcode.formatters._utils import (
    plural,
    rule_label,
    stride_label,
    terminal_safe,
    threat_source,
)
from threatcode.formatters.terminal_layout import TIE, Run, columns, flow, hanging
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Threat, ThreatSource

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

__all__ = ["Layout", "Row", "build_rows", "findings_lines", "layout_of"]

GAP = 2
# The header of the severity column; a mark after a long severity (``CRITICAL^``) widens it.
SEVERITY_HEAD = "SEVERITY"
MAX_TECHNIQUES = 3
# A location column narrower than this wraps an ordinary path on every row; below it the
# location, techniques and category flow instead of lining up.
MIN_LOCATION = 20
HEAD_LOCATION, HEAD_TECHNIQUES, HEAD_STRIDE = "LOCATION", "ATT&CK", "STRIDE"
# The text of a finding that no resource could be found for
UNMATCHED = "(unmatched)"
# The continuation of a wrapped title, and of the rules listed under ``also``
TITLE_HANG = "  "
ALSO_HANG = " " * len("also ")
# STRIDE categories as the terminal shows them: short enough to share a line.
STRIDE_SHORT = {
    "spoofing": "Spoofing",
    "tampering": "Tampering",
    "repudiation": "Repudiation",
    "information_disclosure": "Info disclosure",
    "denial_of_service": "DoS",
    "elevation_of_privilege": "EoP",
}


class Painter(Protocol):
    """What the table needs of the report's painter: color a word, color a line of runs."""

    def __call__(self, text: str, style: str) -> str: ...

    def runs(self, runs: Sequence[Run]) -> str: ...


@dataclass
class Row:
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

    @property
    def label(self) -> str:
        """``HIGH`` or ``HIGH^``: the severity as the first column shows it."""
        return f"{self.severity.upper()}{self.marker}"

    def path_text(self) -> str:
        """``P1``, ``P1,P2`` or ``P1,P2+3``: the attack paths this entry enables."""
        shown = ",".join(f"P{n}" for n in self.paths[:2])
        return shown + (f"+{len(self.paths) - 2}" if len(self.paths) > 2 else "")

    def technique_text(self) -> str:
        """``T1548,T1611,T1105 +2``: three techniques and a count, never a cut id."""
        shown = ",".join(self.techniques[:MAX_TECHNIQUES])
        more = len(self.techniques) - MAX_TECHNIQUES
        return f"{shown} +{more}" if more > 0 else shown

    def meta(self, head: str) -> str:
        """The cell of the line under the title that ``head`` names."""
        if head == HEAD_LOCATION:
            return self.location
        if head == HEAD_TECHNIQUES:
            return self.technique_text()
        return self.stride


# ── rows ──────────────────────────────────────────────────────────────


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


def _resource(threat: Threat) -> str:
    """The resource a finding is about; a scanner finding that matched none says so."""
    address = terminal_safe(threat.resource_address)
    if address:
        return address
    return UNMATCHED if threat.source is ThreatSource.SCANNER else "-"


def build_rows(
    threats: Sequence[Threat],
    enabling: Mapping[str, Sequence[int]],
    graph: InfraGraph | None = None,
) -> list[Row]:
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
    rows: list[Row] = []
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
            Row(
                severity=threat_severity(first).value,
                marker=_marker(first),
                resource=_resource(first),
                rules=rules,
                title=title,
                paths=paths,
                location=_location(first, graph),
                techniques=_techniques(members),
                stride=terminal_safe(
                    STRIDE_SHORT.get(first.stride_category) or stride_label(first.stride_category)
                ),
                members=len(members),
                cause=cause,
            )
        )
    return rows


# ── layout ────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Layout:
    """How the rows of a table are laid out, decided once from the widest of their cells."""

    severity: int
    resource: int
    rule: int
    path: int
    # Whether the rule (and the paths) sit on a line of their own under the resource
    stacked: bool
    # The columns of the line under the title that have any content, in order
    heads: tuple[str, ...]
    # Their widths, or empty when the line is too narrow to line them up and they flow instead
    widths: tuple[int, ...]

    @property
    def indent(self) -> int:
        return self.severity + GAP

    @property
    def aligned(self) -> bool:
        return bool(self.widths)


def _meta_columns(rows: Sequence[Row], room: int) -> tuple[tuple[str, ...], tuple[int, ...]]:
    heads = tuple(
        head
        for head in (HEAD_LOCATION, HEAD_TECHNIQUES, HEAD_STRIDE)
        if any(row.meta(head) for row in rows)
    )
    if not heads:
        return (), ()
    widths = [max([len(head), *(len(row.meta(head)) for row in rows)]) for head in heads]
    over = sum(widths) + GAP * (len(heads) - 1) - room
    if over > 0:
        # Only the location can be long; it wraps inside its column before anything flows
        if heads[0] != HEAD_LOCATION or widths[0] - over < max(MIN_LOCATION, len(HEAD_LOCATION)):
            return heads, ()
        widths[0] -= over
    return heads, tuple(widths)


def layout_of(rows: Sequence[Row], width: int) -> Layout:
    """The layout of ``rows`` on a terminal ``width`` characters wide.

    The severity column is as wide as its header, or wider when a mark follows a long severity.
    The resource and the rule share a line when the longest of each fits beside the other
    without wrapping; otherwise the rule goes under the resource.
    """
    severity = max([len(SEVERITY_HEAD), *(len(row.label) for row in rows)])
    room = max(width - severity - GAP, 1)
    path = max([len(row.path_text()) for row in rows] + [0])
    path = max(path, len("PATHS")) if path else 0
    rule = max([len("RULE"), *(len(row.rules[0]) for row in rows)])
    resource = max([len("RESOURCE"), *(len(row.resource) for row in rows)])
    side_by_side = resource + GAP + rule + (GAP + path if path else 0)
    stacked = side_by_side > room
    if stacked:
        resource = room
        rule = min(rule, max(room - (GAP + path if path else 0), 1))
    heads, widths = _meta_columns(rows, room)
    return Layout(severity, resource, rule, path, stacked, heads, widths)


# ── lines ─────────────────────────────────────────────────────────────


def findings_lines(
    report: ThreatReport,
    enabling: Mapping[str, Sequence[int]],
    paint: Painter,
    width: int,
    graph: InfraGraph | None,
) -> list[str]:
    """The findings section: its heading, the header, every row and the key."""
    rows = build_rows(report.threats, enabling, graph)
    layout = layout_of(rows, width)
    total = len(report.threats)
    hidden = report.coverage.hidden_findings
    counts = f"{total} of {total + hidden} shown" if hidden else str(total)
    if len(rows) < total:
        counts += f", {plural(len(rows), 'row')} after grouping"
    out = [f"Findings ({counts})"]
    out.extend(_header(layout, width))
    for row in rows:
        out.extend(_row_lines(row, layout, paint, width))
    out.extend(_legend(rows, width))
    return out


def _plain(lines: Sequence[Sequence[Run]]) -> list[str]:
    return ["".join(text for text, _ in line).rstrip() for line in lines]


def _identity(
    layout: Layout, label: str, resource: str, rule: str, paths: str, style: str
) -> list[list[Run]]:
    """The line or lines that say which finding this is: severity, resource, rule, paths."""
    sev = (label, layout.severity, style)
    if not layout.stacked:
        cells = [sev, (resource, layout.resource, ""), (rule, layout.rule, "")]
        if layout.path:
            cells.append((paths, layout.path, ""))
        return columns(cells, gap=GAP)
    top = columns([sev, (resource, layout.resource, "")], gap=GAP)
    tail = [(rule, layout.rule, "")]
    if layout.path:
        tail.append((paths, layout.path, ""))
    return [*top, *columns(tail, gap=GAP, lead=" " * layout.indent)]


def _meta(layout: Layout, cells: Sequence[str], style: str, width: int) -> list[list[Run]]:
    """The line under the title, in the columns of the header, or flowing when too narrow."""
    lead = " " * layout.indent
    if layout.aligned:
        return columns(
            [(text, w, style) for text, w in zip(cells, layout.widths, strict=True)],
            gap=GAP,
            lead=lead,
        )
    # A cell is one unit: ``Info disclosure`` is not broken between its words
    items = [(text.replace(" ", TIE), style) for text in cells if text]
    return flow(items, width, sep="  ", first=lead) if items else []


def _header(layout: Layout, width: int) -> list[str]:
    """The column names, in the order the rows print them, over the same offsets."""
    out = _plain(_identity(layout, SEVERITY_HEAD, "RESOURCE", "RULE", "PATHS", ""))
    out.append(" " * layout.indent + "FINDING")
    out.extend(_plain(_meta(layout, layout.heads, "", width)))
    return out


def _row_lines(row: Row, layout: Layout, paint: Painter, width: int) -> list[str]:
    indent = " " * layout.indent
    out = [
        paint.runs(line).rstrip()
        for line in _identity(
            layout, row.label, row.resource, row.rules[0], row.path_text(), row.severity
        )
    ]
    out.extend(hanging(row.title, width, first=indent, rest=indent + TITLE_HANG))
    cells = [row.meta(head) for head in layout.heads]
    if any(cells):
        out.extend(paint.runs(line).rstrip() for line in _meta(layout, cells, "info", width))
    if len(row.rules) > 1:
        out.extend(
            hanging(
                f"also {', '.join(row.rules[1:])}", width, first=indent, rest=indent + ALSO_HANG
            )
        )
    return out


def _legend(rows: Sequence[Row], width: int) -> list[str]:
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
