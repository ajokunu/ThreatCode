"""Plain-text report for a terminal.

The report shows, in order: a verdict line (``3 critical, 14 high, 2 attack paths from the
internet to data``), the attack paths, a table of the findings most severe first, and a coverage
summary that always says what was not analysed and what was set aside.

The table fits the terminal: it drops its least useful columns on a narrow one and cuts long cells
with ``...``.
It names the rule of each finding, because that is the key a suppression is written with.
Findings that share a root cause on one resource are one row.
Colors are used only when ``RenderOptions.color`` is set (the CLI sets it for a terminal) and
``NO_COLOR`` is not, so redirected output and CI logs stay plain.
"""

from __future__ import annotations

import os
import shutil
import sys
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any

import click

from threatcode.formatters import RenderOptions
from threatcode.formatters._utils import (
    attack_path_phrase,
    collapse_whitespace,
    plural,
    severity_counts,
    threat_source,
    truncate,
)
from threatcode.models.attack_path import AttackPath
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.analysis import AnalysisResult

__all__ = ["format_text", "plural"]

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
_MIN_WIDTH = 60
_GAP = 2
_MIN_TEXT = 14
_DROP_TEXT = 20
_MAX_LOCATION = 32
_MAX_RULE = 28
_MIN_RULE = 12
_MAX_TECHNIQUES = 16
_MAX_PATHS = 10
_STRIDE_SHORT = {
    "spoofing": "Spoof",
    "tampering": "Tamper",
    "repudiation": "Repud",
    "information_disclosure": "InfoDisc",
    "denial_of_service": "DoS",
    "elevation_of_privilege": "EoP",
}


def _sort_key(threat: Threat) -> tuple[int, str, str, str]:
    return (-threat_severity(threat).rank, threat.resource_address, threat.rule_id, threat.id)


def _location(threat: Threat, graph: InfraGraph | None = None) -> str:
    file, line, _end = threat_source(threat, graph)
    if not file:
        return ""
    return f"{file}:{line}" if line else file


def terminal_width(options: RenderOptions | None = None) -> int:
    """The width to lay the table out for.

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

    def __call__(self, text: str, severity: str) -> str:
        return click.style(text, **_STYLES[severity]) if self.enabled else text


def format_text(analysis: AnalysisResult, options: RenderOptions | None = None) -> str:
    """Render the report of ``analysis`` as plain text."""
    report = analysis.report
    use_color = bool((options or RenderOptions()).color) and not os.environ.get("NO_COLOR")
    paint = _Painter(use_color)
    width = terminal_width(options)

    lines: list[str] = []
    target = f" of {report.input_file}" if report.input_file else ""
    lines.append(
        f"ThreatCode scan{target}: {plural(report.scanned_resources, 'resource')}, "
        f"{plural(len(report.threats), 'finding')}"
    )
    lines.append("")
    lines.append(_verdict(report, paint))

    if report.attack_paths:
        lines.append("")
        lines.extend(_attack_path_lines(report, paint, width))

    if report.threats:
        lines.append("")
        lines.extend(_table(report.threats, paint, width, analysis.graph))

    lines.append("")
    lines.extend(_coverage_lines(report))
    lines.extend(_llm_lines(report))
    return "\n".join(lines) + "\n"


def _verdict(report: ThreatReport, paint: _Painter) -> str:
    counts = severity_counts(report.threats)
    parts = [paint(f"{n} {name}", name) for name, n in counts.items()]
    phrase = attack_path_phrase(report.attack_paths)
    if phrase:
        worst = max(p.severity for p in report.attack_paths).value
        parts.append(paint(phrase, worst))
    return "Verdict: " + (", ".join(parts) if parts else "no findings")


# ── attack paths ──────────────────────────────────────────────────────


def _attack_path_lines(report: ThreatReport, paint: _Painter, width: int) -> list[str]:
    paths = sorted(report.attack_paths, key=lambda p: (-p.severity.rank, -p.score, p.id))
    lines = [f"Attack paths ({len(paths)})"]
    for path in paths[:_MAX_PATHS]:
        lines.extend(_one_path(path, paint, width))
    if len(paths) > _MAX_PATHS:
        lines.append(
            f"  ... and {len(paths) - _MAX_PATHS} more (see attack_paths in the JSON report)"
        )
    return lines


def _one_path(path: AttackPath, paint: _Painter, width: int) -> list[str]:
    severity = path.severity.value
    hops = max(len(path.hops) - 1, 0)
    label = paint(severity.upper().ljust(8), severity)
    lines = [f"{label}  {path.entry} -> {path.target}  ({plural(hops, 'hop')}, id {path.id})"]
    chain = " > ".join(hop.node_id for hop in path.hops)
    indent = " " * 10
    lines.extend(_wrap(chain, width - len(indent), indent))
    return lines


def _wrap(text: str, width: int, indent: str) -> list[str]:
    """``text`` broken at spaces into lines of at most ``width`` characters, each indented."""
    lines: list[str] = []
    current = ""
    for word in text.split(" "):
        if current and len(current) + 1 + len(word) > width:
            lines.append(indent + current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    if current:
        lines.append(indent + truncate(current, width))
    return lines


# ── findings table ────────────────────────────────────────────────────


def _rows(
    threats: Sequence[Threat], graph: InfraGraph | None = None
) -> list[dict[str, str | Threat]]:
    """One row per finding; findings with one root cause on one resource share a row."""
    groups: dict[tuple[str, str], list[Threat]] = {}
    ordered: list[list[Threat]] = []
    for threat in sorted(threats, key=_sort_key):
        if threat.root_cause:
            key = (threat.resource_address, threat.root_cause)
            if key in groups:
                groups[key].append(threat)
                continue
            groups[key] = [threat]
            ordered.append(groups[key])
        else:
            ordered.append([threat])
    rows: list[dict[str, str | Threat]] = []
    for members in ordered:
        first = members[0]
        title = collapse_whitespace(first.title)
        if len(members) > 1:
            cause = first.root_cause.replace("_", " ").replace("-", " ")
            title += f" (+{len(members) - 1} related: {cause})"
        techniques: dict[str, None] = {}
        for member in members:
            for technique in member.mitre_techniques:
                techniques.setdefault(technique, None)
        rows.append(
            {
                "severity": max(threat_severity(m) for m in members).value,
                "resource": first.resource_address or "-",
                "rule": first.rule_id or first.source.value,
                "finding": title,
                "stride": _STRIDE_SHORT.get(first.stride_category, first.stride_category),
                "attck": ",".join(techniques),
                "location": _location(first, graph),
            }
        )
    return rows


def _middle(text: str, size: int) -> str:
    """``text`` cut in the middle to ``size`` characters, so the end of an address survives."""
    if len(text) <= size or size <= 5:
        return text
    tail = (size - 3) * 3 // 5
    head = size - 3 - tail
    return f"{text[:head]}...{text[len(text) - tail :]}"


def _table(
    threats: Sequence[Threat], paint: _Painter, width: int, graph: InfraGraph | None = None
) -> list[str]:
    rows = _rows(threats, graph)

    def widest(column: str, head: str, cap: int | None = None) -> int:
        size = max([len(head), *(len(str(r[column])) for r in rows)])
        return min(size, cap) if cap else size

    natural = {
        "severity": 8,
        "stride": widest("stride", "STRIDE"),
        "attck": widest("attck", "ATT&CK", _MAX_TECHNIQUES),
        "location": widest("location", "LOCATION", _MAX_LOCATION),
        "rule": widest("rule", "RULE", _MAX_RULE),
        "resource": widest("resource", "RESOURCE"),
        "finding": widest("finding", "FINDING"),
    }
    columns = ["severity", "resource", "rule", "finding", "stride", "attck", "location"]
    # What a narrow terminal gives up first: STRIDE, then the technique ids, then the location
    droppable = ["location", "attck", "stride"]
    text_columns = ("resource", "finding")

    def fixed(cols: list[str]) -> int:
        return sum(natural[c] for c in cols if c not in text_columns)

    def spare(cols: list[str]) -> int:
        return width - fixed(cols) - _GAP * (len(cols) - 1)

    while droppable and spare(columns) < 2 * _DROP_TEXT:
        columns.remove(droppable.pop())
    if spare(columns) < 2 * _MIN_TEXT:
        natural["rule"] = max(_MIN_RULE, natural["rule"] - (2 * _MIN_TEXT - spare(columns)))
    room = max(spare(columns), 2 * _MIN_TEXT)
    resource_w = max(_MIN_TEXT, min(natural["resource"], int(room * 0.4)))
    finding_w = max(_MIN_TEXT, min(natural["finding"], room - resource_w))
    resource_w = max(_MIN_TEXT, min(natural["resource"], room - finding_w))
    sizes = {**natural, "resource": resource_w, "finding": finding_w}

    heads = {
        "severity": "SEVERITY",
        "resource": "RESOURCE",
        "rule": "RULE",
        "finding": "FINDING",
        "stride": "STRIDE",
        "attck": "ATT&CK",
        "location": "LOCATION",
    }
    out = [f"Findings ({len(threats)})"]
    out.append((" " * _GAP).join(heads[c].ljust(sizes[c]) for c in columns).rstrip())
    for row in rows:
        cells = []
        for column in columns:
            text = str(row[column])
            size = sizes[column]
            if column == "location" and len(text) > size:
                text = "..." + text[-(size - 3) :]
            elif column == "resource" and len(text) > size:
                text = _middle(text, size)
            cell = truncate(text, size).ljust(size)
            if column == "severity":
                cell = paint(text.upper().ljust(size), text)
            cells.append(cell)
        out.append((" " * _GAP).join(cells).rstrip())
    return out


# ── coverage ──────────────────────────────────────────────────────────


def _coverage_lines(report: ThreatReport) -> list[str]:
    cov = report.coverage
    head = (
        f"Coverage: {plural(cov.files_discovered, 'file')} discovered, "
        f"{plural(cov.units_parsed, 'unit')} parsed"
    )
    if cov.not_iac_count:
        head += f", {cov.not_iac_count} not infrastructure"
    lines = [head]
    skipped = []
    if cov.symlinks_skipped:
        skipped.append(plural(cov.symlinks_skipped, "symlink"))
    if cov.special_files_skipped:
        skipped.append(plural(cov.special_files_skipped, "special file"))
    if skipped:
        lines.append(f"  Skipped: {', '.join(skipped)} (never opened)")
    if cov.suppressed or cov.baselined:
        lines.append(f"  Set aside: {cov.suppressed} suppressed, {cov.baselined} baselined")
    if cov.errors:
        lines.append(f"  Errors ({len(cov.errors)}):")
        for err in cov.errors[:_LISTED_LIMIT]:
            lines.append(f"    {err.get('file', '')}: {err.get('message', '')}")
        _more(lines, len(cov.errors))
    if cov.gaps:
        lines.append(f"  Gaps ({len(cov.gaps)}):")
        for gap in cov.gaps[:_LISTED_LIMIT]:
            where = f" {gap['file']}" if gap.get("file") else ""
            lines.append(f"    [{gap.get('code', '')}]{where}: {gap.get('message', '')}")
        _more(lines, len(cov.gaps))
    if cov.rule_errors:
        lines.append(f"  Rule errors: {plural(cov.rule_errors, 'rule evaluation')} failed")
    if not (cov.errors or cov.gaps or cov.rule_errors):
        lines.append("  No input errors or coverage gaps were recorded.")
    return lines


def _llm_lines(report: ThreatReport) -> list[str]:
    llm = report.llm
    if not llm:
        return []
    status = str(llm.get("status", ""))
    where = "/".join(str(llm[k]) for k in ("provider", "model") if llm.get(k))
    where = f" ({where})" if where else ""
    if status == "ran":
        count = int(llm.get("threat_count", 0) or 0)
        return [f"LLM: ran{where}, {plural(count, 'advisory finding')} (never fail the gate)"]
    if status == "failed":
        error = collapse_whitespace(str(llm.get("error", "")))
        return [f"LLM: failed{where}: {error}. Only rule-based findings are shown."]
    return []


def _more(lines: list[str], total: int) -> None:
    if total > _LISTED_LIMIT:
        lines.append(f"    ... and {total - _LISTED_LIMIT} more (see coverage in the JSON report)")
