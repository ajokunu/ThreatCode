"""Plain-text summary for a terminal.

The report shows, in order: the severity counts, one line per finding (most severe first), the
attack paths and a coverage summary that always says what was not analysed.
Colors are used only when ``RenderOptions.color`` is set and ``NO_COLOR`` is not, so redirected
output and CI logs stay plain.
"""

from __future__ import annotations

import os
from typing import TYPE_CHECKING

import click

from threatcode.formatters import RenderOptions
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult

__all__ = ["format_text", "plural"]

_SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
_STYLES: dict[str, dict[str, object]] = {
    "critical": {"fg": "red", "bold": True},
    "high": {"fg": "red"},
    "medium": {"fg": "yellow"},
    "low": {"fg": "cyan"},
    "info": {"dim": True},
}
# Errors and gaps beyond this many are summarised, not listed; the JSON report has them all.
_LISTED_LIMIT = 10


def plural(count: int, noun: str, plural_form: str | None = None) -> str:
    """``1 finding`` or ``2 findings``."""
    word = noun if count == 1 else (plural_form or f"{noun}s")
    return f"{count} {word}"


def _sort_key(threat: Threat) -> tuple[int, str, str, str]:
    return (-threat_severity(threat).rank, threat.resource_address, threat.rule_id, threat.id)


def _location(threat: Threat) -> str:
    if not threat.location_file:
        return ""
    line = f":{threat.location_start_line}" if threat.location_start_line else ""
    return f"{threat.location_file}{line}"


def format_text(analysis: AnalysisResult, options: RenderOptions | None = None) -> str:
    """Render the report of ``analysis`` as plain text."""
    report = analysis.report
    use_color = bool((options or RenderOptions()).color) and not os.environ.get("NO_COLOR")

    def paint(text: str, severity: str) -> str:
        return click.style(text, **_STYLES[severity]) if use_color else text  # type: ignore[arg-type]

    lines: list[str] = []
    target = f" of {report.input_file}" if report.input_file else ""
    lines.append(
        f"ThreatCode scan{target}: {plural(report.scanned_resources, 'resource')}, "
        f"{plural(len(report.threats), 'finding')}"
    )
    lines.append("")
    counts = report.summary
    lines.append(
        "  ".join(
            paint(f"{sev} {counts.get(sev, 0)}", sev) if counts.get(sev) else f"{sev} 0"
            for sev in _SEVERITY_ORDER
        )
    )

    if report.threats:
        lines.append("")
        for threat in sorted(report.threats, key=_sort_key):
            severity = threat_severity(threat).value
            label = paint(severity.upper().ljust(8), severity)
            who = threat.rule_id or threat.source.value
            where = _location(threat)
            suffix = f"  ({where})" if where else ""
            address = threat.resource_address or "-"
            lines.append(f"{label}  {address}  {who}  {threat.title}{suffix}")

    if report.attack_paths:
        lines.append("")
        lines.append(f"Attack paths ({len(report.attack_paths)})")
        for path in report.attack_paths:
            severity = path.severity.value
            hops = max(len(path.hops) - 1, 0)
            lines.append(
                f"{paint(severity.upper().ljust(8), severity)}  {path.entry} -> {path.target}  "
                f"({plural(hops, 'hop')}, id {path.id})"
            )

    lines.append("")
    lines.extend(_coverage_lines(report))
    return "\n".join(lines) + "\n"


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


def _more(lines: list[str], total: int) -> None:
    if total > _LISTED_LIMIT:
        lines.append(f"    ... and {total - _LISTED_LIMIT} more (see coverage in the JSON report)")
