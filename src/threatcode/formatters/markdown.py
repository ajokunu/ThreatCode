"""Markdown output formatter for PR comments."""

from __future__ import annotations

from threatcode.models.report import ThreatReport
from threatcode.models.threat import Threat


def format_markdown(report: ThreatReport) -> str:
    """Format threat report as Markdown suitable for PR comments."""
    lines: list[str] = []

    lines.append("# ThreatCode Threat Model Report")
    lines.append("")
    lines.append(f"**Scanned resources:** {report.scanned_resources}")
    lines.append(f"**Total threats:** {len(report.threats)}")
    lines.append(f"**Timestamp:** {report.timestamp}")
    lines.append("")

    # Summary table
    if report.summary:
        lines.append("## Summary")
        lines.append("")
        lines.append("| Severity | Count |")
        lines.append("|----------|-------|")
        for sev in ["critical", "high", "medium", "low", "info"]:
            count = report.summary.get(sev, 0)
            if count > 0:
                icon = _severity_icon(sev)
                lines.append(f"| {icon} {sev.capitalize()} | {count} |")
        lines.append("")

    # Group threats by STRIDE category
    by_stride: dict[str, list[Threat]] = {}
    for t in report.threats:
        by_stride.setdefault(t.stride_category, []).append(t)

    for category, threats in sorted(by_stride.items()):
        lines.append(f"## {category.replace('_', ' ').title()}")
        lines.append("")

        for t in sorted(threats, key=lambda x: -x.severity.rank):
            icon = _severity_icon(t.severity.value)
            lines.append(f"### {icon} {t.title}")
            lines.append("")
            lines.append(
                f"**Severity:** {t.severity.value.capitalize()} | "
                f"**Resource:** `{t.resource_address}` | "
                f"**Source:** {t.source.value}"
            )
            if t.mitre_techniques:
                technique_links = ", ".join(t.mitre_techniques)
                lines.append(f"**MITRE ATT&CK:** {technique_links}")
            lines.append("")
            lines.append(t.description.strip())
            lines.append("")
            if t.mitigation:
                lines.append(f"> **Mitigation:** {t.mitigation.strip()}")
                lines.append("")

    if not report.threats:
        lines.append("No threats detected.")
        lines.append("")

    return "\n".join(lines)


def _severity_icon(severity: str) -> str:
    return {
        "critical": ":red_circle:",
        "high": ":orange_circle:",
        "medium": ":yellow_circle:",
        "low": ":blue_circle:",
        "info": ":white_circle:",
    }.get(severity, "")
