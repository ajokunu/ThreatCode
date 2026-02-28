"""Bitbucket Code Insights report + annotations formatter."""

from __future__ import annotations

import json
from typing import Any

from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity


def format_bitbucket(report: ThreatReport, indent: int = 2) -> str:
    """Format as Bitbucket Code Insights JSON (report + annotations)."""
    output = {
        "report": _build_report(report),
        "annotations": _build_annotations(report),
    }
    return json.dumps(output, indent=indent, sort_keys=False)


def _build_report(report: ThreatReport) -> dict[str, Any]:
    """Build Code Insights report payload."""
    result = (
        "FAILED"
        if any(t.severity in (Severity.CRITICAL, Severity.HIGH) for t in report.threats)
        else "PASSED"
    )

    return {
        "title": "ThreatCode STRIDE Threat Model",
        "details": (
            f"Scanned {report.scanned_resources} resources, "
            f"found {len(report.threats)} threats."
        ),
        "report_type": "SECURITY",
        "reporter": "ThreatCode",
        "result": result,
        "data": [
            {"title": "Total Threats", "type": "NUMBER", "value": len(report.threats)},
            {"title": "Critical", "type": "NUMBER", "value": report.summary.get("critical", 0)},
            {"title": "High", "type": "NUMBER", "value": report.summary.get("high", 0)},
            {"title": "Medium", "type": "NUMBER", "value": report.summary.get("medium", 0)},
            {"title": "Resources Scanned", "type": "NUMBER", "value": report.scanned_resources},
        ],
    }


def _build_annotations(report: ThreatReport) -> list[dict[str, Any]]:
    """Build Code Insights annotations."""
    annotations: list[dict[str, Any]] = []
    for threat in report.threats:
        annotations.append(
            {
                "external_id": threat.id,
                "annotation_type": "VULNERABILITY",
                "summary": threat.title,
                "details": threat.description.strip(),
                "severity": _to_bb_severity(threat.severity),
                "path": threat.resource_address,
                "line": 1,
            }
        )
    return annotations


def _to_bb_severity(severity: Severity) -> str:
    return {
        Severity.CRITICAL: "CRITICAL",
        Severity.HIGH: "HIGH",
        Severity.MEDIUM: "MEDIUM",
        Severity.LOW: "LOW",
        Severity.INFO: "LOW",
    }[severity]
