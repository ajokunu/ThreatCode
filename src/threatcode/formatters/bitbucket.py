"""Bitbucket Code Insights report and annotations.

The output is one JSON document with three parts:

- ``report``: the body for ``PUT .../reports/{reportId}``;
- ``annotations``: every annotation that fits Bitbucket's limit of 1000 per report, most severe
  first;
- ``annotation_batches``: the same annotations in lists of at most 100, which is the most the bulk
  ``POST .../reports/{reportId}/annotations`` endpoint accepts, so a pipeline can post each batch
  as it is.

An annotation sits on the file and line of the resource it is about, never on a resource address,
because Bitbucket shows it in the diff of that file.
The input file and line 1 stand in when a location is unknown.
Attack paths are annotations on the first resource of the path that has a file.

``report.result`` is ``FAILED`` when any finding or attack path is critical or high after context
(its effective severity) and ``PASSED`` otherwise.
That is a fixed reporting policy, not the scan gate: ``threatcode scan --fail-on`` decides the exit
code.
"""

from __future__ import annotations

import json
import os
from typing import TYPE_CHECKING, Any

from threatcode.formatters._utils import (
    collapse_whitespace,
    plural,
    repo_path,
    root_prefix,
    threat_source,
    truncate,
)
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Severity, Threat

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.attack_path import AttackPath

__all__ = ["BATCH_SIZE", "MAX_ANNOTATIONS", "format_bitbucket"]

# Bitbucket's documented limits
MAX_ANNOTATIONS = 1000
BATCH_SIZE = 100
SUMMARY_LIMIT = 450
DETAILS_LIMIT = 2000
REPORT_DETAILS_LIMIT = 2000
EXTERNAL_ID_LIMIT = 64

_BB_SEVERITIES: dict[Severity, str] = {
    Severity.CRITICAL: "CRITICAL",
    Severity.HIGH: "HIGH",
    Severity.MEDIUM: "MEDIUM",
    Severity.LOW: "LOW",
    Severity.INFO: "LOW",
}


def format_bitbucket(
    report: ThreatReport,
    graph: InfraGraph | None = None,
    *,
    source_root: str | os.PathLike[str] | None = None,
    indent: int = 2,
) -> str:
    """Format as Bitbucket Code Insights JSON (report, annotations and bulk batches)."""
    annotations = _annotations(report, graph, root_prefix(source_root))
    kept = annotations[:MAX_ANNOTATIONS]
    omitted = len(annotations) - len(kept)
    output = {
        "report": _build_report(report, len(kept), omitted),
        "annotations": kept,
        "annotation_batches": [
            kept[start : start + BATCH_SIZE] for start in range(0, len(kept), BATCH_SIZE)
        ],
    }
    return json.dumps(output, indent=indent, sort_keys=False)


def _build_report(report: ThreatReport, shown: int, omitted: int) -> dict[str, Any]:
    """The Code Insights report payload."""
    summary = report.summary
    failed = any(summary.get(name, 0) for name in ("critical", "high")) or any(
        path.severity >= Severity.HIGH for path in report.attack_paths
    )
    details = (
        f"Scanned {report.scanned_resources} resources, "
        f"found {plural(len(report.threats), 'threat')} "
        f"and {plural(len(report.attack_paths), 'attack path')}."
    )
    if omitted:
        details += (
            f" {shown} annotations are shown, the most severe first; {omitted} more were left out"
            f" to stay under Bitbucket's limit of {MAX_ANNOTATIONS} per report."
        )
    return {
        "title": "ThreatCode STRIDE Threat Model",
        "details": truncate(details, REPORT_DETAILS_LIMIT),
        "report_type": "SECURITY",
        "reporter": "ThreatCode",
        "result": "FAILED" if failed else "PASSED",
        "data": [
            {"title": "Total Threats", "type": "NUMBER", "value": len(report.threats)},
            {"title": "Critical", "type": "NUMBER", "value": summary.get("critical", 0)},
            {"title": "High", "type": "NUMBER", "value": summary.get("high", 0)},
            {"title": "Medium", "type": "NUMBER", "value": summary.get("medium", 0)},
            {"title": "Low", "type": "NUMBER", "value": summary.get("low", 0)},
            {"title": "Info", "type": "NUMBER", "value": summary.get("info", 0)},
            {"title": "Attack Paths", "type": "NUMBER", "value": len(report.attack_paths)},
            {"title": "Resources Scanned", "type": "NUMBER", "value": report.scanned_resources},
        ],
    }


def _annotations(
    report: ThreatReport, graph: InfraGraph | None, prefix: str
) -> list[dict[str, Any]]:
    """Every annotation, most severe first, then most certain; external ids are unique."""
    fallback = (report.input_paths or report.input_file.split(","))[0].strip() or "."
    ranked: list[tuple[tuple[int, int, float, str, str], dict[str, Any]]] = []
    for path in report.attack_paths:
        file, line = _path_location(path, graph, fallback)
        ranked.append(
            (
                (-path.severity.rank, 0, -path.score, path.entry, path.id),
                _path_annotation(path, repo_path(file, prefix), line),
            )
        )
    for threat in report.threats:
        file, line = _threat_location(threat, graph, fallback)
        ranked.append(
            (
                (
                    -threat_severity(threat).rank,
                    1,
                    -threat.confidence,
                    threat.resource_address,
                    threat.id,
                ),
                _threat_annotation(threat, repo_path(file, prefix), line),
            )
        )
    ranked.sort(key=lambda item: item[0])
    annotations = [annotation for _key, annotation in ranked]
    seen: dict[str, int] = {}
    for annotation in annotations:
        base = annotation["external_id"]
        count = seen.get(base, 0) + 1
        seen[base] = count
        if count > 1:
            annotation["external_id"] = f"{base[: EXTERNAL_ID_LIMIT - 4]}-{count}"
    return annotations


def _threat_location(threat: Threat, graph: InfraGraph | None, fallback: str) -> tuple[str, int]:
    file, line, _end = threat_source(threat, graph)
    if not file:
        return fallback, 1
    return file, max(line or 1, 1)


def _path_location(path: AttackPath, graph: InfraGraph | None, fallback: str) -> tuple[str, int]:
    if graph is not None:
        for hop in path.hops:
            node = graph.get_node(hop.node_id)
            if node is not None and node.source_file:
                return node.source_file, max(node.start_line or 1, 1)
    return fallback, 1


def _threat_annotation(threat: Threat, file: str, line: int) -> dict[str, Any]:
    details = collapse_whitespace(threat.description)
    mitigation = collapse_whitespace(threat.mitigation)
    if mitigation:
        details = f"{details} Mitigation: {mitigation}".strip()
    return {
        "external_id": truncate(threat.id, EXTERNAL_ID_LIMIT),
        "annotation_type": "VULNERABILITY",
        "summary": truncate(collapse_whitespace(threat.title), SUMMARY_LIMIT),
        "details": truncate(details, DETAILS_LIMIT),
        "severity": _BB_SEVERITIES.get(threat_severity(threat), "MEDIUM"),
        "path": file,
        "line": line,
    }


def _path_annotation(path: AttackPath, file: str, line: int) -> dict[str, Any]:
    route = " -> ".join(hop.node_id for hop in path.hops)
    details = f"Attack path of {max(len(path.hops) - 1, 0)} hops: {route}."
    if path.rationale:
        details += f" {path.rationale}"
    return {
        "external_id": truncate(f"path-{path.id}", EXTERNAL_ID_LIMIT),
        "annotation_type": "VULNERABILITY",
        "summary": truncate(
            f"Attack path from {collapse_whitespace(path.entry)} to "
            f"{collapse_whitespace(path.target)}",
            SUMMARY_LIMIT,
        ),
        "details": truncate(collapse_whitespace(details), DETAILS_LIMIT),
        "severity": _BB_SEVERITIES.get(path.severity, "MEDIUM"),
        "path": file,
        "line": line,
    }
