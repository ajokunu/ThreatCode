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

Paths are relative to the repository root (the git top level of the scan root, or ``repo_root``),
which is what Bitbucket resolves them against, whatever directory the scan was started from.

``report.result`` follows the scan gate: ``FAILED`` when a finding or attack path at or above
``fail_on`` (its effective severity; model findings are advisory and never count) remains, and
``PASSED`` otherwise; ``fail_on`` ``none`` always passes.
Without a ``fail_on`` the gate is the default one, ``high``.
The exit code of ``threatcode scan`` and this result therefore never disagree.

An annotation says what is true of its resource (the title, the address, why the severity is what
it is and the mitigation); the explanation that is the same for every instance of a rule is in the
JSON and Markdown reports, not repeated on every line of the diff.
"""

from __future__ import annotations

import json
import os
from collections.abc import Iterable
from typing import TYPE_CHECKING, Any

from threatcode.formatters import RepoPaths
from threatcode.formatters._utils import (
    collapse_whitespace,
    plural,
    threat_source,
    truncate,
)
from threatcode.formatters.sarif import first_sentence
from threatcode.models.report import ThreatReport, threat_severity
from threatcode.models.threat import Severity, Threat, ThreatSource

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.attack_path import AttackPath

__all__ = ["BATCH_SIZE", "MAX_ANNOTATIONS", "format_bitbucket"]

# Bitbucket's documented limits
MAX_ANNOTATIONS = 1000
BATCH_SIZE = 100
SUMMARY_LIMIT = 450
DETAILS_LIMIT = 2000
# What an annotation says beyond its title: the reason for the severity and the mitigation.
MITIGATION_LIMIT = 300
DETAIL_LIMIT = 240
DEFAULT_FAIL_ON = "high"
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
    repo_root: str | os.PathLike[str] | None = None,
    fail_on: str | None = None,
    other_drives: Iterable[str] = (),
    indent: int = 2,
) -> str:
    """Format as Bitbucket Code Insights JSON (report, annotations and bulk batches).

    ``source_root`` is the directory the report's relative paths are relative to (the current
    directory when None) and ``repo_root`` the repository root they are written relative to
    (default: the git top level above ``source_root``).
    ``fail_on`` is the scan gate (a severity name or ``none``) that ``report.result`` follows.
    ``other_drives`` (``AnalysisResult.other_drives``) names the files on other Windows drives,
    which are outside the repository too.
    """
    paths = RepoPaths.resolve(source_root, repo_root, other_drives)
    annotations = _annotations(report, graph, paths)
    kept = annotations[:MAX_ANNOTATIONS]
    omitted = len(annotations) - len(kept)
    output = {
        "report": _build_report(report, len(kept), omitted, fail_on, len(paths.outside)),
        "annotations": kept,
        "annotation_batches": [
            kept[start : start + BATCH_SIZE] for start in range(0, len(kept), BATCH_SIZE)
        ],
    }
    return json.dumps(output, indent=indent, sort_keys=False)


def _gate_tripped(report: ThreatReport, fail_on: str | None) -> bool:
    """Whether a finding or attack path at or above the gate remains: what makes exit code 1."""
    gate = fail_on or DEFAULT_FAIL_ON
    if gate == "none":
        return False
    try:
        threshold = Severity(gate)
    except ValueError:
        threshold = Severity(DEFAULT_FAIL_ON)
    return any(
        threat_severity(threat) >= threshold
        for threat in report.threats
        if threat.source is not ThreatSource.LLM
    ) or any(path.severity >= threshold for path in report.attack_paths)


def _build_report(
    report: ThreatReport, shown: int, omitted: int, fail_on: str | None, outside: int
) -> dict[str, Any]:
    """The Code Insights report payload."""
    summary = report.summary
    failed = _gate_tripped(report, fail_on)
    details = (
        f"Scanned {report.scanned_resources} resources, "
        f"found {plural(len(report.threats), 'threat')} "
        f"and {plural(len(report.attack_paths), 'attack path')}."
    )
    if outside:
        details += (
            f" {plural(outside, 'file')} outside the repository root cannot be placed in a diff."
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
    report: ThreatReport, graph: InfraGraph | None, paths: RepoPaths
) -> list[dict[str, Any]]:
    """Every annotation, most severe first, then most certain; external ids are unique."""
    fallback = (report.input_paths or report.input_file.split(","))[0].strip() or "."
    ranked: list[tuple[tuple[int, int, float, str, str], dict[str, Any]]] = []
    for path in report.attack_paths:
        file, line = _path_location(path, graph, fallback)
        ranked.append(
            (
                (-path.severity.rank, 0, -path.score, path.entry, path.id),
                _path_annotation(path, paths.locate(file), line),
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
                _threat_annotation(threat, paths.locate(file), line),
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
    """An annotation: the title, then what is true of this instance, then the fix.

    A rule's description is the same on every instance, so it is left to the reports; a crossing,
    a scanner's finding, a secret and a model's suggestion are about this instance, and their
    first sentence says how.
    """
    parts = []
    if threat.resource_address:
        parts.append(f"Resource: {collapse_whitespace(threat.resource_address)}.")
    if threat.source is not ThreatSource.RULE:
        detail = first_sentence(threat.description, DETAIL_LIMIT)
        if detail:
            parts.append(detail if detail.endswith((".", "!", "?")) else f"{detail}.")
    reason = collapse_whitespace(threat.severity_reason)
    if reason:
        parts.append(f"Severity: {reason}.")
    mitigation = collapse_whitespace(threat.mitigation)
    if mitigation:
        parts.append(f"Mitigation: {truncate(mitigation, MITIGATION_LIMIT)}")
    return {
        "external_id": truncate(threat.id, EXTERNAL_ID_LIMIT),
        "annotation_type": "VULNERABILITY",
        "summary": truncate(collapse_whitespace(threat.title), SUMMARY_LIMIT),
        "details": truncate(" ".join(parts), DETAILS_LIMIT),
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
