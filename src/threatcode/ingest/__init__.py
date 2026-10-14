"""Scanner result ingestion: Trivy, Grype, OSV-Scanner and SARIF findings joined to graph nodes.

ThreatCode does not scan images or lockfiles itself.
It reads the results of the scanners a team already runs and attaches each finding to the node it
belongs to, so a critical CVE on an exposed workload joins the attack path and its severity.

The scan pipeline calls ``load_and_attach(paths, graph, root)`` once per scan with the files named
by ``--ingest`` and merges ``IngestResult.threats`` into the analysis context and
``IngestResult.diagnostics`` into the graph diagnostics.
``IngestResult.sources`` holds one mapping per tool run (a SARIF file with several runs yields
several) for the report: ``tool``, ``version``, ``format``, ``file`` and the counts ``findings``,
``attached``, ``unattached`` and ``duplicates``, plus ``skipped`` when entries were set aside.

Formats are detected by content, not by file name:

* Trivy JSON: ``SchemaVersion`` with ``Results`` (``threatcode.ingest.trivy``);
* Grype JSON: ``matches`` with ``descriptor`` or ``source`` (``threatcode.ingest.grype``);
* OSV-Scanner JSON: ``results`` of ``source`` and ``packages`` (``threatcode.ingest.osv``);
* SARIF 2.1.0 from any tool (``threatcode.ingest.sarif``).

Findings are normalized to ``ExternalFinding`` (``threatcode.ingest.model``), placed by the join
keys documented in ``threatcode.ingest.attach`` and turned into threats by
``threatcode.ingest.threats``.
A finding no key places is kept with an empty resource address and counted in an
``ingest.unattached`` diagnostic.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

from threatcode.diagnostics import Diagnostic
from threatcode.exceptions import UsageError
from threatcode.ingest import grype, osv, sarif, trivy
from threatcode.ingest.attach import NodeIndex
from threatcode.ingest.model import ExternalFinding, ScannerReport
from threatcode.ingest.reconcile import merge_across_tools, reconcile_native
from threatcode.ingest.threats import to_threats
from threatcode.models.threat import Threat

if TYPE_CHECKING:
    from threatcode.diagnostics import Level
    from threatcode.ir.graph import InfraGraph

__all__ = ["IngestResult", "load_and_attach", "reconcile_native"]

SUPPORTED_FORMATS = "Trivy JSON, Grype JSON, OSV-Scanner JSON and SARIF 2.1.0"
MAX_INGEST_BYTES = 256 * 1024 * 1024

# Checked in this order; the first reader that claims the document reads it.
_READERS: tuple[
    tuple[str, Callable[[object], bool], Callable[[dict[str, Any]], list[ScannerReport]]], ...
] = (
    ("sarif", sarif.detect, sarif.load),
    ("trivy", trivy.detect, trivy.load),
    ("grype", grype.detect, grype.load),
    ("osv-scanner", osv.detect, osv.load),
)


@dataclass
class IngestResult:
    """Findings, diagnostics and per-file source records of one ingestion."""

    threats: list[Threat] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)


def load_and_attach(paths: Sequence[Path], graph: InfraGraph, root: Path) -> IngestResult:
    """Read the scanner result files in ``paths`` and attach their findings to ``graph``.

    ``root`` is the scan root; locations in the returned threats are relative to it.

    Raises:
        UsageError: A file is unreadable or not a recognized scanner result.
    """
    result = IngestResult()
    if not paths:
        return result
    index = NodeIndex(graph, root)
    seen: set[Path] = set()
    collected: list[tuple[dict[str, Any], list[Threat]]] = []
    for path in paths:
        resolved = path.resolve()
        if resolved in seen:
            continue
        seen.add(resolved)
        label = _label(path, root)
        fmt, reports = _read(path)
        for report in reports:
            source, threats, diagnostics = _attach_report(report, fmt, label, index)
            result.diagnostics.extend(diagnostics)
            collected.append((source, threats))

    ordered = [t for _, threats in collected for t in threats]
    kept, folded = merge_across_tools(ordered)
    folded_ids = {id(t) for t in folded}
    for source, threats in collected:
        source["duplicates"] = sum(1 for t in threats if id(t) in folded_ids)
        result.sources.append(source)
    for threat in folded:
        result.diagnostics.append(
            Diagnostic(
                "info",
                "ingest.duplicate",
                f"{threat.rule_id} on {threat.resource_address} is also reported by another "
                "ingested tool, so only one is kept",
                file=threat.location_file,
                line=threat.location_start_line,
            )
        )
    result.threats = kept
    return result


def _label(path: Path, root: Path) -> str:
    """The ingested file as the report names it: root-relative when inside the root."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.name


def _read(path: Path) -> tuple[str, list[ScannerReport]]:
    data = _load_json(path)
    for name, detect, load in _READERS:
        if detect(data) and isinstance(data, dict):
            return name, load(data)
    raise UsageError(
        f"cannot ingest {path}: not a recognized scanner result; supported formats are "
        f"{SUPPORTED_FORMATS}"
    )


def _load_json(path: Path) -> object:
    try:
        if path.is_dir():
            raise UsageError(f"cannot ingest {path}: it is a directory, name a scanner result file")
        size = path.stat().st_size
        if size > MAX_INGEST_BYTES:
            raise UsageError(
                f"cannot ingest {path}: the file is {size // (1024 * 1024)} MB, over the "
                f"{MAX_INGEST_BYTES // (1024 * 1024)} MB limit"
            )
        raw = path.read_bytes()
    except OSError as exc:
        reason = exc.strerror or type(exc).__name__
        raise UsageError(f"cannot ingest {path}: {reason}") from exc
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        if isinstance(exc, json.JSONDecodeError):
            detail = f"{exc.msg} at line {exc.lineno}"
        elif isinstance(exc, UnicodeDecodeError):
            detail = "the file is not UTF-8 text"
        else:
            detail = type(exc).__name__
        raise UsageError(
            f"cannot ingest {path}: not valid JSON ({detail}); supported formats are "
            f"{SUPPORTED_FORMATS}"
        ) from exc


def _attach_report(
    report: ScannerReport, fmt: str, label: str, index: NodeIndex
) -> tuple[dict[str, Any], list[Threat], list[Diagnostic]]:
    threats: list[Threat] = []
    attached = 0
    seen: set[tuple[Any, ...]] = set()
    repeated = 0
    findings: list[ExternalFinding] = []
    for finding in report.findings:
        if finding.identity in seen:
            repeated += 1
            continue
        seen.add(finding.identity)
        findings.append(finding)
    for finding in findings:
        placement = index.place(finding)
        if placement.nodes:
            attached += 1
        threats.extend(to_threats(finding, placement, label))
    unattached = len(findings) - attached
    source: dict[str, Any] = {
        "tool": report.tool,
        "version": report.version,
        "format": fmt,
        "file": label,
        "findings": len(findings),
        "attached": attached,
        "unattached": unattached,
    }
    if repeated:
        report.skip("repeated", repeated)
    if report.skipped:
        source["skipped"] = dict(sorted(report.skipped.items()))
    diagnostics: list[Diagnostic] = []
    if unattached:
        # Nothing joined at all usually means the wrong report for this scan: a gap to look at.
        level: Level = "warning" if attached == 0 else "info"
        diagnostics.append(
            Diagnostic(
                level,
                "ingest.unattached",
                f"{unattached} of {len(findings)} {report.tool} finding(s) in {label} matched no "
                "node in the graph; they are kept in the report with no resource address",
                file=label,
            )
        )
    return source, threats, diagnostics
