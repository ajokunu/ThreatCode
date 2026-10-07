"""Analysis result combining graph topology and threat report."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.attack_path import AttackPath
    from threatcode.models.report import ThreatReport


@dataclass
class AnalysisResult:
    """Result of analyze() - wraps the infrastructure graph and threat report.

    ``root`` is the directory the report's relative paths (threat locations, node source files)
    are relative to, when the scan knows it; formats that must name files from the repository
    root, such as SARIF, use it.
    ``ingest_sources`` has one mapping per ingested scanner result (tool, version, file, counts).
    Both are optional, so a result built by hand renders as before.
    """

    graph: InfraGraph
    report: ThreatReport
    root: Path | None = None
    ingest_sources: list[dict[str, Any]] = field(default_factory=list)

    @property
    def attack_paths(self) -> list[AttackPath]:
        return self.report.attack_paths

    def to_dict(self, *, include_graph: bool = True) -> dict[str, Any]:
        """The report plus the graph the engine saw, as ``--format json`` writes it.

        The graph is the export form: nodes and edges, with no resource properties, because the
        properties come from the input and can hold secrets.
        Ingested scanner results are listed under ``ingest`` when there are any.
        """
        result = self.report.to_dict()
        result["summary_base"] = _base_summary(self.report)
        if self.ingest_sources:
            result["ingest"] = [dict(source) for source in self.ingest_sources]
        if include_graph:
            result["graph"] = self.graph.to_export_dict()
        return result

    def to_svg(self) -> str:
        from threatcode.formatters.diagram import format_diagram

        return format_diagram(self.report, self.graph)


def _base_summary(report: ThreatReport) -> dict[str, int]:
    """Findings per base severity: the rule's own, before context changed it."""
    counts: dict[str, int] = {}
    for threat in report.threats:
        counts[threat.severity.value] = counts.get(threat.severity.value, 0) + 1
    return counts
