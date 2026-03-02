"""Analysis result combining graph topology and threat report."""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph
    from threatcode.models.report import ThreatReport


@dataclass
class AnalysisResult:
    """Result of analyze() — wraps the infrastructure graph and threat report."""

    graph: InfraGraph
    report: ThreatReport

    def to_dict(self) -> dict[str, Any]:
        result = self.report.to_dict()
        result["graph"] = self.graph.to_dict()
        return result

    def to_svg(self) -> str:
        from threatcode.formatters.diagram import format_diagram

        return format_diagram(self.report, self.graph)
