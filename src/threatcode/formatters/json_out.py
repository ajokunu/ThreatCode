"""Raw JSON output formatter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from threatcode.models.report import ThreatReport

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult


__all__ = ["format_json"]


def format_json(
    source: AnalysisResult | ThreatReport, indent: int = 2, *, include_graph: bool = True
) -> str:
    """Format a scan as JSON.

    Given an analysis the document is the report (schema version, timestamp unless the scan left
    it out, summary by effective and by base severity, coverage, threats, attack paths, the LLM
    status) plus the ingested scanner sources and the graph the engine saw, as nodes and edges
    without properties.
    Given a report alone it is the report.
    The order is fixed, so two runs over the same input write the same text:
    threats most severe first, attack paths most severe first.
    """
    from threatcode.models.analysis import AnalysisResult

    if isinstance(source, AnalysisResult):
        data = source.to_dict(include_graph=include_graph)
    else:
        data = source.to_dict()
    data["threats"] = sorted(data["threats"], key=_threat_key)
    data["attack_paths"] = sorted(data["attack_paths"], key=_path_key)
    return json.dumps(data, indent=indent, sort_keys=False)


_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}


def _threat_key(threat: dict[str, object]) -> tuple[int, str, str, str]:
    severity = str(threat.get("effective_severity") or threat.get("severity"))
    return (
        -_RANK.get(severity, 0),
        str(threat.get("resource_address", "")),
        str(threat.get("rule_id", "")),
        str(threat.get("id", "")),
    )


def _path_key(path: dict[str, object]) -> tuple[int, float, str]:
    score = path.get("score", 0)
    number = (
        float(score) if isinstance(score, (int, float)) and not isinstance(score, bool) else 0.0
    )
    return (-_RANK.get(str(path.get("severity")), 0), -number, str(path.get("id", "")))
