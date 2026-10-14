"""Raw JSON output formatter."""

from __future__ import annotations

import json
from typing import TYPE_CHECKING

from threatcode.models.report import ThreatReport

if TYPE_CHECKING:
    from threatcode.models.analysis import AnalysisResult


__all__ = ["format_json"]


def format_json(
    source: AnalysisResult | ThreatReport, indent: int = 2, *, include_graph: bool = False
) -> str:
    """Format a scan as JSON.

    The document is the report: schema version, timestamp unless the scan left it out, summary by
    effective severity, coverage, threats most severe first, attack paths and the LLM status.
    That is exactly what ``ScanResult.to_dict()`` and ``threatcode.scan()`` return, so the CLI and
    the Python API print the same report.
    When scanner results were ingested the document also lists them under ``ingest``, so a scan
    without ingestion is still exactly the report.
    With ``include_graph`` and an analysis the document also carries the graph the engine saw,
    as nodes and edges without resource properties, and the summary by base severity
    (``summary_base``).
    Threats are in a fixed order, so two runs over the same input write the same text.
    """
    from threatcode.models.analysis import AnalysisResult

    if isinstance(source, AnalysisResult) and include_graph:
        data = source.to_dict(include_graph=True)
    elif isinstance(source, AnalysisResult):
        data = source.report.to_dict()
        if source.ingest_sources:
            data["ingest"] = [dict(entry) for entry in source.ingest_sources]
    else:
        data = source.to_dict()
    data["threats"] = sorted(data["threats"], key=_threat_key)
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
