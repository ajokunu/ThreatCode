"""Inputs to an analysis that do not come from the graph itself."""

from __future__ import annotations

from dataclasses import dataclass, field

from threatcode.models.threat import Threat


@dataclass
class AnalysisContext:
    """Findings produced outside the rule engine, handed to ``HybridEngine.analyze``.

    ``secret_findings`` come from the secret detectors and ``external_findings``
    from ingested scanner results. The engine merges both into the report after
    the rule phase and drops any whose id is already present.
    """

    input_label: str = ""
    secret_findings: list[Threat] = field(default_factory=list)
    external_findings: list[Threat] = field(default_factory=list)
