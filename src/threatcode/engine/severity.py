"""Contextual severity phase.

The base severity of a finding comes from its rule. This phase is where the
engine records an effective severity and the reason for it when context changes
the picture: internet reachability, sensitive data classification, an
intentional-exposure tag. It sets ``Threat.effective_severity`` and
``Threat.severity_reason`` and never touches ``Threat.severity``.

Until a package implements those rules the phase leaves every finding as it is.
"""

from __future__ import annotations

from threatcode.ir.graph import InfraGraph
from threatcode.models.report import ThreatReport


def apply(report: ThreatReport, graph: InfraGraph) -> None:
    """Set effective severities on the findings of ``report``, in place."""
    return None
