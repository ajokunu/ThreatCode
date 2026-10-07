"""Attack path phase.

``find`` computes attack paths over directed reachability edges from an entry
point to the targets that matter and returns them in ranked order. The
orchestrator stores the result in ``report.attack_paths``.

Until a package implements the search the phase returns no paths.
"""

from __future__ import annotations

from threatcode.ir.graph import InfraGraph
from threatcode.models.attack_path import AttackPath
from threatcode.models.threat import Threat


def find(graph: InfraGraph, threats: list[Threat]) -> list[AttackPath]:
    """Return the attack paths of ``graph`` given the findings gathered so far."""
    return []
