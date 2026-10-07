"""Trust boundary crossing threats."""

from __future__ import annotations

from threatcode.engine.mitre import BOUNDARY_TACTICS, BOUNDARY_TECHNIQUES
from threatcode.engine.stride import StrideCategory
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id


def analyze(graph: InfraGraph) -> list[Threat]:
    """Generate threats for trust boundary crossings."""
    threats: list[Threat] = []
    for edge in graph.get_boundary_crossing_edges():
        src = graph.get_node(edge.source)
        tgt = graph.get_node(edge.target)
        if not src or not tgt:
            continue

        src_zone = edge.metadata.get("source_zone", "unknown")
        tgt_zone = edge.metadata.get("target_zone", "unknown")
        threat_id = hash_id(f"BOUNDARY_{edge.source}_{edge.target}")

        threats.append(
            Threat(
                id=threat_id,
                title=f"Trust boundary crossing: {src_zone} -> {tgt_zone}",
                description=(
                    f"Data flows from {src.id} ({src_zone} zone) to "
                    f"{tgt.id} ({tgt_zone} zone), crossing a trust boundary. "
                    f"This flow should be authenticated, encrypted, and validated."
                ),
                stride_category=StrideCategory.TAMPERING.value,
                severity=_boundary_severity(src_zone, tgt_zone),
                source=ThreatSource.BOUNDARY,
                resource_type=src.resource_type,
                resource_address=src.id,
                mitigation=(
                    "Ensure all data crossing trust boundaries is encrypted in transit "
                    "(TLS/mTLS), authenticated, and validated at the receiving end."
                ),
                mitre_techniques=list(BOUNDARY_TECHNIQUES),
                mitre_tactics=list(BOUNDARY_TACTICS),
            )
        )
    return threats


def _boundary_severity(src_zone: str, tgt_zone: str) -> Severity:
    """Higher severity for more sensitive boundary crossings."""
    high_risk = {
        ("internet", "private"),
        ("internet", "data"),
        ("dmz", "data"),
        ("internet", "management"),
    }
    pair = (src_zone, tgt_zone)
    reverse = (tgt_zone, src_zone)
    if pair in high_risk or reverse in high_risk:
        return Severity.HIGH
    return Severity.MEDIUM
