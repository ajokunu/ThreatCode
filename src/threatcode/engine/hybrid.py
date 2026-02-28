"""Hybrid threat engine: rules -> boundaries -> LLM -> merge."""

from __future__ import annotations

import hashlib
from typing import TYPE_CHECKING

from threatcode.engine.mitre import BOUNDARY_TACTICS, BOUNDARY_TECHNIQUES, tactics_for_techniques
from threatcode.engine.rules.loader import Rule, load_all_rules
from threatcode.engine.rules.matcher import matches_rule
from threatcode.engine.stride import StrideCategory
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource

if TYPE_CHECKING:
    from pathlib import Path

    from threatcode.config import ThreatCodeConfig
    from threatcode.engine.llm.client import BaseLLMClient


class HybridEngine:
    """Orchestrates rule-based and LLM-augmented threat analysis."""

    def __init__(
        self,
        config: ThreatCodeConfig | None = None,
        extra_rule_paths: list[Path] | None = None,
        llm_client: BaseLLMClient | None = None,
    ) -> None:
        self._rules = load_all_rules(extra_rule_paths)
        self._llm_client = llm_client
        self._config = config

    def analyze(self, graph: InfraGraph, input_file: str = "") -> ThreatReport:
        """Run full analysis pipeline."""
        from threatcode import __version__

        report = ThreatReport(
            scanned_resources=graph.node_count,
            input_file=input_file,
            version=__version__,
        )

        # Phase 1: Rule-based threats
        rule_threats = self._run_rules(graph)
        for t in rule_threats:
            report.add(t)

        # Phase 2: Trust boundary crossing threats
        boundary_threats = self._run_boundary_analysis(graph)
        for t in boundary_threats:
            report.add(t)

        # Phase 3: LLM-augmented analysis (if client available)
        if self._llm_client is not None:
            llm_threats = self._run_llm_analysis(graph, rule_threats)
            for t in llm_threats:
                report.add(t)

        return report

    def _run_rules(self, graph: InfraGraph) -> list[Threat]:
        """Evaluate all rules against all nodes."""
        threats: list[Threat] = []
        for node in graph.nodes.values():
            for rule in self._rules:
                if matches_rule(rule, node):
                    threat = _rule_to_threat(rule, node)
                    threats.append(threat)
        return threats

    def _run_boundary_analysis(self, graph: InfraGraph) -> list[Threat]:
        """Generate threats for trust boundary crossings."""
        threats: list[Threat] = []
        for edge in graph.get_boundary_crossing_edges():
            src = graph.get_node(edge.source)
            tgt = graph.get_node(edge.target)
            if not src or not tgt:
                continue

            src_zone = edge.metadata.get("source_zone", "unknown")
            tgt_zone = edge.metadata.get("target_zone", "unknown")
            threat_id = _hash_id(f"BOUNDARY_{edge.source}_{edge.target}")

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

    def _run_llm_analysis(self, graph: InfraGraph, existing_threats: list[Threat]) -> list[Threat]:
        """Run LLM-augmented threat analysis."""
        if self._llm_client is None:
            return []

        from threatcode.engine.llm.parser import parse_llm_threats
        from threatcode.engine.llm.prompts import build_analysis_prompt
        from threatcode.engine.llm.redactor import Redactor

        redactor = Redactor()
        graph_data = graph.to_dict()
        redacted_data = redactor.redact(graph_data)
        existing_ids = {t.rule_id for t in existing_threats if t.rule_id}

        prompt = build_analysis_prompt(redacted_data, existing_ids)
        response = self._llm_client.analyze(prompt)

        raw_threats = parse_llm_threats(response)
        threats: list[Threat] = []
        for raw in raw_threats:
            # Unredact resource addresses
            address = redactor.unredact_string(raw.get("resource_address", ""))
            techniques = raw.get("mitre_techniques", [])
            tactics = raw.get("mitre_tactics", [])
            if techniques and not tactics:
                tactics = tactics_for_techniques(techniques)
            threats.append(
                Threat(
                    id=_hash_id(f"LLM_{address}_{raw.get('title', '')}"),
                    title=raw.get("title", "LLM-identified threat"),
                    description=raw.get("description", ""),
                    stride_category=raw.get("stride_category", "tampering"),
                    severity=Severity(raw.get("severity", "medium")),
                    source=ThreatSource.LLM,
                    resource_type=raw.get("resource_type", ""),
                    resource_address=address,
                    mitigation=raw.get("mitigation", ""),
                    confidence=raw.get("confidence", 0.7),
                    mitre_techniques=techniques,
                    mitre_tactics=tactics,
                )
            )
        return threats


def _rule_to_threat(rule: Rule, node: InfraNode) -> Threat:
    threat_id = _hash_id(f"{rule.id}_{node.id}")
    mitre = rule.metadata.get("mitre", {})
    techniques = mitre.get("techniques", [])
    tactics = mitre.get("tactics", [])
    if techniques and not tactics:
        tactics = tactics_for_techniques(techniques)
    return Threat(
        id=threat_id,
        title=rule.title,
        description=rule.description,
        stride_category=rule.stride_category,
        severity=Severity(rule.severity),
        source=ThreatSource.RULE,
        resource_type=node.resource_type,
        resource_address=node.id,
        mitigation=rule.mitigation,
        rule_id=rule.id,
        metadata=rule.metadata,
        mitre_techniques=techniques,
        mitre_tactics=tactics,
    )


def _hash_id(seed: str) -> str:
    return hashlib.sha256(seed.encode()).hexdigest()[:12]


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
