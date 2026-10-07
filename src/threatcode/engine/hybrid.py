"""Hybrid threat engine: a phase orchestrator.

``HybridEngine.analyze`` runs these phases in order, each in its own module so
later work fills a module instead of editing this file:

1. rules: every rule against every node (this module)
2. context: secret and ingested scanner findings from the ``AnalysisContext``
3. boundaries: ``engine.boundaries.analyze(graph)``
4. severity: ``engine.severity.apply(report, graph)``
5. paths: ``engine.paths.find(graph, threats)``
6. LLM: ``engine.llm.phase.run_llm_phase(graph, threats, client, config)``

The signatures of the phase functions are contracts.
"""

from __future__ import annotations

import copy
import logging
import os
from typing import TYPE_CHECKING

from threatcode.engine import boundaries, paths, severity
from threatcode.engine.context import AnalysisContext
from threatcode.engine.llm.phase import run_llm_phase
from threatcode.engine.mitre import tactics_for_techniques
from threatcode.engine.rules.loader import Rule, load_all_rules, load_rules_from_file
from threatcode.engine.rules.matcher import matches_rule
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode
from threatcode.models.report import ThreatReport
from threatcode.models.threat import Severity, Threat, ThreatSource, hash_id

if TYPE_CHECKING:
    from pathlib import Path

    from threatcode.config import ThreatCodeConfig
    from threatcode.engine.llm.client import BaseLLMClient

logger = logging.getLogger(__name__)

STRICT_RULES_ENV = "THREATCODE_STRICT_RULES"
"""When set to ``1``, an exception in a built-in rule propagates instead of being recorded."""


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
        # Rule ids are unique across built-in and extra files (the loader
        # enforces it), so the extra ids identify every custom rule.
        self._custom_rule_ids: set[str] = set()
        for path in extra_rule_paths or []:
            self._custom_rule_ids.update(r.id for r in load_rules_from_file(path.resolve()))

    def analyze(
        self,
        graph: InfraGraph,
        input_file: str = "",
        context: AnalysisContext | None = None,
    ) -> ThreatReport:
        """Run full analysis pipeline."""
        from threatcode import __version__

        context = context or AnalysisContext(input_label=input_file)
        logger.info(
            "Analysis started: resources=%d, rules=%d, llm_enabled=%s",
            graph.node_count,
            len(self._rules),
            self._llm_client is not None,
        )

        report = ThreatReport(
            scanned_resources=graph.node_count,
            input_file=input_file,
            version=__version__,
        )

        # Phase 1: rule-based threats
        rule_threats = self._run_rules(graph, report)
        for t in rule_threats:
            report.add(t)

        # Phase 2: findings produced outside the rule engine
        context_threats = self._merge_context(report, context)

        # Phase 3: trust boundary crossing threats
        boundary_threats = boundaries.analyze(graph)
        for t in boundary_threats:
            report.add(t)

        # Phase 4: contextual severity
        severity.apply(report, graph)

        # Phase 5: attack paths
        report.attack_paths = paths.find(graph, report.threats)

        # Phase 6: LLM-augmented analysis
        llm_threats, llm_status = run_llm_phase(
            graph, list(report.threats), self._llm_client, self._config
        )
        for t in llm_threats:
            report.add(t)
        report.llm = llm_status

        logger.info(
            "Analysis complete: total_threats=%d (rule=%d, context=%d, boundary=%d, llm=%d)",
            len(report.threats),
            len(rule_threats),
            len(context_threats),
            len(boundary_threats),
            len(llm_threats),
        )

        return report

    def _run_rules(self, graph: InfraGraph, report: ThreatReport) -> list[Threat]:
        """Evaluate all rules against all nodes.

        A rule that raises on a node does not abort the analysis: the failure is
        recorded in ``report.rule_errors`` and logged once per rule. Built-in
        rules re-raise when ``THREATCODE_STRICT_RULES=1`` so tests catch them.
        """
        strict = os.environ.get(STRICT_RULES_ENV) == "1"
        logged: set[str] = set()
        threats: list[Threat] = []
        for node in graph.nodes.values():
            for rule in self._rules:
                try:
                    matched = matches_rule(rule, node)
                except Exception as e:
                    if strict and rule.id not in self._custom_rule_ids:
                        raise
                    report.rule_errors.append(
                        {
                            "rule_id": rule.id,
                            "node_id": node.id,
                            "error": f"{type(e).__name__}: {e}",
                        }
                    )
                    if rule.id not in logged:
                        logged.add(rule.id)
                        logger.warning(
                            "Rule %s failed on node %s (%s: %s) - recorded in rule_errors",
                            rule.id,
                            node.id,
                            type(e).__name__,
                            e,
                        )
                    continue
                if matched:
                    threats.append(_rule_to_threat(rule, node))
        return threats

    @staticmethod
    def _merge_context(report: ThreatReport, context: AnalysisContext) -> list[Threat]:
        """Add secret and scanner findings to the report, dropping repeated ids."""
        seen = {t.id for t in report.threats}
        merged: list[Threat] = []
        for threat in [*context.secret_findings, *context.external_findings]:
            if threat.id in seen:
                continue
            seen.add(threat.id)
            report.add(threat)
            merged.append(threat)
        return merged


def _rule_to_threat(rule: Rule, node: InfraNode) -> Threat:
    threat_id = hash_id(f"{rule.id}_{node.id}")
    mitre = rule.metadata.get("mitre", {})
    techniques = list(mitre.get("techniques", []))
    tactics = list(mitre.get("tactics", []))
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
        # Copied so mutating one threat's metadata never reaches the rule or
        # the other threats the same rule produced.
        metadata=copy.deepcopy(rule.metadata),
        mitre_techniques=techniques,
        mitre_tactics=tactics,
    )
