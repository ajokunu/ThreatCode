"""End-to-end scan tests for Dockerfiles."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "docker"


def _report(name: str):
    path = FIXTURES_DIR / name
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    return graph, HybridEngine().analyze(graph, input_file=str(path))


class TestInsecureDockerfile:
    def test_headline_findings_fire(self) -> None:
        _graph, report = _report("insecure.Dockerfile")
        fired = {t.rule_id for t in report.threats if t.source == ThreatSource.RULE}
        assert {
            "DOCKER_NO_USER",
            "DOCKER_LATEST_TAG",
            "DOCKER_EXPOSED_SSH",
            "DOCKER_NO_HEALTHCHECK",
            "DOCKER_RUN_CURL_PIPE",
            "DOCKER_RUN_SUDO",
        } <= fired

    def test_instruction_rules_report_instruction_nodes(self) -> None:
        graph, report = _report("insecure.Dockerfile")
        by_rule = defaultdict(set)
        for threat in report.threats:
            if threat.source == ThreatSource.RULE:
                by_rule[threat.rule_id].add(graph.nodes[threat.resource_address].resource_type)
        assert by_rule["DOCKER_RUN_SUDO"] == {"dockerfile_run"}
        assert by_rule["DOCKER_NO_USER"] == {"dockerfile_image"}

    def test_every_finding_sits_on_a_type_the_rule_declares(self) -> None:
        _graph, report = _report("insecure.Dockerfile")
        rules = {r.id: r for r in load_all_rules()}
        for threat in report.threats:
            if threat.source == ThreatSource.RULE:
                assert rules[threat.rule_id].matches_type(threat.resource_type), threat.rule_id


class TestSecureDockerfile:
    def test_nothing_serious_fires(self) -> None:
        _graph, report = _report("secure.Dockerfile")
        assert [t.rule_id for t in report.threats if t.severity >= Severity.HIGH] == []

    def test_it_has_fewer_findings_than_the_insecure_one(self) -> None:
        _g1, secure = _report("secure.Dockerfile")
        _g2, insecure = _report("insecure.Dockerfile")
        assert len(secure.threats) < len(insecure.threats)
