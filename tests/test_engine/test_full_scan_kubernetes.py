"""End-to-end scan tests for Kubernetes manifests."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import load_all_rules
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, ThreatSource
from threatcode.parsers import detect_and_parse

FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "kubernetes"


def _scan(name: str) -> dict[str, set[str]]:
    path = FIXTURES_DIR / name
    graph = InfraGraph.from_parsed(detect_and_parse(path))
    report = HybridEngine().analyze(graph, input_file=str(path))
    found: dict[str, set[str]] = defaultdict(set)
    for threat in report.threats:
        if threat.source == ThreatSource.RULE:
            found[threat.resource_address].add(threat.rule_id)
    return found


class TestInsecureDeployment:
    def test_the_headline_findings_fire(self) -> None:
        (rule_ids,) = _scan("insecure_deployment.yml").values()
        assert {
            "K8S_PRIVILEGED_CONTAINER",
            "K8S_HOST_NETWORK",
            "K8S_HOST_PID",
            "K8S_LATEST_TAG",
            "K8S_HOST_PATH_VOLUME",
            "K8S_RUN_AS_ROOT",
            "K8S_DANGEROUS_CAPABILITIES",
        } <= rule_ids


class TestSecureDeployment:
    def test_nothing_serious_fires(self) -> None:
        path = FIXTURES_DIR / "secure_deployment.yml"
        graph = InfraGraph.from_parsed(detect_and_parse(path))
        report = HybridEngine().analyze(graph, input_file=str(path))
        serious = [t.rule_id for t in report.threats if t.severity >= Severity.HIGH]
        assert serious == []


class TestMultiResourceManifest:
    def test_each_kind_gets_only_the_rules_written_for_it(self) -> None:
        found = _scan("multi_resource.yml")
        rules = {r.id: r for r in load_all_rules()}
        graph = InfraGraph.from_parsed(detect_and_parse(FIXTURES_DIR / "multi_resource.yml"))
        for address, rule_ids in found.items():
            for rule_id in rule_ids:
                assert rules[rule_id].matches_type(graph.nodes[address].resource_type), (
                    address,
                    rule_id,
                )

    def test_the_cluster_admin_binding_is_reported_on_the_binding_only(self) -> None:
        found = _scan("multi_resource.yml")
        by_rule = defaultdict(set)
        for address, rule_ids in found.items():
            for rule_id in rule_ids:
                by_rule[rule_id].add(address)
        assert {a.split(".")[0] for a in by_rule["K8S_CLUSTER_ADMIN_BINDING"]} == {
            "kubernetes_cluster_role_binding"
        }
        assert {a.split(".")[0] for a in by_rule["K8S_WILDCARD_RBAC_VERBS"]} == {
            "kubernetes_cluster_role"
        }

    def test_service_account_gets_its_own_rule_and_nothing_else(self) -> None:
        found = _scan("multi_resource.yml")
        account = next(a for a in found if a.startswith("kubernetes_service_account."))
        assert found[account] == {"K8S_AUTOMOUNT_DEFAULT"}
