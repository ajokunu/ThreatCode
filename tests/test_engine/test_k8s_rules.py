"""Tests for Kubernetes security rules."""

from pathlib import Path

import pytest

from threatcode.engine.rules.loader import load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule
from threatcode.parsers.kubernetes import KubernetesParser


@pytest.fixture
def k8s_rules():
    rules = load_all_rules()
    return [r for r in rules if r.id.startswith("K8S_")]


@pytest.fixture
def insecure_resources():
    parser = KubernetesParser()
    fixture = (
        Path(__file__).parent.parent / "fixtures" / "kubernetes" / "insecure_deployment.yml"
    )
    content = fixture.read_text()
    return parser.parse(content).resources


@pytest.fixture
def secure_resources():
    parser = KubernetesParser()
    fixture = (
        Path(__file__).parent.parent / "fixtures" / "kubernetes" / "secure_deployment.yml"
    )
    content = fixture.read_text()
    return parser.parse(content).resources


class TestK8sRulesExist:
    def test_k8s_rules_loaded(self, k8s_rules) -> None:
        rule_ids = {r.id for r in k8s_rules}
        assert "K8S_PRIVILEGED_CONTAINER" in rule_ids
        assert "K8S_RUN_AS_ROOT" in rule_ids
        assert "K8S_HOST_NETWORK" in rule_ids
        assert "K8S_LATEST_TAG" in rule_ids
        assert "K8S_CLUSTER_ADMIN_BINDING" in rule_ids
        assert len(k8s_rules) >= 20


class TestK8sRulesInsecure:
    def test_insecure_fires_rules(self, k8s_rules, insecure_resources) -> None:
        fired = set()
        for rule in k8s_rules:
            for resource in insecure_resources:
                if resource.resource_type == rule.resource_type:
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        assert "K8S_PRIVILEGED_CONTAINER" in fired
        assert "K8S_RUN_AS_ROOT" in fired
        assert "K8S_HOST_NETWORK" in fired
        assert "K8S_HOST_PID" in fired
        assert "K8S_LATEST_TAG" in fired
        assert "K8S_HOST_PATH_VOLUME" in fired


class TestK8sRulesSecure:
    def test_secure_minimal_fires(self, k8s_rules, secure_resources) -> None:
        fired = set()
        for rule in k8s_rules:
            for resource in secure_resources:
                if resource.resource_type == rule.resource_type:
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        # Secure deployment should not fire critical/high rules
        high_critical_fired = {
            rid
            for rid in fired
            if any(r.id == rid and r.severity in ("high", "critical") for r in k8s_rules)
        }
        assert len(high_critical_fired) == 0
