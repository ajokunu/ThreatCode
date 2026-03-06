"""Tests for Kubernetes manifest parser."""

from pathlib import Path

import pytest

from threatcode.parsers.kubernetes import KubernetesParser


@pytest.fixture
def parser() -> KubernetesParser:
    return KubernetesParser()


class TestKubernetesParser:
    def test_parse_insecure_deployment(self, parser: KubernetesParser) -> None:
        content = Path("tests/fixtures/kubernetes/insecure_deployment.yml").read_text()
        result = parser.parse(content, source_path="insecure.yml")
        assert result.format_type == "kubernetes"
        assert len(result.resources) == 1
        r = result.resources[0]
        assert r.resource_type == "kubernetes_deployment"
        assert r.properties["privileged"] is True
        assert r.properties["host_network"] is True
        assert r.properties["host_pid"] is True
        assert r.properties["uses_latest_tag"] is True
        assert r.properties["has_host_path_volume"] is True
        assert r.properties["has_host_port"] is True
        assert len(r.properties["dangerous_capabilities"]) > 0

    def test_parse_secure_deployment(self, parser: KubernetesParser) -> None:
        content = Path("tests/fixtures/kubernetes/secure_deployment.yml").read_text()
        result = parser.parse(content, source_path="secure.yml")
        assert len(result.resources) == 1
        r = result.resources[0]
        assert r.properties["privileged"] is False
        assert r.properties["run_as_root"] is False
        assert r.properties["has_resource_limits"] is True
        assert r.properties["capabilities_dropped"] is True
        assert r.properties["has_liveness_probe"] is True
        assert r.properties["has_readiness_probe"] is True

    def test_multi_document(self, parser: KubernetesParser) -> None:
        content = Path("tests/fixtures/kubernetes/multi_resource.yml").read_text()
        result = parser.parse(content, source_path="multi.yml")
        types = {r.resource_type for r in result.resources}
        assert "kubernetes_namespace" in types
        assert "kubernetes_service_account" in types
        assert "kubernetes_cluster_role_binding" in types
        assert "kubernetes_cluster_role" in types
        assert "kubernetes_deployment" in types
        assert "kubernetes_network_policy" in types

    def test_rbac_wildcard_detection(self, parser: KubernetesParser) -> None:
        content = Path("tests/fixtures/kubernetes/multi_resource.yml").read_text()
        result = parser.parse(content, source_path="multi.yml")
        roles = [r for r in result.resources if r.resource_type == "kubernetes_cluster_role"]
        assert len(roles) == 1
        assert roles[0].properties["has_wildcard_verbs"] is True
        assert roles[0].properties["has_wildcard_resources"] is True

    def test_cluster_admin_binding(self, parser: KubernetesParser) -> None:
        content = Path("tests/fixtures/kubernetes/multi_resource.yml").read_text()
        result = parser.parse(content, source_path="multi.yml")
        bindings = [
            r for r in result.resources if r.resource_type == "kubernetes_cluster_role_binding"
        ]
        assert bindings[0].properties["role_ref_name"] == "cluster-admin"

    def test_provider_is_kubernetes(self, parser: KubernetesParser) -> None:
        content = (
            "apiVersion: v1\nkind: Pod\nmetadata:\n  name: test\n"
            "spec:\n  containers:\n    - name: test\n      image: nginx:1.0"
        )
        result = parser.parse(content)
        for r in result.resources:
            assert r.provider == "kubernetes"

    def test_pre_parsed_data(self, parser: KubernetesParser) -> None:
        data = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "test-cm", "namespace": "default"},
            "data": {"key": "value"},
        }
        result = parser.parse(data)
        assert len(result.resources) == 1
        assert result.resources[0].resource_type == "kubernetes_config_map"

    def test_non_k8s_yaml_skipped(self, parser: KubernetesParser) -> None:
        data = {"name": "not-k8s", "value": 42}
        result = parser.parse(data)
        assert len(result.resources) == 0
