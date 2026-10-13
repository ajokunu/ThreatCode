"""Tests for Kubernetes manifest parser."""

from __future__ import annotations

import json
import time
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.engine.hybrid import HybridEngine
from threatcode.exceptions import ParseError
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import TrustZone
from threatcode.parsers import detect_and_parse
from threatcode.parsers.base import ParsedOutput
from threatcode.parsers.kubernetes import (
    MAX_LIST_DEPTH,
    KubernetesParser,
    resource_type_for,
)


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


# ---------------------------------------------------------------------------------------
# Documents: List kinds, JSON, mixed files
# ---------------------------------------------------------------------------------------

FIXTURES = Path(__file__).parent.parent / "fixtures" / "kubernetes"

POD = {
    "apiVersion": "v1",
    "kind": "Pod",
    "metadata": {"name": "debug", "namespace": "ops"},
    "spec": {"containers": [{"name": "c", "image": "busybox:1.36"}]},
}
DEPLOYMENT = {
    "apiVersion": "apps/v1",
    "kind": "Deployment",
    "metadata": {"name": "web", "namespace": "ops"},
    "spec": {"template": {"spec": {"containers": [{"name": "c", "image": "web:1"}]}}},
}


def _addresses(output: ParsedOutput) -> list[str]:
    return [r.address for r in output.resources]


class TestListKinds:
    def test_a_list_of_a_pod_and_a_deployment_yields_two_real_resources(
        self, parser: KubernetesParser
    ) -> None:
        output = parser.parse({"apiVersion": "v1", "kind": "List", "items": [POD, DEPLOYMENT]})
        assert _addresses(output) == ["kubernetes_pod.ops.debug", "kubernetes_deployment.ops.web"]
        assert output.diagnostics == []

    def test_the_list_fixture_keeps_the_privileged_finding_of_its_pod(
        self, parser: KubernetesParser
    ) -> None:
        text = (FIXTURES / "list_pod_deployment.yaml").read_text()
        by_name = {r.name: r for r in parser.parse(text).resources}
        assert by_name["debug-shell"].properties["privileged"] is True
        assert by_name["metrics"].properties["privileged"] is False

    def test_a_kind_list_is_flattened_too(self, parser: KubernetesParser) -> None:
        data = {"apiVersion": "apps/v1", "kind": "DeploymentList", "items": [DEPLOYMENT]}
        assert _addresses(parser.parse(data)) == ["kubernetes_deployment.ops.web"]

    def test_the_json_deployment_list_fixture_flattens(self, parser: KubernetesParser) -> None:
        text = (FIXTURES / "deployment_list.json").read_text()
        output = parser.parse(text)
        assert _addresses(output) == [
            "kubernetes_deployment.finance.billing",
            "kubernetes_deployment.finance.ledger",
        ]
        assert output.resources[0].properties["privileged"] is True

    def test_lists_nest(self, parser: KubernetesParser) -> None:
        inner = {"apiVersion": "v1", "kind": "List", "items": [POD]}
        outer = {"apiVersion": "v1", "kind": "List", "items": [inner, DEPLOYMENT]}
        assert _addresses(parser.parse(outer)) == [
            "kubernetes_pod.ops.debug",
            "kubernetes_deployment.ops.web",
        ]

    def test_the_wrapper_contributes_nothing(self, parser: KubernetesParser) -> None:
        wrapper = {
            "apiVersion": "v1",
            "kind": "List",
            "metadata": {"name": "wrapper", "namespace": "wrapper-ns", "labels": {"a": "b"}},
            "items": [{**POD, "metadata": {"name": "p"}}],
        }
        (resource,) = parser.parse(wrapper).resources
        assert resource.address == "kubernetes_pod.default.p"
        assert resource.properties["labels"] == {}

    def test_an_empty_or_missing_items_list_is_no_resources_and_no_warning(
        self, parser: KubernetesParser
    ) -> None:
        for data in (
            {"apiVersion": "v1", "kind": "List", "items": []},
            {"apiVersion": "v1", "kind": "List", "items": None},
            {"apiVersion": "v1", "kind": "List"},
        ):
            output = parser.parse(data)
            assert output.resources == []
            assert output.diagnostics == []

    def test_items_that_are_not_objects_are_skipped_with_a_warning(
        self, parser: KubernetesParser
    ) -> None:
        output = parser.parse(
            {"apiVersion": "v1", "kind": "List", "items": [POD, "x", None, {"name": "no-kind"}]}
        )
        assert _addresses(output) == ["kubernetes_pod.ops.debug"]
        assert [d.code for d in output.diagnostics] == ["k8s.skipped_document"] * 3

    def test_a_self_nested_list_stops_at_the_depth_cap(self, parser: KubernetesParser) -> None:
        document: dict[str, Any] = {"apiVersion": "v1", "kind": "List", "items": [POD]}
        for _ in range(50):
            document = {"apiVersion": "v1", "kind": "List", "items": [document, DEPLOYMENT]}
        output = parser.parse(document)
        # Five levels of List are expanded: the five deployments beside them are reached, the pod
        # six levels down is not
        assert len(output.resources) == MAX_LIST_DEPTH
        assert all(r.resource_type == "kubernetes_deployment" for r in output.resources)
        assert any("deeper than" in d.message for d in output.diagnostics)

    def test_a_list_cannot_expand_past_the_document_cap(
        self, parser: KubernetesParser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.parsers.kubernetes.MAX_DOCUMENTS", 5)
        items = [{**POD, "metadata": {"name": f"p{n}"}} for n in range(50)]
        output = parser.parse({"apiVersion": "v1", "kind": "List", "items": items})
        assert len(output.resources) == 5
        assert any("more than 5" in d.message for d in output.diagnostics)

    def test_a_kind_that_only_ends_in_list_but_has_no_items_is_an_object(
        self, parser: KubernetesParser
    ) -> None:
        output = parser.parse(
            {"apiVersion": "example.com/v1", "kind": "AllowList", "metadata": {"name": "a"}}
        )
        assert _addresses(output) == ["kubernetes_allow_list.default.a"]


class TestDetectAndParse:
    def test_a_kubectl_yaml_list_goes_through_the_registry(self) -> None:
        output = detect_and_parse(FIXTURES / "list_pod_deployment.yaml")
        assert output.format_type == "kubernetes"
        assert _addresses(output) == [
            "kubernetes_pod.ops.debug-shell",
            "kubernetes_deployment.ops.metrics",
        ]

    def test_a_kubectl_json_manifest_goes_through_the_registry(self) -> None:
        output = detect_and_parse(FIXTURES / "deployment_list.json")
        assert output.format_type == "kubernetes"
        assert len(output.resources) == 2

    def test_a_single_json_object_is_a_manifest(self, tmp_path: Path) -> None:
        path = tmp_path / "pod.json"
        path.write_text(json.dumps(POD), encoding="utf-8")
        assert _addresses(detect_and_parse(path)) == ["kubernetes_pod.ops.debug"]

    def test_a_json_array_of_manifests_is_read_item_by_item(self, tmp_path: Path) -> None:
        path = tmp_path / "all.json"
        path.write_text(json.dumps([POD, DEPLOYMENT]), encoding="utf-8")
        assert len(detect_and_parse(path).resources) == 2

    def test_the_real_shape_json_and_yaml_lists_match(self) -> None:
        shapes = Path(__file__).parent.parent / "fixtures" / "real_shapes" / "kubernetes"
        yaml_output = detect_and_parse(shapes / "kubectl_get_all.yaml")
        json_output = detect_and_parse(shapes / "kubectl_get_all.json")
        assert _addresses(yaml_output) == _addresses(json_output)
        assert len(yaml_output.resources) == 3

    def test_a_mixed_file_parses_its_kubernetes_documents_and_reports_the_rest(self) -> None:
        output = detect_and_parse(FIXTURES / "mixed_documents.yml")
        assert _addresses(output) == [
            "kubernetes_config_map.mixed.settings",
            "kubernetes_pod.mixed.probe",
        ]
        warnings = [d for d in output.diagnostics if d.code == "k8s.skipped_document"]
        assert len(warnings) == 2
        assert all(d.level == "warning" for d in warnings)
        assert warnings[0].file.endswith("mixed_documents.yml")
        assert [s["index"] for s in output.metadata["skipped_documents"]] == [1, 2]

    def test_a_clean_manifest_records_no_skipped_documents(self) -> None:
        output = detect_and_parse(FIXTURES / "secure_deployment.yml")
        assert "skipped_documents" not in output.metadata
        assert output.diagnostics == []

    def test_a_deployment_with_a_null_image_parses_through_the_registry(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "d.yaml"
        path.write_text(
            "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d}\n"
            "spec:\n  template:\n    spec:\n      containers:\n"
            "        - name: c\n          image:\n",
            encoding="utf-8",
        )
        (resource,) = detect_and_parse(path).resources
        assert resource.properties["uses_latest_tag"] is False


# ---------------------------------------------------------------------------------------
# Addresses
# ---------------------------------------------------------------------------------------


def _object(kind: str, metadata: dict[str, Any], api: str = "v1") -> dict[str, Any]:
    return {"apiVersion": api, "kind": kind, "metadata": metadata}


class TestAddresses:
    @pytest.mark.parametrize(
        ("kind", "address"),
        [
            ("Namespace", "kubernetes_namespace.prod"),
            ("ClusterRole", "kubernetes_cluster_role.prod"),
            ("ClusterRoleBinding", "kubernetes_cluster_role_binding.prod"),
            ("PersistentVolume", "kubernetes_persistent_volume.prod"),
            ("StorageClass", "kubernetes_storage_class.prod"),
            ("CustomResourceDefinition", "kubernetes_custom_resource_definition.prod"),
            ("Node", "kubernetes_node.prod"),
            ("PriorityClass", "kubernetes_priority_class.prod"),
            ("IngressClass", "kubernetes_ingress_class.prod"),
            ("ValidatingWebhookConfiguration", "kubernetes_validating_webhook_configuration.prod"),
        ],
    )
    def test_cluster_scoped_kinds_have_no_namespace_segment(
        self, parser: KubernetesParser, kind: str, address: str
    ) -> None:
        # Even a namespace written on the object is ignored: the kind has none
        (resource,) = parser.parse(
            _object(kind, {"name": "prod", "namespace": "ignored"})
        ).resources
        assert resource.address == address
        assert resource.properties["namespace"] is None

    @pytest.mark.parametrize(
        ("kind", "address"),
        [
            ("Deployment", "kubernetes_deployment.prod.x"),
            ("Service", "kubernetes_service.prod.x"),
            ("Role", "kubernetes_role.prod.x"),
            ("RoleBinding", "kubernetes_role_binding.prod.x"),
            ("ServiceAccount", "kubernetes_service_account.prod.x"),
            ("ConfigMap", "kubernetes_config_map.prod.x"),
            ("PersistentVolumeClaim", "kubernetes_pvc.prod.x"),
            ("HorizontalPodAutoscaler", "kubernetes_horizontal_pod_autoscaler.prod.x"),
            ("PodDisruptionBudget", "kubernetes_pod_disruption_budget.prod.x"),
            ("ResourceQuota", "kubernetes_resource_quota.prod.x"),
        ],
    )
    def test_namespaced_kinds_keep_their_namespace_segment(
        self, parser: KubernetesParser, kind: str, address: str
    ) -> None:
        (resource,) = parser.parse(_object(kind, {"name": "x", "namespace": "prod"})).resources
        assert resource.address == address

    def test_a_namespaced_object_without_a_namespace_is_in_default(
        self, parser: KubernetesParser
    ) -> None:
        (resource,) = parser.parse(_object("Service", {"name": "x"})).resources
        assert resource.address == "kubernetes_service.default.x"
        assert resource.properties["namespace"] == "default"

    def test_generate_name_gives_the_stem_plus_generated(self, parser: KubernetesParser) -> None:
        (resource,) = parser.parse(
            _object("Job", {"generateName": "backup-", "namespace": "ops"}, "batch/v1")
        ).resources
        assert resource.address == "kubernetes_job.ops.backup-generated"
        assert resource.name == "backup-generated"

    def test_a_name_wins_over_generate_name(self, parser: KubernetesParser) -> None:
        (resource,) = parser.parse(_object("Job", {"name": "real", "generateName": "x-"})).resources
        assert resource.name == "real"

    def test_an_unnamed_object_is_named_after_its_document_index(
        self, parser: KubernetesParser
    ) -> None:
        output = parser.parse(
            {
                "apiVersion": "v1",
                "kind": "List",
                "items": [
                    _object("Secret", {}),
                    _object("Pod", {"name": "p"}),
                    _object("Secret", {"name": ""}),
                ],
            }
        )
        assert _addresses(output) == [
            "kubernetes_secret.default.unnamed-0",
            "kubernetes_pod.default.p",
            "kubernetes_secret.default.unnamed-2",
        ]

    def test_an_object_with_no_metadata_at_all_is_unnamed(self, parser: KubernetesParser) -> None:
        (resource,) = parser.parse(
            {"apiVersion": "v1", "kind": "ConfigMap", "metadata": None}
        ).resources
        assert resource.address == "kubernetes_config_map.default.unnamed-0"

    def test_two_jobs_with_the_same_generate_name_stay_two_nodes_with_both_findings(
        self, parser: KubernetesParser
    ) -> None:
        def job(privileged: bool) -> dict[str, Any]:
            return {
                **_object("Job", {"generateName": "backup-", "namespace": "ops"}, "batch/v1"),
                "spec": {
                    "template": {
                        "spec": {
                            "containers": [
                                {
                                    "name": "c",
                                    "image": "backup:1",
                                    "securityContext": {"privileged": privileged},
                                }
                            ]
                        }
                    }
                },
            }

        output = parser.parse({"apiVersion": "v1", "kind": "List", "items": [job(True), job(True)]})
        graph = InfraGraph.from_parsed(output)
        assert sorted(graph.nodes) == [
            "kubernetes_job.ops.backup-generated",
            "kubernetes_job.ops.backup-generated#2",
        ]
        threats = HybridEngine().analyze(graph).threats
        hits = {t.resource_address for t in threats if t.rule_id == "K8S_PRIVILEGED_CONTAINER"}
        assert hits == set(graph.nodes)
        assert graph.duplicate_count == 1

    def test_unknown_kinds_get_a_snake_case_type(self, parser: KubernetesParser) -> None:
        (resource,) = parser.parse(
            _object("ClusterIssuer", {"name": "x"}, "cert-manager.io/v1")
        ).resources
        assert resource.resource_type == "kubernetes_cluster_issuer"

    @pytest.mark.parametrize(
        ("kind", "resource_type"),
        [
            ("APIService", "kubernetes_api_service"),
            ("CSIDriver", "kubernetes_csi_driver"),
            ("Pod", "kubernetes_pod"),
            ("Weird.Kind", "kubernetes_weird_kind"),
            ("X", "kubernetes_x"),
        ],
    )
    def test_resource_type_for(self, kind: str, resource_type: str) -> None:
        assert resource_type_for(kind) == resource_type


# ---------------------------------------------------------------------------------------
# Null safety
# ---------------------------------------------------------------------------------------


class TestNullSafety:
    def test_a_deployment_with_a_null_image_parses(self, parser: KubernetesParser) -> None:
        doc = {
            **DEPLOYMENT,
            "spec": {"template": {"spec": {"containers": [{"name": "c", "image": None}]}}},
        }
        (resource,) = parser.parse(doc).resources
        assert resource.properties["uses_latest_tag"] is False
        assert resource.properties["images"] == []

    def test_a_cron_job_with_a_null_job_template_parses(self, parser: KubernetesParser) -> None:
        doc = {**_object("CronJob", {"name": "j"}, "batch/v1"), "spec": {"jobTemplate": None}}
        (resource,) = parser.parse(doc).resources
        assert resource.resource_type == "kubernetes_cron_job"
        assert resource.properties["privileged"] is False

    @pytest.mark.parametrize("junk", [None, "placeholder", 7, [], ["x"], True])
    @pytest.mark.parametrize("field", ["spec", "metadata"])
    def test_a_top_level_field_of_the_wrong_type_does_not_raise(
        self, parser: KubernetesParser, field: str, junk: Any
    ) -> None:
        for kind in (
            "Deployment",
            "Service",
            "Ingress",
            "NetworkPolicy",
            "Role",
            "RoleBinding",
            "Pod",
        ):
            doc = {"apiVersion": "v1", "kind": kind, "metadata": {"name": "x"}, "spec": {}}
            doc[field] = junk
            assert len(parser.parse(doc).resources) == 1, (kind, field, junk)

    @pytest.mark.parametrize("junk", [None, "placeholder", 7])
    def test_labels_annotations_and_selectors_of_the_wrong_type_become_empty(
        self, parser: KubernetesParser, junk: Any
    ) -> None:
        # A type given as a string stays what it says; every other junk falls back to ClusterIP
        service_type = junk if isinstance(junk, str) else None
        doc = {
            **_object("Service", {"name": "s", "labels": junk, "annotations": junk}),
            "spec": {"selector": junk, "ports": junk, "type": service_type},
        }
        (resource,) = parser.parse(doc).resources
        assert resource.properties["labels"] == {}
        assert resource.properties["annotations"] == {}
        assert resource.properties["selector"] == {}
        assert resource.properties["ports"] == []
        assert resource.properties["service_type"] == (service_type or "ClusterIP")

    def test_pod_template_labels_of_the_wrong_type_do_not_raise(
        self, parser: KubernetesParser
    ) -> None:
        doc = {
            **DEPLOYMENT,
            "spec": {
                "template": {"metadata": {"labels": "placeholder"}, "spec": {"containers": []}}
            },
        }
        (resource,) = parser.parse(doc).resources
        assert resource.properties["pod_labels"] == {}

    def test_the_insecure_fixture_parses_the_same_as_before(self, parser: KubernetesParser) -> None:
        (resource,) = parser.parse((FIXTURES / "insecure_deployment.yml").read_text()).resources
        props = resource.properties
        assert props["privileged"] is True
        assert props["host_network"] is True
        assert props["secret_env_vars"] == ["DB_PASSWORD"]
        assert props["dangerous_capabilities"] == ["NET_ADMIN", "SYS_ADMIN"]


# ---------------------------------------------------------------------------------------
# Services, Ingresses and the zones they get
# ---------------------------------------------------------------------------------------


class TestServiceAndIngress:
    def test_service_properties(self, parser: KubernetesParser) -> None:
        doc = {
            **_object("Service", {"name": "s", "namespace": "n"}),
            "spec": {"type": "NodePort", "selector": {"app": "x"}, "ports": [{"port": 80}]},
        }
        (resource,) = parser.parse(doc).resources
        assert resource.properties["service_type"] == "NodePort"
        assert resource.properties["selector"] == {"app": "x"}
        assert resource.properties["ports"] == [{"port": 80}]

    @pytest.mark.parametrize(
        ("service_type", "zone"),
        [
            ("LoadBalancer", TrustZone.DMZ),
            ("NodePort", TrustZone.DMZ),
            ("ClusterIP", TrustZone.PRIVATE),
            ("ExternalName", TrustZone.INTERNET),
        ],
    )
    def test_the_graph_zones_a_service_by_its_type(
        self, parser: KubernetesParser, service_type: str, zone: TrustZone
    ) -> None:
        doc = {**_object("Service", {"name": "s"}), "spec": {"type": service_type}}
        graph = InfraGraph.from_parsed(parser.parse(doc))
        assert graph.nodes["kubernetes_service.default.s"].trust_zone == zone

    def test_a_service_without_a_type_is_a_cluster_ip(self, parser: KubernetesParser) -> None:
        graph = InfraGraph.from_parsed(parser.parse(_object("Service", {"name": "s"})))
        assert graph.nodes["kubernetes_service.default.s"].trust_zone == TrustZone.PRIVATE

    def test_ingress_tls_and_rules(self, parser: KubernetesParser) -> None:
        with_both = {
            **_object("Ingress", {"name": "a"}, "networking.k8s.io/v1"),
            "spec": {
                "tls": [{"secretName": "t"}],
                "rules": [
                    {
                        "http": {
                            "paths": [
                                {"backend": {"service": {"name": "s", "port": {"number": 80}}}}
                            ]
                        }
                    }
                ],
            },
        }
        plain = {**_object("Ingress", {"name": "b"}, "networking.k8s.io/v1"), "spec": {"rules": []}}
        by_name = {
            r.name: r.properties
            for r in parser.parse(
                {"apiVersion": "v1", "kind": "List", "items": [with_both, plain]}
            ).resources
        }
        assert by_name["a"]["has_tls"] is True
        assert by_name["a"]["has_rules"] is True
        assert by_name["a"]["ingress_backends"] == [{"service_name": "s", "port": 80}]
        assert by_name["b"]["has_tls"] is False
        assert by_name["b"]["has_rules"] is False
        assert by_name["b"]["ingress_backends"] == []

    def test_an_ingress_with_only_a_default_backend_still_routes(
        self, parser: KubernetesParser
    ) -> None:
        doc = {
            **_object("Ingress", {"name": "a"}, "networking.k8s.io/v1"),
            "spec": {"defaultBackend": {"service": {"name": "s", "port": {"name": "http"}}}},
        }
        (resource,) = parser.parse(doc).resources
        assert resource.properties["has_rules"] is True
        assert resource.properties["ingress_backends"] == [{"service_name": "s", "port": "http"}]

    def test_an_ingress_without_rules_is_private_and_with_rules_is_in_the_dmz(
        self, parser: KubernetesParser
    ) -> None:
        empty = {**_object("Ingress", {"name": "empty"}, "networking.k8s.io/v1"), "spec": {}}
        routed = {
            **_object("Ingress", {"name": "routed"}, "networking.k8s.io/v1"),
            "spec": {
                "rules": [
                    {"host": "x", "http": {"paths": [{"backend": {"service": {"name": "s"}}}]}}
                ]
            },
        }
        graph = InfraGraph.from_parsed(
            parser.parse({"apiVersion": "v1", "kind": "List", "items": [empty, routed]})
        )
        assert graph.nodes["kubernetes_ingress.default.empty"].trust_zone == TrustZone.PRIVATE
        assert graph.nodes["kubernetes_ingress.default.routed"].trust_zone == TrustZone.DMZ

    def test_config_maps_are_private_and_secrets_are_data(self, parser: KubernetesParser) -> None:
        graph = InfraGraph.from_parsed(
            parser.parse(
                {
                    "apiVersion": "v1",
                    "kind": "List",
                    "items": [
                        _object("ConfigMap", {"name": "c"}),
                        _object("Secret", {"name": "s"}),
                    ],
                }
            )
        )
        assert graph.nodes["kubernetes_config_map.default.c"].trust_zone == TrustZone.PRIVATE
        assert graph.nodes["kubernetes_secret.default.s"].trust_zone == TrustZone.DATA

    def test_secret_values_never_reach_the_properties(self, parser: KubernetesParser) -> None:
        doc = {
            **_object("Secret", {"name": "s"}),
            "data": {"password": "aHVudGVyMg=="},
            "stringData": {"token": "ghp_notarealtoken"},
        }
        (resource,) = parser.parse(doc).resources
        assert "hunter2" not in str(resource.properties)
        assert "ghp_notarealtoken" not in str(resource.properties)
        assert "aHVudGVyMg==" not in str(resource.properties)


# ---------------------------------------------------------------------------------------
# Source locations
# ---------------------------------------------------------------------------------------


class TestSourceLocations:
    def test_resources_of_text_get_their_start_lines(self, parser: KubernetesParser) -> None:
        text = (FIXTURES / "multi_resource.yml").read_text()
        lines = {r.name: r.start_line for r in parser.parse(text, "multi.yml").resources}
        assert lines["test-ns"] == 1
        assert lines["test-sa"] == 6
        assert lines["test-admin-binding"] == 12
        assert all(
            r.source_location == "multi.yml" for r in parser.parse(text, "multi.yml").resources
        )

    def test_a_file_read_through_the_registry_has_lines_too(self) -> None:
        output = detect_and_parse(FIXTURES / "multi_resource.yml")
        assert [r.start_line for r in output.resources][:3] == [1, 6, 12]
        assert output.resources[0].source_location.endswith("multi_resource.yml")

    def test_list_items_get_the_line_of_their_own_item(self) -> None:
        output = detect_and_parse(FIXTURES / "list_pod_deployment.yaml")
        assert [r.start_line for r in output.resources] == [7, 20]

    def test_json_items_get_lines_too(self) -> None:
        output = detect_and_parse(FIXTURES / "deployment_list.json")
        assert [r.start_line for r in output.resources] == [6, 27]

    def test_a_dict_with_no_file_has_no_lines(self, parser: KubernetesParser) -> None:
        (resource,) = parser.parse(POD, "does-not-exist.yaml").resources
        assert resource.start_line is None
        assert resource.source_location == "does-not-exist.yaml"

    def test_the_end_line_is_not_guessed(self, parser: KubernetesParser) -> None:
        text = (FIXTURES / "multi_resource.yml").read_text()
        assert all(r.end_line is None for r in parser.parse(text).resources)


# ---------------------------------------------------------------------------------------
# Input forms
# ---------------------------------------------------------------------------------------


class TestInputForms:
    def test_text_with_several_documents_and_comments(self, parser: KubernetesParser) -> None:
        text = (
            "# comment\n---\n"
            + yaml.safe_dump(POD)
            + "---\n# nothing here\n---\n"
            + yaml.safe_dump(DEPLOYMENT)
        )
        assert len(parser.parse(text).resources) == 2

    def test_a_list_of_documents(self, parser: KubernetesParser) -> None:
        assert len(parser.parse([POD, DEPLOYMENT, None, "x"]).resources) == 2

    def test_a_scalar_is_skipped_not_an_error(self, parser: KubernetesParser) -> None:
        output = parser.parse("just text")
        assert output.resources == []
        assert [d.code for d in output.diagnostics] == ["k8s.skipped_document"]

    def test_invalid_yaml_is_a_parse_error_naming_the_file(self, parser: KubernetesParser) -> None:
        with pytest.raises(ParseError, match=r"bad\.yaml"):
            parser.parse("a: [1, 2\nb: : :", "bad.yaml")

    def test_a_corrupt_manifest_through_the_registry_is_not_unsupported(
        self, tmp_path: Path
    ) -> None:
        path = tmp_path / "corrupt.yaml"
        path.write_text("apiVersion: v1\nkind: Pod\nmetadata: {name: x\n", encoding="utf-8")
        with pytest.raises(ParseError) as caught:
            detect_and_parse(path)
        assert "corrupt.yaml" in str(caught.value)


class TestHostileDocuments:
    @staticmethod
    def _bomb(levels: int = 12, fanout: int = 9) -> str:
        """A ClusterRole whose ``rules`` alias themselves into ``fanout ** levels`` nodes."""
        lines = ["apiVersion: rbac.authorization.k8s.io/v1", "kind: ClusterRole"]
        lines.append("metadata: {name: bomb}")
        lines.append("x-a0: &a0 [x, x, x, x, x, x, x, x, x]")
        for level in range(1, levels):
            refs = ", ".join([f"*a{level - 1}"] * fanout)
            lines.append(f"x-a{level}: &a{level} [{refs}]")
        lines.append(f"rules: *a{levels - 1}")
        return "\n".join(lines) + "\n"

    def test_a_value_whose_aliases_expand_without_bound_is_dropped_and_reported(
        self, parser: KubernetesParser
    ) -> None:
        started = time.monotonic()
        output = parser.parse(self._bomb() + "---\n" + yaml.safe_dump(POD))
        assert time.monotonic() - started < 10
        # the object itself is kept, only the value that cannot be copied is dropped
        assert _addresses(output) == ["kubernetes_cluster_role.bomb", "kubernetes_pod.ops.debug"]
        assert output.resources[0].properties["rbac_rules"] == []
        (warning,) = output.diagnostics
        assert warning.code == "k8s.truncated_value"
        assert "rbac_rules" in warning.message and "aliases" in warning.message
        assert warning.level == "warning"

    def test_a_self_containing_anchor_is_dropped_not_followed_forever(
        self, parser: KubernetesParser
    ) -> None:
        text = "apiVersion: v1\nkind: Service\nmetadata: {name: loop}\nspec: {ports: &a [*a, *a]}\n"
        output = parser.parse(text)
        (resource,) = output.resources
        assert resource.properties["ports"] == []
        assert [d.code for d in output.diagnostics] == ["k8s.truncated_value"]

    def test_a_bomb_in_a_field_no_property_keeps_costs_nothing(
        self, parser: KubernetesParser
    ) -> None:
        text = (
            "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: data-bomb}\n"
            "x-a: &a [x, x, x, x, x, x, x, x, x, x]\n"
            + "".join(
                f"x-{n}: &b{n} [{', '.join([('*a' if n == 0 else f'*b{n - 1}')] * 10)}]\n"
                for n in range(10)
            )
            + "data: *b9\n"
        )
        output = parser.parse(text)
        assert _addresses(output) == ["kubernetes_config_map.default.data-bomb"]
        assert output.diagnostics == []

    def test_an_ordinary_large_document_is_kept_whole(self, parser: KubernetesParser) -> None:
        rules = [{"apiGroups": [""], "resources": [f"r{n}"], "verbs": ["get"]} for n in range(500)]
        big = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "big"},
            "rules": rules,
        }
        (resource,) = parser.parse(big).resources
        assert resource.properties["rbac_rules"] == rules

    def test_the_copy_is_bounded_not_shared(self, parser: KubernetesParser) -> None:
        rules = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get"]}]
        doc = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "r"},
            "rules": rules,
        }
        (resource,) = parser.parse(doc).resources
        assert resource.properties["rbac_rules"] == rules
        assert resource.properties["rbac_rules"] is not rules

    def test_a_giant_list_is_cut_at_the_document_cap_without_building_every_item(
        self, parser: KubernetesParser, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setattr("threatcode.parsers.kubernetes.MAX_DOCUMENTS", 100)
        items = [{**POD, "metadata": {"name": f"p{n}"}} for n in range(5_000)]
        output = parser.parse({"apiVersion": "v1", "kind": "List", "items": items})
        assert len(output.resources) == 100
        assert [d.code for d in output.diagnostics].count("k8s.skipped_document") >= 1


def _role(rules: list[dict[str, Any]], kind: str = "ClusterRole") -> dict[str, Any]:
    result = KubernetesParser().parse(
        {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": kind,
            "metadata": {"name": "r", "namespace": "ns"},
            "rules": rules,
        },
        source_path="role.yaml",
    )
    return dict(result.resources[0].properties)


class TestRbacGrantsLimitedToNamedObjects:
    """A grant limited by resourceNames is not a grant over every Secret or every pod."""

    def test_reading_every_secret_is_flagged(self) -> None:
        facts = _role([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get", "list"]}])
        assert facts["has_secrets_read"] is True

    def test_reading_the_one_secret_it_names_is_not(self) -> None:
        facts = _role(
            [
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "resourceNames": ["tls-cert"],
                    "verbs": ["get"],
                }
            ]
        )
        assert facts["has_secrets_read"] is False

    def test_a_named_grant_does_not_hide_a_broad_one_in_the_next_rule(self) -> None:
        facts = _role(
            [
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "resourceNames": ["tls-cert"],
                    "verbs": ["get"],
                },
                {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]},
            ]
        )
        assert facts["has_secrets_read"] is True

    def test_an_empty_resource_names_list_limits_nothing(self) -> None:
        facts = _role(
            [{"apiGroups": [""], "resources": ["secrets"], "resourceNames": [], "verbs": ["get"]}]
        )
        assert facts["has_secrets_read"] is True

    def test_a_wildcard_resource_with_names_is_not_every_secret_either(self) -> None:
        facts = _role(
            [{"apiGroups": ["*"], "resources": ["*"], "resourceNames": ["x"], "verbs": ["get"]}],
            kind="Role",
        )
        assert facts["has_secrets_read"] is False
        assert facts["has_wildcard_resources"] is True

    def test_exec_into_every_pod_is_flagged_and_into_a_named_pod_is_not(self) -> None:
        broad = _role([{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}])
        named = _role(
            [
                {
                    "apiGroups": [""],
                    "resources": ["pods/exec"],
                    "resourceNames": ["debug-0"],
                    "verbs": ["create"],
                }
            ]
        )
        assert broad["has_pod_exec"] is True
        assert named["has_pod_exec"] is False

    def test_the_other_facts_do_not_depend_on_resource_names(self) -> None:
        facts = _role(
            [
                {
                    "apiGroups": [""],
                    "resources": ["secrets"],
                    "resourceNames": ["x"],
                    "verbs": ["*", "escalate"],
                }
            ]
        )
        assert facts["has_wildcard_verbs"] is True
        assert facts["has_escalation_verbs"] is True


class TestNameSource:
    @pytest.mark.parametrize(
        ("metadata", "source"),
        [
            ({"name": "real"}, "name"),
            ({"generateName": "backup-"}, "generateName"),
            ({}, "index"),
            ({"name": ""}, "index"),
        ],
    )
    def test_the_meta_records_where_the_name_came_from(
        self, parser: KubernetesParser, metadata: dict[str, Any], source: str
    ) -> None:
        (resource,) = parser.parse(_object("Job", metadata, "batch/v1")).resources
        assert resource.meta == {"name_source": source}


def _anchors(levels: int = 12, fanout: int = 9) -> str:
    """Anchors ``x-a0`` to ``x-a11``; each is ``fanout`` aliases of the one before it."""
    lines = ["x-a0: &a0 [x, x, x, x, x, x, x, x, x]"]
    for level in range(1, levels):
        refs = ", ".join([f"*a{level - 1}"] * fanout)
        lines.append(f"x-a{level}: &a{level} [{refs}]")
    return "\n".join(lines)


class TestAliasBombsInScalarFields:
    """A field a parser turns into text must not expand a bomb: str() of a list walks it all."""

    BOMB = "*a11"

    def _parse(self, body: str) -> ParsedOutput:
        started = time.monotonic()
        output = KubernetesParser().parse(body)
        assert time.monotonic() - started < 5
        return output

    def test_bombs_in_labels_selectors_limits_and_ids(self) -> None:
        text = f"""
apiVersion: apps/v1
kind: Deployment
metadata:
  name: d
  namespace: n
{_anchors()}
spec:
  template:
    metadata:
      labels: {{app: {self.BOMB}, ok: fine}}
    spec:
      serviceAccountName: {self.BOMB}
      securityContext: {{runAsUser: {self.BOMB}, runAsNonRoot: {self.BOMB}}}
      containers:
        - name: c
          image: {self.BOMB}
          resources: {{limits: {{cpu: {self.BOMB}, memory: {self.BOMB}}}}}
          securityContext: {{privileged: {self.BOMB}, capabilities: {{add: {self.BOMB}}}}}
"""
        (resource,) = self._parse(text).resources
        props = resource.properties
        assert props["pod_labels"] == {"ok": "fine"}
        assert props["pod_run_as_user"] is None
        assert props["pod_run_as_non_root"] is None
        assert props["has_resource_limits"] is False
        assert props["privileged"] is False
        assert props["images"] == []
        assert props["service_account_name"] == "default"

    def test_bombs_in_a_service_selector_and_ports_select_nothing(self) -> None:
        text = f"""
apiVersion: v1
kind: Service
metadata: {{name: s}}
{_anchors()}
spec:
  selector: {{app: web, tier: {self.BOMB}}}
  ports: {self.BOMB}
"""
        (resource,) = self._parse(text).resources
        assert resource.properties["selector"] == {}
        assert resource.properties["ports"] == []

    def test_bombs_in_a_network_policy_selector_cover_nothing(self) -> None:
        text = f"""
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata: {{name: p}}
{_anchors()}
spec:
  podSelector:
    matchLabels: {{app: {self.BOMB}}}
    matchExpressions: [{{key: app, operator: In, values: {self.BOMB}}}]
---
apiVersion: apps/v1
kind: Deployment
metadata: {{name: d}}
spec: {{template: {{metadata: {{labels: {{app: web}}}}, spec: {{containers: []}}}}}}
"""
        output = self._parse(text)
        deployment = next(r for r in output.resources if r.resource_type == "kubernetes_deployment")
        assert deployment.properties["ingress_policy_covered"] is False
        assert output.edges == []

    def test_bombs_in_ids_and_names_of_rbac_and_ingress(self) -> None:
        text = f"""
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata: {{name: b}}
{_anchors()}
roleRef: {{kind: {self.BOMB}, name: {self.BOMB}}}
subjects:
  - {{kind: User, name: {self.BOMB}}}
  - {{kind: Group, name: system:authenticated}}
---
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata: {{name: i}}
{_anchors()}
spec:
  rules:
    - http:
        paths:
          - backend: {{service: {{name: s, port: {{number: {self.BOMB}}}}}}}
"""
        output = self._parse(text)
        binding = next(r for r in output.resources if "binding" in r.resource_type)
        assert binding.properties["role_ref_name"] == ""
        assert binding.properties["binds_authenticated_group"] is True
        assert binding.properties["binds_unauthenticated_group"] is False
        ingress = next(r for r in output.resources if r.resource_type == "kubernetes_ingress")
        assert ingress.properties["ingress_backends"] == [{"service_name": "s", "port": None}]

    def test_an_api_version_or_namespace_that_is_a_bomb_is_text_free(self) -> None:
        text = f"""
{_anchors()}
apiVersion: {self.BOMB}
kind: ConfigMap
metadata: {{name: c, namespace: {self.BOMB}}}
"""
        (resource,) = self._parse(text).resources
        assert resource.properties["apiVersion"] == ""
        assert resource.address == "kubernetes_config_map.default.c"

    @pytest.mark.parametrize("name", [["a"], {"a": 1}, None, 7, True])
    def test_a_subject_name_that_is_not_text_does_not_crash_the_binding(self, name: Any) -> None:
        doc = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "b"},
            "roleRef": {"kind": "ClusterRole", "name": "x"},
            "subjects": [{"kind": "Group", "name": name}],
        }
        (resource,) = KubernetesParser().parse(doc).resources
        assert resource.properties["binds_unauthenticated_group"] is False
