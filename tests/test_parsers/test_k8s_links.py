"""Facts that need the whole input: derived properties and inferred edges.

The Kubernetes parser connects the documents of one input: ServiceAccount token mounting is
settled across the pod and its ServiceAccount, NetworkPolicy coverage across a policy's
``podSelector`` and the workload labels, and the edges across names, labels and references.
Every edge it returns is inferred (``declared`` is false) and names a ``relation``.
"""

from __future__ import annotations

import time
from typing import Any

import pytest
import yaml

from threatcode.ir.graph import InfraGraph
from threatcode.parsers._k8s_links import effective_policy_types, selector_matches
from threatcode.parsers.base import ParsedEdge, ParsedOutput
from threatcode.parsers.kubernetes import KubernetesParser


def _deployment(
    name: str = "web",
    namespace: str | None = "apps",
    labels: dict[str, str] | None = None,
    **pod: Any,
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name}
    if namespace is not None:
        metadata["namespace"] = namespace
    pod_labels = labels if labels is not None else {"app": name}
    return {
        "apiVersion": "apps/v1",
        "kind": "Deployment",
        "metadata": metadata,
        "spec": {
            "selector": {"matchLabels": pod_labels},
            "template": {
                "metadata": {"labels": pod_labels},
                "spec": {"containers": [{"name": "c", "image": "app:1"}], **pod},
            },
        },
    }


def _service(
    name: str = "web",
    namespace: str | None = "apps",
    selector: dict[str, str] | None = None,
    service_type: str = "ClusterIP",
) -> dict[str, Any]:
    metadata: dict[str, Any] = {"name": name}
    if namespace is not None:
        metadata["namespace"] = namespace
    return {
        "apiVersion": "v1",
        "kind": "Service",
        "metadata": metadata,
        "spec": {"type": service_type, "selector": {"app": name} if selector is None else selector},
    }


def _account(name: str = "web", namespace: str = "apps", **fields: Any) -> dict[str, Any]:
    return {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": name, "namespace": namespace},
        **fields,
    }


def _policy(
    name: str,
    namespace: str = "apps",
    pod_selector: Any = None,
    **spec: Any,
) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"podSelector": {} if pod_selector is None else pod_selector, **spec},
    }


def _ingress(
    name: str = "web", namespace: str = "apps", service: str = "web", **spec: Any
) -> dict[str, Any]:
    return {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "Ingress",
        "metadata": {"name": name, "namespace": namespace},
        "spec": {
            "rules": [
                {
                    "http": {
                        "paths": [{"path": "/", "backend": {"service": {"name": service}}}],
                    }
                }
            ],
            **spec,
        },
    }


def _parse(*docs: dict[str, Any]) -> ParsedOutput:
    return KubernetesParser().parse("---\n".join(yaml.safe_dump(d) for d in docs))


def _props(output: ParsedOutput, address: str) -> dict[str, Any]:
    (resource,) = [r for r in output.resources if r.address == address]
    return resource.properties


def _edges(output: ParsedOutput) -> set[tuple[str, str, str, str]]:
    return {(e.source, e.target, e.edge_type, e.metadata["relation"]) for e in output.edges}


# ---------------------------------------------------------------------------------------
# Label selectors
# ---------------------------------------------------------------------------------------


class TestSelectors:
    LABELS = {"app": "web", "tier": "frontend", "version": "2"}

    @pytest.mark.parametrize(
        ("selector", "expected"),
        [
            (None, True),
            ({}, True),
            ({"matchLabels": {"app": "web"}}, True),
            ({"matchLabels": {"app": "web", "tier": "frontend"}}, True),
            ({"matchLabels": {"app": "api"}}, False),
            ({"matchLabels": {"app": "web", "tier": "backend"}}, False),
            ({"matchLabels": {"missing": "x"}}, False),
            ({"matchLabels": {"version": 2}}, True),
            (
                {"matchExpressions": [{"key": "tier", "operator": "In", "values": ["frontend"]}]},
                True,
            ),
            (
                {"matchExpressions": [{"key": "tier", "operator": "In", "values": ["backend"]}]},
                False,
            ),
            ({"matchExpressions": [{"key": "gone", "operator": "In", "values": ["x"]}]}, False),
            (
                {"matchExpressions": [{"key": "tier", "operator": "NotIn", "values": ["backend"]}]},
                True,
            ),
            (
                {
                    "matchExpressions": [
                        {"key": "tier", "operator": "NotIn", "values": ["frontend"]}
                    ]
                },
                False,
            ),
            ({"matchExpressions": [{"key": "gone", "operator": "NotIn", "values": ["x"]}]}, True),
            ({"matchExpressions": [{"key": "app", "operator": "Exists"}]}, True),
            ({"matchExpressions": [{"key": "gone", "operator": "Exists"}]}, False),
            ({"matchExpressions": [{"key": "gone", "operator": "DoesNotExist"}]}, True),
            ({"matchExpressions": [{"key": "app", "operator": "DoesNotExist"}]}, False),
            (
                {
                    "matchLabels": {"app": "web"},
                    "matchExpressions": [{"key": "tier", "operator": "In", "values": ["backend"]}],
                },
                False,
            ),
            (
                {
                    "matchLabels": {"app": "web"},
                    "matchExpressions": [{"key": "tier", "operator": "In", "values": ["frontend"]}],
                },
                True,
            ),
        ],
    )
    def test_selector_semantics(self, selector: Any, expected: bool) -> None:
        assert selector_matches(selector, self.LABELS) is expected

    @pytest.mark.parametrize(
        "selector",
        [
            "placeholder",
            {"matchLabels": "placeholder"},
            {"matchExpressions": "placeholder"},
            {"matchExpressions": ["x"]},
            {"matchExpressions": [{"key": "app", "operator": "Contains"}]},
            {"matchExpressions": [{"operator": "Exists"}]},
        ],
    )
    def test_a_selector_that_cannot_be_read_selects_nothing(self, selector: Any) -> None:
        assert selector_matches(selector, self.LABELS) is False

    def test_an_empty_selector_selects_a_pod_with_no_labels(self) -> None:
        assert selector_matches({}, {}) is True
        assert selector_matches({"matchLabels": {"app": "web"}}, {}) is False


# ---------------------------------------------------------------------------------------
# ServiceAccount token mounting
# ---------------------------------------------------------------------------------------

WEB = "kubernetes_deployment.apps.web"


class TestAutomount:
    def test_a_service_account_records_its_own_setting(self) -> None:
        output = _parse(
            _account("off", automountServiceAccountToken=False),
            _account("on", automountServiceAccountToken=True),
            _account("unset"),
        )
        assert _props(output, "kubernetes_service_account.apps.off")["automount_sa_token"] is False
        assert _props(output, "kubernetes_service_account.apps.on")["automount_sa_token"] is True
        assert _props(output, "kubernetes_service_account.apps.unset")["automount_sa_token"] is None

    def test_the_service_account_setting_applies_when_the_pod_says_nothing(self) -> None:
        output = _parse(
            _account("web", automountServiceAccountToken=False),
            _deployment(serviceAccountName="web"),
        )
        props = _props(output, WEB)
        assert props["effective_automount_sa_token"] is False
        assert props["sa_resolved"] is True

    def test_a_pod_setting_of_true_beats_a_service_account_that_disables_it(self) -> None:
        output = _parse(
            _account("web", automountServiceAccountToken=False),
            _deployment(serviceAccountName="web", automountServiceAccountToken=True),
        )
        assert _props(output, WEB)["effective_automount_sa_token"] is True

    def test_a_pod_setting_of_false_beats_a_service_account_that_enables_it(self) -> None:
        output = _parse(
            _account("web", automountServiceAccountToken=True),
            _deployment(serviceAccountName="web", automountServiceAccountToken=False),
        )
        assert _props(output, WEB)["effective_automount_sa_token"] is False

    def test_the_default_is_to_mount_the_token(self) -> None:
        output = _parse(_account("web"), _deployment(serviceAccountName="web"))
        props = _props(output, WEB)
        assert props["effective_automount_sa_token"] is True
        assert props["sa_resolved"] is True

    def test_a_service_account_defined_elsewhere_is_unresolved(self) -> None:
        props = _props(_parse(_deployment(serviceAccountName="elsewhere")), WEB)
        assert props["effective_automount_sa_token"] is True
        assert props["sa_resolved"] is False

    def test_a_pod_setting_is_resolved_without_any_service_account(self) -> None:
        props = _props(_parse(_deployment(automountServiceAccountToken=False)), WEB)
        assert props["effective_automount_sa_token"] is False
        assert props["sa_resolved"] is True

    def test_the_account_must_be_in_the_same_namespace(self) -> None:
        output = _parse(
            _account("web", namespace="other", automountServiceAccountToken=False),
            _deployment(serviceAccountName="web"),
        )
        props = _props(output, WEB)
        assert props["effective_automount_sa_token"] is True
        assert props["sa_resolved"] is False

    def test_the_default_service_account_is_used_when_the_pod_names_none(self) -> None:
        output = _parse(_account("default", automountServiceAccountToken=False), _deployment())
        assert _props(output, WEB)["effective_automount_sa_token"] is False

    def test_the_pod_value_the_old_rule_reads_is_unchanged(self) -> None:
        output = _parse(
            _account("web", automountServiceAccountToken=False),
            _deployment(serviceAccountName="web"),
        )
        # the rules read effective_automount_sa_token; this raw pod value stays as written
        assert _props(output, WEB)["automount_sa_token"] is True


# ---------------------------------------------------------------------------------------
# NetworkPolicy coverage
# ---------------------------------------------------------------------------------------


class TestNetworkPolicyCoverage:
    def test_the_effective_policy_types_follow_the_api_defaults(self) -> None:
        assert effective_policy_types({"policyTypes": ["Egress"]}) == ["Egress"]
        assert effective_policy_types({"policyTypes": ["Ingress", "Egress"]}) == [
            "Egress",
            "Ingress",
        ]
        assert effective_policy_types({}) == ["Ingress"]
        assert effective_policy_types({"ingress": [{}]}) == ["Ingress"]
        assert effective_policy_types({"egress": [{"to": []}]}) == ["Ingress", "Egress"]
        assert effective_policy_types({"policyTypes": [], "egress": [{}]}) == ["Ingress", "Egress"]
        assert effective_policy_types({"egress": []}) == ["Ingress"]
        assert effective_policy_types({"policyTypes": ["Nonsense"]}) == ["Ingress"]

    def test_a_workload_with_no_policy_is_uncovered(self) -> None:
        props = _props(_parse(_deployment()), WEB)
        assert props["ingress_policy_covered"] is False
        assert props["egress_policy_covered"] is False
        assert props["policy_scope"] == "single-input"

    def test_a_default_deny_policy_covers_both_directions(self) -> None:
        output = _parse(
            _deployment(),
            _policy("deny", policyTypes=["Ingress", "Egress"]),
        )
        props = _props(output, WEB)
        assert props["ingress_policy_covered"] is True
        assert props["egress_policy_covered"] is True

    def test_an_ingress_only_policy_leaves_egress_uncovered(self) -> None:
        output = _parse(
            _deployment(),
            _policy("ingress", policyTypes=["Ingress"], ingress=[{"from": [{"podSelector": {}}]}]),
        )
        props = _props(output, WEB)
        assert props["ingress_policy_covered"] is True
        assert props["egress_policy_covered"] is False

    def test_an_egress_only_policy_leaves_ingress_uncovered(self) -> None:
        output = _parse(_deployment(), _policy("egress", policyTypes=["Egress"]))
        props = _props(output, WEB)
        assert props["ingress_policy_covered"] is False
        assert props["egress_policy_covered"] is True

    def test_a_policy_without_policy_types_covers_ingress_and_egress_only_with_egress_rules(
        self,
    ) -> None:
        plain = _props(_parse(_deployment(), _policy("p", ingress=[{}])), WEB)
        assert plain["ingress_policy_covered"] is True
        assert plain["egress_policy_covered"] is False
        both = _props(
            _parse(_deployment(), _policy("p", egress=[{"to": [{"podSelector": {}}]}])), WEB
        )
        assert both["ingress_policy_covered"] is True
        assert both["egress_policy_covered"] is True

    def test_a_policy_in_another_namespace_covers_nothing_here(self) -> None:
        output = _parse(
            _deployment(namespace="apps"),
            _policy("deny", namespace="other", policyTypes=["Ingress", "Egress"]),
        )
        props = _props(output, WEB)
        assert props["ingress_policy_covered"] is False
        assert props["egress_policy_covered"] is False

    def test_a_policy_with_no_namespace_is_in_default(self) -> None:
        policy = _policy("deny", policyTypes=["Ingress"])
        del policy["metadata"]["namespace"]
        output = _parse(_deployment(namespace=None), policy)
        assert _props(output, "kubernetes_deployment.default.web")["ingress_policy_covered"] is True

    def test_match_labels_select_only_matching_workloads(self) -> None:
        output = _parse(
            _deployment("guarded"),
            _deployment("exposed"),
            _policy("p", pod_selector={"matchLabels": {"app": "guarded"}}, policyTypes=["Ingress"]),
        )
        assert (
            _props(output, "kubernetes_deployment.apps.guarded")["ingress_policy_covered"] is True
        )
        assert (
            _props(output, "kubernetes_deployment.apps.exposed")["ingress_policy_covered"] is False
        )

    def test_match_expressions_select_workloads(self) -> None:
        output = _parse(
            _deployment("a", labels={"app": "a", "tier": "frontend"}),
            _deployment("b", labels={"app": "b", "tier": "backend"}),
            _deployment("c", labels={"app": "c"}),
            _policy(
                "p",
                pod_selector={
                    "matchExpressions": [
                        {"key": "tier", "operator": "In", "values": ["frontend", "edge"]}
                    ]
                },
                policyTypes=["Ingress"],
            ),
        )
        covered = {
            r.name: r.properties["ingress_policy_covered"]
            for r in output.resources
            if r.resource_type == "kubernetes_deployment"
        }
        assert covered == {"a": True, "b": False, "c": False}

    def test_every_workload_kind_can_be_covered(self) -> None:
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "p", "namespace": "apps", "labels": {"app": "web"}},
            "spec": {"containers": [{"name": "c", "image": "a:1"}]},
        }
        job = {
            "apiVersion": "batch/v1",
            "kind": "CronJob",
            "metadata": {"name": "j", "namespace": "apps"},
            "spec": {
                "jobTemplate": {
                    "spec": {
                        "template": {
                            "metadata": {"labels": {"app": "web"}},
                            "spec": {"containers": [{"name": "c", "image": "a:1"}]},
                        }
                    }
                }
            },
        }
        output = _parse(pod, job, _policy("deny", policyTypes=["Ingress", "Egress"]))
        assert _props(output, "kubernetes_pod.apps.p")["egress_policy_covered"] is True
        assert _props(output, "kubernetes_cron_job.apps.j")["egress_policy_covered"] is True

    def test_the_policy_records_its_effective_types(self) -> None:
        output = _parse(_policy("p", policyTypes=["Egress"]))
        props = _props(output, "kubernetes_network_policy.apps.p")
        assert props["effective_policy_types"] == ["Egress"]
        assert props["has_egress_rules"] is False
        assert props["has_ingress_rules"] is False

    def test_a_selector_that_cannot_be_read_covers_nothing(self) -> None:
        output = _parse(_deployment(), _policy("p", pod_selector="placeholder"))
        assert _props(output, WEB)["ingress_policy_covered"] is False


# ---------------------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------------------


class TestEdges:
    def test_every_edge_is_inferred_and_names_its_relation(self) -> None:
        output = _parse(
            _ingress(),
            _service(),
            _deployment(serviceAccountName="web"),
            _account("web"),
            _policy("deny"),
        )
        assert output.edges
        for edge in output.edges:
            assert isinstance(edge, ParsedEdge)
            assert edge.declared is False
            assert edge.metadata["relation"]

    def test_an_ingress_routes_to_the_service_it_names(self) -> None:
        output = _parse(_ingress(service="web"), _service("web"))
        assert _edges(output) == {
            (
                "kubernetes_ingress.apps.web",
                "kubernetes_service.apps.web",
                "network_flow",
                "backend",
            )
        }

    def test_an_ingress_default_backend_and_legacy_backends_route_too(self) -> None:
        default_backend = _ingress(service="web", defaultBackend={"service": {"name": "fallback"}})
        legacy = {
            "apiVersion": "extensions/v1beta1",
            "kind": "Ingress",
            "metadata": {"name": "old", "namespace": "apps"},
            "spec": {
                "backend": {"serviceName": "legacy", "servicePort": 80},
                "rules": [
                    {
                        "http": {
                            "paths": [
                                {"backend": {"serviceName": "legacy-path", "servicePort": 80}}
                            ]
                        }
                    }
                ],
            },
        }
        output = _parse(
            default_backend,
            legacy,
            _service("web"),
            _service("fallback"),
            _service("legacy"),
            _service("legacy-path"),
        )
        targets = {(e.source, e.target) for e in output.edges if e.edge_type == "network_flow"}
        assert ("kubernetes_ingress.apps.web", "kubernetes_service.apps.fallback") in targets
        assert ("kubernetes_ingress.apps.web", "kubernetes_service.apps.web") in targets
        assert ("kubernetes_ingress.apps.old", "kubernetes_service.apps.legacy") in targets
        assert ("kubernetes_ingress.apps.old", "kubernetes_service.apps.legacy-path") in targets

    def test_an_ingress_backend_in_another_namespace_is_not_linked(self) -> None:
        output = _parse(_ingress(service="web"), _service("web", namespace="other"))
        assert output.edges == []

    def test_an_ingress_to_a_service_that_is_not_in_the_input_is_dropped(self) -> None:
        assert _parse(_ingress(service="gone")).edges == []

    def test_a_service_selects_the_workloads_whose_pod_labels_match(self) -> None:
        output = _parse(
            _service("web", selector={"app": "web"}),
            _deployment("web", labels={"app": "web", "tier": "frontend"}),
            _deployment("api", labels={"app": "api"}),
        )
        assert _edges(output) == {
            (
                "kubernetes_service.apps.web",
                "kubernetes_deployment.apps.web",
                "network_flow",
                "selects",
            )
        }

    def test_a_service_selector_must_be_a_subset_of_the_pod_labels(self) -> None:
        output = _parse(
            _service("web", selector={"app": "web", "tier": "backend"}),
            _deployment("web", labels={"app": "web", "tier": "frontend"}),
        )
        assert output.edges == []

    def test_a_service_selecting_several_workloads_links_each(self) -> None:
        output = _parse(
            _service("shared", selector={"team": "core"}),
            _deployment("a", labels={"team": "core", "app": "a"}),
            _deployment("b", labels={"team": "core", "app": "b"}),
        )
        assert {e.target for e in output.edges} == {
            "kubernetes_deployment.apps.a",
            "kubernetes_deployment.apps.b",
        }

    def test_a_service_with_no_selector_links_to_nothing(self) -> None:
        output = _parse(_service("headless", selector={}), _deployment())
        assert output.edges == []

    def test_a_service_selects_only_workloads_in_its_own_namespace(self) -> None:
        output = _parse(
            _service("web", namespace="prod"),
            _deployment("web", namespace="staging"),
        )
        assert output.edges == []

    def test_same_named_services_in_two_namespaces_each_select_their_own_workload(self) -> None:
        output = _parse(
            _service("web", namespace="prod"),
            _service("web", namespace="staging"),
            _deployment("web", namespace="prod"),
            _deployment("web", namespace="staging"),
        )
        assert _edges(output) == {
            (
                "kubernetes_service.prod.web",
                "kubernetes_deployment.prod.web",
                "network_flow",
                "selects",
            ),
            (
                "kubernetes_service.staging.web",
                "kubernetes_deployment.staging.web",
                "network_flow",
                "selects",
            ),
        }

    def test_a_service_selects_a_bare_pod_by_its_metadata_labels(self) -> None:
        pod = {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "shell", "namespace": "apps", "labels": {"run": "shell"}},
            "spec": {"containers": [{"name": "c", "image": "a:1"}]},
        }
        output = _parse(_service("shell", selector={"run": "shell"}), pod)
        assert _edges(output) == {
            (
                "kubernetes_service.apps.shell",
                "kubernetes_pod.apps.shell",
                "network_flow",
                "selects",
            )
        }

    def test_a_workload_reads_its_secrets_config_maps_and_claims(self) -> None:
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "s", "namespace": "apps"},
        }
        config = {
            "apiVersion": "v1",
            "kind": "ConfigMap",
            "metadata": {"name": "c", "namespace": "apps"},
        }
        claim = {
            "apiVersion": "v1",
            "kind": "PersistentVolumeClaim",
            "metadata": {"name": "data", "namespace": "apps"},
        }
        pod_spec = {
            "containers": [
                {
                    "name": "c",
                    "image": "a:1",
                    "envFrom": [{"configMapRef": {"name": "c"}}],
                    "env": [
                        {"name": "T", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}
                    ],
                }
            ],
            "volumes": [{"name": "d", "persistentVolumeClaim": {"claimName": "data"}}],
        }
        deployment = _deployment()
        deployment["spec"]["template"]["spec"] = pod_spec
        output = _parse(secret, config, claim, deployment)
        assert _edges(output) == {
            (WEB, "kubernetes_pvc.apps.data", "dependency", "mounts"),
            (WEB, "kubernetes_config_map.apps.c", "dependency", "env_from"),
            (WEB, "kubernetes_secret.apps.s", "dependency", "secret_key_ref"),
        }

    def test_every_reference_form_is_read(self) -> None:
        pod_spec = {
            "containers": [
                {
                    "name": "c",
                    "image": "a:1",
                    "envFrom": [{"secretRef": {"name": "from-secret"}}],
                    "env": [
                        {
                            "name": "A",
                            "valueFrom": {"configMapKeyRef": {"name": "key-config", "key": "k"}},
                        }
                    ],
                }
            ],
            "initContainers": [
                {
                    "name": "i",
                    "image": "a:1",
                    "env": [
                        {
                            "name": "B",
                            "valueFrom": {"secretKeyRef": {"name": "init-secret", "key": "k"}},
                        }
                    ],
                }
            ],
            "volumes": [
                {"name": "a", "secret": {"secretName": "vol-secret"}},
                {"name": "b", "configMap": {"name": "vol-config"}},
                {
                    "name": "c",
                    "projected": {
                        "sources": [
                            {"secret": {"name": "projected-secret"}},
                            {"configMap": {"name": "projected-config"}},
                        ]
                    },
                },
            ],
        }
        deployment = _deployment()
        deployment["spec"]["template"]["spec"] = pod_spec
        docs = [
            {"apiVersion": "v1", "kind": kind, "metadata": {"name": name, "namespace": "apps"}}
            for kind, name in [
                ("Secret", "from-secret"),
                ("ConfigMap", "key-config"),
                ("Secret", "init-secret"),
                ("Secret", "vol-secret"),
                ("ConfigMap", "vol-config"),
                ("Secret", "projected-secret"),
                ("ConfigMap", "projected-config"),
            ]
        ]
        output = _parse(*docs, deployment)
        relations = {e.target.rsplit(".", 1)[1]: e.metadata["relation"] for e in output.edges}
        assert relations == {
            "from-secret": "env_from",
            "key-config": "config_map_key_ref",
            "init-secret": "secret_key_ref",
            "vol-secret": "mounts",
            "vol-config": "mounts",
            "projected-secret": "mounts",
            "projected-config": "mounts",
        }
        props = _props(output, WEB)
        assert props["secret_refs"] == [
            "from-secret",
            "init-secret",
            "projected-secret",
            "vol-secret",
        ]
        assert props["config_map_refs"] == ["key-config", "projected-config", "vol-config"]
        assert props["pvc_refs"] == []

    def test_a_secret_in_another_namespace_is_not_linked(self) -> None:
        secret = {
            "apiVersion": "v1",
            "kind": "Secret",
            "metadata": {"name": "s", "namespace": "other"},
        }
        deployment = _deployment()
        deployment["spec"]["template"]["spec"]["containers"][0]["env"] = [
            {"name": "T", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}
        ]
        assert _parse(secret, deployment).edges == []

    def test_a_workload_runs_as_its_service_account(self) -> None:
        output = _parse(_deployment(serviceAccountName="web"), _account("web"))
        assert _edges(output) == {
            (WEB, "kubernetes_service_account.apps.web", "iam_binding", "runs_as")
        }

    def test_the_legacy_service_account_field_names_the_account_too(self) -> None:
        output = _parse(_deployment(serviceAccount="web"), _account("web"))
        assert len(output.edges) == 1

    def test_the_default_service_account_is_linked_only_when_it_is_in_the_input(self) -> None:
        assert _parse(_deployment()).edges == []
        output = _parse(_deployment(), _account("default"))
        assert _edges(output) == {
            (WEB, "kubernetes_service_account.apps.default", "iam_binding", "runs_as")
        }

    def test_a_service_account_in_another_namespace_is_not_linked(self) -> None:
        output = _parse(_deployment(serviceAccountName="web"), _account("web", namespace="other"))
        assert output.edges == []

    def test_a_role_binding_grants_its_role_and_names_its_subjects(self) -> None:
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "Role",
            "metadata": {"name": "reader", "namespace": "apps"},
            "rules": [],
        }
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "reader", "namespace": "apps"},
            "roleRef": {"kind": "Role", "name": "reader"},
            "subjects": [
                {"kind": "ServiceAccount", "name": "web", "namespace": "apps"},
                {"kind": "ServiceAccount", "name": "worker"},
                {"kind": "User", "name": "alice"},
            ],
        }
        output = _parse(role, binding, _account("web"), _account("worker"))
        assert _edges(output) == {
            (
                "kubernetes_role_binding.apps.reader",
                "kubernetes_role.apps.reader",
                "iam_binding",
                "grants",
            ),
            (
                "kubernetes_role_binding.apps.reader",
                "kubernetes_service_account.apps.web",
                "iam_binding",
                "bound_subject",
            ),
            (
                "kubernetes_role_binding.apps.reader",
                "kubernetes_service_account.apps.worker",
                "iam_binding",
                "bound_subject",
            ),
        }

    def test_a_role_binding_may_grant_a_cluster_role(self) -> None:
        cluster_role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "view"},
            "rules": [],
        }
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "RoleBinding",
            "metadata": {"name": "view", "namespace": "apps"},
            "roleRef": {"kind": "ClusterRole", "name": "view"},
            "subjects": [],
        }
        output = _parse(cluster_role, binding)
        assert _edges(output) == {
            (
                "kubernetes_role_binding.apps.view",
                "kubernetes_cluster_role.view",
                "iam_binding",
                "grants",
            )
        }

    def test_a_cluster_role_binding_links_to_cluster_scoped_addresses_and_subject_namespaces(
        self,
    ) -> None:
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "admin"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [{"kind": "ServiceAccount", "name": "web", "namespace": "apps"}],
        }
        cluster_role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "cluster-admin"},
            "rules": [],
        }
        output = _parse(binding, cluster_role, _account("web"), _account("web", namespace="other"))
        assert _edges(output) == {
            (
                "kubernetes_cluster_role_binding.admin",
                "kubernetes_cluster_role.cluster-admin",
                "iam_binding",
                "grants",
            ),
            (
                "kubernetes_cluster_role_binding.admin",
                "kubernetes_service_account.apps.web",
                "iam_binding",
                "bound_subject",
            ),
        }

    def test_a_role_ref_that_is_not_in_the_input_is_dropped(self) -> None:
        binding = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRoleBinding",
            "metadata": {"name": "x"},
            "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
            "subjects": [],
        }
        assert _parse(binding).edges == []

    def test_a_network_policy_selects_the_workloads_it_covers(self) -> None:
        output = _parse(
            _deployment("guarded"),
            _deployment("exposed"),
            _policy("p", pod_selector={"matchLabels": {"app": "guarded"}}),
        )
        assert _edges(output) == {
            (
                "kubernetes_network_policy.apps.p",
                "kubernetes_deployment.apps.guarded",
                "dependency",
                "policy",
            )
        }

    def test_an_empty_pod_selector_selects_every_workload_of_the_namespace(self) -> None:
        output = _parse(
            _deployment("a"),
            _deployment("b"),
            _deployment("c", namespace="other"),
            _policy("all"),
        )
        assert {e.target for e in output.edges} == {
            "kubernetes_deployment.apps.a",
            "kubernetes_deployment.apps.b",
        }

    def test_edges_arrive_in_a_stable_order(self) -> None:
        docs = [
            _ingress(),
            _service(),
            _deployment(serviceAccountName="web"),
            _account("web"),
            _policy("deny"),
        ]
        assert [(e.source, e.target) for e in _parse(*docs).edges] == [
            (e.source, e.target) for e in _parse(*docs).edges
        ]

    def test_edges_reach_the_graph_as_inferred_edges_with_relations(self) -> None:
        graph = InfraGraph.from_parsed(
            _parse(_ingress(), _service(), _deployment(serviceAccountName="web"), _account("web"))
        )
        assert graph.edges
        assert all(not edge.declared for edge in graph.edges)
        assert {edge.relation for edge in graph.edges} == {"backend", "selects", "runs_as"}

    def test_duplicate_addresses_do_not_send_every_edge_to_the_first(self) -> None:
        # Two documents with one address become web and web#2 in the graph; each Service
        # selects only the document whose labels match
        first = _deployment("web", labels={"app": "one"})
        second = _deployment("web", labels={"app": "two"})
        output = _parse(
            first,
            second,
            _service("s1", selector={"app": "one"}),
            _service("s2", selector={"app": "two"}),
        )
        graph = InfraGraph.from_parsed(output)
        targets = {(e.source, e.target) for e in graph.edges}
        assert ("kubernetes_service.apps.s1", "kubernetes_deployment.apps.web") in targets
        assert ("kubernetes_service.apps.s2", "kubernetes_deployment.apps.web#2") in targets

    def test_thousands_of_services_and_workloads_link_quickly(self) -> None:
        docs: list[dict[str, Any]] = []
        for index in range(1500):
            name = f"app-{index}"
            docs.append(_deployment(name, namespace="big"))
            docs.append(_service(name, namespace="big"))
        text = "---\n".join(yaml.safe_dump(d) for d in docs)
        started = time.monotonic()
        output = KubernetesParser().parse(text)
        assert time.monotonic() - started < 10
        assert len(output.edges) == 1500


# ---------------------------------------------------------------------------------------
# RBAC properties
# ---------------------------------------------------------------------------------------


def _role(rules: Any, kind: str = "ClusterRole") -> dict[str, Any]:
    return {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": kind,
        "metadata": {"name": "r", "namespace": "apps"},
        "rules": rules,
    }


def _role_props(rules: Any, kind: str = "ClusterRole") -> dict[str, Any]:
    (resource,) = KubernetesParser().parse(_role(rules, kind)).resources
    return resource.properties


class TestRbacProperties:
    def test_wildcards_in_verbs_resources_and_api_groups(self) -> None:
        props = _role_props([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}])
        assert props["has_wildcard_verbs"] is True
        assert props["has_wildcard_resources"] is True
        assert props["has_wildcard_api_groups"] is True

    def test_a_narrow_role_has_none_of_the_flags(self) -> None:
        props = _role_props([{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}])
        for flag in (
            "has_wildcard_verbs",
            "has_wildcard_resources",
            "has_wildcard_api_groups",
            "has_escalation_verbs",
            "has_secrets_read",
            "has_pod_exec",
        ):
            assert props[flag] is False, flag

    def test_a_namespaced_role_gets_the_same_properties(self) -> None:
        props = _role_props([{"resources": ["*"], "verbs": ["*"]}], kind="Role")
        assert props["has_wildcard_verbs"] is True

    @pytest.mark.parametrize("verb", ["escalate", "bind", "impersonate"])
    def test_escalation_verbs(self, verb: str) -> None:
        props = _role_props(
            [{"apiGroups": ["rbac.authorization.k8s.io"], "resources": ["roles"], "verbs": [verb]}]
        )
        assert props["has_escalation_verbs"] is True

    @pytest.mark.parametrize("verb", ["get", "list", "watch", "*"])
    def test_reading_secrets(self, verb: str) -> None:
        props = _role_props([{"apiGroups": [""], "resources": ["secrets"], "verbs": [verb]}])
        assert props["has_secrets_read"] is True

    def test_a_wildcard_resource_reads_secrets_too(self) -> None:
        assert (
            _role_props([{"apiGroups": ["*"], "resources": ["*"], "verbs": ["get"]}])[
                "has_secrets_read"
            ]
            is True
        )

    def test_writing_secrets_is_not_reading_them(self) -> None:
        props = _role_props([{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}])
        assert props["has_secrets_read"] is False

    def test_secrets_of_another_api_group_are_not_core_secrets(self) -> None:
        props = _role_props(
            [{"apiGroups": ["external-secrets.io"], "resources": ["secrets"], "verbs": ["get"]}]
        )
        assert props["has_secrets_read"] is False

    @pytest.mark.parametrize("resource", ["pods/exec", "*", "pods/*", "*/exec"])
    def test_pod_exec(self, resource: str) -> None:
        props = _role_props([{"apiGroups": [""], "resources": [resource], "verbs": ["create"]}])
        assert props["has_pod_exec"] is True

    def test_listing_pods_is_not_exec(self) -> None:
        props = _role_props([{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}])
        assert props["has_pod_exec"] is False

    @pytest.mark.parametrize(
        "rules",
        [
            None,
            "oops",
            [None, "x", 3, []],
            [{"verbs": None, "resources": None, "apiGroups": None}],
            [{"verbs": "*", "resources": "secrets", "apiGroups": ""}],
            [{"verbs": 7, "resources": {"a": 1}, "apiGroups": True}],
            [{"verbs": ["get", 1, None], "resources": [["secrets"]]}],
        ],
    )
    def test_malformed_rules_do_not_raise(self, rules: Any) -> None:
        props = _role_props(rules)
        assert isinstance(props["has_wildcard_verbs"], bool)
        assert isinstance(props["has_secrets_read"], bool)

    def test_string_fields_are_read_as_one_element_lists(self) -> None:
        props = _role_props([{"verbs": "*", "resources": "secrets", "apiGroups": ""}])
        assert props["has_wildcard_verbs"] is True
        assert props["has_secrets_read"] is True

    def test_the_raw_rules_are_kept(self) -> None:
        rules = [{"verbs": ["get"], "resources": ["pods"]}]
        assert _role_props(rules)["rbac_rules"] == rules


class TestBindingProperties:
    @staticmethod
    def _binding(
        subjects: Any, kind: str = "ClusterRoleBinding", role: str = "view"
    ) -> dict[str, Any]:
        return {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": kind,
            "metadata": {"name": "b", "namespace": "apps"},
            "roleRef": {"kind": "ClusterRole", "name": role},
            "subjects": subjects,
        }

    def _props(self, subjects: Any) -> dict[str, Any]:
        (resource,) = KubernetesParser().parse(self._binding(subjects)).resources
        return resource.properties

    def test_anonymous_and_unauthenticated_subjects(self) -> None:
        for name, kind in (("system:anonymous", "User"), ("system:unauthenticated", "Group")):
            props = self._props([{"kind": kind, "name": name}])
            assert props["binds_unauthenticated_group"] is True
            assert props["binds_authenticated_group"] is False

    def test_the_authenticated_group(self) -> None:
        props = self._props([{"kind": "Group", "name": "system:authenticated"}])
        assert props["binds_authenticated_group"] is True
        assert props["binds_unauthenticated_group"] is False

    def test_ordinary_subjects_set_neither_flag(self) -> None:
        props = self._props(
            [
                {"kind": "User", "name": "alice"},
                {"kind": "ServiceAccount", "name": "system:anonymous", "namespace": "x"},
            ]
        )
        assert props["binds_unauthenticated_group"] is False
        assert props["binds_authenticated_group"] is False

    def test_subject_kinds_are_listed_once_sorted(self) -> None:
        props = self._props(
            [
                {"kind": "User", "name": "a"},
                {"kind": "ServiceAccount", "name": "b", "namespace": "x"},
                {"kind": "User", "name": "c"},
            ]
        )
        assert props["subject_kinds"] == ["ServiceAccount", "User"]

    @pytest.mark.parametrize("subjects", [None, "x", [None, 3, "x"], [{"kind": None, "name": 3}]])
    def test_malformed_subjects_do_not_raise(self, subjects: Any) -> None:
        props = self._props(subjects)
        assert props["binds_unauthenticated_group"] is False
        assert isinstance(props["subject_kinds"], list)

    def test_the_role_reference_keeps_its_property_names(self) -> None:
        output = KubernetesParser().parse(self._binding([], role="cluster-admin"))
        props = output.resources[0].properties
        assert props["role_ref_name"] == "cluster-admin"
        assert props["role_ref_kind"] == "ClusterRole"
