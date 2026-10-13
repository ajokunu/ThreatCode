"""Tests for Kubernetes security rules."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.mitre import TECHNIQUE_DB, is_revoked
from threatcode.engine.rules.loader import (
    RESOURCE_TYPE_GROUPS,
    Rule,
    deprecated_rule_ids,
    load_all_rules,
    load_builtin_rules,
)
from threatcode.engine.rules.matcher import evaluate_rule
from threatcode.ir.graph import InfraGraph
from threatcode.models.threat import Severity, Threat
from threatcode.parsers.base import ParsedResource
from threatcode.parsers.kubernetes import KubernetesParser


@pytest.fixture
def k8s_rules() -> list[Rule]:
    rules = load_all_rules()
    return [r for r in rules if r.id.startswith("K8S_")]


@pytest.fixture
def insecure_resources() -> list[ParsedResource]:
    parser = KubernetesParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "kubernetes" / "insecure_deployment.yml"
    content = fixture.read_text()
    return parser.parse(content).resources


@pytest.fixture
def secure_resources() -> list[ParsedResource]:
    parser = KubernetesParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "kubernetes" / "secure_deployment.yml"
    content = fixture.read_text()
    return parser.parse(content).resources


class TestK8sRulesExist:
    def test_k8s_rules_loaded(self, k8s_rules: list[Rule]) -> None:
        rule_ids = {r.id for r in k8s_rules}
        assert "K8S_PRIVILEGED_CONTAINER" in rule_ids
        assert "K8S_RUN_AS_ROOT" in rule_ids
        assert "K8S_HOST_NETWORK" in rule_ids
        assert "K8S_LATEST_TAG" in rule_ids
        assert "K8S_CLUSTER_ADMIN_BINDING" in rule_ids
        assert len(k8s_rules) >= 20


class TestK8sRulesInsecure:
    def test_insecure_fires_rules(
        self, k8s_rules: list[Rule], insecure_resources: list[ParsedResource]
    ) -> None:
        fired = set()
        for rule in k8s_rules:
            for resource in insecure_resources:
                if rule.matches_type(resource.resource_type):
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        assert "K8S_PRIVILEGED_CONTAINER" in fired
        assert "K8S_RUN_AS_ROOT" in fired
        assert "K8S_HOST_NETWORK" in fired
        assert "K8S_HOST_PID" in fired
        assert "K8S_LATEST_TAG" in fired
        assert "K8S_HOST_PATH_VOLUME" in fired


class TestK8sRulesSecure:
    def test_secure_minimal_fires(
        self, k8s_rules: list[Rule], secure_resources: list[ParsedResource]
    ) -> None:
        fired = set()
        for rule in k8s_rules:
            for resource in secure_resources:
                if rule.matches_type(resource.resource_type):
                    if evaluate_rule(rule.condition, resource.properties):
                        fired.add(rule.id)
        # Secure deployment should not fire critical/high rules
        high_critical_fired = {
            rid
            for rid in fired
            if any(r.id == rid and r.severity in ("high", "critical") for r in k8s_rules)
        }
        assert len(high_critical_fired) == 0


# ---------------------------------------------------------------------------
# Workload kinds: the same pod spec must get the same findings whatever carries it
# ---------------------------------------------------------------------------

POD_WORKLOAD_KINDS = [
    "Pod",
    "Deployment",
    "DaemonSet",
    "StatefulSet",
    "ReplicaSet",
    "Job",
    "CronJob",
]

PRIVILEGED_POD_SPEC: dict[str, Any] = {
    "hostNetwork": True,
    "hostPID": True,
    "hostIPC": True,
    "automountServiceAccountToken": True,
    "containers": [
        {
            "name": "app",
            "image": "nginx:latest",
            "securityContext": {"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}},
            "ports": [{"containerPort": 80, "hostPort": 80}],
        }
    ],
    "volumes": [{"name": "host", "hostPath": {"path": "/"}}],
}

HARDENED_POD_SPEC: dict[str, Any] = {
    "automountServiceAccountToken": False,
    "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
    "containers": [
        {
            "name": "app",
            "image": "nginx:1.27.0",
            "securityContext": {
                "privileged": False,
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "runAsNonRoot": True,
                "capabilities": {"drop": ["ALL"]},
            },
            "resources": {"limits": {"cpu": "100m", "memory": "64Mi", "ephemeral-storage": "1Gi"}},
        }
    ],
}

# What the privileged spec above must trigger on every kind that carries a pod template
EXPECTED_ON_EVERY_KIND = {
    "K8S_PRIVILEGED_CONTAINER",
    "K8S_HOST_NETWORK",
    "K8S_HOST_PID",
    "K8S_HOST_IPC",
    "K8S_LATEST_TAG",
    "K8S_RUN_AS_ROOT",
    "K8S_HOST_PATH_VOLUME",
    "K8S_HOSTPORT_USED",
    "K8S_NO_RESOURCE_LIMITS",
    "K8S_EPHEMERAL_STORAGE_UNBOUNDED",
    "K8S_NO_SECCOMP_PROFILE",
    "K8S_DANGEROUS_CAPABILITIES",
    "K8S_ALLOW_PRIVILEGE_ESCALATION",
    "K8S_NO_SECURITY_CONTEXT_DEFAULTS",
    "K8S_DEFAULT_SERVICE_ACCOUNT",
    "K8S_AUTOMOUNT_SA_TOKEN",
}
# Rules that used to exist and were deleted; none may come back
REMOVED_RULES = {
    "K8S_NO_RESOURCE_QUOTAS",
    "K8S_NO_PDB",
    "K8S_NO_LIVENESS_PROBE",
    "K8S_NO_READINESS_PROBE",
}


def _workload(kind: str, pod_spec: dict[str, Any], name: str = "w") -> str:
    """A manifest for ``kind`` whose pod template is ``pod_spec``, nested where the kind puts it."""
    spec: dict[str, Any]
    if kind == "Pod":
        spec = pod_spec
    elif kind == "CronJob":
        spec = {
            "schedule": "* * * * *",
            "jobTemplate": {"spec": {"template": {"spec": pod_spec}}},
        }
    else:
        spec = {
            "selector": {"matchLabels": {"app": name}},
            "template": {"metadata": {"labels": {"app": name}}, "spec": pod_spec},
        }
    api_version = {"Pod": "v1", "Job": "batch/v1", "CronJob": "batch/v1"}.get(kind, "apps/v1")
    doc = {"apiVersion": api_version, "kind": kind, "metadata": {"name": name}, "spec": spec}
    return yaml.safe_dump(doc)


def _scan_manifests(*manifests: str) -> dict[str, set[str]]:
    """Rule ids per resource address after a full parse, graph and rule run."""
    text = "---\n".join(manifests)
    graph = InfraGraph.from_parsed(KubernetesParser().parse(text))
    found: dict[str, set[str]] = defaultdict(set)
    for threat in HybridEngine().analyze(graph).threats:
        if threat.rule_id:
            found[threat.resource_address].add(threat.rule_id)
    return found


class TestWorkloadKinds:
    @pytest.mark.parametrize("kind", POD_WORKLOAD_KINDS)
    def test_every_pod_workload_kind_gets_the_workload_findings(self, kind: str) -> None:
        found = _scan_manifests(_workload(kind, PRIVILEGED_POD_SPEC))
        (rule_ids,) = found.values()
        assert EXPECTED_ON_EVERY_KIND <= rule_ids, sorted(EXPECTED_ON_EVERY_KIND - rule_ids)

    def test_the_findings_are_identical_for_every_kind(self) -> None:
        by_kind = {
            kind: next(iter(_scan_manifests(_workload(kind, PRIVILEGED_POD_SPEC)).values()))
            for kind in POD_WORKLOAD_KINDS
        }
        baseline = by_kind["Deployment"]
        for kind, rule_ids in by_kind.items():
            assert rule_ids == baseline, kind

    @pytest.mark.parametrize("kind", POD_WORKLOAD_KINDS)
    def test_probe_advice_is_gone_for_every_kind(self, kind: str) -> None:
        (rule_ids,) = _scan_manifests(_workload(kind, PRIVILEGED_POD_SPEC)).values()
        assert not rule_ids & REMOVED_RULES

    @pytest.mark.parametrize("kind", POD_WORKLOAD_KINDS)
    def test_a_hardened_spec_is_clean_on_every_kind(self, kind: str) -> None:
        found = _scan_manifests(_workload(kind, HARDENED_POD_SPEC))
        (rule_ids,) = found.values()
        # What is left is advice about the cluster (the default service account, policies that
        # live in another file), never about the workload
        assert rule_ids <= {
            "K8S_DEFAULT_SERVICE_ACCOUNT",
            "K8S_NO_NETWORK_POLICY",
            "K8S_DEFAULT_ALLOW_EGRESS",
        }, sorted(rule_ids)
        assert not rule_ids & {
            "K8S_PRIVILEGED_CONTAINER",
            "K8S_HOST_NETWORK",
            "K8S_HOST_PID",
            "K8S_LATEST_TAG",
            "K8S_RUN_AS_ROOT",
            "K8S_HOST_PATH_VOLUME",
            "K8S_NO_RESOURCE_LIMITS",
            "K8S_NO_SECURITY_CONTEXT",
            "K8S_WRITABLE_ROOT_FS",
            "K8S_ALLOW_PRIVILEGE_ESCALATION",
            "K8S_AUTOMOUNT_SA_TOKEN",
            "K8S_NO_SECCOMP_PROFILE",
            "K8S_EPHEMERAL_STORAGE_UNBOUNDED",
            "K8S_CAPABILITIES_NOT_DROPPED",
        }, sorted(rule_ids)

    def test_a_bare_pod_and_a_cron_job_are_scanned_together(self) -> None:
        found = _scan_manifests(
            _workload("Pod", PRIVILEGED_POD_SPEC, name="p"),
            _workload("CronJob", HARDENED_POD_SPEC, name="c"),
        )
        assert "K8S_PRIVILEGED_CONTAINER" in found["kubernetes_pod.default.p"]
        assert "K8S_PRIVILEGED_CONTAINER" not in found["kubernetes_cron_job.default.c"]

    def test_workload_rules_cover_exactly_the_pod_workload_group(
        self, k8s_rules: list[Rule]
    ) -> None:
        group = set(RESOURCE_TYPE_GROUPS["kubernetes_pod_workloads"])
        privileged = next(r for r in k8s_rules if r.id == "K8S_PRIVILEGED_CONTAINER")
        assert set(privileged.resource_types) == group
        for rtype in group:
            assert privileged.matches_type(rtype)
        assert not privileged.matches_type("kubernetes_pod_disruption_budget")
        assert not privileged.matches_type("kubernetes_service")


class TestRbacTypes:
    ROLE = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRole",
        "metadata": {"name": "everything"},
        "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
    }
    BINDING = {
        "apiVersion": "rbac.authorization.k8s.io/v1",
        "kind": "ClusterRoleBinding",
        "metadata": {"name": "everything"},
        "roleRef": {"kind": "ClusterRole", "name": "cluster-admin"},
        "subjects": [{"kind": "User", "name": "alice"}],
    }

    def test_a_role_rule_does_not_match_a_role_binding(self) -> None:
        found = _scan_manifests(yaml.safe_dump(self.ROLE), yaml.safe_dump(self.BINDING))
        role = found["kubernetes_cluster_role.everything"]
        binding = found["kubernetes_cluster_role_binding.everything"]
        assert {"K8S_WILDCARD_RBAC_VERBS", "K8S_WILDCARD_RBAC_RESOURCES"} <= role
        assert "K8S_CLUSTER_ADMIN_BINDING" not in role
        assert binding == {"K8S_CLUSTER_ADMIN_BINDING"}

    def test_a_service_account_does_not_get_service_rules(self) -> None:
        account = {"apiVersion": "v1", "kind": "ServiceAccount", "metadata": {"name": "sa"}}
        found = _scan_manifests(yaml.safe_dump(account))
        assert found["kubernetes_service_account.default.sa"] == {"K8S_AUTOMOUNT_DEFAULT"}


class TestNamespaceLabels:
    @staticmethod
    def _namespace(labels: dict[str, str] | None) -> str:
        meta: dict[str, Any] = {"name": "team-a"}
        if labels is not None:
            meta["labels"] = labels
        return yaml.safe_dump({"apiVersion": "v1", "kind": "Namespace", "metadata": meta})

    def test_a_namespace_with_the_enforce_label_has_no_psa_finding(self) -> None:
        manifest = self._namespace({"pod-security.kubernetes.io/enforce": "restricted"})
        found = _scan_manifests(manifest)
        assert "K8S_NO_PSA_LABELS" not in found["kubernetes_namespace.team-a"]

    def test_a_namespace_without_it_has_exactly_one(self) -> None:
        graph = InfraGraph.from_parsed(KubernetesParser().parse(self._namespace({"team": "a"})))
        threats = [
            t for t in HybridEngine().analyze(graph).threats if t.rule_id == "K8S_NO_PSA_LABELS"
        ]
        assert len(threats) == 1

    def test_a_namespace_with_no_labels_at_all_has_one(self) -> None:
        found = _scan_manifests(self._namespace(None))
        assert "K8S_NO_PSA_LABELS" in found["kubernetes_namespace.team-a"]

    def test_other_pod_security_labels_do_not_satisfy_the_enforce_check(self) -> None:
        manifest = self._namespace({"pod-security.kubernetes.io/warn": "restricted"})
        found = _scan_manifests(manifest)
        assert "K8S_NO_PSA_LABELS" in found["kubernetes_namespace.team-a"]


# ---------------------------------------------------------------------------------------
# What the parser's effective properties do to the rules that read them
# ---------------------------------------------------------------------------------------


def _deployment_spec(*containers: dict[str, Any], **pod: Any) -> str:
    return _workload("Deployment", {"containers": list(containers), **pod})


def _fired(manifest: str) -> set[str]:
    (rule_ids,) = _scan_manifests(manifest).values()
    return rule_ids


def _app(**fields: Any) -> dict[str, Any]:
    return {"name": "app", "image": "registry.example.com/app:1.0.0", **fields}


class TestEffectivePropertiesReachTheRules:
    def test_a_weak_container_before_a_hardened_one_still_fires_the_container_rules(self) -> None:
        bad = _app(
            name="bad",
            securityContext={"allowPrivilegeEscalation": True, "readOnlyRootFilesystem": False},
        )
        good = _app(
            name="good",
            securityContext={
                "allowPrivilegeEscalation": False,
                "readOnlyRootFilesystem": True,
                "runAsNonRoot": True,
            },
        )
        for containers in ((bad, good), (good, bad)):
            fired = _fired(_deployment_spec(*containers))
            assert {
                "K8S_ALLOW_PRIVILEGE_ESCALATION",
                "K8S_WRITABLE_ROOT_FS",
                "K8S_RUN_AS_ROOT",
            } <= fired

    def test_pod_level_run_as_non_root_silences_the_run_as_root_rule(self) -> None:
        fired = _fired(_deployment_spec(_app(), securityContext={"runAsNonRoot": True}))
        assert "K8S_RUN_AS_ROOT" not in fired

    def test_a_pod_level_non_zero_user_silences_it_too(self) -> None:
        assert "K8S_RUN_AS_ROOT" not in _fired(
            _deployment_spec(_app(), securityContext={"runAsUser": 1000})
        )

    def test_a_container_that_opts_out_of_run_as_non_root_fires_it_again(self) -> None:
        fired = _fired(
            _deployment_spec(
                _app(securityContext={"runAsNonRoot": False}),
                securityContext={"runAsNonRoot": True},
            )
        )
        assert "K8S_RUN_AS_ROOT" in fired

    @pytest.mark.parametrize(
        ("image", "fires"),
        [
            ("registry:5000/app", True),
            ("registry:5000/app:latest", True),
            ("nginx", True),
            ("registry:5000/app:1.2", False),
            ("registry.example.com/app@sha256:" + "a" * 64, False),
        ],
    )
    def test_the_latest_tag_rule_reads_the_image_reference(self, image: str, fires: bool) -> None:
        fired = _fired(_deployment_spec(_app(image=image)))
        assert ("K8S_LATEST_TAG" in fired) is fires

    def test_the_resource_limit_rule_needs_both_cpu_and_memory(self) -> None:
        memory_only = _fired(_deployment_spec(_app(resources={"limits": {"memory": "64Mi"}})))
        both = _fired(_deployment_spec(_app(resources={"limits": {"cpu": "1", "memory": "64Mi"}})))
        assert "K8S_NO_RESOURCE_LIMITS" in memory_only
        assert "K8S_NO_RESOURCE_LIMITS" not in both

    def test_an_init_container_is_not_judged_for_limits_but_is_for_its_security_context(
        self,
    ) -> None:
        init = _app(name="init", securityContext={"privileged": True})
        main = _app(
            resources={"limits": {"cpu": "1", "memory": "64Mi"}},
            securityContext={"allowPrivilegeEscalation": False},
        )
        fired = _fired(_deployment_spec(main, initContainers=[init]))
        assert "K8S_PRIVILEGED_CONTAINER" in fired
        assert "K8S_NO_RESOURCE_LIMITS" not in fired

    def test_a_privileged_ephemeral_container_fires_the_privileged_rule(self) -> None:
        fired = _fired(
            _deployment_spec(
                _app(),
                ephemeralContainers=[
                    {
                        "name": "dbg",
                        "image": "busybox:1.36",
                        "securityContext": {"privileged": True},
                    }
                ],
            )
        )
        assert "K8S_PRIVILEGED_CONTAINER" in fired

    @pytest.mark.parametrize(
        "capability", ["ALL", "CAP_SYS_ADMIN", "BPF", "SYS_RAWIO", "net_admin"]
    )
    def test_added_capabilities_that_give_the_host_away_fire_the_dangerous_capability_rule(
        self, capability: str
    ) -> None:
        fired = _fired(
            _deployment_spec(_app(securityContext={"capabilities": {"add": [capability]}}))
        )
        assert "K8S_DANGEROUS_CAPABILITIES" in fired

    def test_harmless_capabilities_do_not(self) -> None:
        fired = _fired(
            _deployment_spec(_app(securityContext={"capabilities": {"add": ["NET_BIND_SERVICE"]}}))
        )
        assert "K8S_DANGEROUS_CAPABILITIES" not in fired

    def test_a_container_that_drops_all_capabilities_is_not_flagged_for_them(self) -> None:
        dropped = _fired(
            _deployment_spec(_app(securityContext={"capabilities": {"drop": ["ALL"]}}))
        )
        kept = _fired(_deployment_spec(_app()))
        assert "K8S_CAPABILITIES_NOT_DROPPED" not in dropped
        assert "K8S_CAPABILITIES_NOT_DROPPED" in kept

    def test_the_ingress_tls_rule_reads_the_new_property(self) -> None:
        def ingress(**spec: Any) -> str:
            return yaml.safe_dump(
                {
                    "apiVersion": "networking.k8s.io/v1",
                    "kind": "Ingress",
                    "metadata": {"name": "i"},
                    "spec": spec,
                }
            )

        without = _scan_manifests(ingress(rules=[{"host": "x"}]))["kubernetes_ingress.default.i"]
        with_tls = _scan_manifests(ingress(tls=[{"secretName": "t"}]))[
            "kubernetes_ingress.default.i"
        ]
        assert "K8S_INGRESS_NO_TLS" in without
        assert "K8S_INGRESS_NO_TLS" not in with_tls

    def test_malformed_rbac_rules_do_not_stop_the_scan(self) -> None:
        role = {
            "apiVersion": "rbac.authorization.k8s.io/v1",
            "kind": "ClusterRole",
            "metadata": {"name": "odd"},
            "rules": [None, "x", {"verbs": None, "resources": "*"}, {"verbs": ["*"]}],
        }
        found = _scan_manifests(yaml.safe_dump(role))
        assert "K8S_WILDCARD_RBAC_VERBS" in found["kubernetes_cluster_role.odd"]


# ---------------------------------------------------------------------------------------
# Helpers for the rules that read cross-document properties and RBAC
# ---------------------------------------------------------------------------------------


def _threats(*manifests: str) -> dict[str, dict[str, Threat]]:
    """Threats per resource address and rule id after a full parse, graph and rule run."""
    graph = InfraGraph.from_parsed(KubernetesParser().parse("---\n".join(manifests)))
    found: dict[str, dict[str, Threat]] = defaultdict(dict)
    for threat in HybridEngine().analyze(graph).threats:
        if threat.rule_id:
            found[threat.resource_address][threat.rule_id] = threat
    return found


def _dump(doc: dict[str, Any]) -> str:
    return yaml.safe_dump(doc)


def _rule_ids(manifest: str, address: str) -> set[str]:
    return set(_threats(manifest).get(address, {}))


def _hardened_container(**extra: Any) -> dict[str, Any]:
    return {
        "name": "web",
        "image": "registry.example.com/shop/web:1.4.2",
        "securityContext": {
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "capabilities": {"drop": ["ALL"]},
        },
        "resources": {
            "limits": {"cpu": "500m", "memory": "256Mi", "ephemeral-storage": "128Mi"},
        },
        **extra,
    }


def _hardened_pod(**pod: Any) -> dict[str, Any]:
    return {
        "serviceAccountName": "web",
        "automountServiceAccountToken": False,
        "securityContext": {
            "runAsNonRoot": True,
            "runAsUser": 10001,
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        "containers": [_hardened_container()],
        **pod,
    }


WEB = "kubernetes_deployment.shop.web"


def _web(pod_spec: dict[str, Any]) -> str:
    doc = yaml.safe_load(_workload("Deployment", pod_spec, name="web"))
    doc["metadata"]["namespace"] = "shop"
    return _dump(doc)


def _policy(
    types: list[str] | None,
    *,
    namespace: str = "shop",
    selector: dict[str, Any] | None = None,
) -> str:
    body: dict[str, Any] = {"podSelector": selector if selector is not None else {}}
    if types is not None:
        body["policyTypes"] = types
    return _dump(
        {
            "apiVersion": "networking.k8s.io/v1",
            "kind": "NetworkPolicy",
            "metadata": {"name": "p", "namespace": namespace},
            "spec": body,
        }
    )


def _service_account(automount: bool | None) -> str:
    doc: dict[str, Any] = {
        "apiVersion": "v1",
        "kind": "ServiceAccount",
        "metadata": {"name": "web", "namespace": "shop"},
    }
    if automount is not None:
        doc["automountServiceAccountToken"] = automount
    return _dump(doc)


# ---------------------------------------------------------------------------------------
# A hardened workload is clean
# ---------------------------------------------------------------------------------------


class TestHardenedWorkload:
    HARDENING = {
        "K8S_NO_SECCOMP_PROFILE",
        "K8S_RUN_AS_ROOT",
        "K8S_ALLOW_PRIVILEGE_ESCALATION",
        "K8S_WRITABLE_ROOT_FS",
        "K8S_CAPABILITIES_NOT_DROPPED",
        "K8S_NO_SECURITY_CONTEXT",
        "K8S_NO_SECURITY_CONTEXT_DEFAULTS",
        "K8S_NO_RESOURCE_LIMITS",
        "K8S_EPHEMERAL_STORAGE_UNBOUNDED",
        "K8S_AUTOMOUNT_SA_TOKEN",
        "K8S_DEFAULT_SERVICE_ACCOUNT",
        "K8S_LATEST_TAG",
    }

    def test_pod_level_seccomp_run_as_non_root_dropped_capabilities_and_limits_give_none(
        self,
    ) -> None:
        fired = _rule_ids(_web(_hardened_pod()), WEB)
        assert not fired & self.HARDENING, sorted(fired & self.HARDENING)

    def test_the_only_leftovers_are_the_policy_coverage_findings(self) -> None:
        assert _rule_ids(_web(_hardened_pod()), WEB) == {
            "K8S_NO_NETWORK_POLICY",
            "K8S_DEFAULT_ALLOW_EGRESS",
        }

    def test_with_a_default_deny_policy_nothing_is_left(self) -> None:
        found = _threats(_web(_hardened_pod()), _policy(["Ingress", "Egress"]))
        assert found == {}

    def test_removing_each_protection_brings_back_exactly_its_finding(self) -> None:
        def without(remove: str) -> set[str]:
            pod = _hardened_pod()
            container = pod["containers"][0]
            if remove == "seccomp":
                del pod["securityContext"]["seccompProfile"]
            elif remove == "non_root":
                del pod["securityContext"]["runAsNonRoot"]
                del pod["securityContext"]["runAsUser"]
            elif remove == "drop":
                del container["securityContext"]["capabilities"]
            elif remove == "limits":
                container["resources"]["limits"].pop("memory")
            return _rule_ids(_web(pod), WEB) - {"K8S_NO_NETWORK_POLICY", "K8S_DEFAULT_ALLOW_EGRESS"}

        assert without("seccomp") == {"K8S_NO_SECCOMP_PROFILE"}
        # the pod-level setting is also what K8S_NO_SECURITY_CONTEXT_DEFAULTS asks for
        assert without("non_root") == {"K8S_RUN_AS_ROOT", "K8S_NO_SECURITY_CONTEXT_DEFAULTS"}
        assert without("drop") == {"K8S_CAPABILITIES_NOT_DROPPED"}
        assert without("limits") == {"K8S_NO_RESOURCE_LIMITS"}


# ---------------------------------------------------------------------------------------
# Seccomp
# ---------------------------------------------------------------------------------------


class TestSeccomp:
    @staticmethod
    def _fires(pod: dict[str, Any]) -> bool:
        return "K8S_NO_SECCOMP_PROFILE" in _rule_ids(_web(pod), WEB)

    def test_a_pod_level_runtime_default_satisfies_the_rule(self) -> None:
        assert not self._fires(_hardened_pod())

    def test_a_pod_level_localhost_profile_satisfies_it_too(self) -> None:
        pod = _hardened_pod()
        pod["securityContext"]["seccompProfile"] = {
            "type": "Localhost",
            "localhostProfile": "profiles/app.json",
        }
        assert not self._fires(pod)

    def test_no_profile_anywhere_fires_it(self) -> None:
        pod = _hardened_pod()
        del pod["securityContext"]["seccompProfile"]
        assert self._fires(pod)

    def test_a_workload_with_no_security_context_at_all_fires_it(self) -> None:
        pod = {"containers": [{"name": "app", "image": "registry.example.com/app:1.0"}]}
        assert self._fires(pod)

    def test_an_unconfined_profile_fires_it(self) -> None:
        pod = _hardened_pod()
        pod["securityContext"]["seccompProfile"] = {"type": "Unconfined"}
        assert self._fires(pod)

    def test_one_container_that_opts_out_of_the_pod_profile_fires_it(self) -> None:
        pod = _hardened_pod()
        pod["containers"].append(
            _hardened_container(
                name="sidecar", securityContext={"seccompProfile": {"type": "Unconfined"}}
            )
        )
        assert self._fires(pod)

    def test_a_container_level_profile_satisfies_a_pod_without_one(self) -> None:
        pod = _hardened_pod()
        del pod["securityContext"]["seccompProfile"]
        pod["containers"][0]["securityContext"]["seccompProfile"] = {"type": "RuntimeDefault"}
        assert not self._fires(pod)


# ---------------------------------------------------------------------------------------
# NetworkPolicy coverage
# ---------------------------------------------------------------------------------------

COVERAGE = {"K8S_NO_NETWORK_POLICY", "K8S_DEFAULT_ALLOW_EGRESS"}


class TestNetworkPolicyCoverage:
    def test_a_default_deny_policy_is_silent_and_covers_the_workload(self) -> None:
        found = _threats(_web(_hardened_pod()), _policy(["Ingress", "Egress"]))
        assert "kubernetes_network_policy.shop.p" not in found
        assert not set(found.get(WEB, {})) & COVERAGE

    def test_no_rule_matches_a_network_policy_at_all(self) -> None:
        for rule in load_builtin_rules():
            assert not rule.matches_type("kubernetes_network_policy"), rule.id

    def test_an_uncovered_workload_gets_two_low_heuristic_findings(self) -> None:
        threats = _threats(_web(_hardened_pod()))[WEB]
        for rule_id in COVERAGE:
            assert threats[rule_id].severity == Severity.LOW
        rules = {r.id: r for r in load_builtin_rules()}
        for rule_id in COVERAGE:
            assert rules[rule_id].confidence == "heuristic"
            assert "same input" in rules[rule_id].description

    def test_an_ingress_only_policy_leaves_egress_uncovered(self) -> None:
        fired = set(_threats(_web(_hardened_pod()), _policy(["Ingress"]))[WEB])
        assert fired == {"K8S_DEFAULT_ALLOW_EGRESS"}

    def test_an_egress_only_policy_leaves_ingress_uncovered(self) -> None:
        fired = set(_threats(_web(_hardened_pod()), _policy(["Egress"]))[WEB])
        assert fired == {"K8S_NO_NETWORK_POLICY"}

    def test_policy_types_default_to_ingress_when_there_are_no_egress_rules(self) -> None:
        fired = set(_threats(_web(_hardened_pod()), _policy(None))[WEB])
        assert fired == {"K8S_DEFAULT_ALLOW_EGRESS"}

    def test_a_policy_in_another_namespace_covers_nothing(self) -> None:
        fired = set(
            _threats(_web(_hardened_pod()), _policy(["Ingress", "Egress"], namespace="other"))[WEB]
        )
        assert fired == COVERAGE

    def _selected(self, selector: dict[str, Any]) -> bool:
        """True when a both-direction policy with this podSelector covers the web workload."""
        found = _threats(_web(_hardened_pod()), _policy(["Ingress", "Egress"], selector=selector))
        return not set(found.get(WEB, {})) & COVERAGE

    def test_a_selector_that_matches_the_pod_labels_covers_it(self) -> None:
        assert self._selected({"matchLabels": {"app": "web"}})

    def test_a_selector_that_names_other_labels_covers_nothing(self) -> None:
        assert not self._selected({"matchLabels": {"app": "db"}})

    def test_match_expressions_select_workloads(self) -> None:
        within = {"matchExpressions": [{"key": "app", "operator": "In", "values": ["web", "api"]}]}
        outside = {"matchExpressions": [{"key": "app", "operator": "NotIn", "values": ["web"]}]}
        assert self._selected(within)
        assert not self._selected(outside)

    def test_jobs_and_pods_are_judged_too(self) -> None:
        for kind in ("Pod", "Job", "CronJob"):
            fired = set(next(iter(_threats(_workload(kind, _hardened_pod())).values())))
            assert COVERAGE <= fired, kind


# ---------------------------------------------------------------------------------------
# Service account token automounting
# ---------------------------------------------------------------------------------------


class TestAutomount:
    SA = "kubernetes_service_account.shop.web"

    def _pod(self, **pod: Any) -> dict[str, Any]:
        spec = _hardened_pod(**pod)
        spec.pop("automountServiceAccountToken", None)
        spec.update(pod)
        return spec

    def test_a_service_account_with_automount_false_silences_both_rules(self) -> None:
        found = _threats(_web(self._pod()), _service_account(False))
        assert self.SA not in found
        assert "K8S_AUTOMOUNT_SA_TOKEN" not in found.get(WEB, {})

    def test_a_service_account_that_says_nothing_fires_the_service_account_rule(self) -> None:
        found = _threats(_service_account(None))
        assert "K8S_AUTOMOUNT_DEFAULT" in found[self.SA]

    def test_a_service_account_with_automount_true_fires_both(self) -> None:
        found = _threats(_web(self._pod()), _service_account(True))
        assert "K8S_AUTOMOUNT_DEFAULT" in found[self.SA]
        assert "K8S_AUTOMOUNT_SA_TOKEN" in found[WEB]

    def test_a_pod_that_opts_out_silences_the_workload_rule_whatever_the_account_says(self) -> None:
        pod = self._pod(automountServiceAccountToken=False)
        found = _threats(_web(pod), _service_account(True))
        assert "K8S_AUTOMOUNT_SA_TOKEN" not in found.get(WEB, {})

    def test_a_pod_that_opts_in_beats_an_account_that_opts_out(self) -> None:
        pod = self._pod(automountServiceAccountToken=True)
        found = _threats(_web(pod), _service_account(False))
        assert "K8S_AUTOMOUNT_SA_TOKEN" in found[WEB]

    def test_an_account_outside_the_input_is_assumed_to_mount_the_token(self) -> None:
        assert "K8S_AUTOMOUNT_SA_TOKEN" in _threats(_web(self._pod()))[WEB]

    def test_the_workload_rule_is_heuristic_and_low(self) -> None:
        rules = {r.id: r for r in load_builtin_rules()}
        assert rules["K8S_AUTOMOUNT_SA_TOKEN"].confidence == "heuristic"
        assert rules["K8S_AUTOMOUNT_SA_TOKEN"].severity == "low"
        assert "not part of the scanned input" in rules["K8S_AUTOMOUNT_SA_TOKEN"].description

    def test_the_two_automount_rules_name_each_other_and_share_a_cause(self) -> None:
        rules = {r.id: r for r in load_builtin_rules()}
        assert "K8S_AUTOMOUNT_DEFAULT" in rules["K8S_AUTOMOUNT_SA_TOKEN"].description
        assert "K8S_AUTOMOUNT_SA_TOKEN" in rules["K8S_AUTOMOUNT_DEFAULT"].description
        assert (
            rules["K8S_AUTOMOUNT_DEFAULT"].root_cause == rules["K8S_AUTOMOUNT_SA_TOKEN"].root_cause
        )
        assert rules["K8S_AUTOMOUNT_SA_TOKEN"].root_cause


# ---------------------------------------------------------------------------------------
# Namespaces
# ---------------------------------------------------------------------------------------


class TestPodSecurityLabels:
    @staticmethod
    def _namespace(labels: dict[str, str] | None) -> str:
        meta: dict[str, Any] = {"name": "team-a"}
        if labels is not None:
            meta["labels"] = labels
        return _dump({"apiVersion": "v1", "kind": "Namespace", "metadata": meta})

    def test_every_enforcement_level_satisfies_the_rule(self) -> None:
        for level in ("privileged", "baseline", "restricted"):
            manifest = self._namespace({"pod-security.kubernetes.io/enforce": level})
            assert "K8S_NO_PSA_LABELS" not in _rule_ids(manifest, "kubernetes_namespace.team-a")

    def test_the_rule_does_not_fire_on_a_labelled_namespace_beside_an_unlabelled_one(self) -> None:
        labelled = self._namespace({"pod-security.kubernetes.io/enforce": "restricted"})
        bare = _dump({"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": "bare"}})
        found = _threats(labelled, bare)
        assert "K8S_NO_PSA_LABELS" not in found.get("kubernetes_namespace.team-a", {})
        assert "K8S_NO_PSA_LABELS" in found["kubernetes_namespace.bare"]


# ---------------------------------------------------------------------------------------
# RBAC
# ---------------------------------------------------------------------------------------

RBAC = "rbac.authorization.k8s.io/v1"


def _role(kind: str, rules: Any, name: str = "r") -> str:
    meta: dict[str, Any] = {"name": name}
    if kind == "Role":
        meta["namespace"] = "shop"
    return _dump({"apiVersion": RBAC, "kind": kind, "metadata": meta, "rules": rules})


def _binding(
    kind: str, role: str, subjects: list[dict[str, Any]], role_kind: str = "ClusterRole"
) -> str:
    meta: dict[str, Any] = {"name": "b"}
    if kind == "RoleBinding":
        meta["namespace"] = "shop"
    return _dump(
        {
            "apiVersion": RBAC,
            "kind": kind,
            "metadata": meta,
            "roleRef": {"apiGroup": "rbac.authorization.k8s.io", "kind": role_kind, "name": role},
            "subjects": subjects,
        }
    )


def _group(name: str, kind: str = "Group") -> dict[str, Any]:
    return {"kind": kind, "name": name, "apiGroup": "rbac.authorization.k8s.io"}


ROLE_ADDRESS = "kubernetes_role.shop.r"
CLUSTER_ROLE_ADDRESS = "kubernetes_cluster_role.r"
ROLE_BINDING_ADDRESS = "kubernetes_role_binding.shop.b"
CLUSTER_BINDING_ADDRESS = "kubernetes_cluster_role_binding.b"
WILDCARD_RULE = [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]


class TestRoleRules:
    def test_a_namespaced_role_with_wildcards_fires_at_the_lower_severity(self) -> None:
        threats = _threats(_role("Role", WILDCARD_RULE))[ROLE_ADDRESS]
        assert {
            "K8S_ROLE_WILDCARD_VERBS",
            "K8S_ROLE_WILDCARD_RESOURCES",
            "K8S_ROLE_WILDCARD_API_GROUPS",
        } <= set(threats)
        assert not {"K8S_WILDCARD_RBAC_VERBS", "K8S_WILDCARD_RBAC_RESOURCES"} & set(threats)
        cluster = _threats(_role("ClusterRole", WILDCARD_RULE))[CLUSTER_ROLE_ADDRESS]
        assert threats["K8S_ROLE_WILDCARD_VERBS"].severity == Severity.MEDIUM
        assert cluster["K8S_WILDCARD_RBAC_VERBS"].severity == Severity.HIGH
        assert threats["K8S_ROLE_WILDCARD_RESOURCES"].severity == Severity.MEDIUM
        assert cluster["K8S_WILDCARD_RBAC_RESOURCES"].severity == Severity.HIGH
        assert (
            threats["K8S_ROLE_WILDCARD_API_GROUPS"].severity
            < cluster["K8S_WILDCARD_RBAC_API_GROUPS"].severity
        )

    def test_a_cluster_role_gets_the_cluster_rules_and_not_the_role_ones(self) -> None:
        fired = set(_threats(_role("ClusterRole", WILDCARD_RULE))[CLUSTER_ROLE_ADDRESS])
        assert {
            "K8S_WILDCARD_RBAC_VERBS",
            "K8S_WILDCARD_RBAC_RESOURCES",
            "K8S_WILDCARD_RBAC_API_GROUPS",
        } <= fired
        assert not any(rule_id.startswith("K8S_ROLE_") for rule_id in fired)

    def test_specific_verbs_resources_and_groups_are_silent(self) -> None:
        rules = [{"apiGroups": ["apps"], "resources": ["deployments"], "verbs": ["get", "list"]}]
        assert _threats(_role("Role", rules)) == {}
        assert _threats(_role("ClusterRole", rules)) == {}

    def test_a_role_rule_never_matches_a_binding(self) -> None:
        role_rules = [r for r in load_builtin_rules() if r.matches_type("kubernetes_role")] + [
            r for r in load_builtin_rules() if r.matches_type("kubernetes_cluster_role")
        ]
        assert role_rules
        for rule in role_rules:
            assert not rule.matches_type("kubernetes_role_binding"), rule.id
            assert not rule.matches_type("kubernetes_cluster_role_binding"), rule.id

    def test_a_binding_rule_never_matches_a_role(self) -> None:
        for rule in load_builtin_rules():
            if rule.matches_type("kubernetes_role_binding") or rule.matches_type(
                "kubernetes_cluster_role_binding"
            ):
                assert not rule.matches_type("kubernetes_role"), rule.id
                assert not rule.matches_type("kubernetes_cluster_role"), rule.id

    def test_escalation_verbs_fire_in_both_kinds_and_not_without_them(self) -> None:
        for verb in ("escalate", "bind", "impersonate"):
            rules = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", verb]}]
            assert "K8S_RBAC_ESCALATION_VERBS" in _threats(_role("Role", rules))[ROLE_ADDRESS]
            assert (
                "K8S_RBAC_ESCALATION_VERBS"
                in _threats(_role("ClusterRole", rules))[CLUSTER_ROLE_ADDRESS]
            )
        plain = [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list"]}]
        assert _threats(_role("Role", plain)) == {}

    def test_reading_secrets_fires_and_reading_config_maps_does_not(self) -> None:
        secrets = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
        config = [{"apiGroups": [""], "resources": ["configmaps"], "verbs": ["get", "list"]}]
        assert (
            "K8S_RBAC_SECRETS_READ" in _threats(_role("ClusterRole", secrets))[CLUSTER_ROLE_ADDRESS]
        )
        assert "K8S_RBAC_SECRETS_READ" in _threats(_role("Role", secrets))[ROLE_ADDRESS]
        assert _threats(_role("Role", config)) == {}

    def test_a_secrets_grant_limited_by_resource_names_does_not_fire(self) -> None:
        # The parser honours resourceNames, so the rule no longer guesses
        named = [
            {
                "apiGroups": [""],
                "resources": ["secrets"],
                "resourceNames": ["tls-cert"],
                "verbs": ["get", "list", "watch"],
            }
        ]
        assert _threats(_role("Role", named)) == {}
        assert _threats(_role("ClusterRole", named)) == {}
        # A second, unlimited rule in the same role still fires
        mixed = [*named, {"apiGroups": [""], "resources": ["secrets"], "verbs": ["list"]}]
        assert "K8S_RBAC_SECRETS_READ" in _threats(_role("Role", mixed))[ROLE_ADDRESS]

    def test_reading_secrets_is_a_definitive_finding_that_says_what_it_proves(self) -> None:
        rule = next(r for r in load_builtin_rules() if r.id == "K8S_RBAC_SECRETS_READ")
        assert rule.confidence == "definitive"
        assert "cannot tell" not in rule.description
        assert "heuristic" not in rule.description
        assert "resourceNames" in rule.description
        assert "resourceNames" in rule.mitigation
        secrets = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["get"]}]
        threat = _threats(_role("Role", secrets))[ROLE_ADDRESS]["K8S_RBAC_SECRETS_READ"]
        assert threat.confidence == 1.0
        assert threat.severity == Severity.HIGH

    def test_writing_secrets_is_not_reading_them(self) -> None:
        rules = [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]}]
        assert "K8S_RBAC_SECRETS_READ" not in _threats(_role("Role", rules)).get(ROLE_ADDRESS, {})

    def test_secrets_in_another_api_group_are_not_core_secrets(self) -> None:
        rules = [{"apiGroups": ["example.com"], "resources": ["secrets"], "verbs": ["get"]}]
        assert _threats(_role("Role", rules)) == {}

    def test_pod_exec_fires_and_pod_logs_do_not(self) -> None:
        exec_rule = [{"apiGroups": [""], "resources": ["pods/exec"], "verbs": ["create"]}]
        logs = [{"apiGroups": [""], "resources": ["pods", "pods/log"], "verbs": ["get"]}]
        assert (
            "K8S_RBAC_POD_EXEC" in _threats(_role("ClusterRole", exec_rule))[CLUSTER_ROLE_ADDRESS]
        )
        assert "K8S_RBAC_POD_EXEC" in _threats(_role("Role", exec_rule))[ROLE_ADDRESS]
        assert _threats(_role("Role", logs)) == {}

    def test_malformed_rule_entries_do_not_stop_the_scan(self) -> None:
        odd = [
            None,
            "x",
            42,
            {"verbs": None, "resources": "*", "apiGroups": None},
            {"verbs": "*", "resources": 7, "apiGroups": {"a": 1}},
            {"verbs": [None, 3, "get"], "resources": [["pods"]]},
        ]
        found = _threats(_role("Role", odd))
        assert "K8S_ROLE_WILDCARD_VERBS" in found[ROLE_ADDRESS]
        assert "K8S_ROLE_WILDCARD_RESOURCES" in found[ROLE_ADDRESS]
        assert _threats(_role("ClusterRole", "not a list")) == {}
        assert _threats(_role("Role", None)) == {}


class TestBindingRules:
    ADMIN = [_group("platform-ops")]

    def test_a_role_binding_to_cluster_admin_fires_at_medium(self) -> None:
        threats = _threats(_binding("RoleBinding", "cluster-admin", self.ADMIN))
        assert set(threats[ROLE_BINDING_ADDRESS]) == {"K8S_ROLE_BINDING_ADMIN"}
        assert threats[ROLE_BINDING_ADDRESS]["K8S_ROLE_BINDING_ADMIN"].severity == Severity.MEDIUM

    def test_a_role_binding_to_a_role_named_admin_is_not_the_built_in_admin(self) -> None:
        binding = _binding("RoleBinding", "admin", self.ADMIN, role_kind="Role")
        assert _threats(binding) == {}

    def test_a_cluster_role_binding_to_cluster_admin_or_admin_fires_at_high(self) -> None:
        for role in ("cluster-admin", "admin"):
            threats = _threats(_binding("ClusterRoleBinding", role, self.ADMIN))
            assert set(threats[CLUSTER_BINDING_ADDRESS]) == {"K8S_CLUSTER_ADMIN_BINDING"}
            assert (
                threats[CLUSTER_BINDING_ADDRESS]["K8S_CLUSTER_ADMIN_BINDING"].severity
                == Severity.HIGH
            )

    def test_other_roles_are_silent(self) -> None:
        for kind in ("RoleBinding", "ClusterRoleBinding"):
            assert _threats(_binding(kind, "view", self.ADMIN)) == {}

    @pytest.mark.parametrize(
        "subject",
        [
            _group("system:anonymous", "User"),
            _group("system:unauthenticated"),
            _group("system:authenticated"),
        ],
    )
    def test_a_privileged_cluster_binding_to_a_broad_subject_is_one_critical_finding(
        self, subject: dict[str, Any]
    ) -> None:
        threats = _threats(_binding("ClusterRoleBinding", "cluster-admin", [subject]))
        assert set(threats[CLUSTER_BINDING_ADDRESS]) == {"K8S_ANONYMOUS_PRIVILEGED_BINDING"}
        finding = threats[CLUSTER_BINDING_ADDRESS]["K8S_ANONYMOUS_PRIVILEGED_BINDING"]
        assert finding.severity == Severity.CRITICAL

    def test_a_broad_subject_among_named_ones_still_counts(self) -> None:
        subjects = [_group("platform-ops"), _group("system:authenticated")]
        threats = _threats(_binding("ClusterRoleBinding", "cluster-admin", subjects))
        assert set(threats[CLUSTER_BINDING_ADDRESS]) == {"K8S_ANONYMOUS_PRIVILEGED_BINDING"}

    def test_a_non_privileged_role_for_a_broad_subject_is_high_not_critical(self) -> None:
        for kind in ("RoleBinding", "ClusterRoleBinding"):
            threats = _threats(_binding(kind, "view", [_group("system:unauthenticated")]))
            (finding,) = next(iter(threats.values())).values()
            assert finding.rule_id == "K8S_ANONYMOUS_BINDING"
            assert finding.severity == Severity.HIGH

    def test_a_role_binding_of_a_privileged_role_to_a_broad_subject_is_the_high_rule(self) -> None:
        binding = _binding("RoleBinding", "admin", [_group("system:authenticated")])
        assert set(_threats(binding)[ROLE_BINDING_ADDRESS]) == {"K8S_ANONYMOUS_BINDING"}

    @pytest.mark.parametrize(
        "role", ["system:public-info-viewer", "system:basic-user", "system:discovery"]
    )
    def test_the_discovery_roles_are_never_reported(self, role: str) -> None:
        for subject in ("system:unauthenticated", "system:authenticated"):
            for kind in ("RoleBinding", "ClusterRoleBinding"):
                assert _threats(_binding(kind, role, [_group(subject)])) == {}

    def test_a_service_account_named_like_a_broad_group_is_not_one(self) -> None:
        subject = {"kind": "ServiceAccount", "name": "system:authenticated", "namespace": "shop"}
        assert _threats(_binding("ClusterRoleBinding", "view", [subject])) == {}

    def test_malformed_subjects_do_not_stop_the_scan(self) -> None:
        subjects: list[Any] = [None, "x", {"kind": "Group"}, {"kind": "Group", "name": 3}]
        assert _threats(_binding("ClusterRoleBinding", "view", subjects)) == {}
        binding = yaml.safe_load(_binding("ClusterRoleBinding", "view", []))
        binding["subjects"] = "everyone"
        assert _threats(_dump(binding)) == {}

    def test_the_binding_rules_list_the_discovery_roles_the_design_allows(self) -> None:
        rule = next(r for r in load_builtin_rules() if r.id == "K8S_ANONYMOUS_BINDING")
        text = str(rule.condition)
        for role in ("system:public-info-viewer", "system:basic-user", "system:discovery"):
            assert role in text


# ---------------------------------------------------------------------------------------
# Services
# ---------------------------------------------------------------------------------------


def _service(service_type: str | None, ports: Any) -> str:
    spec: dict[str, Any] = {"selector": {"app": "web"}, "ports": ports}
    if service_type is not None:
        spec["type"] = service_type
    return _dump(
        {
            "apiVersion": "v1",
            "kind": "Service",
            "metadata": {"name": "svc", "namespace": "shop"},
            "spec": spec,
        }
    )


SERVICE = "kubernetes_service.shop.svc"


class TestServiceAdminPorts:
    @pytest.mark.parametrize("service_type", ["LoadBalancer", "NodePort"])
    @pytest.mark.parametrize("port", [22, 23, 3389, 5985, 5986])
    def test_an_exposed_administration_port_fires(self, service_type: str, port: int) -> None:
        fired = _rule_ids(_service(service_type, [{"port": port}]), SERVICE)
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" in fired

    def test_the_target_port_counts_as_well(self) -> None:
        manifest = _service("LoadBalancer", [{"port": 2222, "targetPort": 22}])
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" in _rule_ids(manifest, SERVICE)

    def test_a_quoted_port_number_counts(self) -> None:
        manifest = _service("NodePort", [{"port": 8022, "targetPort": "22"}])
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" in _rule_ids(manifest, SERVICE)

    def test_one_admin_port_among_ordinary_ones_is_enough(self) -> None:
        manifest = _service("LoadBalancer", [{"port": 443}, {"port": 22}, {"port": 80}])
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" in _rule_ids(manifest, SERVICE)

    @pytest.mark.parametrize("service_type", [None, "ClusterIP", "ExternalName"])
    def test_a_service_that_stays_inside_the_cluster_is_silent(
        self, service_type: str | None
    ) -> None:
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" not in _rule_ids(
            _service(service_type, [{"port": 22}]), SERVICE
        )

    def test_ordinary_ports_are_silent(self) -> None:
        manifest = _service("LoadBalancer", [{"port": 443, "targetPort": 8443}, {"port": 80}])
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" not in _rule_ids(manifest, SERVICE)

    def test_a_port_that_merely_contains_the_digits_is_not_ssh(self) -> None:
        manifest = _service("LoadBalancer", [{"port": 2222}, {"port": 222}, {"port": 3389 + 1}])
        assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" not in _rule_ids(manifest, SERVICE)

    def test_malformed_ports_do_not_stop_the_scan(self) -> None:
        for ports in (None, "22", [None, "x", {"port": None}], {"port": 22}):
            manifest = _service("LoadBalancer", ports)
            assert "K8S_SERVICE_EXPOSES_ADMIN_PORT" not in _rule_ids(manifest, SERVICE)

    def test_the_rule_ports_are_the_shared_administration_ports(self) -> None:
        from threatcode.vocab import ADMIN_PORTS

        rule = next(r for r in load_builtin_rules() if r.id == "K8S_SERVICE_EXPOSES_ADMIN_PORT")
        numbers = {
            value
            for item in rule.condition["ports"]["any_item"]["any_of"]
            for check in item.values()
            for value in check["matches_any"]
            if isinstance(value, int)
        }
        assert numbers == set(ADMIN_PORTS)


# ---------------------------------------------------------------------------------------
# Calibration and the shape of the rule set
# ---------------------------------------------------------------------------------------

SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CAP_BY_CONFIDENCE = {"definitive": "critical", "heuristic": "high", "absence": "medium"}


class TestRuleSet:
    @pytest.fixture
    def rules(self) -> dict[str, Any]:
        return {r.id: r for r in load_builtin_rules() if r.id.startswith("K8S_")}

    def test_every_rule_respects_the_confidence_cap(self, rules: dict[str, Any]) -> None:
        for rule in rules.values():
            cap = SEVERITY_RANK[CAP_BY_CONFIDENCE[rule.confidence]]
            assert SEVERITY_RANK[rule.severity] <= cap, (rule.id, rule.severity, rule.confidence)

    def test_critical_is_definitive_and_rare(self, rules: dict[str, Any]) -> None:
        critical = {r.id for r in rules.values() if r.severity == "critical"}
        assert critical == {"K8S_PRIVILEGED_CONTAINER", "K8S_ANONYMOUS_PRIVILEGED_BINDING"}
        assert all(rules[rule_id].confidence == "definitive" for rule_id in critical)

    def test_the_rules_that_fire_on_a_missing_setting_say_so(self, rules: dict[str, Any]) -> None:
        for rule_id in (
            "K8S_NO_SECCOMP_PROFILE",
            "K8S_NO_PSA_LABELS",
            "K8S_NO_RESOURCE_LIMITS",
            "K8S_NO_SECURITY_CONTEXT",
            "K8S_WRITABLE_ROOT_FS",
            "K8S_ALLOW_PRIVILEGE_ESCALATION",
        ):
            assert rules[rule_id].confidence == "absence", rule_id

    def test_the_removed_rules_are_gone_and_recorded(self, rules: dict[str, Any]) -> None:
        assert not REMOVED_RULES & set(rules)
        assert REMOVED_RULES <= deprecated_rule_ids()

    def test_no_rule_is_about_probes_or_quotas(self, rules: dict[str, Any]) -> None:
        for rule in rules.values():
            text = f"{rule.id} {rule.title}".lower()
            assert "probe" not in text and "quota" not in text and "disruption" not in text

    def test_related_hardening_findings_share_one_root_cause(self, rules: dict[str, Any]) -> None:
        grouped = {r.id for r in rules.values() if r.root_cause == "container_hardening"}
        assert grouped == {
            "K8S_NO_SECURITY_CONTEXT",
            "K8S_NO_SECURITY_CONTEXT_DEFAULTS",
            "K8S_RUN_AS_ROOT",
            "K8S_WRITABLE_ROOT_FS",
            "K8S_ALLOW_PRIVILEGE_ESCALATION",
            "K8S_CAPABILITIES_NOT_DROPPED",
            "K8S_NO_SECCOMP_PROFILE",
        }
        wildcards = {r.id for r in rules.values() if r.root_cause == "rbac_wildcard"}
        assert len(wildcards) == 6

    def test_a_bare_workload_stacks_the_hardening_findings_under_one_cause(self) -> None:
        bare = {"containers": [{"name": "app", "image": "nginx:1.27"}]}
        threats = next(iter(_threats(_workload("Deployment", bare)).values()))
        rules = {r.id: r for r in load_builtin_rules()}
        causes = {rules[rule_id].root_cause for rule_id in threats} - {""}
        assert "container_hardening" in causes
        stacked = [r for r in threats if rules[r].root_cause == "container_hardening"]
        assert len(stacked) >= 5

    def test_every_rule_maps_to_known_unrevoked_techniques_and_derives_its_tactics(
        self, rules: dict[str, Any]
    ) -> None:
        for rule in rules.values():
            mitre = rule.metadata.get("mitre", {})
            assert mitre.get("techniques"), rule.id
            assert "tactics" not in mitre, f"{rule.id} writes tactics the engine derives"
            for technique in mitre["techniques"]:
                assert technique in TECHNIQUE_DB, (rule.id, technique)
                assert not is_revoked(technique), (rule.id, technique)

    def test_host_access_rules_map_to_escape_to_host(self, rules: dict[str, Any]) -> None:
        for rule_id in ("K8S_HOST_PID", "K8S_HOST_IPC", "K8S_HOST_PATH_VOLUME"):
            assert rules[rule_id].metadata["mitre"]["techniques"] == ["T1611"], rule_id

    def test_no_hygiene_rule_is_mapped_to_an_availability_technique(
        self, rules: dict[str, Any]
    ) -> None:
        availability = {
            r.id for r in rules.values() if "T1499" in r.metadata["mitre"]["techniques"]
        }
        assert availability == {"K8S_NO_RESOURCE_LIMITS", "K8S_EPHEMERAL_STORAGE_UNBOUNDED"}

    def test_every_rule_has_a_bad_and_a_good_example(self, rules: dict[str, Any]) -> None:
        from tests.test_rules.harness import discover_cases

        covered = {case.rule_id for case in discover_cases() if case.pending is None}
        assert set(rules) <= covered, sorted(set(rules) - covered)

    def test_the_uncovered_lists_for_kubernetes_are_empty(self) -> None:
        from tests.test_rules.harness import read_uncovered

        for group, ids in read_uncovered().items():
            if group.startswith("kubernetes__"):
                assert ids == [], group

    def test_the_workload_rules_stay_on_the_pod_workload_group(self, rules: dict[str, Any]) -> None:
        group = set(RESOURCE_TYPE_GROUPS["kubernetes_pod_workloads"])
        for rule in rules.values():
            if rule.source_group in ("kubernetes__workloads",):
                assert set(rule.resource_types) == group, rule.id

    def test_every_rule_names_a_mitigation(self, rules: dict[str, Any]) -> None:
        for rule in rules.values():
            assert rule.mitigation.strip(), rule.id

    def test_no_em_dash_in_the_rule_files(self) -> None:
        from pathlib import Path

        import threatcode.engine.rules as rules_pkg

        for path in (Path(rules_pkg.__file__).parent / "builtin" / "kubernetes").glob("*.yml"):
            assert "\u2014" not in path.read_text(encoding="utf-8"), path.name


# ---------------------------------------------------------------------------------------
# Rule integrity: a condition may only read what the parser emits
# ---------------------------------------------------------------------------------------

TESTS_DIR = Path(__file__).parent.parent


def _condition_keys(condition: Any) -> set[str]:
    """First path segment of every property a condition reads (not inside quantifiers)."""
    from threatcode.engine.rules.matcher import (
        ELEMENT_PREDICATES,
        LOGICAL_OPERATORS,
        QUANTIFIER_OPERATORS,
        parse_path,
    )

    keys: set[str] = set()
    if isinstance(condition, dict):
        for key, value in condition.items():
            if key in LOGICAL_OPERATORS:
                items = value if isinstance(value, list) else [value]
                for item in items:
                    keys |= _condition_keys(item)
            elif key not in ELEMENT_PREDICATES and key not in QUANTIFIER_OPERATORS:
                keys.add(parse_path(key)[0].text)
    return keys


def _emitted_properties() -> dict[str, set[str]]:
    """Property names per resource type over every Kubernetes example in the test tree."""
    emitted: dict[str, set[str]] = defaultdict(set)
    sources = sorted((TESTS_DIR / "test_rules" / "cases").glob("kubernetes__*/*/*.k8s.yaml"))
    sources += sorted((TESTS_DIR / "fixtures" / "kubernetes").glob("*.yml"))
    for path in sources:
        for resource in KubernetesParser().parse(path.read_text(encoding="utf-8")).resources:
            emitted[resource.resource_type] |= set(resource.properties)
    return emitted


class TestRuleIntegrity:
    def test_every_property_a_rule_reads_is_emitted_for_its_resource_types(self) -> None:
        emitted = _emitted_properties()
        dead = {}
        for rule in load_builtin_rules():
            if not rule.id.startswith("K8S_"):
                continue
            available = set().union(*(emitted.get(t, set()) for t in rule.resource_types))
            missing = _condition_keys(rule.condition) - available
            if missing:
                dead[rule.id] = sorted(missing)
        assert dead == {}

    def test_the_check_would_catch_a_rule_that_reads_a_property_nothing_emits(self) -> None:
        # the walk finds the properties of nested conditions and ignores the element conditions
        condition = {
            "all_of": [
                {"has_tls": {"equals": False}},
                {"not": {"role_ref_name": {"matches_any": ["a"]}}},
                {"ports": {"any_item": {"port": {"equals": 22}}}},
            ]
        }
        assert _condition_keys(condition) == {"has_tls", "role_ref_name", "ports"}
        assert "no_such_property" not in _emitted_properties()["kubernetes_deployment"]

    def test_the_labels_rule_reads_the_one_dotted_key(self) -> None:
        rule = next(r for r in load_builtin_rules() if r.id == "K8S_NO_PSA_LABELS")
        assert _condition_keys(rule.condition) == {"labels"}
