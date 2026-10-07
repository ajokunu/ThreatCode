"""Tests for Kubernetes security rules."""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Any

import pytest
import yaml

from threatcode.engine.hybrid import HybridEngine
from threatcode.engine.rules.loader import RESOURCE_TYPE_GROUPS, load_all_rules
from threatcode.engine.rules.matcher import evaluate_rule
from threatcode.ir.graph import InfraGraph
from threatcode.parsers.kubernetes import KubernetesParser


@pytest.fixture
def k8s_rules():
    rules = load_all_rules()
    return [r for r in rules if r.id.startswith("K8S_")]


@pytest.fixture
def insecure_resources():
    parser = KubernetesParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "kubernetes" / "insecure_deployment.yml"
    content = fixture.read_text()
    return parser.parse(content).resources


@pytest.fixture
def secure_resources():
    parser = KubernetesParser()
    fixture = Path(__file__).parent.parent / "fixtures" / "kubernetes" / "secure_deployment.yml"
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
    def test_secure_minimal_fires(self, k8s_rules, secure_resources) -> None:
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
LONG_RUNNING_KINDS = ["Pod", "Deployment", "DaemonSet", "StatefulSet", "ReplicaSet"]

PRIVILEGED_POD_SPEC: dict[str, Any] = {
    "hostNetwork": True,
    "hostPID": True,
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
    "securityContext": {"runAsNonRoot": True},
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
            "resources": {"limits": {"cpu": "100m", "memory": "64Mi"}},
            "livenessProbe": {"httpGet": {"path": "/", "port": 80}},
            "readinessProbe": {"httpGet": {"path": "/", "port": 80}},
        }
    ],
}

# What the privileged spec above must trigger on every kind that carries a pod template
EXPECTED_ON_EVERY_KIND = {
    "K8S_PRIVILEGED_CONTAINER",
    "K8S_HOST_NETWORK",
    "K8S_HOST_PID",
    "K8S_LATEST_TAG",
    "K8S_RUN_AS_ROOT",
    "K8S_HOST_PATH_VOLUME",
    "K8S_HOSTPORT_USED",
    "K8S_NO_RESOURCE_LIMITS",
    "K8S_DANGEROUS_CAPABILITIES",
    "K8S_ALLOW_PRIVILEGE_ESCALATION",
    "K8S_NO_SECURITY_CONTEXT_DEFAULTS",
    "K8S_DEFAULT_SERVICE_ACCOUNT",
    "K8S_AUTOMOUNT_SA_TOKEN",
}
PROBE_RULES = {"K8S_NO_LIVENESS_PROBE", "K8S_NO_READINESS_PROBE"}


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

    def test_the_findings_are_identical_for_every_kind_except_probes(self) -> None:
        by_kind = {
            kind: next(iter(_scan_manifests(_workload(kind, PRIVILEGED_POD_SPEC)).values()))
            for kind in POD_WORKLOAD_KINDS
        }
        baseline = by_kind["Deployment"] - PROBE_RULES
        for kind, rule_ids in by_kind.items():
            assert rule_ids - PROBE_RULES == baseline, kind

    @pytest.mark.parametrize("kind", LONG_RUNNING_KINDS)
    def test_long_running_kinds_get_probe_findings(self, kind: str) -> None:
        (rule_ids,) = _scan_manifests(_workload(kind, PRIVILEGED_POD_SPEC)).values()
        assert PROBE_RULES <= rule_ids

    @pytest.mark.parametrize("kind", ["Job", "CronJob"])
    def test_batch_kinds_do_not_get_probe_findings(self, kind: str) -> None:
        (rule_ids,) = _scan_manifests(_workload(kind, PRIVILEGED_POD_SPEC)).values()
        assert not rule_ids & PROBE_RULES

    @pytest.mark.parametrize("kind", POD_WORKLOAD_KINDS)
    def test_a_hardened_spec_is_clean_on_every_kind(self, kind: str) -> None:
        found = _scan_manifests(_workload(kind, HARDENED_POD_SPEC))
        (rule_ids,) = found.values()
        # The only expected leftovers are advice about defaults, never exposure
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
            "K8S_NO_LIVENESS_PROBE",
            "K8S_NO_READINESS_PROBE",
        }, sorted(rule_ids)

    def test_probe_rules_stay_off_pods_that_have_probes(self) -> None:
        (rule_ids,) = _scan_manifests(_workload("StatefulSet", HARDENED_POD_SPEC)).values()
        assert not rule_ids & PROBE_RULES

    def test_a_bare_pod_and_a_cron_job_are_scanned_together(self) -> None:
        found = _scan_manifests(
            _workload("Pod", PRIVILEGED_POD_SPEC, name="p"),
            _workload("CronJob", HARDENED_POD_SPEC, name="c"),
        )
        assert "K8S_PRIVILEGED_CONTAINER" in found["kubernetes_pod.default.p"]
        assert "K8S_PRIVILEGED_CONTAINER" not in found["kubernetes_cron_job.default.c"]

    def test_workload_rules_cover_exactly_the_pod_workload_group(self, k8s_rules) -> None:
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

    def test_a_pod_with_only_init_containers_gets_no_probe_findings(self) -> None:
        manifest = _workload("Deployment", {"containers": [], "initContainers": [_app()]})
        fired = _fired(manifest)
        assert not fired & PROBE_RULES

    def test_a_probeless_init_container_beside_a_probed_container_adds_no_probe_finding(
        self,
    ) -> None:
        probes = {
            "livenessProbe": {"httpGet": {"port": 80}},
            "readinessProbe": {"httpGet": {"port": 80}},
        }
        fired = _fired(_deployment_spec(_app(**probes), initContainers=[_app(name="init")]))
        assert not fired & PROBE_RULES

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
