"""The effective security context and container facts of Kubernetes workloads.

``_k8s_security`` reads every pod-bearing kind into one property shape. These tests cover the
Kubernetes precedence rules (container over pod), the single aggregation rule (any applicable
container unsafe makes the workload unsafe), which containers each check judges, and that the
outcome does not depend on the order of the containers.
"""

from __future__ import annotations

import itertools
from typing import Any

import pytest

from threatcode.parsers._k8s_security import (
    PLACEHOLDER_PREFIX,
    WORKLOAD_KINDS,
    container_views,
    effective_context,
    pod_template,
    security_properties,
    uses_floating_tag,
)
from threatcode.parsers.base import ParsedResource
from threatcode.parsers.kubernetes import KubernetesParser


def _pod_spec(*containers: dict[str, Any], **pod: Any) -> dict[str, Any]:
    return {"containers": list(containers), **pod}


def _container(name: str = "app", **fields: Any) -> dict[str, Any]:
    return {"name": name, "image": "registry.example.com/app:1.0.0", **fields}


def _props(*containers: dict[str, Any], **pod: Any) -> dict[str, Any]:
    return security_properties(_pod_spec(*containers, **pod))


def _manifest(kind: str, pod_spec: dict[str, Any], name: str = "w") -> dict[str, Any]:
    """A manifest of ``kind`` with ``pod_spec`` nested where that kind puts it."""
    if kind == "Pod":
        return {"apiVersion": "v1", "kind": kind, "metadata": {"name": name}, "spec": pod_spec}
    if kind == "CronJob":
        spec: dict[str, Any] = {
            "schedule": "* * * * *",
            "jobTemplate": {"spec": {"template": {"spec": pod_spec}}},
        }
    else:
        spec = {
            "selector": {"matchLabels": {"app": name}},
            "template": {"metadata": {"labels": {"app": name}}, "spec": pod_spec},
        }
    return {"apiVersion": "apps/v1", "kind": kind, "metadata": {"name": name}, "spec": spec}


def _parse_one(doc: dict[str, Any]) -> ParsedResource:
    (resource,) = KubernetesParser().parse(doc).resources
    return resource


# ---------------------------------------------------------------------------------------
# Pod specs of every kind
# ---------------------------------------------------------------------------------------


class TestPodTemplates:
    @pytest.mark.parametrize("kind", sorted(WORKLOAD_KINDS))
    def test_every_kind_yields_its_pod_spec(self, kind: str) -> None:
        pod_spec = _pod_spec(_container(), hostNetwork=True)
        template = pod_template(_manifest(kind, pod_spec))
        assert template is not None
        assert template.spec["hostNetwork"] is True
        assert template.spec["containers"][0]["name"] == "app"

    def test_a_kind_without_a_pod_has_no_template(self) -> None:
        assert pod_template({"kind": "ConfigMap", "spec": {}}) is None
        assert pod_template({"kind": "Service", "spec": {"template": {"spec": {}}}}) is None

    def test_pod_labels_come_from_the_template_and_for_a_pod_from_its_metadata(self) -> None:
        deployment = pod_template(_manifest("Deployment", _pod_spec(_container()), name="web"))
        assert deployment is not None and deployment.labels == {"app": "web"}
        pod_doc = _manifest("Pod", _pod_spec(_container()))
        pod_doc["metadata"]["labels"] = {"run": "shell"}
        pod = pod_template(pod_doc)
        assert pod is not None and pod.labels == {"run": "shell"}

    def test_numeric_and_boolean_label_values_are_text(self) -> None:
        doc = _manifest("Deployment", _pod_spec(_container()))
        doc["spec"]["template"]["metadata"]["labels"] = {"version": 2, "canary": True}
        template = pod_template(doc)
        assert template is not None
        assert template.labels == {"version": "2", "canary": "true"}

    @pytest.mark.parametrize(
        "doc",
        [
            {"kind": "Deployment", "spec": None},
            {"kind": "Deployment", "spec": {"template": None}},
            {"kind": "Deployment", "spec": {"template": {"spec": "placeholder"}}},
            {"kind": "CronJob", "spec": {"jobTemplate": None}},
            {"kind": "CronJob", "spec": {"jobTemplate": {"spec": {"template": None}}}},
            {"kind": "Pod", "spec": "placeholder"},
            {"kind": "Pod"},
        ],
    )
    def test_a_missing_or_malformed_level_is_an_empty_pod_spec(self, doc: dict[str, Any]) -> None:
        template = pod_template(doc)
        assert template is not None
        assert template.spec == {}


# ---------------------------------------------------------------------------------------
# Identical properties for identical pod specs
# ---------------------------------------------------------------------------------------

PRIVILEGED = _pod_spec(
    _container(
        "app",
        image="nginx:latest",
        securityContext={"privileged": True, "capabilities": {"add": ["SYS_ADMIN"]}},
        ports=[{"containerPort": 80, "hostPort": 80}],
    ),
    hostNetwork=True,
    hostPID=True,
    volumes=[{"name": "host", "hostPath": {"path": "/"}}],
)
SECURITY_KEYS = (
    "privileged",
    "run_as_root",
    "allow_privilege_escalation",
    "writable_root_fs",
    "capabilities_dropped",
    "dangerous_capabilities",
    "has_security_context",
    "seccomp_profile_type",
    "has_seccomp_profile",
    "uses_latest_tag",
    "has_host_port",
    "has_resource_limits",
    "has_cpu_limit",
    "has_memory_limit",
    "has_ephemeral_storage_limit",
    "images",
    "container_findings",
    "host_network",
    "host_pid",
    "host_ipc",
    "has_host_path_volume",
    "service_account_name",
)


class TestEveryKindGetsTheSameProperties:
    @pytest.mark.parametrize("kind", sorted(WORKLOAD_KINDS))
    def test_a_privileged_container_is_privileged_in_every_kind(self, kind: str) -> None:
        props = _parse_one(_manifest(kind, PRIVILEGED)).properties
        assert props["privileged"] is True
        assert props["host_network"] is True
        assert props["host_pid"] is True
        assert props["has_host_path_volume"] is True
        assert props["has_host_port"] is True
        assert props["uses_latest_tag"] is True
        assert props["dangerous_capabilities"] == ["SYS_ADMIN"]

    def test_the_security_properties_are_identical_across_kinds(self) -> None:
        baseline = _parse_one(_manifest("Deployment", PRIVILEGED)).properties
        for kind in sorted(WORKLOAD_KINDS):
            props = _parse_one(_manifest(kind, PRIVILEGED)).properties
            for key in SECURITY_KEYS:
                assert props[key] == baseline[key], (kind, key)

    @pytest.mark.parametrize("kind", sorted(WORKLOAD_KINDS))
    def test_a_hardened_spec_is_safe_in_every_kind(self, kind: str) -> None:
        hardened = _pod_spec(
            _container(
                securityContext={
                    "allowPrivilegeEscalation": False,
                    "readOnlyRootFilesystem": True,
                    "runAsNonRoot": True,
                    "capabilities": {"drop": ["ALL"]},
                    "seccompProfile": {"type": "RuntimeDefault"},
                },
                resources={"limits": {"cpu": "1", "memory": "1Gi"}},
                livenessProbe={"httpGet": {"port": 80}},
                readinessProbe={"httpGet": {"port": 80}},
            )
        )
        props = _parse_one(_manifest(kind, hardened)).properties
        assert props["privileged"] is False
        assert props["run_as_root"] is False
        assert props["allow_privilege_escalation"] is False
        assert props["writable_root_fs"] is False
        assert props["capabilities_dropped"] is True
        assert props["has_seccomp_profile"] is True
        assert props["has_resource_limits"] is True
        assert props["container_findings"] == {
            "has_ephemeral_storage_limit": ["app"],
        }


# ---------------------------------------------------------------------------------------
# Pod over container precedence
# ---------------------------------------------------------------------------------------


class TestEffectiveContext:
    def test_pod_level_run_as_non_root_applies_to_a_container_with_no_context(self) -> None:
        props = _props(_container(), securityContext={"runAsNonRoot": True})
        assert props["run_as_root"] is False

    def test_pod_level_non_zero_user_means_non_root_when_run_as_non_root_is_unset(self) -> None:
        props = _props(_container(), securityContext={"runAsUser": 10001})
        assert props["run_as_root"] is False

    def test_a_zero_user_is_root(self) -> None:
        assert _props(_container(), securityContext={"runAsUser": 0})["run_as_root"] is True

    def test_nothing_set_may_run_as_root(self) -> None:
        assert _props(_container())["run_as_root"] is True

    def test_a_container_run_as_non_root_false_beats_the_pod_true(self) -> None:
        props = _props(
            _container(securityContext={"runAsNonRoot": False}),
            securityContext={"runAsNonRoot": True},
        )
        assert props["run_as_root"] is True
        assert props["container_findings"]["run_as_root"] == ["app"]

    def test_a_container_user_overrides_the_pod_user(self) -> None:
        props = _props(
            _container(securityContext={"runAsUser": 0}), securityContext={"runAsUser": 10001}
        )
        assert props["run_as_root"] is True

    def test_a_container_non_root_overrides_a_pod_that_allows_root(self) -> None:
        props = _props(
            _container(securityContext={"runAsNonRoot": True}),
            securityContext={"runAsNonRoot": False},
        )
        assert props["run_as_root"] is False

    def test_the_seccomp_profile_is_the_container_value_else_the_pod_value(self) -> None:
        assert (
            _props(_container(), securityContext={"seccompProfile": {"type": "RuntimeDefault"}})[
                "seccomp_profile_type"
            ]
            == "RuntimeDefault"
        )
        override = _props(
            _container(securityContext={"seccompProfile": {"type": "Unconfined"}}),
            securityContext={"seccompProfile": {"type": "RuntimeDefault"}},
        )
        assert override["seccomp_profile_type"] == "Unconfined"
        assert override["has_seccomp_profile"] is False

    def test_no_seccomp_profile_anywhere_is_none(self) -> None:
        props = _props(_container())
        assert props["seccomp_profile_type"] is None
        assert props["has_seccomp_profile"] is False

    def test_a_localhost_profile_counts_as_a_profile(self) -> None:
        props = _props(
            _container(
                securityContext={"seccompProfile": {"type": "Localhost", "localhostProfile": "x"}}
            )
        )
        assert props["seccomp_profile_type"] == "Localhost"
        assert props["has_seccomp_profile"] is True

    def test_a_pod_level_context_alone_counts_as_a_security_context(self) -> None:
        assert (
            _props(_container(), securityContext={"fsGroup": 2000})["has_security_context"] is True
        )
        assert _props(_container())["has_security_context"] is False

    def test_the_effective_context_of_one_container(self) -> None:
        context = effective_context(
            {"securityContext": {"capabilities": {"add": ["cap_net_admin"], "drop": ["all"]}}},
            {"runAsUser": 5, "seccompProfile": {"type": "RuntimeDefault"}},
        )
        assert context.run_as_root is False
        assert context.run_as_user == 5
        assert context.seccomp_type == "RuntimeDefault"
        assert context.dangerous_capabilities == ("NET_ADMIN",)
        assert context.drops_all_capabilities is True
        assert context.allow_privilege_escalation is True
        assert context.writable_root_fs is True

    def test_string_booleans_are_read_and_junk_is_ignored(self) -> None:
        assert effective_context({"securityContext": {"privileged": "true"}}, {}).privileged is True
        assert effective_context({"securityContext": {"privileged": "yes"}}, {}).privileged is False
        assert (
            effective_context(
                {"securityContext": {"readOnlyRootFilesystem": "TRUE"}}, {}
            ).writable_root_fs
            is False
        )

    def test_pod_run_as_properties_keep_their_names(self) -> None:
        props = _parse_one(
            _manifest(
                "Deployment",
                _pod_spec(_container(), securityContext={"runAsNonRoot": True, "runAsUser": 7}),
            )
        ).properties
        assert props["pod_run_as_non_root"] is True
        assert props["pod_run_as_user"] == 7


# ---------------------------------------------------------------------------------------
# One aggregation rule, whatever the order
# ---------------------------------------------------------------------------------------


def _weak(name: str) -> dict[str, Any]:
    return _container(
        name,
        image="nginx:latest",
        securityContext={
            "privileged": True,
            "allowPrivilegeEscalation": True,
            "readOnlyRootFilesystem": False,
            "capabilities": {"add": ["BPF"]},
        },
        ports=[{"containerPort": 1, "hostPort": 1}],
        env=[{"name": "TOKEN", "valueFrom": {"secretKeyRef": {"name": "s", "key": "k"}}}],
    )


def _strong(name: str) -> dict[str, Any]:
    return _container(
        name,
        securityContext={
            "allowPrivilegeEscalation": False,
            "readOnlyRootFilesystem": True,
            "runAsNonRoot": True,
            "capabilities": {"drop": ["ALL"]},
            "seccompProfile": {"type": "RuntimeDefault"},
        },
        resources={
            "limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "1Gi"},
        },
        livenessProbe={"httpGet": {"port": 80}},
        readinessProbe={"httpGet": {"port": 80}},
    )


class TestAggregation:
    def test_one_unsafe_container_makes_the_workload_unsafe(self) -> None:
        props = _props(_strong("good"), _weak("bad"))
        assert props["privileged"] is True
        assert props["run_as_root"] is True
        assert props["allow_privilege_escalation"] is True
        assert props["writable_root_fs"] is True
        assert props["capabilities_dropped"] is False
        assert props["uses_latest_tag"] is True
        assert props["has_host_port"] is True
        assert props["has_resource_limits"] is False
        assert props["has_liveness_probe"] is False
        assert props["has_readiness_probe"] is False
        assert props["has_seccomp_profile"] is False
        assert props["has_security_context"] is True
        assert props["dangerous_capabilities"] == ["BPF"]
        assert props["secret_env_vars"] == ["TOKEN"]

    def test_only_safe_containers_leave_the_workload_safe(self) -> None:
        props = _props(_strong("a"), _strong("b"))
        assert props["privileged"] is False
        assert props["run_as_root"] is False
        assert props["capabilities_dropped"] is True
        assert props["has_resource_limits"] is True
        assert props["has_ephemeral_storage_limit"] is True
        assert props["has_liveness_probe"] is True
        assert props["container_findings"] == {}

    def test_capabilities_are_dropped_only_when_every_container_drops_all(self) -> None:
        assert _props(_strong("a"), _container("b"))["capabilities_dropped"] is False
        assert _props(_strong("a"), _strong("b"))["capabilities_dropped"] is True

    def test_the_offending_containers_are_named(self) -> None:
        props = _props(_strong("good"), _weak("bad"), _weak("worse"))
        findings = props["container_findings"]
        assert findings["privileged"] == ["bad", "worse"]
        assert findings["run_as_root"] == ["bad", "worse"]
        assert "good" not in findings["writable_root_fs"]
        assert findings["has_resource_limits"] == ["bad", "worse"]
        assert findings["uses_latest_tag"] == ["bad", "worse"]

    def test_the_sidecar_privilege_is_attributed_to_the_sidecar(self) -> None:
        props = _props(
            _strong("api"),
            _container("log-shipper", securityContext={"privileged": True}),
        )
        assert props["privileged"] is True
        assert props["container_findings"]["privileged"] == ["log-shipper"]

    def test_limits_need_both_cpu_and_memory(self) -> None:
        only_memory = _props(_container(resources={"limits": {"memory": "1Gi"}}))
        assert only_memory["has_memory_limit"] is True
        assert only_memory["has_cpu_limit"] is False
        assert only_memory["has_resource_limits"] is False
        only_cpu = _props(_container(resources={"limits": {"cpu": "1"}}))
        assert only_cpu["has_cpu_limit"] is True
        assert only_cpu["has_memory_limit"] is False
        assert only_cpu["has_resource_limits"] is False

    def test_requests_alone_do_not_bound_anything(self) -> None:
        props = _props(
            _container(
                resources={"requests": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "1Gi"}}
            )
        )
        assert props["has_resource_limits"] is False
        assert props["has_ephemeral_storage_limit"] is False

    def test_the_ephemeral_storage_limit_is_its_own_fact(self) -> None:
        with_limit = _props(
            _container(
                resources={"limits": {"cpu": "1", "memory": "1Gi", "ephemeral-storage": "1Gi"}}
            )
        )
        assert with_limit["has_resource_limits"] is True
        assert with_limit["has_ephemeral_storage_limit"] is True
        without = _props(_container(resources={"limits": {"cpu": "1", "memory": "1Gi"}}))
        assert without["has_resource_limits"] is True
        assert without["has_ephemeral_storage_limit"] is False

    @pytest.mark.parametrize("ordering", list(itertools.permutations(range(3))))
    def test_every_flag_is_independent_of_the_container_order(
        self, ordering: tuple[int, ...]
    ) -> None:
        containers = [_weak("bad"), _strong("good"), _container("bare")]
        reference = _props(*containers)
        shuffled = _props(*(containers[i] for i in ordering))
        assert shuffled == reference

    @pytest.mark.parametrize("ordering", list(itertools.permutations(range(3))))
    def test_the_order_does_not_matter_with_init_and_ephemeral_containers_either(
        self, ordering: tuple[int, ...]
    ) -> None:
        extras = [
            ("containers", _strong("main")),
            ("initContainers", _weak("migrate")),
            ("ephemeralContainers", _container("debug", securityContext={"privileged": True})),
        ]

        def build(order: tuple[int, ...]) -> dict[str, Any]:
            spec: dict[str, list[dict[str, Any]]] = {}
            for index in order:
                key, container = extras[index]
                spec.setdefault(key, []).append(container)
            return security_properties(spec)

        assert build(ordering) == build((0, 1, 2))


# ---------------------------------------------------------------------------------------
# Which containers each check judges
# ---------------------------------------------------------------------------------------


class TestContainerRoles:
    def test_roles(self) -> None:
        views = container_views(
            {
                "containers": [_container("main")],
                "initContainers": [
                    _container("migrate"),
                    _container("proxy", restartPolicy="Always"),
                ],
                "ephemeralContainers": [_container("debug")],
            }
        )
        assert {v.name: v.role for v in views} == {
            "main": "regular",
            "migrate": "init",
            "proxy": "sidecar",
            "debug": "ephemeral",
        }

    def test_non_mapping_and_unnamed_containers_are_tolerated(self) -> None:
        views = container_views({"containers": ["x", None, {"image": "a:1"}, {"name": "ok"}]})
        assert [v.name for v in views] == ["containers[2]", "ok"]

    def test_init_only_pods_get_no_probe_or_limit_findings(self) -> None:
        props = security_properties({"initContainers": [_container("only-init")]})
        assert props["has_liveness_probe"] is True
        assert props["has_readiness_probe"] is True
        assert props["has_resource_limits"] is True
        assert props["has_cpu_limit"] is True

    def test_a_bare_init_container_is_not_judged_on_probes_but_is_on_security(self) -> None:
        props = _props(
            _strong("main"),
            initContainers=[_container("bare-init")],
        )
        assert props["has_liveness_probe"] is True
        assert props["has_readiness_probe"] is True
        assert props["has_resource_limits"] is True
        # the init container has no security context, so the workload is not hardened
        assert props["writable_root_fs"] is True
        assert props["container_findings"]["writable_root_fs"] == ["bare-init"]
        assert props["container_findings"]["run_as_root"] == ["bare-init"]
        assert props["capabilities_dropped"] is False

    def test_a_sidecar_is_judged_on_probes_and_limits(self) -> None:
        props = _props(
            _strong("main"),
            initContainers=[_container("proxy", restartPolicy="Always")],
        )
        assert props["has_liveness_probe"] is False
        assert props["has_resource_limits"] is False
        assert props["container_findings"]["has_liveness_probe"] == ["proxy"]

    def test_a_privileged_ephemeral_container_is_flagged(self) -> None:
        props = _props(
            _strong("main"),
            ephemeralContainers=[
                {
                    "name": "debugger",
                    "image": "busybox:1.36",
                    "securityContext": {"privileged": True},
                }
            ],
        )
        assert props["privileged"] is True
        assert props["container_findings"]["privileged"] == ["debugger"]

    def test_an_ephemeral_container_does_not_fail_the_probe_check(self) -> None:
        props = _props(
            _strong("main"),
            ephemeralContainers=[{"name": "debugger", "image": "busybox:1.36"}],
        )
        assert props["has_liveness_probe"] is True
        assert props["has_resource_limits"] is True

    def test_a_workload_with_no_containers_has_nothing_to_flag(self) -> None:
        props = security_properties({})
        assert props["privileged"] is False
        assert props["run_as_root"] is False
        assert props["has_resource_limits"] is True
        assert props["capabilities_dropped"] is True
        assert props["container_findings"] == {}
        assert props["images"] == []

    def test_a_pod_level_seccomp_profile_stands_when_there_are_no_containers(self) -> None:
        props = security_properties({"securityContext": {"seccompProfile": {"type": "Localhost"}}})
        assert props["seccomp_profile_type"] == "Localhost"


# ---------------------------------------------------------------------------------------
# Capabilities
# ---------------------------------------------------------------------------------------


class TestCapabilities:
    def test_all_cap_sys_admin_bpf_and_sys_rawio_are_dangerous(self) -> None:
        props = _props(
            _container(
                securityContext={
                    "capabilities": {"add": ["ALL", "CAP_SYS_ADMIN", "BPF", "SYS_RAWIO"]}
                }
            )
        )
        assert props["dangerous_capabilities"] == ["ALL", "BPF", "SYS_ADMIN", "SYS_RAWIO"]

    def test_names_are_normalized_so_every_spelling_matches(self) -> None:
        props = _props(
            _container(securityContext={"capabilities": {"add": ["net_admin", "CAP_NET_RAW"]}})
        )
        assert props["dangerous_capabilities"] == ["NET_ADMIN", "NET_RAW"]

    def test_harmless_capabilities_are_not_listed(self) -> None:
        props = _props(
            _container(securityContext={"capabilities": {"add": ["NET_BIND_SERVICE", "KILL"]}})
        )
        assert props["dangerous_capabilities"] == []

    def test_capabilities_are_the_union_over_containers(self) -> None:
        props = _props(
            _container("a", securityContext={"capabilities": {"add": ["BPF"]}}),
            _container("b", securityContext={"capabilities": {"add": ["SYS_PTRACE"]}}),
        )
        assert props["dangerous_capabilities"] == ["BPF", "SYS_PTRACE"]
        assert props["container_findings"]["dangerous_capabilities"] == ["a", "b"]

    def test_lowercase_all_drops_everything(self) -> None:
        props = _props(_container(securityContext={"capabilities": {"drop": ["all"]}}))
        assert props["capabilities_dropped"] is True

    @pytest.mark.parametrize("junk", [None, "ALL", ["ALL", 3, None], {"drop": "ALL"}, 7])
    def test_malformed_capabilities_do_not_raise(self, junk: Any) -> None:
        props = _props(_container(securityContext={"capabilities": junk}))
        assert props["dangerous_capabilities"] == []


# ---------------------------------------------------------------------------------------
# Images
# ---------------------------------------------------------------------------------------


class TestImages:
    @pytest.mark.parametrize(
        ("image", "floating"),
        [
            ("nginx", True),
            ("nginx:latest", True),
            ("registry:5000/app", True),
            ("registry:5000/app:latest", True),
            ("localhost:5000/app", True),
            ("ghcr.io/org/app", True),
            ("nginx:stable", True),
            ("nginx:1.27.0", False),
            ("registry:5000/app:1.2", False),
            ("localhost:5000/app:v2", False),
            ("app@sha256:" + "0" * 64, False),
            ("app:latest@sha256:" + "0" * 64, False),
            ("registry:5000/app@sha256:" + "a" * 64, False),
            ("", False),
            ("${IMAGE}", False),
            ("app:${TAG}", False),
            (PLACEHOLDER_PREFIX + "templates-deployment-yaml-0-1", False),
            (f"{PLACEHOLDER_PREFIX}x-0-1:{PLACEHOLDER_PREFIX}x-0-2", False),
        ],
    )
    def test_floating_tag_detection(self, image: str, floating: bool) -> None:
        assert uses_floating_tag(image) is floating

    def test_a_registry_port_is_not_mistaken_for_a_tag(self) -> None:
        props = _props(_container(image="registry:5000/app"))
        assert props["uses_latest_tag"] is True
        assert props["container_findings"]["uses_latest_tag"] == ["app"]

    def test_digest_pinned_images_are_exempt(self) -> None:
        props = _props(_container(image="registry.example.com/app@sha256:" + "f" * 64))
        assert props["uses_latest_tag"] is False

    def test_an_init_container_with_a_floating_tag_counts(self) -> None:
        props = _props(_container("main"), initContainers=[_container("init", image="busybox")])
        assert props["uses_latest_tag"] is True
        assert props["container_findings"]["uses_latest_tag"] == ["init"]

    def test_images_lists_every_reference_once(self) -> None:
        props = _props(
            _container("a", image="x:1"),
            _container("b", image="y:2"),
            _container("c", image="x:1"),
            initContainers=[_container("i", image="z:3")],
        )
        assert props["images"] == ["x:1", "y:2", "z:3"]

    @pytest.mark.parametrize("image", [None, 7, ["x"], {"a": 1}])
    def test_a_null_or_malformed_image_does_not_raise_or_count_as_latest(self, image: Any) -> None:
        props = _props({"name": "app", "image": image})
        assert props["uses_latest_tag"] is False
        assert props["images"] == []


# ---------------------------------------------------------------------------------------
# Malformed fields never raise
# ---------------------------------------------------------------------------------------


class TestMalformedFields:
    @pytest.mark.parametrize("junk", [None, "placeholder", 5, [], ["x"]])
    def test_resources_and_context_that_are_not_mappings_count_as_unset(self, junk: Any) -> None:
        props = _props(
            _container(resources=junk, securityContext=junk, livenessProbe=junk, ports=junk),
            securityContext=junk,
        )
        assert props["has_resource_limits"] is False
        assert props["has_security_context"] is False
        assert props["privileged"] is False
        assert props["has_host_port"] is False

    def test_limits_that_are_not_a_mapping_count_as_unset(self) -> None:
        props = _props(_container(resources={"limits": "placeholder"}))
        assert props["has_resource_limits"] is False

    def test_resources_given_as_a_string_parse_through_the_whole_parser(self) -> None:
        doc = _manifest("Deployment", _pod_spec(_container(resources="placeholder")))
        props = _parse_one(doc).properties
        assert props["has_resource_limits"] is False

    def test_env_entries_that_are_not_mappings_are_skipped(self) -> None:
        props = _props(_container(env=["x", None, {"name": "T", "valueFrom": "oops"}]))
        assert props["secret_env_vars"] == []

    def test_host_ports_and_volumes_that_are_malformed_are_skipped(self) -> None:
        props = _parse_one(
            _manifest(
                "Deployment",
                _pod_spec(_container(ports=["80", {"hostPort": 0}]), volumes="placeholder"),
            )
        ).properties
        assert props["has_host_port"] is False
        assert props["has_host_path_volume"] is False

    def test_service_account_and_automount_defaults(self) -> None:
        props = _parse_one(_manifest("Deployment", _pod_spec(_container()))).properties
        assert props["service_account_name"] == "default"
        assert props["automount_sa_token"] is True
        assert props["pod_automount_sa_token"] is None

    def test_an_explicit_pod_automount_setting_is_kept(self) -> None:
        props = _parse_one(
            _manifest("Deployment", _pod_spec(_container(), automountServiceAccountToken=False))
        ).properties
        assert props["automount_sa_token"] is False
        assert props["pod_automount_sa_token"] is False
