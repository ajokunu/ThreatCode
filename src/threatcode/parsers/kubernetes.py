"""Kubernetes manifest parser for ThreatCode."""

from __future__ import annotations

import logging
from typing import Any

import yaml

from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)

# K8s resource kinds that contain PodTemplateSpec
_WORKLOAD_KINDS = frozenset(
    {
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }
)

_KIND_TO_RESOURCE_TYPE: dict[str, str] = {
    "Deployment": "kubernetes_deployment",
    "DaemonSet": "kubernetes_daemon_set",
    "StatefulSet": "kubernetes_stateful_set",
    "ReplicaSet": "kubernetes_replica_set",
    "Job": "kubernetes_job",
    "CronJob": "kubernetes_cron_job",
    "Pod": "kubernetes_pod",
    "Service": "kubernetes_service",
    "Ingress": "kubernetes_ingress",
    "ConfigMap": "kubernetes_config_map",
    "Secret": "kubernetes_secret",
    "NetworkPolicy": "kubernetes_network_policy",
    "ServiceAccount": "kubernetes_service_account",
    "Role": "kubernetes_role",
    "ClusterRole": "kubernetes_cluster_role",
    "RoleBinding": "kubernetes_role_binding",
    "ClusterRoleBinding": "kubernetes_cluster_role_binding",
    "Namespace": "kubernetes_namespace",
    "PersistentVolumeClaim": "kubernetes_pvc",
}


class KubernetesParser(BaseParser):
    """Parse Kubernetes YAML manifests into ParsedResource objects."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        resources: list[ParsedResource] = []

        # Handle both pre-parsed data and raw YAML string
        if isinstance(data, str):
            docs = list(yaml.safe_load_all(data))
        elif isinstance(data, dict):
            docs = [data]
        elif isinstance(data, list):
            docs = data
        else:
            docs = [data]

        for doc in docs:
            if not isinstance(doc, dict):
                continue
            if "apiVersion" not in doc or "kind" not in doc:
                continue

            kind = doc.get("kind", "")
            api_version = doc.get("apiVersion", "")
            metadata = doc.get("metadata", {}) or {}
            name = metadata.get("name", "unknown")
            namespace = metadata.get("namespace", "default")
            spec = doc.get("spec", {}) or {}

            resource_type = _KIND_TO_RESOURCE_TYPE.get(kind, f"kubernetes_{kind.lower()}")
            address = f"{resource_type}.{namespace}.{name}"

            props: dict[str, Any] = {
                "kind": kind,
                "apiVersion": api_version,
                "name": name,
                "namespace": namespace,
                "labels": metadata.get("labels", {}),
                "annotations": metadata.get("annotations", {}),
            }

            # Extract container security properties from workloads
            if kind in _WORKLOAD_KINDS or kind == "Pod":
                pod_spec = self._get_pod_spec(doc)
                if pod_spec:
                    container_props = self._extract_container_security(pod_spec)
                    props.update(container_props)
                    props["host_network"] = pod_spec.get("hostNetwork", False)
                    props["host_pid"] = pod_spec.get("hostPID", False)
                    props["host_ipc"] = pod_spec.get("hostIPC", False)
                    sa = pod_spec.get("serviceAccountName", "default")
                    props["service_account_name"] = sa
                    automount = pod_spec.get("automountServiceAccountToken")
                    props["automount_sa_token"] = automount if automount is not None else True
                    # Check for hostPath volumes
                    volumes = pod_spec.get("volumes", []) or []
                    props["has_host_path_volume"] = any(
                        isinstance(v, dict) and "hostPath" in v for v in volumes
                    )
                    # Pod security context
                    pod_sc = pod_spec.get("securityContext", {}) or {}
                    props["pod_run_as_non_root"] = pod_sc.get("runAsNonRoot")
                    props["pod_run_as_user"] = pod_sc.get("runAsUser")

            # RBAC-specific
            if kind in ("Role", "ClusterRole"):
                # rules is a top-level field in K8s Role/ClusterRole
                rules = doc.get("rules", []) or spec.get("rules", []) or []
                props["rbac_rules"] = rules
                props["has_wildcard_verbs"] = any(
                    "*" in (r.get("verbs", []) or []) for r in rules if isinstance(r, dict)
                )
                props["has_wildcard_resources"] = any(
                    "*" in (r.get("resources", []) or []) for r in rules if isinstance(r, dict)
                )

            if kind in ("RoleBinding", "ClusterRoleBinding"):
                # roleRef and subjects are top-level fields in K8s bindings
                role_ref = doc.get("roleRef", {}) or spec.get("roleRef", {}) or {}
                props["role_ref_name"] = role_ref.get("name", "")
                props["role_ref_kind"] = role_ref.get("kind", "")
                subjects = doc.get("subjects", []) or spec.get("subjects", []) or []
                props["subjects"] = subjects

            # Service
            if kind == "Service":
                props["service_type"] = spec.get("type", "ClusterIP")
                ports = spec.get("ports", []) or []
                props["ports"] = ports

            # NetworkPolicy
            if kind == "NetworkPolicy":
                props["has_ingress_rules"] = bool(spec.get("ingress"))
                props["has_egress_rules"] = bool(spec.get("egress"))
                props["policy_types"] = spec.get("policyTypes", [])

            resources.append(
                ParsedResource(
                    resource_type=resource_type,
                    address=address,
                    name=name,
                    provider="kubernetes",
                    properties=props,
                    source_location=source_path,
                )
            )

        return ParsedOutput(
            resources=resources,
            source_path=source_path,
            format_type="kubernetes",
        )

    def _get_pod_spec(self, doc: dict[str, Any]) -> dict[str, Any] | None:
        """Extract PodSpec from various workload types."""
        kind = doc.get("kind", "")
        spec = doc.get("spec", {}) or {}

        if kind == "Pod":
            pod_spec: dict[str, Any] = spec
            return pod_spec
        if kind == "CronJob":
            job_spec = spec.get("jobTemplate", {}).get("spec", {})
            cron_pod_spec: dict[str, Any] = job_spec.get("template", {}).get("spec", {})
            return cron_pod_spec
        # Deployment, DaemonSet, StatefulSet, ReplicaSet, Job
        template = spec.get("template", {})
        result: dict[str, Any] | None = template.get("spec", {}) if template else None
        return result

    def _extract_container_security(self, pod_spec: dict[str, Any]) -> dict[str, Any]:
        """Extract security-relevant properties from all containers."""
        props: dict[str, Any] = {
            "privileged": False,
            "run_as_root": True,  # Default: not set = could run as root
            "has_resource_limits": True,
            "has_security_context": True,
            "writable_root_fs": True,
            "allow_privilege_escalation": True,
            "capabilities_dropped": False,
            "dangerous_capabilities": [],
            "uses_latest_tag": False,
            "has_liveness_probe": True,
            "has_readiness_probe": True,
            "has_host_port": False,
            "secret_env_vars": [],
        }

        containers = (pod_spec.get("containers", []) or []) + (
            pod_spec.get("initContainers", []) or []
        )
        if not containers:
            return props

        for container in containers:
            if not isinstance(container, dict):
                continue

            # Image tag check
            image = container.get("image", "")
            if ":" not in image or image.endswith(":latest"):
                props["uses_latest_tag"] = True

            # Security context
            sc = container.get("securityContext", {})
            if not sc:
                props["has_security_context"] = False

            if isinstance(sc, dict):
                if sc.get("privileged"):
                    props["privileged"] = True
                if sc.get("allowPrivilegeEscalation", True):
                    props["allow_privilege_escalation"] = True
                else:
                    props["allow_privilege_escalation"] = False
                if not sc.get("readOnlyRootFilesystem", False):
                    props["writable_root_fs"] = True
                else:
                    props["writable_root_fs"] = False
                run_as_non_root = sc.get("runAsNonRoot")
                if run_as_non_root:
                    props["run_as_root"] = False

                caps = sc.get("capabilities", {})
                if isinstance(caps, dict):
                    drop = caps.get("drop", []) or []
                    if "ALL" in drop or "all" in drop:
                        props["capabilities_dropped"] = True
                    add = caps.get("add", []) or []
                    dangerous = [
                        c
                        for c in add
                        if c
                        in (
                            "NET_ADMIN",
                            "SYS_ADMIN",
                            "SYS_PTRACE",
                            "NET_RAW",
                            "SYS_MODULE",
                            "DAC_OVERRIDE",
                        )
                    ]
                    if dangerous:
                        props["dangerous_capabilities"].extend(dangerous)

            # Resource limits
            resources = container.get("resources", {})
            if not resources or not resources.get("limits"):
                props["has_resource_limits"] = False

            # Probes
            if not container.get("livenessProbe"):
                props["has_liveness_probe"] = False
            if not container.get("readinessProbe"):
                props["has_readiness_probe"] = False

            # Host ports
            ports = container.get("ports", []) or []
            for port in ports:
                if isinstance(port, dict) and port.get("hostPort"):
                    props["has_host_port"] = True

            # Secret env vars
            env = container.get("env", []) or []
            for e in env:
                if isinstance(e, dict):
                    value_from = e.get("valueFrom", {})
                    if isinstance(value_from, dict) and "secretKeyRef" in value_from:
                        props["secret_env_vars"].append(e.get("name", ""))

        return props
