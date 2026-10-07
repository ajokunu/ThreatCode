"""Facts that need the whole input: derived properties and inferred edges.

A rule sees one node, but some Kubernetes questions only have an answer across documents:
does a NetworkPolicy select this workload, does its ServiceAccount turn off the token mount,
which workload does this Service send traffic to. ``ManifestSet`` indexes the documents of one
input once, then ``derive_properties`` writes the answers onto the nodes and ``link_edges``
returns the edges, all marked as inferred (``declared=False``) because the manifests do not
state them as edges.

Everything is scoped to the one input: a policy, ServiceAccount or Service that lives in
another file is not visible, which is why the derived coverage properties carry
``policy_scope: "single-input"``.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from threatcode.parsers._k8s_security import (
    PodTemplate,
    as_dict,
    as_list,
    as_str_list,
    container_views,
    label_text,
)
from threatcode.parsers.base import ParsedEdge, ParsedResource

logger = logging.getLogger(__name__)

POLICY_SCOPE = "single-input"

# Edge types and relations, as the strings the graph reads
NETWORK_FLOW = "network_flow"
DEPENDENCY = "dependency"
IAM_BINDING = "iam_binding"


@dataclass
class Entry:
    """One manifest document that became a resource."""

    resource: ParsedResource
    kind: str
    # None for a cluster-scoped kind
    namespace: str | None
    name: str
    # The address the graph keys this resource by inside the input; two documents with the
    # same address get "#2", "#3" in input order, as the graph numbers them
    key: str
    doc: dict[str, Any]
    pod: PodTemplate | None = None

    @property
    def props(self) -> dict[str, Any]:
        return self.resource.properties


# ---------------------------------------------------------------------------------------
# Label selectors
# ---------------------------------------------------------------------------------------


def selector_matches(selector: object, labels: Mapping[str, str]) -> bool:
    """Kubernetes LabelSelector semantics over ``matchLabels`` and ``matchExpressions``.

    A missing or empty selector selects everything, as ``podSelector: {}`` does. A selector
    that is not a mapping (an unresolved template value) or an expression with an operator
    other than In, NotIn, Exists and DoesNotExist selects nothing, so no edge is invented from
    a value that cannot be read.
    """
    if selector is None:
        return True
    if not isinstance(selector, dict):
        return False
    match_labels = selector.get("matchLabels")
    if match_labels is not None:
        if not isinstance(match_labels, dict):
            return False
        for key, value in match_labels.items():
            if labels.get(str(key)) != label_text(value):
                return False
    expressions = selector.get("matchExpressions")
    if expressions is not None:
        if not isinstance(expressions, list):
            return False
        for expression in expressions:
            if not _expression_matches(expression, labels):
                return False
    return True


def _expression_matches(expression: object, labels: Mapping[str, str]) -> bool:
    if not isinstance(expression, dict):
        return False
    key = expression.get("key")
    if not isinstance(key, str):
        return False
    values = [label_text(v) for v in as_list(expression.get("values"))]
    present = key in labels
    operator = expression.get("operator")
    if operator == "In":
        return present and labels[key] in values
    if operator == "NotIn":
        return not present or labels[key] not in values
    if operator == "Exists":
        return present
    if operator == "DoesNotExist":
        return not present
    return False


# ---------------------------------------------------------------------------------------
# What a workload references
# ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Reference:
    kind: str  # Secret, ConfigMap or PersistentVolumeClaim
    name: str
    relation: str  # mounts, env_from, secret_key_ref, config_map_key_ref


def _named(value: object, key: str) -> str:
    name = as_dict(value).get(key)
    return name if isinstance(name, str) and name else ""


def workload_references(pod_spec: dict[str, Any]) -> list[Reference]:
    """The Secrets, ConfigMaps and PersistentVolumeClaims a pod spec reads, without repeats.

    Volumes come first, then per container ``envFrom`` and ``env``. An image pull secret is not
    listed: the kubelet reads it, the containers never see it.
    """
    found: dict[Reference, None] = {}

    def add(kind: str, name: str, relation: str) -> None:
        if name:
            found.setdefault(Reference(kind, name, relation))

    for volume in as_list(pod_spec.get("volumes")):
        volume = as_dict(volume)
        add("Secret", _named(volume.get("secret"), "secretName"), "mounts")
        add("ConfigMap", _named(volume.get("configMap"), "name"), "mounts")
        add(
            "PersistentVolumeClaim",
            _named(volume.get("persistentVolumeClaim"), "claimName"),
            "mounts",
        )
        for source in as_list(as_dict(volume.get("projected")).get("sources")):
            source = as_dict(source)
            add("Secret", _named(source.get("secret"), "name"), "mounts")
            add("ConfigMap", _named(source.get("configMap"), "name"), "mounts")

    for view in container_views(pod_spec):
        for source in as_list(view.spec.get("envFrom")):
            source = as_dict(source)
            add("ConfigMap", _named(source.get("configMapRef"), "name"), "env_from")
            add("Secret", _named(source.get("secretRef"), "name"), "env_from")
        for variable in as_list(view.spec.get("env")):
            value_from = as_dict(as_dict(variable).get("valueFrom"))
            add("Secret", _named(value_from.get("secretKeyRef"), "name"), "secret_key_ref")
            add(
                "ConfigMap", _named(value_from.get("configMapKeyRef"), "name"), "config_map_key_ref"
            )
    return list(found)


# ---------------------------------------------------------------------------------------
# The indexed input
# ---------------------------------------------------------------------------------------


class _PodIndex:
    """The workloads of one namespace, indexed by label for fast selection."""

    def __init__(self, workloads: list[Entry]) -> None:
        self.workloads = workloads
        self._by_label: dict[tuple[str, str], set[int]] = {}
        for position, workload in enumerate(workloads):
            labels = workload.pod.labels if workload.pod else {}
            for item in labels.items():
                self._by_label.setdefault(item, set()).add(position)

    def with_labels(self, required: Mapping[str, str]) -> list[Entry]:
        """Workloads whose pod labels include every pair of ``required``."""
        if not required:
            return list(self.workloads)
        candidates: list[set[int]] = []
        for item in required.items():
            matching = self._by_label.get(item)
            if not matching:
                return []
            candidates.append(matching)
        candidates.sort(key=len)
        positions = set(candidates[0])
        for other in candidates[1:]:
            positions &= other
        return [self.workloads[p] for p in sorted(positions)]

    def selected_by(self, selector: object) -> list[Entry]:
        """Workloads a LabelSelector selects."""
        required: Mapping[str, str] = {}
        if isinstance(selector, dict) and isinstance(selector.get("matchLabels"), dict):
            required = {
                str(k): label_text(v) for k, v in as_dict(selector.get("matchLabels")).items()
            }
        return [w for w in self.with_labels(required) if _labels_of(w, selector)]


def _labels_of(workload: Entry, selector: object) -> bool:
    return selector_matches(selector, workload.pod.labels if workload.pod else {})


class ManifestSet:
    """Index of the documents of one input."""

    def __init__(self, entries: Sequence[Entry]) -> None:
        self.entries = list(entries)
        self.accounts: dict[tuple[str | None, str], Entry] = {}
        self.services: dict[tuple[str | None, str], Entry] = {}
        self.roles: dict[tuple[str | None, str], Entry] = {}
        self.cluster_roles: dict[str, Entry] = {}
        self.targets: dict[tuple[str, str | None, str], Entry] = {}
        pods: dict[str | None, list[Entry]] = {}
        for entry in self.entries:
            scope = (entry.namespace, entry.name)
            # The first document wins, as the graph keeps the first under the plain address
            self.targets.setdefault((entry.kind, entry.namespace, entry.name), entry)
            if entry.kind == "ServiceAccount":
                self.accounts.setdefault(scope, entry)
            elif entry.kind == "Service":
                self.services.setdefault(scope, entry)
            elif entry.kind == "Role":
                self.roles.setdefault(scope, entry)
            elif entry.kind == "ClusterRole":
                self.cluster_roles.setdefault(entry.name, entry)
            if entry.pod is not None:
                pods.setdefault(entry.namespace, []).append(entry)
        self.pod_index = {namespace: _PodIndex(workloads) for namespace, workloads in pods.items()}
        self._policy_selection: dict[str, list[Entry]] = {}

    @property
    def workloads(self) -> list[Entry]:
        return [e for e in self.entries if e.pod is not None]

    def selected_by_policy(self, policy: Entry) -> list[Entry]:
        """The workloads a NetworkPolicy's ``podSelector`` selects in its own namespace."""
        cached = self._policy_selection.get(policy.key)
        if cached is not None:
            return cached
        index = self.pod_index.get(policy.namespace)
        selected: list[Entry] = []
        if index is not None:
            selector = as_dict(policy.doc.get("spec")).get("podSelector")
            selected = index.selected_by(selector)
        self._policy_selection[policy.key] = selected
        return selected

    def selected_by_service(self, service: Entry) -> list[Entry]:
        """The workloads whose pod labels include every pair of the Service selector."""
        selector = as_dict(service.props.get("selector"))
        index = self.pod_index.get(service.namespace)
        if not selector or index is None:
            return []
        return index.with_labels({str(k): label_text(v) for k, v in selector.items()})


# ---------------------------------------------------------------------------------------
# Derived properties
# ---------------------------------------------------------------------------------------


def effective_policy_types(spec: Mapping[str, Any]) -> list[str]:
    """The policy types of a NetworkPolicy spec as the API server defaults them.

    ``spec.policyTypes`` when it lists any; otherwise Ingress, plus Egress only when the policy
    has egress rules.
    """
    declared = [t for t in as_str_list(spec.get("policyTypes")) if t in ("Ingress", "Egress")]
    if declared:
        return sorted(set(declared))
    types = ["Ingress"]
    if spec.get("egress"):
        types.append("Egress")
    return types


def derive_properties(manifests: ManifestSet) -> None:
    """Write the cross-document properties onto the nodes of the input.

    ServiceAccount token mounting: ``effective_automount_sa_token`` is the pod's own setting,
    else the same-namespace ServiceAccount's, else true (the Kubernetes default);
    ``sa_resolved`` is false when neither the pod nor a ServiceAccount in this input decided it.

    NetworkPolicy: ``ingress_policy_covered`` and ``egress_policy_covered`` say whether a
    policy of this input, in the workload's namespace, selects the workload for that direction.
    A policy that selects a pod and lists no rules is the default-deny case and covers it.
    """
    for workload in manifests.workloads:
        pod_value = workload.props.get("pod_automount_sa_token")
        account_name = workload.props.get("service_account_name", "default")
        account = manifests.accounts.get((workload.namespace, account_name))
        if pod_value is not None:
            effective, resolved = bool(pod_value), True
        elif account is not None:
            declared = account.props.get("automount_sa_token")
            effective, resolved = (True if declared is None else bool(declared)), True
        else:
            effective, resolved = True, False
        workload.props["effective_automount_sa_token"] = effective
        workload.props["sa_resolved"] = resolved
        workload.props["ingress_policy_covered"] = False
        workload.props["egress_policy_covered"] = False
        workload.props["policy_scope"] = POLICY_SCOPE

    for policy in manifests.entries:
        if policy.kind != "NetworkPolicy":
            continue
        types = policy.props["effective_policy_types"]
        for workload in manifests.selected_by_policy(policy):
            if "Ingress" in types:
                workload.props["ingress_policy_covered"] = True
            if "Egress" in types:
                workload.props["egress_policy_covered"] = True


# ---------------------------------------------------------------------------------------
# Edges
# ---------------------------------------------------------------------------------------


def _edge(source: Entry, target: Entry, edge_type: str, relation: str) -> ParsedEdge:
    return ParsedEdge(
        source=source.key,
        target=target.key,
        edge_type=edge_type,
        metadata={"relation": relation},
        declared=False,
    )


def link_edges(manifests: ManifestSet) -> list[ParsedEdge]:
    """The edges the manifests imply, in input order; a target that is not in the input is dropped.

    * Ingress to Service (network_flow, backend), by backend name in the Ingress namespace.
    * Service to workload (network_flow, selects), by selector against the pod template labels.
    * Workload to Secret, ConfigMap and PersistentVolumeClaim (dependency, mounts, env_from,
      secret_key_ref or config_map_key_ref).
    * Workload to ServiceAccount (iam_binding, runs_as).
    * RoleBinding and ClusterRoleBinding to the Role or ClusterRole (iam_binding, grants) and to
      each ServiceAccount subject (iam_binding, bound_subject).
    * NetworkPolicy to the workloads it selects (dependency, policy).
    """
    edges: list[ParsedEdge] = []
    for entry in manifests.entries:
        edges.extend(_edges_of(manifests, entry))
    return edges


def _edges_of(manifests: ManifestSet, entry: Entry) -> Iterable[ParsedEdge]:
    kind = entry.kind
    if kind == "Ingress":
        yield from _ingress_edges(manifests, entry)
    elif kind == "Service":
        for workload in manifests.selected_by_service(entry):
            yield _edge(entry, workload, NETWORK_FLOW, "selects")
    elif entry.pod is not None:
        yield from _workload_edges(manifests, entry, entry.pod)
    elif kind in ("RoleBinding", "ClusterRoleBinding"):
        yield from _binding_edges(manifests, entry)
    elif kind == "NetworkPolicy":
        for workload in manifests.selected_by_policy(entry):
            yield _edge(entry, workload, DEPENDENCY, "policy")


def _ingress_edges(manifests: ManifestSet, ingress: Entry) -> Iterable[ParsedEdge]:
    for backend in as_list(ingress.props.get("ingress_backends")):
        name = as_dict(backend).get("service_name")
        service = manifests.services.get((ingress.namespace, name)) if name else None
        if service is not None:
            yield _edge(ingress, service, NETWORK_FLOW, "backend")
        elif name:
            logger.debug(
                "Ingress %s routes to Service %s, which is not in the input", ingress.key, name
            )


def _workload_edges(
    manifests: ManifestSet, workload: Entry, pod: PodTemplate
) -> Iterable[ParsedEdge]:
    for reference in workload_references(pod.spec):
        target = manifests.targets.get((reference.kind, workload.namespace, reference.name))
        if target is not None:
            yield _edge(workload, target, DEPENDENCY, reference.relation)
    account_name = workload.props.get("service_account_name", "default")
    account = manifests.accounts.get((workload.namespace, account_name))
    if account is not None:
        yield _edge(workload, account, IAM_BINDING, "runs_as")


def _binding_edges(manifests: ManifestSet, binding: Entry) -> Iterable[ParsedEdge]:
    role_kind = binding.props.get("role_ref_kind")
    role_name = binding.props.get("role_ref_name")
    role: Entry | None = None
    if role_kind == "ClusterRole" and isinstance(role_name, str):
        role = manifests.cluster_roles.get(role_name)
    elif role_kind == "Role" and binding.kind == "RoleBinding" and isinstance(role_name, str):
        role = manifests.roles.get((binding.namespace, role_name))
    if role is not None:
        yield _edge(binding, role, IAM_BINDING, "grants")
    for subject in as_list(binding.props.get("subjects")):
        subject = as_dict(subject)
        if subject.get("kind") != "ServiceAccount":
            continue
        name = subject.get("name")
        namespace = subject.get("namespace")
        if not isinstance(name, str) or not name:
            continue
        if not isinstance(namespace, str) or not namespace:
            namespace = binding.namespace or "default"
        account = manifests.accounts.get((namespace, name))
        if account is not None:
            yield _edge(binding, account, IAM_BINDING, "bound_subject")
