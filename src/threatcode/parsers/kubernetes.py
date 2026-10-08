"""Kubernetes manifest parser for ThreatCode.

Reads YAML and JSON manifests, including ``kubectl get -o yaml|json`` output (``List`` and
``<Kind>List`` documents are flattened into their items) and files that mix Kubernetes
objects with other YAML (the other documents are skipped with a warning).

Every workload kind is normalized to one property shape (see ``_k8s_security``), documents
are connected into inferred edges and cross-document properties (see ``_k8s_links``), and
nothing that reads a manifest raises on a malformed field: a null ``image``, ``jobTemplate``
or ``resources``, or a value that is a string where a mapping belongs, is treated as unset.
"""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from types import MappingProxyType
from typing import Any

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.exceptions import ParseError
from threatcode.parsers._json_lines import json_line_index
from threatcode.parsers._k8s_links import (
    Entry,
    ManifestSet,
    derive_properties,
    effective_policy_types,
    link_edges,
    workload_references,
)
from threatcode.parsers._k8s_security import (
    PLACEHOLDER_PREFIX,
    WORKLOAD_KINDS,
    PodTemplate,
    as_dict,
    as_list,
    as_str_list,
    pod_properties,
    pod_template,
    scalar_or_none,
    security_properties,
    string_map,
)
from threatcode.parsers._text import MAX_INPUT_SIZE_BYTES, decode_input
from threatcode.parsers._yaml import load_yaml_documents
from threatcode.parsers.base import BaseParser, ParsedOutput, ParsedResource

logger = logging.getLogger(__name__)

register_code(
    "k8s.truncated_value",
    "A Kubernetes value was dropped because its YAML aliases expand without bound",
)

# Bounds on what one input may expand to
MAX_LIST_DEPTH = 5
MAX_DOCUMENTS = 20_000
# A value kept in a property is copied through its YAML aliases; one that expands past this many
# nodes is dropped, because anything that serialized it later would run away
MAX_PROPERTY_NODES = 10_000
_MAX_PROPERTY_DEPTH = 64
# Recovering line numbers re-reads the file, so it is skipped for larger inputs
_MAX_LINE_INDEX_BYTES = 2 * 1024 * 1024
# How many skipped documents are described in ``metadata['skipped_documents']``
_MAX_SKIPPED_LISTED = 50

# The kinds that carry a PodTemplateSpec; a bare Pod is its own template and is not listed
_WORKLOAD_KINDS = frozenset(kind for kind in WORKLOAD_KINDS if kind != "Pod")

_KIND_TO_RESOURCE_TYPE: dict[str, str] = {
    **WORKLOAD_KINDS,
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

# Kinds that belong to no namespace: their address is ``<type>.<name>``, never a made-up
# namespace segment. These are the cluster-scoped kinds of the built-in Kubernetes APIs.
CLUSTER_SCOPED_KINDS = frozenset(
    {
        "Namespace",
        "ClusterRole",
        "ClusterRoleBinding",
        "PersistentVolume",
        "StorageClass",
        "CustomResourceDefinition",
        "Node",
        "PriorityClass",
        "IngressClass",
        "RuntimeClass",
        "CSIDriver",
        "CSINode",
        "VolumeAttachment",
        "ValidatingWebhookConfiguration",
        "MutatingWebhookConfiguration",
        "ValidatingAdmissionPolicy",
        "ValidatingAdmissionPolicyBinding",
        "APIService",
        "CertificateSigningRequest",
        "PodSecurityPolicy",
    }
)

# Properties that keep a value as the manifest wrote it
_RAW_PROPERTIES = (
    "labels",
    "annotations",
    "rbac_rules",
    "subjects",
    "ports",
    "pod_selector",
    "policy_types",
)

_CAMEL_BOUNDARY = re.compile(r"(?<=[a-z0-9])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_NOT_IDENTIFIER = re.compile(r"[^a-z0-9]+")

# What the lists of an Ingress backend, a Service or a binding call things
_WILDCARD = "*"
_ESCALATION_VERBS = frozenset({"escalate", "bind", "impersonate"})
_READ_VERBS = frozenset({"get", "list", "watch", _WILDCARD})
_EXEC_RESOURCES = frozenset({"pods/exec", "pods/*", "*/exec", "*/*", _WILDCARD})
_ANONYMOUS_SUBJECTS = frozenset({"system:anonymous", "system:unauthenticated"})
_AUTHENTICATED_SUBJECT = "system:authenticated"


# Every property a Kubernetes resource can carry, by resource type.
# A rule may read a property of a ``kubernetes_*`` resource only if it is listed here: the
# provenance gate (tests/test_engine/test_rule_property_provenance.py) fails a rule that reads
# anything else, because such a rule can never fire, and it fails when the parser emits a
# property this table does not list or this table lists one the parser never emits.
_METADATA_PROPERTIES = frozenset(
    {"annotations", "apiVersion", "kind", "labels", "name", "namespace"}
)
# The shared shape of every kind that carries a pod template, see _k8s_security and _k8s_links
_WORKLOAD_PROPERTIES = frozenset(
    {
        "allow_privilege_escalation",
        "automount_sa_token",
        "capabilities_dropped",
        "config_map_refs",
        "container_findings",
        "dangerous_capabilities",
        "effective_automount_sa_token",
        "egress_policy_covered",
        "has_cpu_limit",
        "has_ephemeral_storage_limit",
        "has_host_path_volume",
        "has_host_port",
        "has_liveness_probe",
        "has_memory_limit",
        "has_readiness_probe",
        "has_resource_limits",
        "has_seccomp_profile",
        "has_security_context",
        "host_ipc",
        "host_network",
        "host_pid",
        "images",
        "ingress_policy_covered",
        "pod_automount_sa_token",
        "pod_labels",
        "pod_run_as_non_root",
        "pod_run_as_user",
        "policy_scope",
        "privileged",
        "pvc_refs",
        "replicas",
        "run_as_root",
        "sa_resolved",
        "seccomp_profile_type",
        "secret_env_vars",
        "secret_refs",
        "service_account_name",
        "uses_latest_tag",
        "writable_root_fs",
    }
)
_ROLE_PROPERTIES = frozenset(
    {
        "has_escalation_verbs",
        "has_pod_exec",
        "has_secrets_read",
        "has_wildcard_api_groups",
        "has_wildcard_resources",
        "has_wildcard_verbs",
        "rbac_rules",
    }
)
_BINDING_PROPERTIES = frozenset(
    {
        "binds_authenticated_group",
        "binds_unauthenticated_group",
        "role_ref_kind",
        "role_ref_name",
        "subject_kinds",
        "subjects",
    }
)

PRODUCED: Mapping[str, frozenset[str]] = MappingProxyType(
    {
        **dict.fromkeys(WORKLOAD_KINDS.values(), _METADATA_PROPERTIES | _WORKLOAD_PROPERTIES),
        "kubernetes_cluster_role": _METADATA_PROPERTIES | _ROLE_PROPERTIES,
        "kubernetes_role": _METADATA_PROPERTIES | _ROLE_PROPERTIES,
        "kubernetes_cluster_role_binding": _METADATA_PROPERTIES | _BINDING_PROPERTIES,
        "kubernetes_role_binding": _METADATA_PROPERTIES | _BINDING_PROPERTIES,
        "kubernetes_ingress": _METADATA_PROPERTIES | {"has_rules", "has_tls", "ingress_backends"},
        "kubernetes_network_policy": _METADATA_PROPERTIES
        | {
            "effective_policy_types",
            "has_egress_rules",
            "has_ingress_rules",
            "pod_selector",
            "policy_types",
        },
        "kubernetes_service": _METADATA_PROPERTIES | {"ports", "selector", "service_type"},
        "kubernetes_service_account": _METADATA_PROPERTIES | {"automount_sa_token"},
        "kubernetes_config_map": _METADATA_PROPERTIES,
        "kubernetes_namespace": _METADATA_PROPERTIES,
        "kubernetes_secret": _METADATA_PROPERTIES,
    }
)


def resource_type_for(kind: str) -> str:
    """The resource type of a kind: the table entry, else ``kubernetes_<snake_case_kind>``."""
    known = _KIND_TO_RESOURCE_TYPE.get(kind)
    if known is not None:
        return known
    snake = _NOT_IDENTIFIER.sub("_", _CAMEL_BOUNDARY.sub("_", kind).lower()).strip("_")
    return f"kubernetes_{snake or 'unknown'}"


@dataclass(frozen=True)
class ManifestDocument:
    """One parsed document and where it came from.

    ``lines`` maps a JSON pointer inside the document to its 1-based start line, and
    ``pointer`` is where this document's root sits in that map. ``start_line`` overrides the
    lookup for a caller that knows the line itself (the Helm parser does).
    """

    data: Any
    file: str = ""
    lines: Mapping[str, int] | None = None
    pointer: str = ""
    start_line: int | None = None

    def line_at(self, pointer: str) -> int | None:
        if self.lines is not None and pointer in self.lines:
            return self.lines[pointer]
        return self.start_line


@dataclass
class _Item:
    doc: dict[str, Any]
    file: str
    line: int | None


class KubernetesParser(BaseParser):
    """Parse Kubernetes YAML and JSON manifests into ParsedResource objects."""

    def parse(self, data: Any, source_path: str = "") -> ParsedOutput:
        return self.parse_documents(self._load(data, source_path), source_path)

    def parse_documents(
        self, documents: Sequence[ManifestDocument], source_path: str = ""
    ) -> ParsedOutput:
        """Parse documents that were loaded elsewhere, for one connected set of resources."""
        diagnostics: list[Diagnostic] = []
        skipped: list[dict[str, Any]] = []
        items = self._flatten(documents, source_path, diagnostics, skipped)

        entries: list[Entry] = []
        seen: set[str] = set()
        for index, item in enumerate(items):
            entries.append(self._build(item, index, source_path, seen, diagnostics))

        manifests = ManifestSet(entries)
        derive_properties(manifests)
        edges = link_edges(manifests)

        metadata: dict[str, Any] = {}
        if skipped:
            metadata["skipped_documents"] = skipped[:_MAX_SKIPPED_LISTED]
        return ParsedOutput(
            resources=[entry.resource for entry in entries],
            source_path=source_path,
            format_type="kubernetes",
            metadata=metadata,
            edges=edges,
            diagnostics=diagnostics,
        )

    # -- loading -------------------------------------------------------------------------

    def _load(self, data: Any, source_path: str) -> list[ManifestDocument]:
        name = Path(source_path).name if source_path else "<input>"
        if isinstance(data, str):
            return _documents_from_text(data, source_path, name)
        documents = data if isinstance(data, list) else [data]
        return _attach_lines(documents, source_path, isinstance(data, list))

    def _flatten(
        self,
        documents: Sequence[ManifestDocument],
        source_path: str,
        diagnostics: list[Diagnostic],
        skipped: list[dict[str, Any]],
    ) -> list[_Item]:
        """Expand ``List`` kinds into their items and drop what is not a Kubernetes object."""
        items: list[_Item] = []

        def skip(position: int, reason: str, file: str, line: int | None) -> None:
            skipped.append({"index": position, "reason": reason})
            where = f" in {Path(file).name}" if file else ""
            diagnostics.append(
                Diagnostic(
                    "warning",
                    "k8s.skipped_document",
                    f"Document {position}{where} was skipped: {reason}",
                    file,
                    line,
                )
            )

        pending: list[tuple[Any, ManifestDocument, str, int, int]] = [
            (doc.data, doc, doc.pointer, 0, position)
            for position, doc in reversed(list(enumerate(documents)))
        ]
        while pending:
            data, source, pointer, depth, position = pending.pop()
            file = source.file or source_path
            line = source.line_at(pointer)
            if len(items) >= MAX_DOCUMENTS:
                skip(position, f"more than {MAX_DOCUMENTS} documents in one input", file, line)
                break
            if not isinstance(data, dict):
                skip(position, "it is not a mapping", file, line)
                continue
            if _is_list_kind(data):
                if depth >= MAX_LIST_DEPTH:
                    skip(position, f"List nested deeper than {MAX_LIST_DEPTH} levels", file, line)
                    continue
                children = as_list(data.get("items"))
                room = max(0, MAX_DOCUMENTS - len(items) - len(pending))
                if len(children) > room:
                    skip(position, f"more than {MAX_DOCUMENTS} documents in one input", file, line)
                    children = children[:room]
                pending.extend(
                    (child, source, f"{pointer}/items/{n}", depth + 1, position)
                    for n, child in reversed(list(enumerate(children)))
                )
                continue
            if not isinstance(data.get("kind"), str) or "apiVersion" not in data:
                skip(
                    position,
                    "it has no apiVersion and kind, so it is not a Kubernetes object",
                    file,
                    line,
                )
                continue
            items.append(_Item(data, file, line))
        return items

    # -- one resource --------------------------------------------------------------------

    def _build(
        self,
        item: _Item,
        index: int,
        source_path: str,
        seen: set[str],
        diagnostics: list[Diagnostic],
    ) -> Entry:
        doc = item.doc
        kind = str(doc.get("kind"))
        metadata = as_dict(doc.get("metadata"))
        spec = as_dict(doc.get("spec"))
        name, name_source = _resource_name(metadata, index)
        name = readable_placeholders(name, "name")
        cluster_scoped = kind in CLUSTER_SCOPED_KINDS
        namespace_value = metadata.get("namespace")
        namespace = (
            readable_placeholders(namespace_value, "namespace")
            if isinstance(namespace_value, str) and namespace_value
            else "default"
        )

        resource_type = resource_type_for(kind)
        address = (
            f"{resource_type}.{name}" if cluster_scoped else f"{resource_type}.{namespace}.{name}"
        )
        key = address
        number = 2
        while key in seen:
            key = f"{address}#{number}"
            number += 1
        seen.add(key)

        props: dict[str, Any] = {
            "kind": kind,
            "apiVersion": _text(doc.get("apiVersion")),
            "name": name,
            "namespace": None if cluster_scoped else namespace,
            "labels": as_dict(metadata.get("labels")),
            "annotations": as_dict(metadata.get("annotations")),
        }

        pod = pod_template(doc)
        if pod is not None:
            props.update(_workload_properties(pod, spec))
        elif kind in ("Role", "ClusterRole"):
            props.update(_role_properties(doc, spec))
        elif kind in ("RoleBinding", "ClusterRoleBinding"):
            props.update(_binding_properties(doc, spec))
        elif kind == "ServiceAccount":
            props["automount_sa_token"] = _optional_bool(doc.get("automountServiceAccountToken"))
        elif kind == "Service":
            props.update(_service_properties(spec))
        elif kind == "Ingress":
            props.update(_ingress_properties(spec))
        elif kind == "NetworkPolicy":
            props.update(_network_policy_properties(spec))

        for prop in _RAW_PROPERTIES:
            if prop in props:
                props[prop], dropped = _bounded_copy(props[prop])
                if dropped:
                    diagnostics.append(
                        Diagnostic(
                            "warning",
                            "k8s.truncated_value",
                            f"{kind} {name}: {prop} expands to more than {MAX_PROPERTY_NODES} "
                            "nodes through YAML aliases and was dropped",
                            item.file or source_path,
                            item.line,
                        )
                    )

        resource = ParsedResource(
            resource_type=resource_type,
            address=address,
            name=name,
            provider="kubernetes",
            properties=props,
            source_location=item.file or source_path,
            start_line=item.line,
            # How the name was found: a made-up name is worth knowing about in a report
            meta={"name_source": name_source},
        )
        return Entry(
            resource=resource,
            kind=kind,
            namespace=None if cluster_scoped else namespace,
            name=name,
            key=key,
            doc=doc,
            pod=pod,
        )


# ---------------------------------------------------------------------------------------
# Loading helpers
# ---------------------------------------------------------------------------------------


def _documents_from_text(text: str, source_path: str, name: str) -> list[ManifestDocument]:
    """Documents of a YAML or JSON text, each with the line index of its keys and items."""
    stripped = text.lstrip("\ufeff").lstrip()
    if stripped.startswith(("{", "[")):
        # JSON that YAML would refuse (a tab between tokens) still loads as JSON
        try:
            value = json.loads(text)
        except (ValueError, RecursionError):
            pass
        else:
            lines = json_line_index(text)
            if isinstance(value, list):
                return [
                    ManifestDocument(item, source_path, lines, f"/{n}")
                    for n, item in enumerate(value)
                ]
            return [ManifestDocument(value, source_path, lines, "")]
    documents, indexes = load_yaml_documents(text, with_lines=True, source=name)
    return [
        ManifestDocument(doc, source_path, index)
        for doc, index in zip(documents, indexes, strict=False)
    ]


def _attach_lines(
    documents: list[Any], source_path: str, from_list: bool
) -> list[ManifestDocument]:
    """Wrap documents the registry already loaded, recovering their lines from the file.

    The registry hands over loaded values, never text, so the lines come from reading the file
    once more. A file that cannot be read, is too large or does not hold as many documents as
    were loaded simply has no line numbers.
    """
    indexes = _recover_lines(source_path, len(documents), from_list)
    if indexes is None:
        return [ManifestDocument(doc, source_path) for doc in documents]
    return [
        ManifestDocument(doc, source_path, lines, pointer)
        for doc, (lines, pointer) in zip(documents, indexes, strict=False)
    ]


def _recover_lines(
    source_path: str, count: int, from_list: bool
) -> list[tuple[Mapping[str, int], str]] | None:
    if not source_path or count == 0:
        return None
    path = Path(source_path)
    try:
        if not path.is_file() or path.stat().st_size > min(
            _MAX_LINE_INDEX_BYTES, MAX_INPUT_SIZE_BYTES
        ):
            return None
        text = decode_input(path)
        if path.suffix.lower() == ".json":
            index = json_line_index(text)
            if from_list:
                return [(index, f"/{n}") for n in range(count)]
            return [(index, "")] if count == 1 else None
        _, per_document = load_yaml_documents(text, with_lines=True, source=path.name)
    except (OSError, ParseError):
        return None
    if len(per_document) != count:
        return None
    return [(index, "") for index in per_document]


class _TooBigError(Exception):
    pass


def _bounded_copy(value: Any) -> tuple[Any, bool]:
    """Copy a loaded value, or give an empty one of the same kind when it is too big.

    Every visit counts, so aliases that expand to billions of nodes (or an anchor that holds
    itself) stop at ``MAX_PROPERTY_NODES`` visits. Returns the copy and whether it was dropped.
    """
    budget = [MAX_PROPERTY_NODES]

    def copy(node: Any, depth: int) -> Any:
        budget[0] -= 1
        if budget[0] < 0 or depth > _MAX_PROPERTY_DEPTH:
            raise _TooBigError
        if isinstance(node, dict):
            return {key: copy(item, depth + 1) for key, item in node.items()}
        if isinstance(node, list):
            return [copy(item, depth + 1) for item in node]
        return node

    try:
        return copy(value, 0), False
    except _TooBigError:
        return ({} if isinstance(value, dict) else [] if isinstance(value, list) else None), True


def _is_list_kind(doc: Mapping[str, Any]) -> bool:
    """True for ``List`` and ``<Kind>List`` documents, which wrap objects under ``items``."""
    kind = doc.get("kind")
    if not isinstance(kind, str):
        return False
    return kind == "List" or (kind.endswith("List") and "items" in doc)


_PLACEHOLDER = re.compile(rf"{PLACEHOLDER_PREFIX}([a-z0-9]+(?:-[a-z0-9]+)*?)-(\d+)-(\d+)")
_CHART_FOLDERS = frozenset({"charts", "templates"})
_TEMPLATE_SUFFIXES = ("-yaml", "-yml", "-tpl", "-json")


def readable_placeholders(value: str, field: str) -> str:
    """A name or namespace the Helm fallback renderer could not resolve, in words.

    The renderer prints ``placeholder-<template>-<document>-<n>`` for a value it cannot know,
    which made an address such as ``kubernetes_service.placeholder-templates-svc-yaml-0-2.
    placeholder-templates-svc-yaml-0-1``.
    The template (``svc``) and the document number are what tell two unresolved names apart, so
    the name becomes ``unresolved-svc`` (``unresolved-svc-1`` for the second document) and the
    namespace ``unresolved-namespace``, which every template of the chart shares because they
    all print the same expression.
    """

    def replace(match: re.Match[str]) -> str:
        if field == "namespace":
            return "unresolved-namespace"
        template = match.group(1)
        for suffix in _TEMPLATE_SUFFIXES:
            if template.endswith(suffix):
                template = template[: -len(suffix)]
                break
        # `charts/redis/templates/svc.yaml` is the slug `charts-redis-templates-svc-yaml`
        template = "-".join(part for part in template.split("-") if part not in _CHART_FOLDERS)
        document = int(match.group(2))
        return f"unresolved-{template}{f'-{document}' if document else ''}"

    return _PLACEHOLDER.sub(replace, value) if PLACEHOLDER_PREFIX in value else value


def _resource_name(metadata: Mapping[str, Any], index: int) -> tuple[str, str]:
    """The name and where it came from.

    ``metadata.name``, else the ``generateName`` stem plus ``-generated``, else
    ``unnamed-<index>``.
    """
    name = metadata.get("name")
    if isinstance(name, str) and name.strip():
        return name, "name"
    if isinstance(name, (int, float)) and not isinstance(name, bool):
        return str(name), "name"
    generate = metadata.get("generateName")
    if isinstance(generate, str):
        stem = generate.strip().rstrip("-")
        if stem:
            return f"{stem}-generated", "generateName"
    return f"unnamed-{index}", "index"


def _optional_bool(value: object) -> bool | None:
    if isinstance(value, bool):
        return value
    if isinstance(value, str) and value.strip().lower() in ("true", "false"):
        return value.strip().lower() == "true"
    return None


# ---------------------------------------------------------------------------------------
# Properties per kind
# ---------------------------------------------------------------------------------------


def _workload_properties(pod: PodTemplate, spec: Mapping[str, Any]) -> dict[str, Any]:
    props: dict[str, Any] = {}
    props.update(security_properties(pod.spec))
    props.update(pod_properties(pod.spec))
    props["pod_labels"] = dict(pod.labels)
    replicas = spec.get("replicas")
    props["replicas"] = (
        replicas if isinstance(replicas, int) and not isinstance(replicas, bool) else None
    )
    references = workload_references(pod.spec)
    for kind, field_name in (
        ("Secret", "secret_refs"),
        ("ConfigMap", "config_map_refs"),
        ("PersistentVolumeClaim", "pvc_refs"),
    ):
        props[field_name] = sorted({r.name for r in references if r.kind == kind})
    return props


def _rules_of(doc: Mapping[str, Any], spec: Mapping[str, Any]) -> list[Any]:
    # rules is a top-level field of a Role, ClusterRole and bindings; older exports nest it
    return as_list(doc.get("rules") or spec.get("rules"))


def _role_properties(doc: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    """RBAC facts of a Role or ClusterRole; a rule whose fields are not lists is tolerated."""
    raw = _rules_of(doc, spec)
    wildcard_verbs = wildcard_resources = wildcard_groups = False
    escalation = secrets_read = pod_exec = False
    for rule in raw:
        if not isinstance(rule, dict):
            continue
        verbs = set(as_str_list(rule.get("verbs")))
        resources = set(as_str_list(rule.get("resources")))
        groups = set(as_str_list(rule.get("apiGroups")))
        wildcard_verbs = wildcard_verbs or _WILDCARD in verbs
        wildcard_resources = wildcard_resources or _WILDCARD in resources
        wildcard_groups = wildcard_groups or _WILDCARD in groups
        escalation = escalation or bool(verbs & _ESCALATION_VERBS)
        # Secrets and pods/exec live in the core group, which is "" (or no group at all)
        core = not groups or "" in groups or _WILDCARD in groups
        # A grant limited to named objects is not a grant over every Secret or every pod
        named = bool(as_str_list(rule.get("resourceNames")))
        if (
            core
            and not named
            and bool({"secrets", _WILDCARD} & resources)
            and bool(verbs & _READ_VERBS)
        ):
            secrets_read = True
        if (
            core
            and not named
            and bool(resources & _EXEC_RESOURCES)
            and bool({"create", _WILDCARD} & verbs)
        ):
            pod_exec = True
    return {
        "rbac_rules": raw,
        "has_wildcard_verbs": wildcard_verbs,
        "has_wildcard_resources": wildcard_resources,
        "has_wildcard_api_groups": wildcard_groups,
        "has_escalation_verbs": escalation,
        "has_secrets_read": secrets_read,
        "has_pod_exec": pod_exec,
    }


def _binding_properties(doc: Mapping[str, Any], spec: Mapping[str, Any]) -> dict[str, Any]:
    role_ref = as_dict(doc.get("roleRef") or spec.get("roleRef"))
    subjects = as_list(doc.get("subjects") or spec.get("subjects"))
    kinds = sorted(
        {s["kind"] for s in subjects if isinstance(s, dict) and isinstance(s.get("kind"), str)}
    )
    anonymous = authenticated = False
    for subject in subjects:
        if not isinstance(subject, dict) or subject.get("kind") not in ("User", "Group"):
            continue
        name = subject.get("name")
        if not isinstance(name, str):
            continue
        anonymous = anonymous or name in _ANONYMOUS_SUBJECTS
        authenticated = authenticated or name == _AUTHENTICATED_SUBJECT
    return {
        "role_ref_name": _text(role_ref.get("name")),
        "role_ref_kind": _text(role_ref.get("kind")),
        "subjects": subjects,
        "subject_kinds": kinds,
        "binds_unauthenticated_group": anonymous,
        "binds_authenticated_group": authenticated,
    }


def _text(value: object) -> str:
    return value if isinstance(value, str) else ""


def _service_properties(spec: Mapping[str, Any]) -> dict[str, Any]:
    service_type = spec.get("type")
    return {
        "service_type": service_type
        if isinstance(service_type, str) and service_type
        else "ClusterIP",
        "ports": as_list(spec.get("ports")),
        "selector": string_map(spec.get("selector"), all_or_nothing=True),
    }


def _ingress_properties(spec: Mapping[str, Any]) -> dict[str, Any]:
    backends: list[dict[str, Any]] = []

    def add(backend: object) -> None:
        fields = as_dict(backend)
        service = as_dict(fields.get("service"))
        name = service.get("name") or fields.get("serviceName")  # serviceName: legacy form
        if not isinstance(name, str) or not name:
            return
        port = as_dict(service.get("port"))
        number = port.get("number")
        backends.append(
            {
                "service_name": name,
                "port": scalar_or_none(
                    number if number is not None else port.get("name", fields.get("servicePort"))
                ),
            }
        )

    add(spec.get("defaultBackend"))
    add(spec.get("backend"))
    for rule in as_list(spec.get("rules")):
        for path in as_list(as_dict(as_dict(rule).get("http")).get("paths")):
            add(as_dict(path).get("backend"))
    return {
        "has_tls": bool(spec.get("tls")),
        # A default backend routes traffic with no rule at all, so it counts as routing
        "has_rules": bool(spec.get("rules"))
        or bool(spec.get("defaultBackend") or spec.get("backend")),
        "ingress_backends": backends,
    }


def _network_policy_properties(spec: Mapping[str, Any]) -> dict[str, Any]:
    return {
        "has_ingress_rules": bool(spec.get("ingress")),
        "has_egress_rules": bool(spec.get("egress")),
        "policy_types": spec.get("policyTypes", []),
        "effective_policy_types": effective_policy_types(spec),
        "pod_selector": as_dict(spec.get("podSelector")),
    }
