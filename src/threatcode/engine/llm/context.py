"""The infrastructure context the model sees: pseudonymous, allowlisted, sized to a budget.

``build_context`` turns the graph and the findings gathered so far into a JSON-ready mapping:

- every node gets an opaque handle ``<resource_type>.n<k>`` (``AddressMap``), used for node keys,
  edge ends and any address inside a string, so user-chosen names never leave the machine and the
  model's answer maps back locally;
- each node carries its type-level facts (zone, exposure, boundary, evidence), the ids of the
  rules that already fired on it, and a small set of security-relevant properties;
- the properties come from a per-resource-type allowlist and go through the redactor; anything the
  allowlist does not name is dropped (deny by default);
- each edge carries its type, the zones it joins, whether it crosses a trust boundary and what the
  input declared about it (protocol, ports, authentication, encryption).

When the result would not fit the budget, large groups of alike nodes collapse into one summary
line, then nodes without findings lose their properties, then whole low-value nodes are dropped
with their edges.
JSON is never cut, what was summarized or dropped is counted and logged, and a context that still
does not fit raises ``LLMError``.
"""

from __future__ import annotations

import json
import logging
import re
from collections import defaultdict
from collections.abc import Iterable, Mapping
from dataclasses import asdict, dataclass, field
from typing import Any

from threatcode.engine.llm.prompts import dump_context
from threatcode.engine.llm.redactor import Redactor
from threatcode.exceptions import LLMError
from threatcode.ir.edges import InfraEdge
from threatcode.ir.graph import InfraGraph
from threatcode.ir.nodes import InfraNode
from threatcode.models.threat import Threat, ThreatSource
from threatcode.values import UNKNOWN_TEXT, is_unknown

logger = logging.getLogger(__name__)

# Groups of at least this many alike, finding-free nodes are summarized first, then smaller ones.
GROUP_THRESHOLDS: tuple[int, ...] = (8, 3)
MAX_RULES_PER_NODE = 20
_RULE_ID_RE = re.compile(r"[^A-Za-z0-9_.\-]")
_TYPE_RE = re.compile(r"[^A-Za-z0-9_:\-]")
_UNKNOWN_MARK = "(unknown)"

# ---------------------------------------------------------------------------------------------
# The allowlist. A key not named here never reaches the prompt. ``True`` keeps the whole value
# (still redacted); a mapping keeps only the keys it names.
# ---------------------------------------------------------------------------------------------

_RULE_KEYS: dict[str, Any] = {
    "cidr_blocks": True,
    "ipv6_cidr_blocks": True,
    "from_port": True,
    "to_port": True,
    "protocol": True,
    "self": True,
    "type": True,
}

_STATEMENT_KEYS: dict[str, Any] = {
    "effect": True,
    "actions": True,
    "not_actions": True,
    "resources": True,
    "not_resources": True,
    "principals": True,
    "has_condition": True,
    "condition_keys": True,
}

# What the graph builder derives from companions and policies (see ir/enrichment/companions.py).
_DERIVED_KEYS: dict[str, Any] = {
    "versioning_enabled": True,
    "sse_algorithm": True,
    "logging_enabled": True,
    "public_access_block": True,
    "acl": True,
    "object_ownership": True,
    "has_flow_log": True,
    "rotation_enabled": True,
    "has_logging_config": True,
    "has_diagnostic_settings": True,
    "auditing_enabled": True,
    "alert_policy_enabled": True,
    "invoker_members": True,
    "access_members": True,
    "policy_statements": _STATEMENT_KEYS,
    "attached_policy_statements": _STATEMENT_KEYS,
    "inline_policy_statements": _STATEMENT_KEYS,
    "assume_role_statements": _STATEMENT_KEYS,
    "role_policy_statements": _STATEMENT_KEYS,
    "ingress": _RULE_KEYS,
    "egress": _RULE_KEYS,
}

_FLAGS = (
    # exposure and network
    "publicly_accessible",
    "public",
    "public_access",
    "public_network_access",
    "public_network_access_enabled",
    "associate_public_ip_address",
    "map_public_ip_on_launch",
    "internal",
    "scheme",
    "load_balancer_type",
    "enable_http2",
    "drop_invalid_header_fields",
    "ssl_policy",
    "protocol",
    "port",
    "from_port",
    "to_port",
    "cidr_blocks",
    "ipv6_cidr_blocks",
    "source_ranges",
    "destination_ranges",
    "source_address_prefix",
    "source_address_prefixes",
    "destination_port_range",
    "destination_port_ranges",
    "direction",
    "access",
    "priority",
    "self",
    "type",
    "endpoint_public_access",
    "endpoint_private_access",
    "public_access_cidrs",
    "default_action",
    "bypass",
    "viewer_protocol_policy",
    # encryption and transport
    "encrypted",
    "storage_encrypted",
    "kms_encrypted",
    "encryption",
    "encryption_at_rest",
    "encryption_in_transit",
    "at_rest_encryption_enabled",
    "transit_encryption_enabled",
    "enable_encryption",
    "server_side_encryption",
    "sse_algorithm",
    "sse_enabled",
    "tls_enabled",
    "min_tls_version",
    "minimum_tls_version",
    "require_ssl",
    "https_only",
    "https_traffic_only_enabled",
    "enable_https_traffic_only",
    "ssl_enforcement_enabled",
    # logging, backup and protection
    "logging",
    "enable_logging",
    "logging_enabled",
    "versioning",
    "versioning_enabled",
    "mfa_delete",
    "multi_az",
    "deletion_protection",
    "enable_deletion_protection",
    "backup_retention_period",
    "skip_final_snapshot",
    "enable_key_rotation",
    "enable_log_file_validation",
    "is_multi_region_trail",
    "include_global_service_events",
    "monitoring",
    "enable_monitoring",
    "retention_in_days",
    "point_in_time_recovery",
    "force_destroy",
    "iam_database_authentication_enabled",
    "auto_minor_version_upgrade",
    "enable_dns_support",
    "enable_dns_hostnames",
    "enabled",
    "acl",
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
    "object_lock_enabled",
    "ebs_optimized",
    # compute and identity
    "instance_type",
    "instance_class",
    "engine",
    "engine_version",
    "runtime",
    "http_tokens",
    "http_endpoint",
    "http_put_response_hop_limit",
    "billing_mode",
    "tier",
    "sku",
    "account_tier",
    "account_replication_type",
    "allow_blob_public_access",
    "allow_nested_items_to_be_public",
    "enable_rbac_authorization",
    "purge_protection_enabled",
    "soft_delete_retention_days",
    "uniform_bucket_level_access",
    "public_access_prevention",
    "enable_private_nodes",
    "enable_shielded_nodes",
)

_NESTED_FLAGS: dict[str, Any] = {
    "ingress": _RULE_KEYS,
    "egress": _RULE_KEYS,
    "metadata_options": True,
    "root_block_device": True,
    "ebs_block_device": True,
    "server_side_encryption_configuration": True,
    "versioning": True,
    "logging": True,
    "vpc_config": True,
    "derived": _DERIVED_KEYS,
}

_KUBERNETES = (
    "kind",
    "privileged",
    "run_as_root",
    "allow_privilege_escalation",
    "writable_root_fs",
    "capabilities_dropped",
    "dangerous_capabilities",
    "has_security_context",
    "has_seccomp_profile",
    "seccomp_profile_type",
    "uses_latest_tag",
    "has_host_port",
    "has_cpu_limit",
    "has_memory_limit",
    "has_ephemeral_storage_limit",
    "has_resource_limits",
    "has_liveness_probe",
    "has_readiness_probe",
    "host_network",
    "host_pid",
    "host_ipc",
    "automount_sa_token",
    "pod_automount_sa_token",
    "effective_automount_sa_token",
    "sa_resolved",
    "has_host_path_volume",
    "pod_run_as_non_root",
    "replicas",
    "ingress_policy_covered",
    "egress_policy_covered",
    "policy_scope",
    "type",
    "rules_wildcard",
    "has_wildcard_verbs",
    "has_wildcard_resources",
    "role_ref_kind",
    "tls",
    "has_tls",
)

_MCP = (
    "client_format",
    "scope",
    "transport",
    "is_remote",
    "is_loopback",
    "uses_plaintext_transport",
    "bridge",
    "bridge_allow_http",
    "has_configured_auth",
    "remote_without_configured_auth",
    "has_literal_secret",
    "has_high_confidence_secret",
    "has_possible_secret",
    "secret_confidence",
    "runner",
    "package_unpinned",
    "broad_filesystem_access",
    "exposes_sensitive_paths",
    "exposes_shell_exec",
    "container_privileged",
    "container_lacks_no_new_privileges",
    "sandbox_enabled",
    "disabled",
    "capability_tags",
    "capabilities",
    "reads_private_data",
    "ingests_untrusted_content",
    "can_exfiltrate_or_act",
    "server_count",
    "enabled_server_count",
)

_DOCKER = (
    "instruction",
    "stage_index",
    "is_root",
    "is_root_user",
    "has_user",
    "user_value",
    "uses_latest_tag",
    "final_stage_uses_latest_tag",
    "kind",
    "base_kind",
    "digest_pinned",
    "has_digest_pin",
    "has_ssh_exposed",
    "has_privileged_port",
    "exposed_ports",
    "ports",
    "has_healthcheck",
    "has_curl_pipe",
    "has_sudo",
    "is_url_add",
    "has_sensitive_file",
    "has_secret_pattern",
    "is_non_minimal",
)


def _allow(names: Iterable[str], nested: Mapping[str, Any] | None = None) -> dict[str, Any]:
    allowed: dict[str, Any] = dict.fromkeys(names, True)
    allowed.update(nested or {})
    return allowed


GENERIC_ALLOWLIST: dict[str, Any] = _allow(_FLAGS, _NESTED_FLAGS)

# Added to the generic allowlist for a resource type with this prefix.
TYPE_ALLOWLISTS: dict[str, dict[str, Any]] = {
    "kubernetes_": _allow(_KUBERNETES, {"derived": _DERIVED_KEYS}),
    "mcp_": _allow(_MCP),
    "dockerfile_": _allow(_DOCKER),
}


def allowlist_for(resource_type: str) -> dict[str, Any]:
    """The properties of ``resource_type`` that may be sent: the generic set plus its family's."""
    allowed = dict(GENERIC_ALLOWLIST)
    for prefix, extra in TYPE_ALLOWLISTS.items():
        if resource_type.startswith(prefix):
            allowed.update(extra)
    return allowed


# Edge attributes the input may declare that are safe and useful to send.
EDGE_ATTRIBUTE_ALLOWLIST: dict[str, Any] = _allow(
    (
        "protocol",
        "port",
        "ports",
        "from_port",
        "to_port",
        "authenticated",
        "encrypted",
        "direction",
        "transport",
        "access",
        "tls",
    )
)


class AddressMap:
    """Opaque handles for graph nodes, and the way back.

    A handle is ``<resource_type>.n<k>``: it keeps the type, which the model needs, and drops the
    name, which only identifies the user.
    ``resolve`` also accepts a node id that exists in the graph, because a model that echoes an
    address is still pointing at a real node.
    """

    def __init__(self, graph: InfraGraph) -> None:
        self._to_handle: dict[str, str] = {}
        self._to_node: dict[str, str] = {}
        for index, (node_id, node) in enumerate(graph.nodes.items(), start=1):
            kind = _TYPE_RE.sub("_", node.resource_type)[:64] or "resource"
            handle = f"{kind}.n{index}"
            self._to_handle[node_id] = handle
            self._to_node[handle] = node_id
        self._known = set(graph.nodes)
        self._handle_pattern: re.Pattern[str] | None = None
        self._node_pattern: re.Pattern[str] | None = None

    def __len__(self) -> int:
        return len(self._to_handle)

    def handle(self, node_id: str) -> str:
        return self._to_handle[node_id]

    def resolve(self, address: str) -> str | None:
        """The node id behind a handle or a known node id, or None."""
        address = address.strip()
        if address in self._to_node:
            return self._to_node[address]
        if address in self._known:
            return address
        return None

    def restore_text(self, text: str) -> str:
        """Write the real addresses back over every handle in ``text``."""
        if not self._to_node or "." not in text:
            return text
        if self._handle_pattern is None:
            self._handle_pattern = _alternation(self._to_node)
        return self._handle_pattern.sub(lambda m: self._to_node[m.group()], text)

    def mask_text(self, text: str) -> str:
        """Replace every known node id inside ``text`` with its handle."""
        if not self._to_handle or not text:
            return text
        if self._node_pattern is None:
            self._node_pattern = _alternation(self._to_handle)
        return self._node_pattern.sub(lambda m: self._to_handle[m.group()], text)


def _alternation(names: Mapping[str, str]) -> re.Pattern[str]:
    """One pattern matching any of the keys as a whole token, longest first."""
    ordered = sorted(names, key=len, reverse=True)
    body = "|".join(re.escape(name) for name in ordered)
    return re.compile(rf"(?<![\w.\-/])(?:{body})(?![\w\-])")


@dataclass
class ContextStats:
    """What went into the context and what the budget removed."""

    nodes_total: int = 0
    nodes_sent: int = 0
    nodes_summarized: int = 0
    groups: int = 0
    nodes_dropped: int = 0
    props_stripped: int = 0
    edges_total: int = 0
    edges_sent: int = 0
    edges_merged: int = 0
    edges_dropped: int = 0
    chars: int = 0
    reduced: bool = field(default=False)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class LLMContext:
    data: dict[str, Any]
    stats: ContextStats
    addresses: AddressMap


def rule_hits(threats: Iterable[Threat], known: Iterable[str]) -> dict[str, list[str]]:
    """The ids of the findings gathered so far, by the node they were reported on."""
    nodes = set(known)
    hits: dict[str, set[str]] = defaultdict(set)
    for threat in threats:
        label = threat.rule_id
        if not label and threat.source is ThreatSource.BOUNDARY:
            label = "boundary_crossing"
        label = _RULE_ID_RE.sub("", label)[:64]
        if not label:
            continue
        for address in (threat.resource_address, threat.target_address):
            if address in nodes:
                hits[address].add(label)
    return {node: sorted(ids)[:MAX_RULES_PER_NODE] for node, ids in hits.items()}


def build_context(
    graph: InfraGraph,
    threats: Iterable[Threat],
    redactor: Redactor,
    *,
    max_chars: int | None = None,
) -> LLMContext:
    """Serialize the graph for the model, within ``max_chars`` of JSON when given.

    Raises:
        LLMError: The context does not fit even after summarizing and dropping, or redaction
            failed closed.
    """
    addresses = AddressMap(graph)
    hits = rule_hits(threats, graph.nodes)
    stats = ContextStats(nodes_total=len(graph.nodes), edges_total=len(graph.edges))

    nodes: dict[str, dict[str, Any]] = {}
    for node_id, node in graph.nodes.items():
        nodes[addresses.handle(node_id)] = _node_entry(
            node, node_id, hits.get(node_id, []), redactor, addresses
        )
    edges = [e for e in (_edge_entry(edge, addresses, redactor) for edge in graph.edges) if e]

    groups: list[dict[str, Any]] = []
    if max_chars is not None and _size(edges, nodes, groups) > max_chars:
        edges, nodes, groups = _reduce(graph, addresses, edges, nodes, hits, max_chars, stats)
        stats.reduced = True

    stats.nodes_sent = len(nodes)
    stats.edges_sent = len(edges)
    data: dict[str, Any] = {"edges": edges, "nodes": nodes}
    if groups:
        data["groups"] = groups
    stats.chars = len(dump_context(data))
    if max_chars is not None and stats.chars > max_chars:
        raise LLMError(
            f"The infrastructure context is {stats.chars} characters, over the {max_chars} "
            "the token limit allows even after summarizing; raise llm.max_input_tokens "
            "or scan a smaller part of the infrastructure"
        )
    if stats.reduced:
        logger.warning(
            "LLM context reduced to fit the budget: %d node(s) summarized into %d group(s), "
            "%d node(s) and %d edge(s) dropped, %d node(s) lost their properties",
            stats.nodes_summarized,
            stats.groups,
            stats.nodes_dropped,
            stats.edges_dropped,
            stats.props_stripped,
        )
    return LLMContext(data=data, stats=stats, addresses=addresses)


# ---------------------------------------------------------------------------------------------
# Entries
# ---------------------------------------------------------------------------------------------


def _node_entry(
    node: InfraNode,
    node_id: str,
    rules: list[str],
    redactor: Redactor,
    addresses: AddressMap,
) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "zone": node.trust_zone.value,
        "category": node.category.value,
    }
    if node.exposure != "unknown":
        entry["exposure"] = node.exposure
    if node.evidence != "config":
        entry["evidence"] = node.evidence
    if node.mode != "managed":
        entry["mode"] = node.mode
    with redactor.scope(node_id):
        if node.boundary:
            entry["boundary"] = redactor.placeholder_for(node.boundary, "boundary")
        if rules:
            entry["rules"] = rules
        props = _properties(node, redactor, addresses)
        if props:
            entry["props"] = props
    return entry


def _properties(node: InfraNode, redactor: Redactor, addresses: AddressMap) -> dict[str, Any]:
    allowed = allowlist_for(node.resource_type)
    lowered = {key.lower() for key in allowed}
    chosen = {
        key: _plain(value) for key, value in node.properties.items() if str(key).lower() in lowered
    }
    if not chosen:
        return {}
    # The graph builder folds inline and companion rules into derived.ingress/egress; sending the
    # raw block too would say everything twice
    derived = chosen.get("derived")
    if isinstance(derived, dict):
        for side in ("ingress", "egress"):
            if side in derived:
                chosen.pop(side, None)
    kept = redactor.redact_allowlisted(chosen, allowed)
    masked = _mask(kept, addresses)
    return masked if isinstance(masked, dict) else {}


def _edge_entry(
    edge: InfraEdge, addresses: AddressMap, redactor: Redactor
) -> dict[str, Any] | None:
    try:
        source = addresses.handle(edge.source)
        target = addresses.handle(edge.target)
    except KeyError:
        return None
    entry: dict[str, Any] = {"from": source, "to": target, "type": edge.edge_type.value}
    zones = [z.value if z is not None else "unknown" for z in (edge.source_zone, edge.target_zone)]
    if any(z != "unknown" for z in zones):
        entry["zones"] = zones
    if edge.crosses_boundary:
        entry["crosses_boundary"] = True
    if edge.relation:
        entry["relation"] = edge.relation[:64]
    if edge.declared:
        entry["declared"] = True
    attributes = redactor.redact_allowlisted(_plain(edge.attributes), EDGE_ATTRIBUTE_ALLOWLIST)
    if isinstance(attributes, dict) and attributes:
        entry["attrs"] = attributes
    return entry


def _plain(value: Any, _depth: int = 0) -> Any:
    """JSON-ready data: Unknown becomes a marker, odd containers and types become plain ones."""
    if _depth > 20:
        return _UNKNOWN_MARK
    if is_unknown(value) or value == UNKNOWN_TEXT:
        return _UNKNOWN_MARK
    if value is None or isinstance(value, bool | int | float | str):
        return value
    if isinstance(value, Mapping):
        return {str(k): _plain(v, _depth + 1) for k, v in value.items()}
    if isinstance(value, list | tuple | set | frozenset):
        items = sorted(value, key=str) if isinstance(value, set | frozenset) else value
        return [_plain(v, _depth + 1) for v in items]
    return str(value)


def _mask(value: Any, addresses: AddressMap) -> Any:
    if isinstance(value, str):
        return addresses.mask_text(value)
    if isinstance(value, dict):
        return {k: _mask(v, addresses) for k, v in value.items()}
    if isinstance(value, list):
        return [_mask(v, addresses) for v in value]
    return value


# ---------------------------------------------------------------------------------------------
# Budget
# ---------------------------------------------------------------------------------------------


def _json_len(value: Any) -> int:
    return len(json.dumps(value, ensure_ascii=True, separators=(",", ":")))


def _size(
    edges: list[dict[str, Any]], nodes: dict[str, dict[str, Any]], groups: list[dict[str, Any]]
) -> int:
    data: dict[str, Any] = {"edges": edges, "nodes": nodes}
    if groups:
        data["groups"] = groups
    return len(dump_context(data))


def _reduce(
    graph: InfraGraph,
    addresses: AddressMap,
    edges: list[dict[str, Any]],
    nodes: dict[str, dict[str, Any]],
    hits: Mapping[str, list[str]],
    max_chars: int,
    stats: ContextStats,
) -> tuple[list[dict[str, Any]], dict[str, dict[str, Any]], list[dict[str, Any]]]:
    """Make the context fit: summarize groups, strip properties, then drop low-value nodes."""
    nodes = dict(nodes)
    groups: list[dict[str, Any]] = []
    plain_handles = [addresses.handle(node_id) for node_id in graph.nodes if not hits.get(node_id)]
    plain_set = set(plain_handles)
    crossing = {e["from"] for e in edges if e.get("crosses_boundary")} | {
        e["to"] for e in edges if e.get("crosses_boundary")
    }
    handle_type = {addresses.handle(nid): n.resource_type for nid, n in graph.nodes.items()}
    node_map: dict[str, str] = {}  # summarized handle -> group handle

    for threshold in GROUP_THRESHOLDS:
        buckets: dict[tuple[str, str, str, str], list[str]] = defaultdict(list)
        for handle in plain_handles:
            if handle not in nodes or handle in crossing:
                continue
            entry = nodes[handle]
            key = (
                handle_type[handle],
                str(entry.get("zone")),
                str(entry.get("exposure", "")),
                str(entry.get("evidence", "")),
            )
            buckets[key].append(handle)
        for (kind, zone, _exposure, _evidence), members in sorted(buckets.items()):
            if len(members) < threshold:
                continue
            group_handle = f"{_TYPE_RE.sub('_', kind)[:64] or 'resource'}.g{len(groups) + 1}"
            groups.append(
                {
                    "id": group_handle,
                    "summary": f"{len(members)} x {kind} in zone {zone}",
                    "count": len(members),
                }
            )
            for handle in members:
                node_map[handle] = group_handle
                del nodes[handle]
            stats.nodes_summarized += len(members)
        stats.groups = len(groups)
        edges = _remap_edges(edges, node_map, stats)
        if _size(edges, nodes, groups) <= max_chars:
            return edges, nodes, groups

    # Next: nodes without findings keep their place in the topology but lose their properties.
    for handle in plain_handles:
        remaining = nodes.get(handle)
        if remaining is not None and "props" in remaining:
            del remaining["props"]
            stats.props_stripped += 1
    if _size(edges, nodes, groups) <= max_chars:
        return edges, nodes, groups

    # Last: drop whole nodes, the least valuable first, with the edges that touch them.
    degree: dict[str, int] = defaultdict(int)
    for edge in edges:
        degree[edge["from"]] += 1
        degree[edge["to"]] += 1
    droppable = sorted(
        (h for h in nodes if h in plain_set and h not in crossing),
        key=lambda h: (degree[h], h),
    )
    droppable += sorted((h for h in nodes if h in plain_set and h in crossing), key=lambda h: h)
    size = _size(edges, nodes, groups)
    dropped: set[str] = set()
    incident: dict[str, list[int]] = defaultdict(list)
    for index, edge in enumerate(edges):
        incident[edge["from"]].append(index)
        incident[edge["to"]].append(index)
    dead_edges: set[int] = set()
    for handle in droppable:
        if size <= max_chars:
            break
        size -= _json_len(nodes[handle]) + len(handle) + 4
        dropped.add(handle)
        for index in incident[handle]:
            if index not in dead_edges:
                dead_edges.add(index)
                size -= _json_len(edges[index]) + 1
    if dropped:
        edges = [e for i, e in enumerate(edges) if i not in dead_edges]
        for handle in dropped:
            del nodes[handle]
        stats.nodes_dropped = len(dropped)
        stats.edges_dropped += len(dead_edges)
    return edges, nodes, groups


def _remap_edges(
    edges: list[dict[str, Any]], node_map: Mapping[str, str], stats: ContextStats
) -> list[dict[str, Any]]:
    """Point edges at group handles and merge the ones that became identical."""
    if not node_map:
        return edges
    merged: dict[tuple[Any, ...], dict[str, Any]] = {}
    for edge in edges:
        source = node_map.get(edge["from"], edge["from"])
        target = node_map.get(edge["to"], edge["to"])
        if source == target and (source != edge["from"] or target != edge["to"]):
            continue  # inside one group: the group line already says they belong together
        key = (source, target, edge["type"], bool(edge.get("crosses_boundary")))
        count = int(edge.get("count", 1))
        existing = merged.get(key)
        if existing is None:
            merged[key] = dict(edge, **{"from": source, "to": target, "count": count})
        else:
            existing["count"] += count
    result = list(merged.values())
    for edge in result:
        if edge["count"] == 1:
            del edge["count"]
    stats.edges_merged += len(edges) - len(result)
    return result
