"""Attack path phase.

``find`` computes attack paths over directed reachability edges from an entry
point to the targets that matter and returns them in ranked order. The
orchestrator stores the result in ``report.attack_paths``.

What a path is
--------------

An attack path is a chain of resources an attacker can follow from the internet to a crown
jewel: a hop is a resource, and the edge from one hop to the next is a reachability edge
(`threatcode.ir.reachability`), so a path follows traffic and authority in the direction they
travel and never crosses a node only because two nodes share a network.

- **Entries.**
  The synthetic ``internet`` node.
  A graph without one (no edge started at the internet) uses the nodes whose ``exposure`` is
  ``internet``, except networks and namespaces.
- **Crown jewels** (the targets):
  data stores and secret stores (database, storage and secret categories, not a ConfigMap and
  not the companion resources that configure a store), identities with administrator access (a
  role whose policy allows every action on every resource), Kubernetes Secrets, cluster-admin
  bindings and wildcard roles, and MCP servers that read private data or credential paths.
  Monitoring nodes, networks, namespaces and Dockerfile instructions are never targets, and a
  path never runs through them.
  A path ends at the first crown jewel it reaches.
- **Edges followed.**
  Network flows and data flows, and the IAM bindings that carry authority: a resource that runs
  code assumes its role, a role may act on a resource, a role may assume another, a service
  runs its task definition, a workload runs as its service account, an agent invokes its server.
  Attachments (a policy attached to a role, a resource policy) are not followed.
  A resource that does not run code (a load balancer, a database, an EKS control plane) does
  not hand its role to whoever reaches it.
- **Enabling findings.**
  A hop is enabled by the rule, secret and scanner findings on its resource and on the nodes the
  edge to the next hop names in ``via`` (the security group whose rule admits the traffic, the
  listener, the role binding), except repudiation and denial of service findings, which do not
  help an attacker move.
  The target's own findings enable the last hop.
  A path is kept only when it has an enabling finding: an architecture with nothing wrong on its
  way to the data has no attack path.
  The ids of the enabling findings go to ``Threat.path_ids``.
- **Severity.**
  The worst effective severity of the enabling findings, one level higher when the target is a
  data store tagged with a sensitive classification, and at most ``high`` unless every edge of
  the path is definite (stated by the input, not guessed).
- **Score.**
  ``severity * 1.5`` (info 0 to critical 6), 2 when the first edge is open to the whole
  internet, ``(8 - edges) * 0.2`` for a short path, and up to 0.6 for the target (a sensitive
  data store, a secret store or an administrator).
  Paths are ordered by score, then severity, then length, then id.
- **Techniques.**
  Each hop lists the ATT&CK techniques of the step that reaches it (`mitre.PATH_TECHNIQUES`):
  ``T1190`` for an exposed application, ``T1133`` for an exposed remote administration port,
  ``T1552.005`` where the instance allows IMDSv1, ``T1078.004`` for a role assumed, ``T1530`` for
  cloud storage read, ``T1552.007`` for a Kubernetes Secret read and ``T1611`` for a privileged
  container.

Search
------

Paths are simple (no node twice) and at most ``MAX_HOPS`` edges long.
The search is bounded: ``MAX_CANDIDATES`` routes in all and ``MAX_VISITS`` steps, and it
records a ``paths.search_truncated`` warning when a bound cuts it short.
Routes through the instances of one counted resource (``app[0]`` and ``app[1]``) differ by the
instance number only, so the first stands for the others (``AttackPath.alternatives``).
A path that is a contiguous part of a longer kept path is dropped, and the best
``MAX_PATHS_PER_TARGET`` routes to each target are kept.
The order, and every id, depends only on the input.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.engine.mitre import PATH_TECHNIQUES, tactics_for_techniques
from threatcode.engine.severity import is_sensitive_data_store
from threatcode.engine.stride import StrideCategory
from threatcode.ir.addressing import base_address
from threatcode.ir.edges import (
    AGENT,
    PUBLIC_ENDPOINT,
    REACHABILITY,
    EdgeType,
    InfraEdge,
    port_sort_key,
)
from threatcode.ir.graph import InfraGraph
from threatcode.ir.iam import classify_access
from threatcode.ir.nodes import (
    DATA_CATEGORIES,
    INTERNET_ID,
    NON_TRAFFIC_SUFFIXES,
    InfraNode,
    NodeCategory,
)
from threatcode.models.attack_path import AttackHop, AttackPath, attack_path_id
from threatcode.models.report import threat_severity
from threatcode.models.threat import Severity, Threat, ThreatSource

logger = logging.getLogger(__name__)

register_code(
    "paths.search_truncated",
    "The attack path search reached a limit, so some attack paths may be missing",
)

MAX_HOPS = 8
"""Most edges on a path."""
MAX_PATHS_PER_TARGET = 5
"""Most routes kept to one target from one entry."""
MAX_PATHS = 100
"""Most paths returned."""
MAX_CANDIDATES = 5_000
"""Most routes the search collects before it ranks them."""
MAX_CANDIDATES_PER_TARGET = 200
MAX_VISITS = 250_000
"""Most steps the search takes."""

# IAM relations that do not carry authority to someone who reaches the source
_NOT_FOLLOWED = frozenset({"has_policy", "attaches", "resource_policy", "grants", "bound_subject"})
_ASSUME = frozenset({"assumes", "can_assume"})
# Resources that never hand over a role to whoever reaches them
_NOT_EXECUTING = frozenset({"aws_eks_cluster", "aws_ecs_cluster"})
_EXECUTING = frozenset({NodeCategory.COMPUTE, NodeCategory.SERVERLESS, NodeCategory.CONTAINER})
# Resource types that configure a store and are not a store themselves: the settings, policies and
# rotations of a bucket, a table, a secret or a database, and the companions that attach to one
_STORE_COMPANION_PREFIXES = (
    "aws_s3_bucket_",
    "aws_dynamodb_table_",
    "aws_secretsmanager_secret_",
    "aws_db_instance_",
)
_STORE_COMPANIONS = frozenset(
    {
        "aws_kms_alias",
        "aws_kms_grant",
        "aws_kms_key_policy",
        "aws_efs_mount_target",
        "aws_efs_access_point",
        "aws_rds_cluster_endpoint",
        "aws_rds_cluster_snapshot",
        "aws_rds_cluster_activity_stream",
    }
)
_NOT_STORES = frozenset({"kubernetes_config_map"})
# A Dockerfile COPY or a lockfile entry is not a data store, whatever its category says
_NOT_CLOUD_RESOURCES = ("dockerfile_", "dependency_")
# Ports of remote administration services: reaching them is initial access through T1133
REMOTE_SERVICE_PORTS = frozenset({"22", "23", "3389", "5900", "5985", "5986"})
# Findings that do not help an attacker move along a path
_NOT_ENABLING = frozenset(
    {StrideCategory.REPUDIATION.value, StrideCategory.DENIAL_OF_SERVICE.value}
)
_ENABLING_SOURCES = frozenset({ThreatSource.RULE, ThreatSource.SECRET, ThreatSource.SCANNER})
_SEVERITIES = (Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL)
_EDGE_ORDER = {EdgeType.NETWORK_FLOW: 0, EdgeType.DATA_FLOW: 1, EdgeType.IAM_BINDING: 2}
_IMDS_RULE = "EC2_IMDSV1"


def find(graph: InfraGraph, threats: list[Threat]) -> list[AttackPath]:
    """Return the attack paths of ``graph`` given the findings gathered so far."""
    return _Finder(graph, threats).run()


# ---------------------------------------------------------------------------
# Crown jewels
# ---------------------------------------------------------------------------


def crown_jewel_kind(graph: InfraGraph, node: InfraNode) -> str:
    """What makes a node a crown jewel (a label for reports), or the empty string.

    ``data store`` and ``secret store`` for the data categories, ``administrator identity`` for a
    role that may do everything, ``cluster-admin grant`` for a Kubernetes binding or role with
    cluster-wide control and ``private data`` for an MCP server that reads files or credentials.
    """
    if node.mode == "data" or node.is_internet or node.is_container:
        return ""
    if node.resource_type.startswith(_NOT_CLOUD_RESOURCES):
        return ""
    if node.resource_type.startswith("kubernetes_"):
        return _kubernetes_kind(node)
    if node.resource_type == "mcp_server":
        return _mcp_kind(node)
    if node.category in DATA_CATEGORIES:
        if _is_store_companion(node.resource_type):
            return ""
        return "secret store" if node.category is NodeCategory.SECRET else "data store"
    if node.resource_type == "aws_iam_role" and _is_admin_role(graph, node):
        return "administrator identity"
    return ""


def _is_store_companion(resource_type: str) -> bool:
    return (
        resource_type in _NOT_STORES
        or resource_type in _STORE_COMPANIONS
        or resource_type.startswith(_STORE_COMPANION_PREFIXES)
        or resource_type.endswith(NON_TRAFFIC_SUFFIXES)
    )


def _kubernetes_kind(node: InfraNode) -> str:
    props = node.properties
    if node.resource_type == "kubernetes_secret":
        return "secret store"
    if node.resource_type == "kubernetes_cluster_role_binding":
        return "cluster-admin grant" if props.get("role_ref_name") == "cluster-admin" else ""
    if node.resource_type in ("kubernetes_cluster_role", "kubernetes_role"):
        wildcard = props.get("has_wildcard_verbs") is True
        wildcard = wildcard and props.get("has_wildcard_resources") is True
        return "cluster-admin grant" if wildcard else ""
    return ""


def _mcp_kind(node: InfraNode) -> str:
    props = node.properties
    if props.get("disabled") is True:
        return ""
    tags = props.get("capability_tags")
    reads = isinstance(tags, list) and "reads_private_data" in tags
    if reads or props.get("exposes_sensitive_paths") is True:
        return "private data"
    return ""


def _is_admin_role(graph: InfraGraph, role: InfraNode) -> bool:
    """Whether a role may do everything: a statement of `*` on `*`, or AdministratorAccess."""
    derived = role.properties.get("derived")
    if not isinstance(derived, dict):
        return False
    arns = derived.get("attached_policy_arns")
    if isinstance(arns, list) and any(
        isinstance(a, str) and a.endswith("policy/AdministratorAccess") for a in arns
    ):
        return True
    statements: list[object] = []
    for key in ("inline_policy_statements", "attached_policy_statements"):
        found = derived.get(key)
        if isinstance(found, list):
            statements.extend(found)
    for edge in graph.edges_from(role.id):
        if edge.edge_type is EdgeType.IAM_BINDING and edge.relation == "has_policy":
            policy = graph.get_node(edge.target)
            held = policy.properties.get("derived", {}).get("policy_statements") if policy else None
            if isinstance(held, list):
                statements.extend(held)
    return any(_is_admin_statement(s) for s in statements)


def _is_admin_statement(statement: object) -> bool:
    if not isinstance(statement, dict) or statement.get("effect") != "Allow":
        return False
    if statement.get("has_condition") or statement.get("not_actions"):
        return False
    actions = [a for a in statement.get("actions") or () if isinstance(a, str)]
    resources = [r for r in statement.get("resources") or () if isinstance(r, str)]
    return "*" in actions and "*" in resources and classify_access(actions) == "admin"


# ---------------------------------------------------------------------------
# The search
# ---------------------------------------------------------------------------


@dataclass
class _Route:
    """A walk from an entry to a crown jewel: the nodes and the edge between each pair."""

    nodes: list[str]
    edges: list[InfraEdge]


@dataclass
class _Finder:
    graph: InfraGraph
    threats: list[Threat]
    truncated: list[str] = field(default_factory=list)
    visits: int = 0
    nodes: dict[str, InfraNode] = field(init=False)

    def __post_init__(self) -> None:
        # `graph.nodes` copies the mapping, so it is read once
        self.nodes = self.graph.nodes

    def run(self) -> list[AttackPath]:
        entries = self._entries()
        if not entries:
            return []
        adjacency = self._adjacency()
        targets = {
            n.id: kind
            for n in sorted(self.nodes.values(), key=lambda n: n.id)
            if (kind := crown_jewel_kind(self.graph, n))
        }
        if not targets:
            return []
        useful = _can_reach(adjacency, set(targets))
        routes = self._routes(entries, adjacency, targets, useful)
        enabling = self._enabling_findings()
        paths = [p for r in routes if (p := self._build(r, enabling, targets)) is not None]
        paths = _collapse_instances(paths)
        paths = _best_per_target(paths)
        paths = _drop_subpaths(paths)
        paths.sort(key=lambda p: (-p.score, -p.severity.rank, len(p.hops), p.id))
        if len(paths) > MAX_PATHS:
            self.truncated.append(f"more than {MAX_PATHS} attack paths")
            paths = paths[:MAX_PATHS]
        self._tag_findings(paths, enabling)
        self._report_truncation()
        return paths

    # -- inputs -----------------------------------------------------------------

    def _entries(self) -> list[str]:
        if self.graph.internet_node is not None:
            return [INTERNET_ID]
        return sorted(
            n.id
            for n in self.nodes.values()
            if n.exposure == "internet" and n.mode != "data" and not n.is_container
        )

    def _adjacency(self) -> dict[str, list[InfraEdge]]:
        """One edge per ordered pair of nodes: the strongest of those a path may follow."""
        best: dict[tuple[str, str], InfraEdge] = {}
        for edge in self.graph.edges:
            if edge.edge_type not in REACHABILITY or not self._followable(edge):
                continue
            key = (edge.source, edge.target)
            current = best.get(key)
            if current is None or _edge_rank(edge) < _edge_rank(current):
                best[key] = edge
        adjacency: dict[str, list[InfraEdge]] = {}
        for (source, _target), edge in sorted(best.items()):
            adjacency.setdefault(source, []).append(edge)
        return adjacency

    def _followable(self, edge: InfraEdge) -> bool:
        source = self.graph.get_node(edge.source)
        target = self.graph.get_node(edge.target)
        if source is None or target is None or edge.source == edge.target:
            return False
        if target.is_container or source.is_container or target.mode == "data":
            return False
        if NodeCategory.MONITORING in (source.category, target.category):
            return False
        if edge.edge_type is not EdgeType.IAM_BINDING:
            return True
        if edge.relation in _NOT_FOLLOWED:
            return False
        if edge.relation == "assumes":
            return source.category is NodeCategory.IAM or _executes_code(source)
        if edge.relation in ("instance_profile", "runs", "runs_as"):
            return _executes_code(source)
        return True

    # -- enumeration ----------------------------------------------------------------

    def _routes(
        self,
        entries: Sequence[str],
        adjacency: dict[str, list[InfraEdge]],
        targets: dict[str, str],
        useful: set[str],
    ) -> list[_Route]:
        routes: list[_Route] = []
        per_target: dict[tuple[str, str], int] = {}

        def walk(nodes: list[str], edges: list[InfraEdge]) -> None:
            self.visits += 1
            if self.visits > MAX_VISITS or len(routes) >= MAX_CANDIDATES:
                return
            here = nodes[-1]
            if len(nodes) > 1 and here in targets:
                key = (nodes[0], here)
                if per_target.get(key, 0) < MAX_CANDIDATES_PER_TARGET:
                    per_target[key] = per_target.get(key, 0) + 1
                    routes.append(_Route(list(nodes), list(edges)))
                else:
                    self.truncated.append(f"more than {MAX_CANDIDATES_PER_TARGET} routes to {here}")
                return
            if len(edges) >= MAX_HOPS:
                return
            for edge in adjacency.get(here, ()):
                following = edge.target
                if following in nodes or following not in useful:
                    continue
                nodes.append(following)
                edges.append(edge)
                walk(nodes, edges)
                nodes.pop()
                edges.pop()

        for entry in entries:
            walk([entry], [])
        if self.visits > MAX_VISITS:
            self.truncated.append(f"more than {MAX_VISITS} steps")
        if len(routes) >= MAX_CANDIDATES:
            self.truncated.append(f"more than {MAX_CANDIDATES} routes")
        return routes

    def _enabling_findings(self) -> dict[str, list[Threat]]:
        """Findings that can enable a hop, by the address of the resource they sit on."""
        found: dict[str, list[Threat]] = {}
        for threat in self.threats:
            if (
                threat.source in _ENABLING_SOURCES
                and threat.stride_category not in _NOT_ENABLING
                and threat_severity(threat) > Severity.INFO
            ):
                found.setdefault(threat.resource_address, []).append(threat)
        return found

    # -- one path -------------------------------------------------------------------

    def _build(
        self, route: _Route, enabling: dict[str, list[Threat]], targets: dict[str, str]
    ) -> AttackPath | None:
        hops: list[AttackHop] = []
        used: dict[str, Threat] = {}
        for position, node_id in enumerate(route.nodes):
            node = self.nodes[node_id]
            edge = route.edges[position] if position < len(route.edges) else None
            sites = [node_id] + (_edge_via(edge) if edge is not None else [])
            hop_threats = _unique(t for site in sites for t in enabling.get(site, ()))
            for threat in hop_threats:
                used.setdefault(threat.id, threat)
            arrival = route.edges[position - 1] if position > 0 else None
            hops.append(
                AttackHop(
                    node_id=node_id,
                    resource_type=node.resource_type,
                    zone=node.trust_zone.value,
                    edge_type_to_next=edge.edge_type.value if edge is not None else None,
                    via=_edge_details(edge) if edge is not None else {},
                    enabled_by=[t.id for t in _worst_first(hop_threats)],
                    techniques=self._techniques(node, arrival, hop_threats),
                )
            )
        if not used:
            return None
        target = self.nodes[route.nodes[-1]]
        severity = self._severity(list(used.values()), route.edges, target)
        techniques = list(dict.fromkeys(t for hop in hops for t in hop.techniques))
        path = AttackPath(
            id=attack_path_id(route.nodes),
            entry=route.nodes[0],
            target=route.nodes[-1],
            hops=hops,
            severity=severity,
            score=_score(severity, route.edges, target, targets[target.id]),
            techniques=techniques,
            tactics=tactics_for_techniques(techniques),
        )
        path.rationale = _rationale(path, targets[target.id], list(used.values()))
        return path

    def _severity(self, used: list[Threat], edges: list[InfraEdge], target: InfraNode) -> Severity:
        worst = max((threat_severity(t) for t in used), default=Severity.INFO)
        level = _SEVERITIES.index(worst)
        if is_sensitive_data_store(target):
            level += 1
        severity = _SEVERITIES[min(level, len(_SEVERITIES) - 1)]
        if severity is Severity.CRITICAL and not all(e.definite for e in edges):
            severity = Severity.HIGH
        return severity

    def _techniques(
        self,
        node: InfraNode,
        arrival: InfraEdge | None,
        hop_threats: list[Threat],
    ) -> list[str]:
        found: list[str] = []
        props = node.properties
        if arrival is not None:
            entering = self.nodes[arrival.source]
            if entering.is_internet:
                found.append(_entry_technique(arrival))
            if arrival.relation in _ASSUME and node.resource_type == "aws_iam_role":
                found.append(PATH_TECHNIQUES["role_assumption"])
            if node.resource_type == "aws_s3_bucket" or (
                node.category is NodeCategory.STORAGE and node.resource_type.startswith("aws_")
            ):
                found.append(PATH_TECHNIQUES["cloud_storage_data"])
            if node.resource_type == "kubernetes_secret":
                found.append(PATH_TECHNIQUES["container_secret"])
            if node.resource_type == "mcp_server" and crown_jewel_kind(self.graph, node):
                found.append(PATH_TECHNIQUES["local_data"])
                if props.get("exposes_sensitive_paths") is True:
                    found.append(PATH_TECHNIQUES["credentials_in_files"])
        if any(t.rule_id == _IMDS_RULE for t in hop_threats):
            found.append(PATH_TECHNIQUES["instance_metadata"])
        if props.get("privileged") is True:
            found.append(PATH_TECHNIQUES["container_escape"])
        return list(dict.fromkeys(found))

    # -- results ----------------------------------------------------------------------

    def _tag_findings(self, paths: list[AttackPath], enabling: dict[str, list[Threat]]) -> None:
        by_id = {t.id: t for threats in enabling.values() for t in threats}
        for path in paths:
            for hop in path.hops:
                for threat_id in hop.enabled_by:
                    threat = by_id.get(threat_id)
                    if threat is not None and path.id not in threat.path_ids:
                        threat.path_ids.append(path.id)
        for threat in by_id.values():
            threat.path_ids.sort()

    def _report_truncation(self) -> None:
        if not self.truncated:
            return
        detail = "; ".join(dict.fromkeys(self.truncated))
        message = (
            f"The attack path search stopped early ({detail}), so some attack paths may be missing."
        )
        logger.warning(message)
        self.graph.diagnostics.append(Diagnostic("warning", "paths.search_truncated", message))


def _executes_code(node: InfraNode) -> bool:
    return node.category in _EXECUTING and node.resource_type not in _NOT_EXECUTING


def _edge_rank(edge: InfraEdge) -> tuple[int, int, str]:
    return (0 if edge.definite else 1, _EDGE_ORDER[edge.edge_type], edge.relation)


def _can_reach(adjacency: dict[str, list[InfraEdge]], targets: set[str]) -> set[str]:
    """The nodes from which some target can be reached (the targets included)."""
    reverse: dict[str, list[str]] = {}
    for source, edges in adjacency.items():
        for edge in edges:
            reverse.setdefault(edge.target, []).append(source)
    reached = set(targets)
    stack = list(targets)
    while stack:
        for source in reverse.get(stack.pop(), ()):
            if source not in reached:
                reached.add(source)
                stack.append(source)
    return reached


def _edge_via(edge: InfraEdge) -> list[str]:
    via = edge.attributes.get("via")
    return [v for v in via if isinstance(v, str)] if isinstance(via, list) else []


def _edge_details(edge: InfraEdge) -> dict[str, object]:
    """What the edge to the next hop is, for the hop's ``via``."""
    details: dict[str, object] = {}
    if edge.relation:
        details["relation"] = edge.relation
    kind = edge.source_kind
    if kind:
        details["source"] = kind
    protocols = edge.protocols
    if protocols:
        details["protocol"] = protocols[0] if len(protocols) == 1 else "/".join(protocols)
    ports = sorted(edge.ports, key=port_sort_key)
    if ports:
        details["ports"] = ports
    via = _edge_via(edge)
    if via:
        details["via"] = via
    access = edge.attributes.get("access")
    if isinstance(access, str):
        details["access"] = access
    actions = edge.attributes.get("actions")
    if isinstance(actions, list):
        details["actions"] = [a for a in actions if isinstance(a, str)]
    if edge.world_open:
        details["world_open"] = True
    if not edge.definite:
        details["definite"] = False
    return details


def _entry_technique(edge: InfraEdge) -> str:
    if edge.source_kind == AGENT:
        return PATH_TECHNIQUES["content_injection"]
    if edge.source_kind != PUBLIC_ENDPOINT and set(edge.ports) & REMOTE_SERVICE_PORTS:
        return PATH_TECHNIQUES["exposed_remote_service"]
    return PATH_TECHNIQUES["exposed_application"]


def _unique(threats: Iterable[Threat]) -> list[Threat]:
    return list({t.id: t for t in threats}.values())


def _worst_first(threats: Iterable[Threat]) -> list[Threat]:
    return sorted(threats, key=lambda t: (-threat_severity(t).rank, t.id))


def _score(severity: Severity, edges: list[InfraEdge], target: InfraNode, kind: str) -> float:
    score = severity.rank * 1.5
    if edges and edges[0].world_open:
        score += 2.0
    score += max(0, MAX_HOPS - len(edges)) * 0.2
    if is_sensitive_data_store(target):
        score += 0.6
    elif kind in ("secret store", "administrator identity", "cluster-admin grant"):
        score += 0.4
    return round(score, 2)


def _rationale(path: AttackPath, kind: str, used: list[Threat]) -> str:
    first = path.hops[0]
    start = "The internet" if path.entry == INTERNET_ID else path.entry
    reach = path.hops[1].node_id if len(path.hops) > 1 else path.target
    via = first.via
    protocol = via.get("protocol")
    ports = via.get("ports")
    where = ""
    if isinstance(ports, list) and ports:
        where = f" on {protocol or 'port'}/{','.join(str(p) for p in ports)}"
    elif isinstance(protocol, str):
        where = f" over {protocol}"
    middle = len(path.hops) - 2
    through = f", then {middle} more hop{'s' if middle != 1 else ''}," if middle > 0 else ""
    worst = _worst_first(used)[0]
    count = len(used)
    return (
        f"{start} reaches {reach}{where}{through} and ends at {path.target} ({kind}); "
        f"{count} finding{'s' if count != 1 else ''} enable{'' if count != 1 else 's'} it, "
        f"the worst being {worst.title} ({threat_severity(worst).value})."
    )


# ---------------------------------------------------------------------------
# Ranking and de-duplication
# ---------------------------------------------------------------------------


def _collapse_instances(paths: list[AttackPath]) -> list[AttackPath]:
    """Keep one path for the routes that differ only by the instance of a counted resource."""
    groups: dict[tuple[str, ...], list[AttackPath]] = {}
    for path in paths:
        groups.setdefault(tuple(base_address(n) for n in path.node_ids), []).append(path)
    kept: list[AttackPath] = []
    for key in sorted(groups):
        group = sorted(groups[key], key=lambda p: [_natural(n) for n in p.node_ids])
        # The representative is the first by node order; it stands for the others
        best = group[0]
        best.alternatives = len(group) - 1
        if best.alternatives:
            best.rationale = best.rationale.rstrip(".") + (
                f"; {best.alternatives} more route{'s' if best.alternatives != 1 else ''} "
                "through other instances of the same resources."
            )
        kept.append(best)
    return kept


def _natural(address: str) -> list[tuple[int, int, str]]:
    """Sort key that puts `app[2]` before `app[10]`."""
    return [
        (1, int(part), "") if part.isdigit() else (0, 0, part)
        for part in re.split(r"(\d+)", address)
    ]


def _best_per_target(paths: list[AttackPath]) -> list[AttackPath]:
    by_pair: dict[tuple[str, str], list[AttackPath]] = {}
    for path in paths:
        by_pair.setdefault((path.entry, path.target), []).append(path)
    kept: list[AttackPath] = []
    for key in sorted(by_pair):
        ranked = sorted(by_pair[key], key=lambda p: (-p.score, -p.severity.rank, len(p.hops), p.id))
        kept.extend(ranked[:MAX_PATHS_PER_TARGET])
    return kept


def _drop_subpaths(paths: list[AttackPath]) -> list[AttackPath]:
    """Drop every path whose nodes are a contiguous part of a longer path's nodes."""
    sequences = [(p, p.node_ids) for p in paths]
    kept: list[AttackPath] = []
    for path, nodes in sequences:
        if not any(len(other) > len(nodes) and _contains(other, nodes) for _p, other in sequences):
            kept.append(path)
    return kept


def _contains(longer: list[str], shorter: list[str]) -> bool:
    width = len(shorter)
    return any(longer[i : i + width] == shorter for i in range(len(longer) - width + 1))
