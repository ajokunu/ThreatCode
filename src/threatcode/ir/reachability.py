"""Reachability: the directed edges an attacker can follow, and the synthetic internet node.

`apply` runs after exposure, when every node has its zone and its `exposure`, and before the
trust boundary crossings are marked, so the edges it adds are marked and analysed like any other.
It adds `network_flow`, `data_flow` and `iam_binding` edges in the direction traffic or authority
travels, with the attributes documented in `threatcode.ir.edges`, and a node `internet`
(resource type `internet`, zone `internet`) that is created only when some edge starts there.
Attack paths (`threatcode.engine.paths`) walk these edges and nothing else.

Nothing here guesses: an edge exists because the input states the facts that make it, and an
unknown value never creates one.
An edge that rests on a fact the input cannot settle (a server of unknown capability) is marked
`definite: false`.

AWS
---

=======================  ==============================================================
facts                    edge
=======================  ==============================================================
security group ingress   `internet -> X` for every resource X attached to the group when the
from a world CIDR        rule is open to `0.0.0.0/0` or `::/0` and X is reachable from outside
                         (`exposure` internet, so a public address in a public subnet, an
                         internet-facing load balancer, a publicly accessible database).
                         A world-open group on a resource in a private subnet adds nothing.
security group ingress   `A -> B` for every A attached to the source group and every B attached
from another group       to the group that has the rule, with the rule's protocol and ports.
(or from itself)         Egress rules are ignored.
load balancer            `lb -> target` for the targets of the target groups its listeners
                         forward to: attachments, Auto Scaling groups, ECS services, Lambda
                         functions, inline targets and a classic load balancer's instances.
                         `internet -> lb` only where a security group of the load balancer
                         admits the world, or for an internet-facing one with no group at all.
CloudFront               `internet -> distribution`, `distribution -> origin` (bucket, load
                         balancer, API).
API Gateway              `internet -> api`, `api -> function` through its integrations and
                         Lambda permissions.
Lambda function URL      `internet -> url` for auth NONE, `url -> function`.
public S3 bucket,        `internet -> X` for a bucket a policy or ACL opens to everyone, and
EKS public endpoint      for a cluster whose API endpoint is public.
Auto Scaling group,      `asg -> launch template` and `service -> task definition`
ECS service              (`iam_binding`, `runs`), so the identity of the instances or tasks
                         can be followed to what it may reach.
=======================  ==============================================================

The IAM edges (`resource -> role`, `role -> resource` with their access level) come from
`threatcode.ir.iam` and are reachability edges as they stand.
Network address translation is not modelled: a private subnet's egress through a NAT gateway is
not an edge.

Kubernetes
----------

These edges are derived from the properties the parser leaves on the nodes, so they join
manifests that live in different files (the parser links a single input only).
An edge that the parser already added merges with the one found here.

- `internet -> Service` for a `LoadBalancer` or `NodePort` Service, `internet -> Ingress` for an
  Ingress with rules.
- `Ingress -> Service` for each backend, `Service -> workload` for the workloads of the same
  namespace whose pod labels contain the selector.
- `workload -> Secret` for the Secrets the workload reads, `workload -> ServiceAccount`.
- `ServiceAccount -> Role` through each binding that names it (the binding points at both, so
  the walk needs this edge), and `Role -> Secret` when the role may read Secrets, within the
  scope of its bindings (the cluster for a ClusterRoleBinding, the namespace otherwise).
  A binding to the built-in `cluster-admin` role has no role node, so the account reaches the
  binding itself.

MCP agent configurations
------------------------

`internet -> server` (`data_flow`) for an enabled server that ingests untrusted content and for
a remote server, whose content and responses an outsider controls.
The parser's edges `server -> agent` (content) and `agent -> server` (invocation) complete the
walk from untrusted content, through the agent, to the servers that read private data or act.
A remote server of unknown capability is a `definite: false` entry.

Limits
------

A rule that would add more than `graph.max_fanout` edges (500 by default, the
`THREATCODE_MAX_FANOUT` variable or `InfraGraph(max_fanout=...)`) keeps the first ones and the
graph records one `graph.edge_cap` warning, because a truncated walk can hide a path.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator, Mapping, Sequence
from typing import TYPE_CHECKING, Any

from threatcode.diagnostics import Diagnostic
from threatcode.ir.edges import (
    AGENT,
    API_INTEGRATION,
    CDN_ORIGIN,
    IAM,
    INGRESS,
    K8S_SERVICE,
    LB_LISTENER,
    PUBLIC_ENDPOINT,
    RBAC,
    SG_RULE,
    WORKLOAD,
    EdgeType,
)
from threatcode.ir.enrich import EnrichContext
from threatcode.ir.exposure import is_world_cidr
from threatcode.ir.nodes import InfraNode, tri_state
from threatcode.ir.references import ReferenceIndex, TypeMatcher, type_is
from threatcode.values import is_unknown

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

SG_TYPES = frozenset({"aws_security_group", "aws_default_security_group"})
LB_TYPES = frozenset({"aws_lb", "aws_alb", "aws_nlb", "aws_elb"})
LISTENER_TYPES = frozenset({"aws_lb_listener", "aws_alb_listener"})
LISTENER_RULE_TYPES = frozenset({"aws_lb_listener_rule", "aws_alb_listener_rule"})
TARGET_GROUP_TYPES = frozenset({"aws_lb_target_group", "aws_alb_target_group"})
ATTACHMENT_TYPES = frozenset(
    {
        "aws_lb_target_group_attachment",
        "aws_alb_target_group_attachment",
        "aws_autoscaling_attachment",
    }
)
TARGET_TYPES = frozenset(
    {"aws_instance", "aws_autoscaling_group", "aws_ecs_service", "aws_lambda_function"}
)
LAUNCH_TEMPLATE_TYPES = frozenset({"aws_launch_template", "aws_launch_configuration"})
API_TYPES = frozenset({"aws_api_gateway_rest_api", "aws_apigatewayv2_api"})
INTEGRATION_TYPES = frozenset(
    {"aws_api_gateway_integration", "aws_apigatewayv2_integration", "aws_lambda_permission"}
)
ORIGIN_TYPES = (
    LB_TYPES | API_TYPES | frozenset({"aws_s3_bucket", "aws_lambda_function_url", "aws_instance"})
)
_GROUP_ARN_PATHS = (
    "default_action.target_group_arn",
    "default_action.forward.target_group.arn",
    "action.target_group_arn",
    "action.forward.target_group.arn",
)
_ATTACHMENT_GROUP_PATHS = ("target_group_arn", "lb_target_group_arn", "alb_target_group_arn")
_ATTACHMENT_TARGET_PATHS = ("target_id", "instance", "autoscaling_group_name")
# Resources that answer to anyone once exposure says so, with no security group in front
PUBLIC_ENDPOINT_PORTS: dict[str, list[str]] = {
    "aws_s3_bucket": ["443"],
    "aws_cloudfront_distribution": ["443"],
    "aws_api_gateway_rest_api": ["443"],
    "aws_apigatewayv2_api": ["443"],
    "aws_lambda_function_url": ["443"],
    "aws_eks_cluster": ["443"],
}
# A security group member that only configures other resources or holds no traffic of its own
NOT_ENDPOINTS = LAUNCH_TEMPLATE_TYPES
# Functions are invoked, they do not listen: a security group rule cannot admit traffic to one
NOT_LISTENERS = frozenset({"aws_lambda_function"})

_PROTOCOLS = {"-1": "all", "all": "all", "6": "tcp", "17": "udp", "1": "icmp", "icmp": "icmp"}
_S3_DOMAIN = re.compile(r"^(?P<bucket>.+?)\.s3[.-](?:[a-z0-9-]+\.)?amazonaws\.com(?:\.cn)?$")
_MAX_WALK_DEPTH = 6
_RBAC_READ_VERBS = frozenset({"get", "list", "watch", "*"})
_RBAC_SECRET_RESOURCES = frozenset({"secrets", "*"})
_CLUSTER_ADMIN = "cluster-admin"


def apply(graph: InfraGraph) -> None:
    """Add the reachability edges and, if one starts there, the internet node."""
    _Reach(graph).run()


# ---------------------------------------------------------------------------
# Reading properties
# ---------------------------------------------------------------------------


def _values(properties: Any, path: str) -> list[Any]:
    """Every value at a dotted path, through nested blocks (a block is a list of mappings)."""
    current: list[Any] = [properties]
    for segment in path.split("."):
        following: list[Any] = []
        for item in current:
            for entry in item if isinstance(item, list) else [item]:
                if isinstance(entry, Mapping) and segment in entry:
                    following.append(entry[segment])
        current = following
        if not current:
            return []
    flat: list[Any] = []
    for value in current:
        flat.extend(value if isinstance(value, list) else [value])
    return flat


def _first(properties: Any, *paths: str) -> Any:
    for path in paths:
        found = _values(properties, path)
        if found:
            return found[0]
    return None


def _list(value: Any) -> list[Any]:
    """The items of a list or tuple; anything else (a parser left a malformed value) is empty."""
    return list(value) if isinstance(value, (list, tuple)) else []


def _text_list(value: Any) -> list[str]:
    """The plain strings in a value; an `Unknown` and anything else is left out."""
    items = value if isinstance(value, (list, tuple)) else [value]
    return [i for i in items if isinstance(i, str) and not is_unknown(i) and i]


def _port_text(value: Any) -> str | None:
    """A port as text, or None when it is not a known number."""
    if isinstance(value, bool) or is_unknown(value) or value is None:
        return None
    if isinstance(value, int):
        return str(value)
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return str(int(value.strip()))
    return None


def _protocol_name(value: Any) -> str:
    if is_unknown(value) or value is None:
        return ""
    text = str(value).strip().lower()
    return _PROTOCOLS.get(text, text)


def _lb_protocol(value: Any) -> str:
    """The transport of a load balancer protocol (`HTTPS` and `TLS` both ride on tcp)."""
    name = _protocol_name(value)
    if name in ("udp", "tcp_udp", "geneve"):
        return "udp"
    return "tcp" if name else ""


def _walk_security_group_values(value: Any, depth: int = 0) -> Iterator[Any]:
    """Values stored under a key that names security groups, at any depth."""
    if depth > _MAX_WALK_DEPTH or not isinstance(value, Mapping):
        return
    for key, item in value.items():
        if key == "derived":
            continue
        if "security_group" in str(key).lower():
            yield item
        elif isinstance(item, Mapping):
            yield from _walk_security_group_values(item, depth + 1)
        elif isinstance(item, list):
            for entry in item:
                yield from _walk_security_group_values(entry, depth + 1)


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------


class _BalancerModel:
    """What the listeners and target groups of the input connect."""

    def __init__(self) -> None:
        # load balancer id -> its listeners and listener rules
        self.listeners: dict[str, list[InfraNode]] = {}
        # listener or rule id -> the target groups it forwards to
        self.groups: dict[str, list[InfraNode]] = {}
        # target group id -> what it sends traffic to
        self.targets: dict[str, list[InfraNode]] = {}

    def add_targets(self, group_id: str, targets: Iterable[InfraNode]) -> None:
        known = self.targets.setdefault(group_id, [])
        present = {n.id for n in known}
        for target in targets:
            if target.id not in present:
                present.add(target.id)
                known.append(target)
        known.sort(key=lambda n: n.id)


class _Budget:
    """How many more edges one rule may add."""

    def __init__(self, label: str, limit: int) -> None:
        self.label = label
        self.left = limit
        self.dropped = 0

    def take(self) -> bool:
        if self.left <= 0:
            self.dropped += 1
            return False
        self.left -= 1
        return True


class _Reach:
    def __init__(self, graph: InfraGraph) -> None:
        self.graph = graph
        self.ctx = EnrichContext(graph, ReferenceIndex(graph.nodes))
        self.nodes: list[InfraNode] = [
            node
            for _node_id, node in sorted(graph.nodes.items())
            if node.mode == "managed" and not node.is_internet
        ]
        self.by_type: dict[str, list[InfraNode]] = {}
        for node in self.nodes:
            self.by_type.setdefault(node.resource_type, []).append(node)
        self._members: dict[str, list[InfraNode]] | None = None
        self._truncated: list[_Budget] = []

    # -- plumbing -----------------------------------------------------------

    def run(self) -> None:
        self._security_groups()
        self._load_balancers()
        self._cloudfront()
        self._api_gateway()
        self._lambda_urls()
        self._public_endpoints()
        self._runs()
        self._kubernetes()
        self._mcp()
        self._report_truncation()

    def of_types(self, types: Iterable[str]) -> list[InfraNode]:
        found: list[InfraNode] = []
        for resource_type in sorted(types):
            found.extend(self.by_type.get(resource_type, ()))
        return found

    def node(self, node_id: str) -> InfraNode | None:
        return self.graph.get_node(node_id)

    def successors(self, node: InfraNode, types: frozenset[str]) -> list[InfraNode]:
        found: list[InfraNode] = []
        for node_id in self.graph.successors(node.id):
            other = self.node(node_id)
            if other is not None and other.resource_type in types:
                found.append(other)
        return found

    def predecessors(self, node: InfraNode, types: frozenset[str]) -> list[InfraNode]:
        found: list[InfraNode] = []
        for node_id in self.graph.predecessors(node.id):
            other = self.node(node_id)
            if other is not None and other.resource_type in types:
                found.append(other)
        return found

    def budget(self, label: str) -> _Budget:
        budget = _Budget(label, self.graph.max_fanout)
        self._truncated.append(budget)
        return budget

    def add(
        self,
        budget: _Budget,
        source: str,
        target: str,
        edge_type: EdgeType,
        *,
        kind: str,
        relation: str = "",
        via: Iterable[str] = (),
        protocol: str = "",
        ports: Iterable[Any] = (),
        world_open: bool = False,
        definite: bool = True,
        extra: Mapping[str, Any] | None = None,
    ) -> bool:
        if source == target or not budget.take():
            return False
        self.graph.add_reachability_edge(
            source,
            target,
            edge_type,
            kind=kind,
            relation=relation,
            via=via,
            protocol=protocol,
            ports=ports,
            world_open=world_open,
            definite=definite,
            extra=extra,
        )
        return True

    def from_internet(
        self,
        budget: _Budget,
        target: InfraNode,
        *,
        kind: str,
        relation: str = "",
        via: Iterable[str] = (),
        protocol: str = "",
        ports: Iterable[Any] = (),
        definite: bool = True,
        edge_type: EdgeType = EdgeType.NETWORK_FLOW,
    ) -> None:
        internet = self.graph.ensure_internet_node()
        self.add(
            budget,
            internet.id,
            target.id,
            edge_type,
            kind=kind,
            relation=relation,
            via=via,
            protocol=protocol,
            ports=ports,
            world_open=True,
            definite=definite,
        )

    def _report_truncation(self) -> None:
        cut = [b for b in self._truncated if b.dropped]
        if not cut:
            return
        shown = ", ".join(f"{b.label} (+{b.dropped})" for b in cut[:5])
        more = f", and {len(cut) - 5} more" if len(cut) > 5 else ""
        self.graph.diagnostics.append(
            Diagnostic(
                "warning",
                "graph.edge_cap",
                f"{len(cut)} reachability rule(s) reached the fan-out limit of "
                f"{self.graph.max_fanout} edges and skipped the rest: {shown}{more}. Paths "
                "through the skipped edges are not found. Raise the limit with "
                "InfraGraph(max_fanout=...) or the THREATCODE_MAX_FANOUT environment variable.",
            )
        )

    def resolve(self, node: InfraNode, raw: Any, matcher: TypeMatcher) -> list[InfraNode]:
        """The nodes a property value names (a reference, a literal or an `Unknown`)."""
        index = self.ctx.index_for(node)
        found = index.resolve_value(raw, node.module, required_type=matcher)
        return [n for node_id in found.ids if (n := self.node(node_id)) is not None]

    # -- security groups ----------------------------------------------------

    def members(self) -> dict[str, list[InfraNode]]:
        """For each security group id, the resources attached to it, in id order."""
        if self._members is not None:
            return self._members
        members: dict[str, list[InfraNode]] = {}
        for node in self.nodes:
            if not node.can_exchange_traffic or node.resource_type in NOT_ENDPOINTS:
                continue
            groups = self._attached_groups(node)
            if node.resource_type == "aws_autoscaling_group":
                # The instances of a group take the security groups of its launch template
                for template in self.successors(node, LAUNCH_TEMPLATE_TYPES):
                    groups.extend(self._attached_groups(template))
            for group in dict.fromkeys(groups):
                members.setdefault(group, []).append(node)
        self._members = members
        return members

    def _attached_groups(self, node: InfraNode) -> list[str]:
        """Ids of the security groups a resource names: attachment edges, then any property."""
        found: dict[str, None] = {}
        for edge in self.graph.edges_from(node.id):
            target = self.node(edge.target)
            if edge.relation == "security_group" and target and target.resource_type in SG_TYPES:
                found.setdefault(target.id)
        for raw in _walk_security_group_values(node.properties):
            for group in self.resolve(node, raw, _is_group):
                found.setdefault(group.id)
        return list(found)

    def _reachable_from_outside(self, node: InfraNode) -> bool:
        """Whether the internet can send traffic to a resource once a group admits it."""
        if node.resource_type in NOT_LISTENERS or not node.can_exchange_traffic:
            return False
        if node.exposure == "internet":
            return True
        return node.resource_type == "aws_ecs_service" and self._ecs_public(node)

    def _ecs_public(self, node: InfraNode) -> bool:
        """An ECS service whose tasks get a public address in a public subnet."""
        flag = _first(node.properties, "network_configuration.assign_public_ip")
        if tri_state(flag, node.evidence) != "true":
            return False
        for edge in self.graph.edges_from(node.id):
            subnet = self.node(edge.target)
            if subnet is not None and subnet.resource_type == "aws_subnet":
                if subnet.exposure == "internet":
                    return True
        return False

    def _ingress_rules(self, group: InfraNode) -> list[Mapping[str, Any]]:
        derived = self.ctx.derived(group).get("ingress")
        rules = derived if derived is not None else _values(group.properties, "ingress")
        if not isinstance(rules, list):
            return []
        return [rule for rule in rules if isinstance(rule, Mapping)]

    def _security_groups(self) -> None:
        members = self.members()
        for group in self.of_types(SG_TYPES):
            attached = members.get(group.id, [])
            for number, rule in enumerate(self._ingress_rules(group), start=1):
                protocol, ports, definite = _traffic(rule)
                label = f"{group.id} ingress rule {number}"
                if _world_open(rule):
                    budget = self.budget(f"{label} from the internet")
                    for member in attached:
                        if self._reachable_from_outside(member):
                            self.from_internet(
                                budget,
                                member,
                                kind=SG_RULE,
                                via=[group.id],
                                protocol=protocol,
                                ports=ports,
                                definite=definite,
                            )
                receivers = [m for m in attached if m.resource_type not in NOT_LISTENERS]
                for source_group in self._source_groups(group, rule):
                    senders = members.get(source_group.id, [])
                    self._connect(label, senders, receivers, group, source_group, rule)
                if rule.get("self") is True:
                    self._connect(label, attached, receivers, group, group, rule)

    def _source_groups(self, group: InfraNode, rule: Mapping[str, Any]) -> list[InfraNode]:
        raw = rule.get("source_security_groups")
        if raw is None or (is_unknown(raw) and not raw.reference):
            return []
        return [g for g in self.resolve(group, raw, _is_group) if g.id != group.id]

    def _connect(
        self,
        label: str,
        senders: Sequence[InfraNode],
        receivers: Sequence[InfraNode],
        group: InfraNode,
        source_group: InfraNode,
        rule: Mapping[str, Any],
    ) -> None:
        protocol, ports, definite = _traffic(rule)
        via = [group.id] if source_group.id == group.id else [group.id, source_group.id]
        budget = self.budget(f"{label} from {source_group.id}")
        for sender in senders:
            for receiver in receivers:
                self.add(
                    budget,
                    sender.id,
                    receiver.id,
                    EdgeType.NETWORK_FLOW,
                    kind=SG_RULE,
                    via=via,
                    protocol=protocol,
                    ports=ports,
                    definite=definite,
                )

    # -- load balancers -----------------------------------------------------

    def linked(
        self,
        node: InfraNode,
        paths: Sequence[str],
        types: frozenset[str],
    ) -> list[InfraNode]:
        """The nodes of some types a node names: in the properties at `paths`, or by an edge.

        The properties are read first because an input can name a node without the parser
        having made it a reference (a `${...}` string in a nested block); the edges the parser
        and the builder found cover the rest.
        """
        found: dict[str, InfraNode] = {}
        for path in paths:
            for raw in _values(node.properties, path):
                for other in self.resolve(node, raw, types.__contains__):
                    found.setdefault(other.id, other)
        for other in self.successors(node, types):
            found.setdefault(other.id, other)
        return [found[k] for k in sorted(found)]

    def _load_balancers(self) -> None:
        model = self._balancer_model()
        for lb in self.of_types(LB_TYPES):
            listeners = model.listeners.get(lb.id, [])
            if (
                lb.exposure == "internet"
                and lb.resource_type != "aws_elb"
                and not _walk_has_security_groups(lb)
            ):
                # A network load balancer without a security group admits every address
                ports = sorted({p for listener in listeners for p in _listener_ports(listener)})
                self.from_internet(
                    self.budget(f"{lb.id} from the internet"),
                    lb,
                    kind=LB_LISTENER,
                    via=[listener.id for listener in listeners],
                    protocol="tcp",
                    ports=ports,
                    definite=bool(ports),
                )
            budget = self.budget(f"{lb.id} targets")
            for target, via, protocol, port in self._targets(lb, listeners, model):
                self.add(
                    budget,
                    lb.id,
                    target.id,
                    EdgeType.NETWORK_FLOW,
                    kind=LB_LISTENER,
                    via=via,
                    protocol=protocol,
                    ports=[port] if port else [],
                    definite=bool(port),
                )

    def _balancer_model(self) -> _BalancerModel:
        """Which listeners belong to which load balancer, and what each target group reaches."""
        model = _BalancerModel()
        for listener in self.of_types(LISTENER_TYPES):
            for lb in self.linked(listener, ["load_balancer_arn"], LB_TYPES):
                model.listeners.setdefault(lb.id, []).append(listener)
        for rule in self.of_types(LISTENER_RULE_TYPES):
            for listener in self.linked(rule, ["listener_arn"], LISTENER_TYPES):
                for lb_id, listeners in list(model.listeners.items()):
                    if any(known.id == listener.id for known in listeners):
                        model.listeners[lb_id].append(rule)
        for listener in self.of_types(LISTENER_TYPES | LISTENER_RULE_TYPES):
            model.groups[listener.id] = self.linked(listener, _GROUP_ARN_PATHS, TARGET_GROUP_TYPES)
        for attachment in self.of_types(ATTACHMENT_TYPES):
            groups = self.linked(attachment, _ATTACHMENT_GROUP_PATHS, TARGET_GROUP_TYPES)
            targets = self.linked(attachment, _ATTACHMENT_TARGET_PATHS, TARGET_TYPES)
            for group in groups:
                model.add_targets(group.id, targets)
        for owner in self.of_types({"aws_autoscaling_group", "aws_ecs_service"}):
            paths = ["target_group_arns", "load_balancer.target_group_arn"]
            for group in self.linked(owner, paths, TARGET_GROUP_TYPES):
                model.add_targets(group.id, [owner])
        for group in self.of_types(TARGET_GROUP_TYPES):
            inline = [
                entry.get("id") if isinstance(entry, Mapping) else entry
                for entry in _values(group.properties, "targets")
            ]
            for raw in inline:
                model.add_targets(group.id, self.resolve(group, raw, TARGET_TYPES.__contains__))
        return model

    def _targets(
        self, lb: InfraNode, listeners: Sequence[InfraNode], model: _BalancerModel
    ) -> list[tuple[InfraNode, list[str], str, str]]:
        """(target, via, protocol, port) for everything a load balancer sends traffic to."""
        found: list[tuple[InfraNode, list[str], str, str]] = []
        seen: set[tuple[str, str]] = set()
        for listener in listeners:
            for group in model.groups.get(listener.id, []):
                protocol = _lb_protocol(group.properties.get("protocol"))
                port = _port_text(group.properties.get("port")) or ""
                for target in model.targets.get(group.id, []):
                    key = (target.id, listener.id)
                    if key not in seen:
                        seen.add(key)
                        found.append((target, [listener.id, group.id], protocol, port))
        if lb.resource_type == "aws_elb":
            ports = sorted({p for listener in _elb_listeners(lb) for p in listener[1]})
            for target in self.resolve(lb, lb.properties.get("instances"), type_is("aws_instance")):
                for port in ports or [""]:
                    found.append((target, [], "tcp", port))
        return found

    # -- CDN, API and the other managed endpoints ----------------------------

    def _cloudfront(self) -> None:
        for dist in self.of_types({"aws_cloudfront_distribution"}):
            if dist.exposure != "internet":
                continue
            budget = self.budget(f"{dist.id} origins")
            self.from_internet(budget, dist, kind=PUBLIC_ENDPOINT, protocol="tcp", ports=["443"])
            for origin in self._origins(dist):
                self.add(
                    budget,
                    dist.id,
                    origin.id,
                    EdgeType.NETWORK_FLOW,
                    kind=CDN_ORIGIN,
                    protocol="tcp",
                    ports=["443"],
                )

    def _origins(self, dist: InfraNode) -> list[InfraNode]:
        found: dict[str, InfraNode] = {}
        for key in ("origin", "origins", "Origins"):
            for entry in _values(dist.properties, key):
                if not isinstance(entry, Mapping):
                    continue
                domain = entry.get("domain_name", entry.get("DomainName"))
                for origin in self.resolve(dist, domain, ORIGIN_TYPES.__contains__):
                    found.setdefault(origin.id, origin)
                for name in _text_list(domain):
                    bucket = self._bucket_for_domain(name)
                    if bucket is not None:
                        found.setdefault(bucket.id, bucket)
        return [found[k] for k in sorted(found)]

    def _bucket_for_domain(self, domain: str) -> InfraNode | None:
        match = _S3_DOMAIN.match(domain.strip().lower())
        if match is None:
            return None
        name = match.group("bucket")
        hits = [
            bucket
            for bucket in self.by_type.get("aws_s3_bucket", ())
            if str(bucket.properties.get("bucket", "")).lower() == name
        ]
        return hits[0] if len(hits) == 1 else None

    def _api_gateway(self) -> None:
        for api in self.of_types(API_TYPES):
            if api.exposure == "internet":
                self.from_internet(
                    self.budget(f"{api.id} from the internet"),
                    api,
                    kind=PUBLIC_ENDPOINT,
                    protocol="tcp",
                    ports=["443"],
                )
        budget = self.budget("API Gateway integrations")
        for integration in self.of_types(INTEGRATION_TYPES):
            apis = self.linked(integration, ["rest_api_id", "api_id", "source_arn"], API_TYPES)
            invoked = frozenset({"aws_lambda_function", *LB_TYPES})
            targets = self.linked(integration, ["uri", "integration_uri", "function_name"], invoked)
            for api in apis:
                for target in targets:
                    self.add(
                        budget,
                        api.id,
                        target.id,
                        EdgeType.NETWORK_FLOW,
                        kind=API_INTEGRATION,
                        via=[integration.id],
                        protocol="tcp",
                        ports=["443"],
                    )

    def _lambda_urls(self) -> None:
        budget = self.budget("Lambda function URLs")
        for url in self.of_types({"aws_lambda_function_url"}):
            if url.exposure == "internet":
                self.from_internet(budget, url, kind=PUBLIC_ENDPOINT, protocol="tcp", ports=["443"])
            for function in self.linked(url, ["function_name"], frozenset({"aws_lambda_function"})):
                self.add(
                    budget,
                    url.id,
                    function.id,
                    EdgeType.NETWORK_FLOW,
                    kind=API_INTEGRATION,
                    protocol="tcp",
                    ports=["443"],
                )

    def _public_endpoints(self) -> None:
        budget = self.budget("public endpoints")
        for resource_type in ("aws_s3_bucket", "aws_eks_cluster"):
            for node in self.by_type.get(resource_type, ()):
                if node.exposure == "internet":
                    self.from_internet(
                        budget,
                        node,
                        kind=PUBLIC_ENDPOINT,
                        protocol="tcp",
                        ports=PUBLIC_ENDPOINT_PORTS[resource_type],
                    )

    def _runs(self) -> None:
        """A group launches the instances of its template, a service runs its task definition."""
        budget = self.budget("launch templates and task definitions")
        for group in self.of_types({"aws_autoscaling_group"}):
            paths = [
                "launch_template.id",
                "launch_template.name",
                "launch_configuration",
                "mixed_instances_policy.launch_template.launch_template_specification.launch_template_id",
            ]
            for template in self.linked(group, paths, LAUNCH_TEMPLATE_TYPES):
                self._runs_edge(budget, group, template)
        for service in self.of_types({"aws_ecs_service"}):
            tasks = self.linked(
                service, ["task_definition"], frozenset({"aws_ecs_task_definition"})
            )
            for task in tasks:
                self._runs_edge(budget, service, task)

    def _runs_edge(self, budget: _Budget, source: InfraNode, target: InfraNode) -> None:
        self.add(budget, source.id, target.id, EdgeType.IAM_BINDING, kind=IAM, relation="runs")

    # -- Kubernetes -----------------------------------------------------------

    def _kubernetes(self) -> None:
        _Kubernetes(self).run()

    # -- MCP --------------------------------------------------------------------

    def _mcp(self) -> None:
        budget = self.budget("MCP servers")
        for server in self.by_type.get("mcp_server", ()):
            props = server.properties
            if props.get("disabled") is True:
                continue
            tags = props.get("capability_tags")
            untrusted = isinstance(tags, list) and "ingests_untrusted_content" in tags
            remote = props.get("is_remote") is True
            if not (untrusted or remote):
                continue
            scheme = props.get("url_scheme")
            self.from_internet(
                budget,
                server,
                kind=AGENT,
                relation="untrusted_content" if untrusted else "remote_server",
                protocol=scheme if isinstance(scheme, str) and not untrusted else "",
                definite=untrusted or props.get("capability_known") is True,
                edge_type=EdgeType.DATA_FLOW,
            )


def _is_group(resource_type: str) -> bool:
    return resource_type in SG_TYPES


def _world_open(rule: Mapping[str, Any]) -> bool:
    for key in ("cidr_blocks", "ipv6_cidr_blocks"):
        blocks = rule.get(key)
        if isinstance(blocks, list) and any(is_world_cidr(block) for block in blocks):
            return True
    return False


def _traffic(rule: Mapping[str, Any]) -> tuple[str, list[str], bool]:
    """(protocol, ports, definite) of a security group rule.

    `definite` is false when the protocol or a port is unknown, so the edge says it is not sure of
    what it carries.
    """
    protocol = _protocol_name(rule.get("protocol"))
    if protocol == "all":
        return protocol, ["0-65535"], True
    if protocol == "icmp":
        return protocol, [], True
    low = _port_text(rule.get("from_port"))
    high = _port_text(rule.get("to_port"))
    if not protocol or low is None or high is None:
        return protocol, [], False
    return protocol, [low if low == high else f"{low}-{high}"], True


def _walk_has_security_groups(node: InfraNode) -> bool:
    """Whether the node names any security group, resolved or not."""
    return any(True for _ in _walk_security_group_values(node.properties))


def _listener_ports(listener: InfraNode) -> list[str]:
    port = _port_text(listener.properties.get("port"))
    return [port] if port else []


def _elb_listeners(lb: InfraNode) -> list[tuple[str, list[str]]]:
    found: list[tuple[str, list[str]]] = []
    for block in _values(lb.properties, "listener"):
        if isinstance(block, Mapping):
            port = _port_text(block.get("lb_port"))
            found.append(("tcp", [port] if port else []))
    return found


# ---------------------------------------------------------------------------
# Kubernetes
# ---------------------------------------------------------------------------


def _namespace(node: InfraNode) -> str | None:
    value = node.properties.get("namespace")
    return value if isinstance(value, str) and value else None


def _name(node: InfraNode) -> str:
    value = node.properties.get("name")
    return value if isinstance(value, str) and value else node.name


class _Kubernetes:
    """Services, Ingresses, workloads, Secrets and RBAC joined across input files."""

    def __init__(self, reach: _Reach) -> None:
        self.reach = reach
        self.graph = reach.graph
        self.index: dict[tuple[str, str | None, str], InfraNode] = {}
        for node in reach.nodes:
            if node.resource_type.startswith("kubernetes_"):
                self.index[(node.resource_type, _namespace(node), _name(node))] = node
        self.workloads = [
            node
            for node in reach.nodes
            if node.resource_type.startswith("kubernetes_")
            and isinstance(node.properties.get("pod_labels"), Mapping)
        ]

    def lookup(self, resource_type: str, namespace: str | None, name: str) -> InfraNode | None:
        return self.index.get((resource_type, namespace, name))

    def run(self) -> None:
        if not self.index:
            return
        self._entries()
        self._ingress_routes()
        self._service_selection()
        self._workload_links()
        self._rbac()

    def _entries(self) -> None:
        budget = self.reach.budget("Kubernetes entry points")
        for service in self.reach.by_type.get("kubernetes_service", ()):
            if service.exposure != "internet":
                continue
            ports = _service_ports(service, "port")
            self.reach.from_internet(
                budget,
                service,
                kind=K8S_SERVICE,
                protocol="tcp",
                ports=ports,
                definite=bool(ports),
            )
        for ingress in self.reach.by_type.get("kubernetes_ingress", ()):
            if ingress.exposure != "internet":
                continue
            secure = ingress.properties.get("has_tls") is True
            self.reach.from_internet(
                budget,
                ingress,
                kind=INGRESS,
                protocol="https" if secure else "http",
                ports=["443"] if secure else ["80"],
            )

    def _ingress_routes(self) -> None:
        budget = self.reach.budget("Kubernetes ingress routes")
        for ingress in self.reach.by_type.get("kubernetes_ingress", ()):
            for backend in _list(ingress.properties.get("ingress_backends")):
                if not isinstance(backend, Mapping):
                    continue
                name = backend.get("service_name")
                service = (
                    self.lookup("kubernetes_service", _namespace(ingress), name)
                    if isinstance(name, str)
                    else None
                )
                if service is None:
                    continue
                port = _port_text(backend.get("port"))
                self.reach.add(
                    budget,
                    ingress.id,
                    service.id,
                    EdgeType.NETWORK_FLOW,
                    kind=INGRESS,
                    relation="backend",
                    protocol="tcp",
                    ports=[port] if port else [],
                )

    def _service_selection(self) -> None:
        budget = self.reach.budget("Kubernetes service selectors")
        for service in self.reach.by_type.get("kubernetes_service", ()):
            selector = service.properties.get("selector")
            if not isinstance(selector, Mapping) or not selector:
                continue
            ports = _service_ports(service, "targetPort") or _service_ports(service, "port")
            for workload in self.workloads:
                labels = workload.properties.get("pod_labels")
                if _namespace(workload) != _namespace(service) or not isinstance(labels, Mapping):
                    continue
                if all(labels.get(k) == v for k, v in selector.items()):
                    self.reach.add(
                        budget,
                        service.id,
                        workload.id,
                        EdgeType.NETWORK_FLOW,
                        kind=K8S_SERVICE,
                        relation="selects",
                        protocol="tcp",
                        ports=ports,
                    )

    def _workload_links(self) -> None:
        budget = self.reach.budget("Kubernetes workloads")
        for workload in self.workloads:
            namespace = _namespace(workload)
            for name in _text_list(workload.properties.get("secret_refs")):
                secret = self.lookup("kubernetes_secret", namespace, name)
                if secret is not None:
                    self.reach.add(
                        budget,
                        workload.id,
                        secret.id,
                        EdgeType.DATA_FLOW,
                        kind=WORKLOAD,
                        relation="reads_secret",
                    )
            account = workload.properties.get("service_account_name") or "default"
            service_account = (
                self.lookup("kubernetes_service_account", namespace, account)
                if isinstance(account, str)
                else None
            )
            if service_account is not None:
                self.reach.add(
                    budget,
                    workload.id,
                    service_account.id,
                    EdgeType.IAM_BINDING,
                    kind=WORKLOAD,
                    relation="runs_as",
                )

    # -- RBAC -----------------------------------------------------------------

    def _bindings(self) -> list[tuple[InfraNode, InfraNode | None, list[InfraNode]]]:
        """(binding, role node or None, service accounts) for each binding of the input."""
        found: list[tuple[InfraNode, InfraNode | None, list[InfraNode]]] = []
        for resource_type in ("kubernetes_cluster_role_binding", "kubernetes_role_binding"):
            for binding in self.reach.by_type.get(resource_type, ()):
                props = binding.properties
                ref_name = props.get("role_ref_name")
                ref_kind = props.get("role_ref_kind")
                role: InfraNode | None = None
                if isinstance(ref_name, str):
                    if ref_kind == "ClusterRole":
                        role = self.lookup("kubernetes_cluster_role", None, ref_name)
                    elif ref_kind == "Role":
                        role = self.lookup("kubernetes_role", _namespace(binding), ref_name)
                accounts: list[InfraNode] = []
                for subject in _list(props.get("subjects")):
                    if not isinstance(subject, Mapping) or subject.get("kind") != "ServiceAccount":
                        continue
                    name = subject.get("name")
                    namespace = subject.get("namespace") or _namespace(binding)
                    account = (
                        self.lookup("kubernetes_service_account", namespace, name)
                        if isinstance(name, str)
                        else None
                    )
                    if account is not None:
                        accounts.append(account)
                found.append((binding, role, accounts))
        return found

    def _rbac(self) -> None:
        budget = self.reach.budget("Kubernetes RBAC")
        scopes: dict[str, set[str | None]] = {}
        for binding, role, accounts in self._bindings():
            cluster_wide = binding.resource_type == "kubernetes_cluster_role_binding"
            if role is not None:
                scope = scopes.setdefault(role.id, set())
                if cluster_wide and role.resource_type == "kubernetes_cluster_role":
                    scope.add("*")
                else:
                    scope.add(_namespace(binding))
            target = role
            if target is None and binding.properties.get("role_ref_name") == _CLUSTER_ADMIN:
                target = binding
            if target is None:
                continue
            for account in accounts:
                self.reach.add(
                    budget,
                    account.id,
                    target.id,
                    EdgeType.IAM_BINDING,
                    kind=RBAC,
                    relation="bound_role",
                    via=[binding.id],
                )
        secrets = self.reach.by_type.get("kubernetes_secret", ())
        roles = self.reach.of_types({"kubernetes_cluster_role", "kubernetes_role"})
        for role in roles:
            verbs = _secret_verbs(role)
            if not verbs:
                continue
            scope = scopes.get(role.id, set())
            grant = {
                "actions": [f"secrets:{verb}" for verb in verbs],
                "access": "read" if set(verbs) <= {"get", "list", "watch"} else "admin",
                "wildcard": False,
                "conditional": False,
            }
            for secret in secrets:
                if "*" in scope or _namespace(secret) in scope:
                    self.reach.add(
                        budget,
                        role.id,
                        secret.id,
                        EdgeType.IAM_BINDING,
                        kind=RBAC,
                        relation="permission",
                        extra=grant,
                    )


def _service_ports(service: InfraNode, key: str) -> list[str]:
    found: list[str] = []
    for entry in _list(service.properties.get("ports")):
        if isinstance(entry, Mapping):
            text = _port_text(entry.get(key))
            if text and text not in found:
                found.append(text)
    return found


def _secret_verbs(role: InfraNode) -> list[str]:
    """The read verbs a role's rules grant on Secrets, in order; empty when it grants none."""
    found: list[str] = []
    for rule in _list(role.properties.get("rbac_rules")):
        if not isinstance(rule, Mapping):
            continue
        resources = {str(r) for r in _list(rule.get("resources"))}
        if not resources & _RBAC_SECRET_RESOURCES:
            continue
        for verb in _list(rule.get("verbs")):
            if str(verb) in _RBAC_READ_VERBS and str(verb) not in found:
                found.append(str(verb))
    return found
