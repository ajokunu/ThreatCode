"""Exposure: which nodes face the internet, and the zones that follow.

`apply` runs after enrichment and IAM linking and before trust boundary crossings are marked.
It sets `InfraNode.exposure` to `internet` for a node the configuration puts within reach of the
internet, to `internal` for a node that is known to be kept off it, and leaves `unknown` for
everything else, including every node whose deciding value is an `Unknown`.
An `Unknown`, an unresolved expression and a missing value on a design input never select an
exposure.

Only the zones of load balancers, public subnets and exposed instances move with the exposure.
A data store never leaves the DATA zone: it keeps its zone and gains `exposure = internet`, so an
attack path can still end at it.

Property signals
----------------

==============================================  ===========================================
node                                            exposure
==============================================  ===========================================
load balancer, `internal` true                  internal, zone PRIVATE
load balancer, `internal` false or absent       internet, zone DMZ
`aws_lambda_function_url`, auth `NONE`          internet
API Gateway REST API, EDGE or REGIONAL          internet (EDGE when no configuration, HCL/CFN)
API Gateway REST API, PRIVATE                   internal, zone PRIVATE
API Gateway HTTP API                            internet
CloudFront distribution                         internet
`aws_db_instance`, `aws_rds_cluster`...,        internet, zone stays DATA
`publicly_accessible` true
S3 bucket with a public ACL or a policy for     internet, zone stays DATA
`*`, not blocked by its public access block
security group with world-open ingress          internet
Azure rule: Inbound, Allow, world source        internet
GCP firewall: ingress allow from a world range  internet
EKS cluster, public endpoint                    internet
AKS cluster, not private                        internet
Azure PaaS, public network access               internet
Kubernetes LoadBalancer or NodePort Service     internet
Kubernetes Ingress with rules                   internet
==============================================  ===========================================

Provider defaults
-----------------

A template or an HCL file leaves out the values a plan materialises, so the signals above read a
documented default when an attribute is absent.
`DEFAULTS` lists them; the provider rule packages put the same values in their enrichment
`DEFAULTS` tables so that exposure and rules never disagree:

- EKS `endpoint_public_access` is true,
- AKS `private_cluster_enabled` is false,
- `public_network_access_enabled` is true for the Azure services listed in `PUBLIC_NETWORK_TYPES`,
- `azurerm_storage_account` `allow_nested_items_to_be_public` is true.

A default applies only to config evidence from Terraform HCL and CloudFormation.
An absent attribute in a plan, or on a design input, is unknown.

Graph facts
-----------

- A subnet is public when its route table routes `0.0.0.0/0` or `::/0` to an internet gateway, or
  when `map_public_ip_on_launch` is true (exposure internet, zone DMZ).
  A subnet associated only with route tables that have no such route is internal.
  An internet gateway attached to a VPC does not make a subnet public.
- An instance or launch template with a public IP address (its own flag or an Elastic IP) in a
  public subnet and an attached security group that is exposed is internet, zone DMZ.
- A listener takes the exposure and zone of its load balancer.
"""

from __future__ import annotations

import ipaddress
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from threatcode.ir.catalog import azure
from threatcode.ir.edges import EdgeType
from threatcode.ir.enrich import DEFAULT_FORMATS, EnrichContext
from threatcode.ir.nodes import DATA_CATEGORIES, Exposure, InfraNode, TrustZone, tri_state
from threatcode.ir.references import ReferenceIndex, type_is
from threatcode.values import is_unknown
from threatcode.vocab import is_world_source

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

# The documented provider defaults exposure assumes for an attribute a template or HCL file omits
DEFAULTS: Mapping[str, Mapping[str, Any]] = {
    "aws_eks_cluster": {"vpc_config.endpoint_public_access": True},
    "azurerm_kubernetes_cluster": {"private_cluster_enabled": False},
    "azurerm_storage_account": {
        "public_network_access_enabled": True,
        "allow_nested_items_to_be_public": True,
    },
}

# Azure services whose `public_network_access_enabled` is true unless the configuration says not
PUBLIC_NETWORK_TYPES: frozenset[str] = frozenset(
    {
        "azurerm_storage_account",
        "azurerm_key_vault",
        "azurerm_mssql_server",
        "azurerm_postgresql_server",
        "azurerm_postgresql_flexible_server",
        "azurerm_mysql_server",
        "azurerm_mysql_flexible_server",
        "azurerm_mariadb_server",
        "azurerm_cosmosdb_account",
        "azurerm_redis_cache",
        "azurerm_container_registry",
        "azurerm_linux_web_app",
        "azurerm_windows_web_app",
        "azurerm_linux_function_app",
        "azurerm_windows_function_app",
        "azurerm_cognitive_account",
        "azurerm_search_service",
        "azurerm_servicebus_namespace",
        "azurerm_eventhub_namespace",
    }
)
_LOAD_BALANCERS = frozenset({"aws_lb", "aws_alb", "aws_nlb", "aws_elb"})
_LISTENERS = frozenset(
    {"aws_lb_listener", "aws_alb_listener", "aws_lb_listener_rule", "aws_alb_listener_rule"}
)
_PUBLIC_DATABASES = frozenset(
    {"aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance", "aws_redshift_cluster"}
)
_PUBLIC_ACLS = frozenset({"public-read", "public-read-write"})
_COMPUTE_TYPES = frozenset({"aws_instance", "aws_launch_template", "aws_spot_instance_request"})
_UNSET: Any = object()


@dataclass(frozen=True)
class Verdict:
    """What the exposure analysis concluded for one node."""

    exposure: Exposure
    zone: TrustZone | None = None


# ---------------------------------------------------------------------------
# Reading attributes
# ---------------------------------------------------------------------------


def is_world_cidr(value: Any) -> bool:
    """Whether a CIDR or a keyword means the whole internet (`0.0.0.0/0`, `::/0`, `*`, ...)."""
    if not isinstance(value, str) or is_unknown(value):
        return False
    if is_world_source(value):
        return True
    try:
        return ipaddress.ip_network(value.strip(), strict=False).prefixlen == 0
    except ValueError:
        return False


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


class _Analysis:
    """The graph, the enrichable nodes and what the passes have decided so far."""

    def __init__(self, graph: InfraGraph) -> None:
        self.graph = graph
        self.ctx = EnrichContext(graph, ReferenceIndex(graph.nodes))
        self.nodes = sorted(self.ctx.nodes, key=lambda n: n.id)

    def derived(self, node: InfraNode) -> dict[str, Any]:
        return self.ctx.derived(node)

    def option(self, node: InfraNode, path: str, default: Any = _UNSET) -> str:
        """The tri-state of an attribute, reading a documented default where one may apply.

        An absent attribute is the default for Terraform HCL and CloudFormation config input,
        false for a flag that has no default, and unknown on a plan or a design input.
        """
        values = _values(node.properties, path)
        if values:
            return tri_state(values[0], node.evidence)
        if default is not _UNSET and self.default_applies(node):
            return tri_state(default, node.evidence)
        return "unknown"

    def default_applies(self, node: InfraNode) -> bool:
        return node.evidence == "config" and self.graph.node_formats.get(node.id) in DEFAULT_FORMATS

    def default_for(self, node: InfraNode, path: str) -> Any:
        return DEFAULTS.get(node.resource_type, {}).get(path, _UNSET)

    def flag(self, node: InfraNode, path: str) -> str:
        return self.option(node, path, self.default_for(node, path))

    def targets(self, node: InfraNode, attribute: str, resource_type: str) -> list[str]:
        """The ids of the nodes of a type that an attribute of `node` names."""
        if attribute not in node.properties:
            return []
        found = self.ctx.index_for(node).resolve_value(
            node.properties[attribute], node.module, required_type=type_is(resource_type)
        )
        return list(found.ids)


# ---------------------------------------------------------------------------
# Property signals
# ---------------------------------------------------------------------------


def _load_balancer(a: _Analysis, node: InfraNode) -> Verdict | None:
    internal = a.option(node, "internal", False)
    if internal == "true":
        return Verdict("internal", TrustZone.PRIVATE)
    if internal == "false":
        return Verdict("internet", TrustZone.DMZ)
    return None


def _lambda_url(a: _Analysis, node: InfraNode) -> Verdict | None:
    auth = node.properties.get("authorization_type")
    if isinstance(auth, str) and not is_unknown(auth) and auth.strip().upper() == "NONE":
        return Verdict("internet")
    return None


def _endpoint_types(node: InfraNode) -> list[str] | None:
    """The upper-cased endpoint types of an API Gateway REST API; None when unreadable."""
    values = _values(node.properties, "endpoint_configuration.types")
    if any(is_unknown(v) or not isinstance(v, str) for v in values):
        return None
    return [str(v).strip().upper() for v in values]


def _rest_api(a: _Analysis, node: InfraNode) -> Verdict | None:
    types = _endpoint_types(node)
    if types is None:
        return None
    if not types:
        # With no endpoint configuration the REST API is EDGE optimised, which is public. A plan
        # always materialises the block, so an absent one is only an answer for HCL and templates
        return Verdict("internet") if a.default_applies(node) else None
    if "EDGE" in types or "REGIONAL" in types:
        return Verdict("internet")
    if types == ["PRIVATE"]:
        return Verdict("internal", TrustZone.PRIVATE)
    return None


def _http_api(a: _Analysis, node: InfraNode) -> Verdict | None:
    if a.option(node, "disable_execute_api_endpoint", False) == "false":
        return Verdict("internet")
    return None


def _cloudfront(a: _Analysis, node: InfraNode) -> Verdict | None:
    return Verdict("internet")


def _public_database(a: _Analysis, node: InfraNode) -> Verdict | None:
    if tri_state(node.properties.get("publicly_accessible"), node.evidence) == "true":
        return Verdict("internet")
    return None


def _blocks(flags: Any, names: tuple[str, ...]) -> str:
    """`true` when any named flag is true, `unknown` when none is but some are not known."""
    if not isinstance(flags, Mapping):
        return "false"
    states = [tri_state(flags.get(name), "config") for name in names]
    if "true" in states:
        return "true"
    return "unknown" if "unknown" in states else "false"


def _s3_bucket(a: _Analysis, node: InfraNode) -> Verdict | None:
    derived = a.derived(node)
    acl = derived.get("acl")
    statements = derived.get("policy_statements")
    block = derived.get("public_access_block")
    acl_public = "unknown" if is_unknown(acl) else str(acl) in _PUBLIC_ACLS
    if is_unknown(statements):
        policy_public: Any = "unknown"
    else:
        policy_public = _policy_is_public(statements)
    if is_unknown(block):
        return None
    acl_blocked = _blocks(block, ("block_public_acls", "ignore_public_acls"))
    policy_blocked = _blocks(block, ("block_public_policy", "restrict_public_buckets"))
    if acl_public is True and acl_blocked == "false":
        return Verdict("internet")
    if policy_public is True and policy_blocked == "false":
        return Verdict("internet")
    return None


def _policy_is_public(statements: Any) -> bool:
    """Whether an Allow statement names `*` as its principal and has no condition."""
    return isinstance(statements, list) and any(
        isinstance(s, Mapping)
        and s.get("effect") == "Allow"
        and "*" in (s.get("principals") or ())
        and not s.get("has_condition")
        for s in statements
    )


def _security_group(a: _Analysis, node: InfraNode) -> Verdict | None:
    ingress = a.derived(node).get("ingress")
    if ingress is None:
        # Enrichment folds the rules of `aws_security_group` only; the default group's inline
        # blocks have the same shape
        ingress = _values(node.properties, "ingress")
    if not isinstance(ingress, list):
        return None
    for rule in ingress:
        if not isinstance(rule, Mapping):
            continue
        for key in ("cidr_blocks", "ipv6_cidr_blocks"):
            blocks = rule.get(key)
            if isinstance(blocks, list) and any(is_world_cidr(b) for b in blocks):
                return Verdict("internet")
    return None


def _azure_rule(a: _Analysis, node: InfraNode) -> Verdict | None:
    if azure.allows_inbound_from_world(node.properties):
        return Verdict("internet")
    return None


def _azure_group(a: _Analysis, node: InfraNode) -> Verdict | None:
    for rule in _values(node.properties, "security_rule"):
        if isinstance(rule, Mapping) and azure.allows_inbound_from_world(dict(rule)):
            return Verdict("internet")
    return None


def _gcp_firewall(a: _Analysis, node: InfraNode) -> Verdict | None:
    props = node.properties
    direction = props.get("direction")
    if isinstance(direction, str) and not is_unknown(direction):
        if direction.strip().upper() != "INGRESS":
            return None
    elif direction is not None:
        return None
    if tri_state(props.get("disabled"), node.evidence) != "false":
        return None
    ranges = props.get("source_ranges")
    if not isinstance(ranges, list) or not any(is_world_cidr(r) for r in ranges):
        return None
    if _values(props, "allow") and not _values(props, "deny"):
        return Verdict("internet")
    return None


def _eks_cluster(a: _Analysis, node: InfraNode) -> Verdict | None:
    if a.flag(node, "vpc_config.endpoint_public_access") != "true":
        return None
    cidrs = _values(node.properties, "vpc_config.public_access_cidrs")
    if cidrs and not any(is_world_cidr(c) for c in cidrs):
        return None
    return Verdict("internet")


def _aks_cluster(a: _Analysis, node: InfraNode) -> Verdict | None:
    if a.flag(node, "private_cluster_enabled") == "false":
        return Verdict("internet")
    return None


def _azure_paas(a: _Analysis, node: InfraNode) -> Verdict | None:
    path = "public_network_access_enabled"
    if a.option(node, path, True) != "true":
        return None
    if node.resource_type == "azurerm_storage_account" and (
        a.flag(node, "allow_nested_items_to_be_public") != "true"
    ):
        return None
    for acls in ("network_acls", "network_rules"):
        for default_action in _values(node.properties, f"{acls}.default_action"):
            if isinstance(default_action, str) and default_action.strip().lower() == "deny":
                return None
    return Verdict("internet")


def _kubernetes_service(a: _Analysis, node: InfraNode) -> Verdict | None:
    service_type = node.properties.get("service_type")
    if (
        isinstance(service_type, str)
        and not is_unknown(service_type)
        and service_type.strip().lower() in ("loadbalancer", "nodeport")
    ):
        return Verdict("internet")
    return None


def _kubernetes_ingress(a: _Analysis, node: InfraNode) -> Verdict | None:
    if node.properties.get("has_rules") is True:
        return Verdict("internet")
    return None


PropertySignal = Callable[[_Analysis, InfraNode], Verdict | None]

_SIGNALS: dict[str, PropertySignal] = {
    **dict.fromkeys(_LOAD_BALANCERS, _load_balancer),
    "aws_lambda_function_url": _lambda_url,
    "aws_api_gateway_rest_api": _rest_api,
    "aws_apigatewayv2_api": _http_api,
    "aws_cloudfront_distribution": _cloudfront,
    **dict.fromkeys(_PUBLIC_DATABASES, _public_database),
    "aws_s3_bucket": _s3_bucket,
    "aws_security_group": _security_group,
    "aws_default_security_group": _security_group,
    "azurerm_network_security_rule": _azure_rule,
    "azurerm_network_security_group": _azure_group,
    "google_compute_firewall": _gcp_firewall,
    "aws_eks_cluster": _eks_cluster,
    "azurerm_kubernetes_cluster": _aks_cluster,
    **dict.fromkeys(PUBLIC_NETWORK_TYPES, _azure_paas),
    "kubernetes_service": _kubernetes_service,
    "kubernetes_ingress": _kubernetes_ingress,
}


def _set(a: _Analysis, node: InfraNode, verdict: Verdict | None) -> None:
    if verdict is None:
        return
    node.exposure = verdict.exposure
    _move(a, node, verdict.zone)


def _move(a: _Analysis, node: InfraNode, zone: TrustZone | None) -> None:
    """Move a node to a zone, unless it is a data store or the input declared its zone."""
    if zone is None or node.category in DATA_CATEGORIES or node.id in a.graph.zone_declared:
        return
    node.trust_zone = zone


# ---------------------------------------------------------------------------
# Graph facts
# ---------------------------------------------------------------------------


def _is_default_route(*cidrs: Any) -> bool:
    """Whether any of the destinations is the default route (`0.0.0.0/0` or `::/0`)."""
    for cidr in cidrs:
        if isinstance(cidr, str) and not is_unknown(cidr):
            try:
                if ipaddress.ip_network(cidr.strip(), strict=False).prefixlen == 0:
                    return True
            except ValueError:
                continue
    return False


def _routes_to_gateway(a: _Analysis, node: InfraNode, route: Mapping[str, Any]) -> str:
    """`public` when a default route goes to an internet gateway, `private` when it does not.

    `unknown` when the destination or the gateway is not known.
    """
    destination = (
        route.get("cidr_block"),
        route.get("ipv6_cidr_block"),
        route.get("destination_cidr_block"),
        route.get("destination_ipv6_cidr_block"),
    )
    if any(is_unknown(d) for d in destination):
        return "unknown"
    if not _is_default_route(*destination):
        return "private"
    gateway = route.get("gateway_id")
    if gateway is None:
        return "private"
    if is_unknown(gateway) and not gateway.reference:
        return "unknown"
    if isinstance(gateway, str) and not is_unknown(gateway) and gateway.startswith("igw-"):
        return "public"
    found = a.ctx.index_for(node).resolve_value(
        gateway, node.module, required_type=type_is("aws_internet_gateway")
    )
    if found.ids:
        return "public"
    return "unknown" if is_unknown(gateway) else "private"


def _route_table_states(a: _Analysis) -> dict[str, str]:
    """For each route table id: `public`, `private` or `unknown`."""
    states: dict[str, str] = {}

    def merge(table_id: str, state: str) -> None:
        current = states.get(table_id, "private")
        if "public" in (current, state):
            states[table_id] = "public"
        elif "unknown" in (current, state):
            states[table_id] = "unknown"
        else:
            states[table_id] = "private"

    for node in a.nodes:
        if node.resource_type == "aws_route_table":
            states.setdefault(node.id, "private")
            for route in _values(node.properties, "route"):
                if isinstance(route, Mapping):
                    merge(node.id, _routes_to_gateway(a, node, route))
    for node in a.nodes:
        if node.resource_type == "aws_route":
            tables = a.targets(node, "route_table_id", "aws_route_table")
            state = _routes_to_gateway(a, node, node.properties)
            if not tables:
                continue
            for table_id in tables:
                merge(table_id, state)
    return states


def _subnets(a: _Analysis) -> None:
    """Decide the exposure and the zone of every subnet from its route table or its flag."""
    tables = _route_table_states(a)
    associated: dict[str, list[str]] = {}
    for node in a.nodes:
        if node.resource_type != "aws_route_table_association":
            continue
        subnets = a.targets(node, "subnet_id", "aws_subnet")
        for table_id in a.targets(node, "route_table_id", "aws_route_table"):
            for subnet_id in subnets:
                associated.setdefault(subnet_id, []).append(table_id)
    for node in a.nodes:
        if node.resource_type != "aws_subnet":
            continue
        flag = tri_state(node.properties.get("map_public_ip_on_launch"), node.evidence)
        states = [tables.get(t, "unknown") for t in associated.get(node.id, ())]
        if flag == "true" or "public" in states:
            node.exposure = "internet"
            _move(a, node, TrustZone.DMZ)
        elif states and all(s == "private" for s in states) and flag == "false":
            node.exposure = "internal"


def _has_public_address(a: _Analysis, node: InfraNode, elastic: set[str]) -> bool:
    if node.id in elastic:
        return True
    for path in ("associate_public_ip_address", "network_interfaces.associate_public_ip_address"):
        if any(tri_state(v, node.evidence) == "true" for v in _values(node.properties, path)):
            return True
    return False


def _elastic_ip_targets(a: _Analysis) -> set[str]:
    """The ids of the instances an Elastic IP is attached to."""
    found: set[str] = set()
    for node in a.nodes:
        if node.resource_type == "aws_eip":
            found.update(a.targets(node, "instance", "aws_instance"))
        elif node.resource_type == "aws_eip_association":
            found.update(a.targets(node, "instance_id", "aws_instance"))
    return found


def _compute(a: _Analysis) -> None:
    """An instance with a public address in a public subnet behind an exposed group is exposed."""
    elastic = _elastic_ip_targets(a)
    for node in a.nodes:
        if node.resource_type not in _COMPUTE_TYPES or not _has_public_address(a, node, elastic):
            continue
        in_public_subnet = False
        behind_exposed_group = False
        for edge in a.graph.edges_from(node.id):
            target = a.graph.get_node(edge.target)
            if target is None:
                continue
            if edge.edge_type is EdgeType.CONTAINMENT and target.resource_type == "aws_subnet":
                in_public_subnet = in_public_subnet or target.exposure == "internet"
            elif edge.relation == "security_group":
                behind_exposed_group = behind_exposed_group or target.exposure == "internet"
        if in_public_subnet and behind_exposed_group:
            _set(a, node, Verdict("internet", TrustZone.DMZ))


def _listeners(a: _Analysis) -> None:
    """A listener is exactly as exposed, and in the same zone, as its load balancer."""
    for node in a.nodes:
        if node.resource_type not in _LISTENERS:
            continue
        for attribute in ("load_balancer_arn", "listener_arn"):
            for target_type in sorted(_LOAD_BALANCERS | _LISTENERS - {node.resource_type}):
                for target_id in a.targets(node, attribute, target_type):
                    target = a.graph.get_node(target_id)
                    if target is not None and target.exposure != "unknown":
                        node.exposure = target.exposure
                        _move(a, node, target.trust_zone)
                        break


def apply(graph: InfraGraph) -> None:
    """Set the exposure and the final zone of the nodes of a built, enriched graph."""
    analysis = _Analysis(graph)
    for node in analysis.nodes:
        signal = _SIGNALS.get(node.resource_type)
        if signal is not None:
            _set(analysis, node, signal(analysis, node))
    _subnets(analysis)
    _compute(analysis)
    _listeners(analysis)
