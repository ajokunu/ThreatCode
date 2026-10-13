"""IAM edges: who runs as which role, what a role holds, and what it may reach.

`link` runs after enrichment, when every role carries the statements of its inline and attached
policies (`derived.inline_policy_statements`, `derived.attached_policy_statements`) and its trust
policy (`derived.assume_role_statements`).
Every edge is an `iam_binding` edge and points the way authority flows: a resource runs as a role,
and the role holds policies and may act on resources.

=============================  ==========================================================
edge (source -> target)        what it says
=============================  ==========================================================
resource -> role               `assumes`: the resource runs as the role (a function, a task
                               definition, an instance profile, a node group, a SageMaker
                               notebook).
                               Added while the graph is built from the reference or the
                               literal in `role`, `role_arn`, `execution_role_arn` and the like.
resource -> instance profile   `instance_profile`: an instance or launch template.
attachment -> role             `assumes`: the attachment or inline policy belongs to the role.
attachment -> policy           `attaches`: the policy an attachment names.
role -> policy                 `has_policy`: the policy is attached to, or inline in, the role.
principal role -> role         `can_assume`: the trust policy of the target lets the principal
                               role assume it.
policy -> resource             `resource_policy`: a bucket, queue, topic or secret policy
                               governs its resource.
role -> resource               `permission`: an Allow statement of the role's policies covers
                               the resource.
                               The attributes are `actions`, `access` (`read`, `write` or
                               `admin`), `wildcard` and `conditional`.
=============================  ==========================================================

A role is found by the reference the input holds, then by the `name` attribute, then by an ARN,
and last by the resource label (`ReferenceIndex.resolve_literal`).
The index is built once.

Service principals of a trust policy are not graph nodes, so they stay metadata:
`derived.assume_role_trust` on the role lists `services`, `accounts`, `principals` and
`any_principal`.

Permission edges say what an Allow statement grants.
A Deny statement is not subtracted, a statement with `NotAction` or `NotResource` is not read, and
a condition only sets `conditional`.
A wildcard resource (`*`, or an ARN pattern such as `arn:aws:s3:::logs-*`) fans out to the nodes of
the services the statement's actions name, in id order, capped at `MAX_WILDCARD_TARGETS` per role.
The edges of a capped fan-out carry `wildcard`, and the build reports one
`graph.iam_fanout_capped` diagnostic for the role.

A resource of `*` (or a pattern that matches any name) reaches the nodes of the role's own input
only.
In a repository of unrelated templates and modules, an administrator role of one stack is not
the administrator of every bucket in every other stack, and joining them would put an attack path
from the internet to each of them.
An ARN or a pattern with a literal part (`arn:aws:s3:::acme-logs-*`) names its targets and
reaches them in any input.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from threatcode.diagnostics import Diagnostic, register_code
from threatcode.ir.edges import EdgeType
from threatcode.ir.enrich import EnrichContext, Produced, produced
from threatcode.ir.nodes import InfraNode
from threatcode.ir.references import ArnParts, ReferenceIndex, parse_arn, type_is
from threatcode.values import is_unknown

if TYPE_CHECKING:
    from threatcode.ir.graph import InfraGraph

register_code(
    "graph.iam_fanout_capped",
    "A wildcard IAM permission matches more nodes than the per-role limit, so only some are linked",
)

# The one derived fact this module writes, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py)
PRODUCED: Produced = produced(("aws_iam_role",), "assume_role_trust")

# How many nodes a role's wildcard permissions are linked to, in total, before the rest are skipped
MAX_WILDCARD_TARGETS = 25

ROLE = "aws_iam_role"
_ACCESS_RANK = {"read": 0, "write": 1, "admin": 2}
_READ_VERBS = (
    "get",
    "list",
    "describe",
    "head",
    "query",
    "scan",
    "select",
    "batchget",
    "read",
    "view",
    "lookup",
    "search",
    "retrieve",
    "check",
    "decrypt",
    "verify",
    "simulate",
)
_SERVICE_PRINCIPAL = re.compile(r"^[a-z0-9.-]+\.amazonaws\.com(\.cn)?$")
# The six characters Secrets Manager appends to a name in the ARN of a secret, written out
# (a1B2c3), as a pattern of six question marks, or as the star of arn:...:secret:name-*
_SECRET_SUFFIX = re.compile(r"-(?:[A-Za-z0-9]{6}|\?{6}|\*)$")

# Resource policy types: the attribute that names the resource and the type it must be
_RESOURCE_POLICIES: dict[str, tuple[tuple[str, ...], str]] = {
    "aws_s3_bucket_policy": (("bucket",), "aws_s3_bucket"),
    "aws_sqs_queue_policy": (("queue_url",), "aws_sqs_queue"),
    "aws_sns_topic_policy": (("arn",), "aws_sns_topic"),
    "aws_secretsmanager_secret_policy": (("secret_arn",), "aws_secretsmanager_secret"),
}
_ATTACHMENTS = ("aws_iam_role_policy_attachment", "aws_iam_policy_attachment")
_INLINE_POLICY = "aws_iam_role_policy"


# ---------------------------------------------------------------------------
# What the actions of a statement say
# ---------------------------------------------------------------------------


def classify_access(actions: Iterable[Any]) -> str:
    """`read`, `write` or `admin` for a set of IAM actions.

    `*` and `service:*` are admin.
    Any action whose verb does not start like a read (`Get`, `List`, `Describe`, `Query`, ...) is a
    write, so an unfamiliar verb is never taken as harmless.
    An action that is not known is ignored.
    """
    level = "read"
    for action in actions:
        if not isinstance(action, str) or is_unknown(action):
            continue
        text = action.strip()
        if text == "*" or text.endswith(":*"):
            return "admin"
        verb = text.split(":", 1)[-1].lower()
        if not verb.startswith(_READ_VERBS):
            level = "write"
    return level


def _stronger(first: str, second: str) -> str:
    return first if _ACCESS_RANK[first] >= _ACCESS_RANK[second] else second


# ---------------------------------------------------------------------------
# Services: how a statement's resources and actions find graph nodes
# ---------------------------------------------------------------------------


def _last(arn: ArnParts) -> str:
    return arn.name


def _s3_name(arn: ArnParts) -> str:
    return arn.resource.split("/", 1)[0]


def _after(kind: str) -> Callable[[ArnParts], str]:
    def name(arn: ArnParts) -> str:
        flat = arn.resource.replace(":", "/")
        head = f"{kind}/"
        return flat[len(head) :].split("/", 1)[0] if flat.startswith(head) else ""

    return name


def _secret_name(arn: ArnParts) -> str:
    resource = arn.resource.removeprefix("secret:")
    return _SECRET_SUFFIX.sub("", resource)


def _parameter_name(arn: ArnParts) -> str:
    return "/" + arn.resource.removeprefix("parameter").lstrip("/")


@dataclass(frozen=True)
class Service:
    """A service a statement can name: its node types and how its ARNs name them."""

    types: tuple[str, ...]
    # Properties of the node that hold the name an ARN of this service ends with
    name_keys: tuple[str, ...]
    name_of: Callable[[ArnParts], str]


# The order is the order a capped wildcard fan-out fills its budget: data and secret stores first
SERVICES: dict[str, Service] = {
    "s3": Service(("aws_s3_bucket",), ("bucket", "id"), _s3_name),
    "dynamodb": Service(("aws_dynamodb_table",), ("name", "id"), _after("table")),
    "kms": Service(("aws_kms_key",), ("arn", "key_id", "id"), _after("key")),
    "secretsmanager": Service(("aws_secretsmanager_secret",), ("name",), _secret_name),
    "ssm": Service(("aws_ssm_parameter",), ("name",), _parameter_name),
    "rds": Service(
        ("aws_db_instance", "aws_rds_cluster", "aws_rds_cluster_instance"),
        ("identifier", "cluster_identifier", "id"),
        _last,
    ),
    "redshift": Service(("aws_redshift_cluster",), ("cluster_identifier",), _last),
    "es": Service(
        ("aws_elasticsearch_domain", "aws_opensearch_domain"), ("domain_name",), _after("domain")
    ),
    "elasticache": Service(
        ("aws_elasticache_replication_group", "aws_elasticache_cluster"),
        ("replication_group_id", "cluster_id"),
        _last,
    ),
    "kinesis": Service(("aws_kinesis_stream",), ("name",), _after("stream")),
    "sqs": Service(("aws_sqs_queue",), ("name",), _last),
    "sns": Service(("aws_sns_topic",), ("name",), _last),
    "ecr": Service(("aws_ecr_repository",), ("name",), _after("repository")),
    "lambda": Service(("aws_lambda_function",), ("function_name", "id"), _last),
    "sagemaker": Service(("aws_sagemaker_notebook_instance",), ("name",), _last),
    "ec2": Service(("aws_instance",), ("id",), _last),
    "iam": Service((ROLE,), ("name",), _last),
    "sts": Service((ROLE,), ("name",), _last),
}
_TYPE_RANK: dict[str, int] = {
    resource_type: rank
    for rank, resource_type in enumerate(
        dict.fromkeys(t for spec in SERVICES.values() for t in spec.types)
    )
}
_SERVICE_ALIASES = {"opensearch": "es", "dax": "dynamodb"}


def _service_of(action: str) -> str | None:
    """The service key an action or an ARN service prefix names, else None."""
    prefix = action.split(":", 1)[0].strip().lower()
    prefix = _SERVICE_ALIASES.get(prefix, prefix)
    return prefix if prefix in SERVICES else None


class _Targets:
    """Finds the graph nodes an ARN, a pattern or a reference in a policy names.

    Built once per graph: node lists by type and name lookups by service, so a policy with many
    resources never scans every node.
    """

    def __init__(self, ctx: EnrichContext) -> None:
        self.ctx = ctx
        self._by_type: dict[str, list[InfraNode]] = {}
        for node in ctx.nodes:
            self._by_type.setdefault(node.resource_type, []).append(node)
        self._sorted: dict[str, list[InfraNode]] = {}
        self._patterns: dict[tuple[str, str], list[InfraNode]] = {}
        self._names: dict[str, dict[str, list[InfraNode]]] = {}
        for service, spec in SERVICES.items():
            names: dict[str, list[InfraNode]] = {}
            for resource_type in spec.types:
                for node in self._by_type.get(resource_type, ()):
                    for key in spec.name_keys:
                        value = node.properties.get(key)
                        if isinstance(value, str) and not is_unknown(value) and value:
                            names.setdefault(value, []).append(node)
            self._names[service] = names

    def of_type(self, resource_type: str) -> list[InfraNode]:
        """The nodes of one type, sorted by id; computed once."""
        found = self._sorted.get(resource_type)
        if found is None:
            found = sorted(self._by_type.get(resource_type, ()), key=lambda n: n.id)
            self._sorted[resource_type] = found
        return found

    def of_arn(self, arn: ArnParts, full: str) -> tuple[list[InfraNode], bool]:
        """The nodes an ARN names, and whether the match came from a wildcard in the ARN."""
        service = _service_of(arn.service)
        if service is None:
            return [], False
        spec = SERVICES[service]
        name = spec.name_of(arn)
        names = self._names[service]
        if not name:
            return self._by_arn_property(service, full), False
        if "*" in name or "?" in name:
            return self._matching(service, name), True
        hits = list(names.get(name, ()))
        if not hits and service == "ssm":
            hits = list(names.get(name.lstrip("/"), ()))
        return hits or self._by_arn_property(service, full), False

    def _matching(self, service: str, pattern: str) -> list[InfraNode]:
        """The nodes of a service whose name matches a pattern, sorted by id; computed once."""
        key = (service, pattern)
        found = self._patterns.get(key)
        if found is None:
            matched = {
                node.id: node
                for known, nodes in self._names[service].items()
                if fnmatch.fnmatchcase(known, pattern)
                for node in nodes
            }
            found = [matched[k] for k in sorted(matched)]
            self._patterns[key] = found
        return found

    def _by_arn_property(self, service: str, full: str) -> list[InfraNode]:
        exact = full.rstrip("/*") if full.endswith("/*") else full
        return [
            node
            for resource_type in SERVICES[service].types
            for node in self._by_type.get(resource_type, ())
            if node.properties.get("arn") in (full, exact)
        ]


# ---------------------------------------------------------------------------
# The pass
# ---------------------------------------------------------------------------


def link(graph: InfraGraph) -> None:
    """Add the IAM edges of a built, enriched graph; see the module docstring."""
    ctx = EnrichContext(graph, ReferenceIndex(graph.nodes))
    roles = [n for n in ctx.nodes if n.resource_type == ROLE]
    _link_policies(graph, ctx)
    _link_resource_policies(graph, ctx)
    if not roles:
        return
    targets = _Targets(ctx)
    for role in sorted(roles, key=lambda n: n.id):
        _link_trust(graph, ctx, role)
        _link_permissions(graph, ctx, targets, role)


def _is_role(resource_type: str) -> bool:
    return resource_type == ROLE


# -- attachments and inline policies ---------------------------------------


def _link_policies(graph: InfraGraph, ctx: EnrichContext) -> None:
    """role -> policy for every attachment and inline policy, from the edges already built."""
    for node in sorted(ctx.nodes, key=lambda n: n.id):
        if node.resource_type in _ATTACHMENTS:
            roles = _successors(graph, node, "assumes", _is_role)
            policies = _successors(graph, node, "attaches", _is_policy)
            for role in roles:
                for policy in policies:
                    graph.add_edge(role, policy, EdgeType.IAM_BINDING, relation="has_policy")
        elif node.resource_type == _INLINE_POLICY:
            for role in _successors(graph, node, "assumes", _is_role):
                graph.add_edge(role, node.id, EdgeType.IAM_BINDING, relation="has_policy")


def _is_policy(resource_type: str) -> bool:
    return resource_type == "aws_iam_policy"


def _successors(
    graph: InfraGraph, node: InfraNode, relation: str, matcher: Callable[[str], bool]
) -> list[str]:
    found: dict[str, None] = {}
    for edge in graph.edges_from(node.id):
        target = graph.get_node(edge.target)
        if (
            edge.edge_type is EdgeType.IAM_BINDING
            and edge.relation == relation
            and target is not None
            and matcher(target.resource_type)
        ):
            found.setdefault(edge.target)
    return list(found)


# -- resource policies -------------------------------------------------------


def _link_resource_policies(graph: InfraGraph, ctx: EnrichContext) -> None:
    """policy -> resource for a bucket, queue, topic or secret policy."""
    for node in sorted(ctx.nodes, key=lambda n: n.id):
        spec = _RESOURCE_POLICIES.get(node.resource_type)
        if spec is None:
            continue
        attributes, target_type = spec
        matcher = type_is(target_type)
        index = ctx.index_for(node)
        found: dict[str, None] = {}
        for attribute in attributes:
            if attribute not in node.properties:
                continue
            resolution = index.resolve_value(
                node.properties[attribute], node.module, required_type=matcher
            )
            found.update(dict.fromkeys(resolution.ids))
        statements = ctx.derived(node).get("policy_statements")
        public = _grants_everyone(statements)
        for target in found:
            if target != node.id:
                graph.add_edge(
                    node.id,
                    target,
                    EdgeType.IAM_BINDING,
                    {"public": public},
                    relation="resource_policy",
                )


def _grants_everyone(statements: Any) -> bool:
    """Whether an Allow statement names `*` as its principal and has no condition."""
    if not isinstance(statements, list):
        return False
    return any(
        isinstance(s, Mapping)
        and s.get("effect") == "Allow"
        and "*" in (s.get("principals") or ())
        and not s.get("has_condition")
        for s in statements
    )


# -- trust policies ----------------------------------------------------------


@dataclass
class _TrustFacts:
    """Who a role's trust policies let assume it, gathered over every Allow statement."""

    services: dict[str, None] = field(default_factory=dict)
    accounts: dict[str, None] = field(default_factory=dict)
    others: dict[str, None] = field(default_factory=dict)
    principals: dict[str, None] = field(default_factory=dict)
    any_principal: bool = False

    def add_roles(self, index: ReferenceIndex, role: InfraNode, principal: Any) -> bool:
        """Record the roles ``principal`` names; False when it names none in this graph."""
        resolved = index.resolve_value(principal, role.module, required_type=type_is(ROLE)).ids
        for source in resolved:
            if source != role.id:
                self.principals.setdefault(source)
        return bool(resolved)

    def read(self, index: ReferenceIndex, role: InfraNode, principal: Any) -> None:
        if is_unknown(principal):
            if not self.add_roles(index, role, principal):
                self.others.setdefault(principal.reference or "unresolved")
        elif not isinstance(principal, str):
            return
        elif principal == "*":
            self.any_principal = True
        elif _SERVICE_PRINCIPAL.match(principal):
            self.services.setdefault(principal)
        else:
            arn = parse_arn(principal)
            if arn is not None and arn.service == "iam" and arn.resource == "root":
                self.accounts.setdefault(arn.account)
            elif not self.add_roles(index, role, principal):
                self.others.setdefault(principal)


def _link_trust(graph: InfraGraph, ctx: EnrichContext, role: InfraNode) -> None:
    """principal role -> role for each role principal; the rest becomes `assume_role_trust`."""
    statements = ctx.derived(role).get("assume_role_statements")
    if not isinstance(statements, list):
        return
    index = ctx.index_for(role)
    facts = _TrustFacts()
    for statement in statements:
        if not isinstance(statement, Mapping) or statement.get("effect") != "Allow":
            continue
        for principal in statement.get("principals") or ():
            facts.read(index, role, principal)
    for source in facts.principals:
        graph.add_edge(source, role.id, EdgeType.IAM_BINDING, relation="can_assume")
    trust: dict[str, Any] = {
        "services": sorted(facts.services),
        "accounts": sorted(facts.accounts),
        "principals": sorted(facts.others),
        "any_principal": facts.any_principal,
    }
    ctx.contribute(role, {"assume_role_trust": trust})


# -- permissions ---------------------------------------------------------------


@dataclass
class _Grant:
    """What a role may do to one node, merged over every statement that reaches it."""

    actions: set[str]
    access: str
    wildcard: bool
    conditional: bool


def _role_statements(graph: InfraGraph, ctx: EnrichContext, role: InfraNode) -> list[Any]:
    """Every raw permission statement the role holds, inline, attached and by edge."""
    derived = ctx.derived(role)
    raw_statements: list[Any] = []
    for key in ("inline_policy_statements", "attached_policy_statements"):
        found = derived.get(key)
        if isinstance(found, list):
            raw_statements.extend(found)
    # A policy the role holds in this graph contributes its own statements as well: enrichment
    # reads an attachment only when its policy_arn is an ARN or a reference, and the edges also
    # join a literal address. A statement read twice merges into one grant
    for edge in graph.edges_from(role.id):
        if edge.edge_type is EdgeType.IAM_BINDING and edge.relation == "has_policy":
            policy = graph.get_node(edge.target)
            found = ctx.derived(policy).get("policy_statements") if policy else None
            if isinstance(found, list):
                raw_statements.extend(found)
    return raw_statements


def _link_within_budget(
    targets: _Targets,
    role: InfraNode,
    grants: dict[str, _Grant],
    pool: Mapping[str, list[_Statement]],
    everywhere: Mapping[str, list[_Statement]],
) -> int:
    """Add the wildcard grants while the role's budget lasts; return how many nodes were skipped."""
    budget = MAX_WILDCARD_TARGETS
    skipped = 0
    for node_id in sorted(pool, key=lambda i: (_rank(targets, i), i)):
        if node_id not in grants:
            if budget <= 0:
                skipped += 1
                continue
            budget -= 1
        for statement in pool[node_id]:
            _record(grants, node_id, statement, True)
    # A `*` resource reaches every node of its services: the first ones, data stores first, are
    # linked, and the rest are counted without being visited, so the cost is the budget
    for resource_type in sorted(everywhere, key=lambda t: _TYPE_RANK.get(t, len(_TYPE_RANK))):
        nodes = [n for n in targets.of_type(resource_type) if targets.ctx.same_input(role, n)]
        for position, node in enumerate(nodes):
            if node.id == role.id:
                continue
            if node.id not in grants:
                if budget <= 0:
                    skipped += len(nodes) - position
                    break
                budget -= 1
            for statement in everywhere[resource_type]:
                _record(grants, node.id, statement, True)
    return skipped


def _link_permissions(
    graph: InfraGraph, ctx: EnrichContext, targets: _Targets, role: InfraNode
) -> None:
    grants: dict[str, _Grant] = {}
    # Nodes an ARN pattern reaches: each is linked only while the role's budget lasts
    pool: dict[str, list[_Statement]] = {}
    # The types a `*` resource reaches, with the statements that reach them
    everywhere: dict[str, list[_Statement]] = {}
    for statement in _statements(_role_statements(graph, ctx, role)):
        for node, wildcard in _concrete_targets(ctx, targets, role, statement):
            if node.id == role.id:
                continue
            if wildcard:
                pool.setdefault(node.id, []).append(statement)
            else:
                _record(grants, node.id, statement, False)
        if statement.wants_everything:
            for service in _statement_services(statement):
                for resource_type in SERVICES[service].types:
                    covering = everywhere.setdefault(resource_type, [])
                    if statement not in covering:
                        covering.append(statement)
    skipped = _link_within_budget(targets, role, grants, pool, everywhere)
    if skipped:
        graph.diagnostics.append(
            Diagnostic(
                "info",
                "graph.iam_fanout_capped",
                f"Role {role.id} has wildcard permissions that match at least {skipped} more "
                f"nodes than it is linked to; only the first {MAX_WILDCARD_TARGETS} are linked",
                role.source_file,
                role.start_line or None,
            )
        )
    for node_id in sorted(grants):
        grant = grants[node_id]
        graph.add_edge(
            role.id,
            node_id,
            EdgeType.IAM_BINDING,
            {
                "actions": sorted(grant.actions),
                "access": grant.access,
                "wildcard": grant.wildcard,
                "conditional": grant.conditional,
            },
            relation="permission",
        )


def _statements(raw_statements: list[Any]) -> list[_Statement]:
    """The distinct Allow statements, in order; a statement read from two places counts once."""
    found: list[_Statement] = []
    seen: set[str] = set()
    for raw in raw_statements:
        key = repr(raw)
        if key in seen:
            continue
        seen.add(key)
        statement = _read_statement(raw)
        if statement is not None:
            found.append(statement)
    return found


def _rank(targets: _Targets, node_id: str) -> int:
    """The position of a node's type in `SERVICES`: where it stands in a capped fan-out."""
    node = targets.ctx.graph.get_node(node_id)
    return _TYPE_RANK.get(node.resource_type, len(_TYPE_RANK)) if node else len(_TYPE_RANK)


@dataclass(frozen=True)
class _Statement:
    actions: tuple[str, ...]
    resources: tuple[Any, ...]
    conditional: bool

    @property
    def wants_everything(self) -> bool:
        return any(r == "*" for r in self.resources)

    @property
    def access(self) -> str:
        return classify_access(self.actions)


def _read_statement(raw: Any) -> _Statement | None:
    """An Allow statement with actions and resources, else None."""
    if not isinstance(raw, Mapping) or raw.get("effect") != "Allow":
        return None
    if raw.get("not_actions") or raw.get("not_resources"):
        return None
    actions = tuple(a for a in raw.get("actions") or () if isinstance(a, str) and not is_unknown(a))
    resources = tuple(raw.get("resources") or ())
    if not actions or not resources:
        return None
    return _Statement(actions, resources, bool(raw.get("has_condition")))


def _record(grants: dict[str, _Grant], node_id: str, statement: _Statement, wildcard: bool) -> None:
    grant = grants.get(node_id)
    if grant is None:
        grants[node_id] = _Grant(
            set(statement.actions), statement.access, wildcard, statement.conditional
        )
        return
    grant.actions.update(statement.actions)
    grant.access = _stronger(grant.access, statement.access)
    grant.wildcard = grant.wildcard or wildcard
    grant.conditional = grant.conditional and statement.conditional


def _concrete_targets(
    ctx: EnrichContext, targets: _Targets, role: InfraNode, statement: _Statement
) -> list[tuple[InfraNode, bool]]:
    """The nodes the resources of a statement name, other than the bare `*`."""
    found: list[tuple[InfraNode, bool]] = []
    index = ctx.index_for(role)
    services = _statement_services(statement)
    for resource in statement.resources:
        if resource == "*":
            continue
        if is_unknown(resource):
            reference = resource.reference
            for node_id in index.resolve(reference, role.module) if reference else ():
                found.append((_node(ctx, node_id), False))
            continue
        if not isinstance(resource, str):
            continue
        arn = parse_arn(resource)
        if arn is not None:
            nodes, wildcard = targets.of_arn(arn, resource)
            if wildcard and _matches_any_name(arn):
                nodes = [n for n in nodes if ctx.same_input(role, n)]
            found.extend((n, wildcard) for n in nodes if _service_matches(n, services))
            continue
        for node_id in index.resolve(resource, role.module):
            found.append((_node(ctx, node_id), False))
    return found


def _matches_any_name(arn: ArnParts) -> bool:
    """Whether an ARN pattern has no literal part in the name: ``arn:aws:s3:::*``."""
    service = _service_of(arn.service)
    if service is None:
        return False
    name = SERVICES[service].name_of(arn)
    return bool(name) and not name.strip("*?")


def _node(ctx: EnrichContext, node_id: str) -> InfraNode:
    node = ctx.graph.get_node(node_id)
    if node is None:  # a resolved id always names a node of the graph
        raise KeyError(node_id)
    return node


def _statement_services(statement: _Statement) -> set[str]:
    found: set[str] = set()
    for action in statement.actions:
        if action.strip() == "*":
            return set(SERVICES)
        service = _service_of(action)
        if service:
            found.add(service)
    return found


def _service_matches(node: InfraNode, services: set[str]) -> bool:
    """Whether the statement's actions are of a service that owns this node's type."""
    return any(node.resource_type in SERVICES[s].types for s in services)
