"""Companion resources folded into their parent, and the policy documents of every resource.

Many resources configure another resource from the outside.
Since AWS provider v4 a bucket's versioning, encryption, logging, public access block, ACL, policy
and ownership controls are separate resources, a security group's rules can be, a role's
permissions come from attachments, and a diagnostic setting, an audit policy or a flow log points
at the resource it watches.
Each `CompanionSpec` below says which companion belongs to which parent, which attribute points
at the parent, and which derived facts the companion contributes.

Every parent gets the documented keys even when it has no companion (``versioning_enabled`` is
``False``, ``ingress`` is ``[]``), so a rule can read the fact directly.
A companion whose link cannot be resolved makes the keys of every candidate parent of its own
input Unknown (and reports a coverage gap), and a companion that names something outside the scan
or outside its own input is ignored.
The rules of a security group are the exception to "Unknown": a rule resource can only add to the
list, so an unresolved one adds a single Unknown entry and the rules the scan does know still
decide ``SG_UNRESTRICTED_INGRESS``.
Legacy inline attributes (provider v3 style) are merged in by the derivers at the bottom, with the
companion winning when both say something.

Documented derived keys, by parent:

``aws_s3_bucket``
    ``versioning_enabled``, ``sse_algorithm`` (None when unset), ``logging_enabled``,
    ``public_access_block`` (the four flags, None without a block), ``acl``,
    ``object_ownership``, ``policy_statements``.
``aws_vpc``
    ``has_flow_log``.
``aws_secretsmanager_secret``
    ``rotation_enabled``.
``aws_wafv2_web_acl``
    ``has_logging_config``, ``associated_resource_arns``.
``azurerm_*``
    ``has_diagnostic_settings``.
``azurerm_mssql_server``
    ``auditing_enabled``, ``alert_policy_enabled``.
``google_cloud_run_service``, ``google_cloud_run_v2_service``, ``google_cloudfunctions_function``,
``google_cloudfunctions2_function``
    ``invoker_members``.
``google_bigquery_dataset``
    ``access_members``.
``aws_iam_role``
    ``attached_policy_arns``, ``attached_policy_statements``, ``inline_policy_statements``,
    ``assume_role_statements``.
``aws_security_group``
    ``ingress`` and ``egress``: lists of
    ``{cidr_blocks, ipv6_cidr_blocks, from_port, to_port, protocol, source_security_groups, self}``
    folded from the inline blocks and the standalone rule resources.

Policy-bearing resources (IAM policies and role/user/group policies, KMS keys, bucket, queue and
topic policies, and their resource-policy companions) get ``policy_statements``: a list of
`ir.policy.Statement.to_dict` mappings, or Unknown when the document cannot be read.
``aws_ecs_task_definition`` gets ``container_definitions`` (a list of mappings) and
``aws_sqs_queue`` gets ``redrive_policy`` (a mapping), parsed from their JSON strings.
The original attributes are left as written.
"""

from __future__ import annotations

import json
from collections.abc import Mapping, Sequence
from typing import Any

from threatcode.ir.enrich import (
    CompanionSpec,
    Deriver,
    EnrichContext,
    Produced,
    as_list,
    block,
    blocks,
    merge_produced,
    produced,
    produced_by_companions,
    text,
    tri_bool,
    type_matcher,
)
from threatcode.ir.nodes import InfraNode
from threatcode.ir.policy import normalize_policy, read_document, statements_to_dicts
from threatcode.values import Unknown, is_unknown

Facts = Mapping[str, Any]

# ---------------------------------------------------------------------------
# Small readers
# ---------------------------------------------------------------------------


def dig(value: Any, *path: str) -> Any:
    """The first value at ``path`` through nested blocks.

    Blocks are lists of mappings in HCL and in plan JSON.
    Returns an Unknown as soon as one is met on the way, and None when the path is missing.
    """
    items: list[Any] = [value]
    for segment in path:
        following: list[Any] = []
        for item in items:
            if is_unknown(item):
                return item
            for found in blocks(item):
                if segment in found:
                    following.append(found[segment])
        items = following
        if not items:
            return None
    for item in items:
        if item is not None:
            return item
    return None


def _first(properties: Mapping[str, Any], *names: str) -> Any:
    """The value of the first of ``names`` that is present."""
    for name in names:
        if name in properties:
            return properties[name]
    return None


def _flag(value: Any, default: bool = False) -> bool | Unknown:
    """A boolean attribute where an absent value means ``default``."""
    found = tri_bool(value)
    if found is None:
        return default
    return found


def _list_of(value: Any) -> Any:
    """A list attribute as a list; an Unknown stays one."""
    if is_unknown(value):
        return value
    return [item for item in as_list(value) if item is not None]


def _equals(value: Any, expected: str) -> bool | Unknown:
    if is_unknown(value):
        return value
    return isinstance(value, str) and value.strip().lower() == expected


def statements_of(value: Any) -> list[dict[str, Any]] | Unknown:
    """A policy attribute as statement dicts, or Unknown when it cannot be read."""
    parsed = normalize_policy(value)
    if isinstance(parsed, Unknown):
        return parsed
    return statements_to_dicts(parsed)


def provider_computed(value: Any) -> bool:
    """Whether an optional attribute holds the marker of a value the provider computes.

    A Terraform plan marks an attribute that the configuration does not set but the provider
    fills in after apply (the deprecated inline settings of an S3 bucket, the default policy of a
    queue) as unknown, and gives that Unknown no reference.
    An Unknown that carries a reference (``logging = var.logging``) is a value somebody wrote and
    the scan cannot read, which is different.
    """
    return is_unknown(value) and not value.reference


def stands_for_the_setting(node: InfraNode, ctx: EnrichContext, key: str, value: Any) -> bool:
    """Whether an inline attribute may speak for the derived fact ``key`` of its node.

    A computed marker says nothing about the setting, so once a companion resource has given the
    setting (a bucket encryption resource beside a bucket whose inline ``server_side_encryption``
    a plan prints unknown), the companion's value stands and the marker must not erase it.
    Without a companion the marker still keeps the fact unknown: the scan cannot tell a bucket
    that is unconfigured from one configured somewhere it cannot see.
    """
    return not (provider_computed(value) and key in ctx.supplied(node))


# Resources whose ``policy`` is optional and computed, so a plan prints it unknown when unset
_POLICY_COMPUTED_WHEN_UNSET = frozenset(
    {"aws_s3_bucket", "aws_sqs_queue", "aws_sns_topic", "aws_kms_key"}
)


def own_policy_statements(
    node: InfraNode, ctx: EnrichContext | None = None
) -> list[dict[str, Any]] | Unknown | None:
    """The statements of the policy a node declares itself, None when it declares none.

    With ``ctx`` a computed marker in the ``policy`` of a bucket, queue, topic or key declares
    nothing once a companion policy resource has given the node its statements.
    """
    spec = POLICY_ATTRIBUTES.get(node.resource_type)
    if spec is None:
        return None
    for name in spec:
        value = node.properties.get(name)
        if value is None:
            continue
        if (
            ctx is not None
            and node.resource_type in _POLICY_COMPUTED_WHEN_UNSET
            and not stands_for_the_setting(node, ctx, "policy_statements", value)
        ):
            continue
        return statements_of(value)
    return None


# ---------------------------------------------------------------------------
# S3
# ---------------------------------------------------------------------------

_PUBLIC_ACCESS_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)


def _s3_versioning(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    status = dig(companion.properties, "versioning_configuration", "status")
    return {"versioning_enabled": _equals(status, "enabled")}


def _s3_sse(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {
        "sse_algorithm": text(
            dig(
                companion.properties,
                "rule",
                "apply_server_side_encryption_by_default",
                "sse_algorithm",
            )
        )
    }


def _s3_logging(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"logging_enabled": True}


def _s3_public_access_block(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    # An omitted flag is false: the provider does not block anything by default
    return {
        "public_access_block": {
            flag: _flag(companion.properties.get(flag)) for flag in _PUBLIC_ACCESS_FLAGS
        }
    }


def _s3_acl(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"acl": text(companion.properties.get("acl"))}


def _s3_policy(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    found = own_policy_statements(companion)
    return {"policy_statements": found if found is not None else []}


def _s3_ownership(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"object_ownership": text(dig(companion.properties, "rule", "object_ownership"))}


_S3 = "aws_s3_bucket"
_S3_SPECS = (
    CompanionSpec(
        _S3,
        "aws_s3_bucket_versioning",
        ("bucket",),
        _s3_versioning,
        absent={"versioning_enabled": False},
    ),
    CompanionSpec(
        _S3,
        "aws_s3_bucket_server_side_encryption_configuration",
        ("bucket",),
        _s3_sse,
        absent={"sse_algorithm": None},
    ),
    CompanionSpec(
        _S3,
        "aws_s3_bucket_logging",
        ("bucket",),
        _s3_logging,
        absent={"logging_enabled": False},
    ),
    CompanionSpec(
        _S3,
        "aws_s3_bucket_public_access_block",
        ("bucket",),
        _s3_public_access_block,
        absent={"public_access_block": None},
    ),
    CompanionSpec(_S3, "aws_s3_bucket_acl", ("bucket",), _s3_acl, absent={"acl": None}),
    CompanionSpec(
        _S3, "aws_s3_bucket_policy", ("bucket",), _s3_policy, absent={"policy_statements": []}
    ),
    CompanionSpec(
        _S3,
        "aws_s3_bucket_ownership_controls",
        ("bucket",),
        _s3_ownership,
        absent={"object_ownership": None},
    ),
)

# ---------------------------------------------------------------------------
# Flow logs, rotation, WAF, Azure diagnostics and auditing
# ---------------------------------------------------------------------------

_FLOW_LOG_OTHER_TARGETS = (
    "subnet_id",
    "eni_id",
    "transit_gateway_id",
    "transit_gateway_attachment_id",
    "regional_nat_gateway_id",
)


def _flow_log_targets_vpc(companion: InfraNode) -> bool:
    props = companion.properties
    return "vpc_id" in props or not any(attr in props for attr in _FLOW_LOG_OTHER_TARGETS)


def _true(key: str) -> Any:
    def derive(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
        return {key: True}

    return derive


def _waf_association(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"associated_resource_arns": _list_of(companion.properties.get("resource_arn"))}


def _auditing(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    # The audit policy is on unless it says enabled = false
    return {"auditing_enabled": _flag(companion.properties.get("enabled"), default=True)}


def _alert_policy(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"alert_policy_enabled": _equals(companion.properties.get("state"), "enabled")}


_MISC_SPECS = (
    CompanionSpec(
        "aws_vpc",
        "aws_flow_log",
        ("vpc_id",),
        _true("has_flow_log"),
        absent={"has_flow_log": False},
        applies=_flow_log_targets_vpc,
    ),
    CompanionSpec(
        "aws_secretsmanager_secret",
        "aws_secretsmanager_secret_rotation",
        ("secret_id",),
        _true("rotation_enabled"),
        absent={"rotation_enabled": False},
    ),
    CompanionSpec(
        "aws_wafv2_web_acl",
        "aws_wafv2_web_acl_logging_configuration",
        ("resource_arn",),
        _true("has_logging_config"),
        absent={"has_logging_config": False},
    ),
    CompanionSpec(
        "aws_wafv2_web_acl",
        "aws_wafv2_web_acl_association",
        ("web_acl_arn",),
        _waf_association,
        absent={"associated_resource_arns": []},
    ),
    CompanionSpec(
        "azurerm_*",
        "azurerm_monitor_diagnostic_setting",
        ("target_resource_id",),
        _true("has_diagnostic_settings"),
        absent={"has_diagnostic_settings": False},
    ),
    CompanionSpec(
        "azurerm_mssql_server",
        "azurerm_mssql_server_extended_auditing_policy",
        ("server_id",),
        _auditing,
        absent={"auditing_enabled": False},
    ),
    CompanionSpec(
        "azurerm_mssql_server",
        "azurerm_mssql_server_security_alert_policy",
        ("server_id",),
        _alert_policy,
        absent={"alert_policy_enabled": False},
    ),
)

# ---------------------------------------------------------------------------
# Google IAM members and bindings
# ---------------------------------------------------------------------------

_RUN_INVOKER = frozenset({"roles/run.invoker"})
_FUNCTION_INVOKER = frozenset({"roles/cloudfunctions.invoker", "roles/run.invoker"})
ALL_USERS = ("allUsers", "allAuthenticatedUsers")


def _invokers(roles: frozenset[str], key: str, member_attrs: tuple[str, ...]) -> Any:
    def derive(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
        role = companion.properties.get("role")
        if is_unknown(role):
            return {key: role}
        if role not in roles:
            return {}
        members = _list_of(_first(companion.properties, *member_attrs))
        return {key: members}

    return derive


def _bigquery_access(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"access_members": _access_members([companion.properties])}


def _access_members(entries: Sequence[Mapping[str, Any]]) -> Any:
    """Members named by dataset access entries (google_bigquery_dataset_access or access blocks)."""
    members: list[Any] = []
    prefixes = (
        ("iam_member", ""),
        ("special_group", ""),
        ("user_by_email", "user:"),
        ("group_by_email", "group:"),
        ("domain", "domain:"),
    )
    for entry in entries:
        for attr, prefix in prefixes:
            value = entry.get(attr)
            if is_unknown(value):
                return value
            if isinstance(value, str) and value:
                members.append(prefix + value)
    return members


def _members_spec(
    parent: str, companion: str, link_attrs: tuple[str, ...], key: str, derive: Any
) -> CompanionSpec:
    return CompanionSpec(parent, companion, link_attrs, derive, absent={key: []})


def _google_specs() -> list[CompanionSpec]:
    specs: list[CompanionSpec] = []
    run_targets = (
        ("google_cloud_run_service", "google_cloud_run_service", ("service", "name")),
        ("google_cloud_run_v2_service", "google_cloud_run_v2_service", ("name", "service")),
    )
    for parent, prefix, links in run_targets:
        specs.append(
            _members_spec(
                parent,
                f"{prefix}_iam_member",
                links,
                "invoker_members",
                _invokers(_RUN_INVOKER, "invoker_members", ("member",)),
            )
        )
        specs.append(
            _members_spec(
                parent,
                f"{prefix}_iam_binding",
                links,
                "invoker_members",
                _invokers(_RUN_INVOKER, "invoker_members", ("members",)),
            )
        )
    for parent, prefix in (
        ("google_cloudfunctions_function", "google_cloudfunctions_function"),
        ("google_cloudfunctions2_function", "google_cloudfunctions2_function"),
    ):
        for suffix, attr in (("iam_member", "member"), ("iam_binding", "members")):
            specs.append(
                _members_spec(
                    parent,
                    f"{prefix}_{suffix}",
                    ("cloud_function",),
                    "invoker_members",
                    _invokers(_FUNCTION_INVOKER, "invoker_members", (attr,)),
                )
            )
    for suffix, attr in (("iam_member", "member"), ("iam_binding", "members")):
        specs.append(
            _members_spec(
                "google_bigquery_dataset",
                f"google_bigquery_dataset_{suffix}",
                ("dataset_id",),
                "access_members",
                _bigquery_member(attr),
            )
        )
    specs.append(
        _members_spec(
            "google_bigquery_dataset",
            "google_bigquery_dataset_access",
            ("dataset_id",),
            "access_members",
            _bigquery_access,
        )
    )
    return specs


def _bigquery_member(attr: str) -> Any:
    def derive(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
        return {"access_members": _list_of(companion.properties.get(attr))}

    return derive


# ---------------------------------------------------------------------------
# IAM roles
# ---------------------------------------------------------------------------

_ROLE = "aws_iam_role"
_ROLE_ABSENT: Facts = {
    "attached_policy_arns": [],
    "attached_policy_statements": [],
    "inline_policy_statements": [],
}


def _attachment(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    """A managed policy attached to a role: its ARN, plus its statements when the scan sees it."""
    raw = _first(companion.properties, "policy_arn", "PolicyArn")
    if is_unknown(raw):
        reference = raw.reference
    elif isinstance(raw, str) and "${" not in raw:
        return {"attached_policy_arns": [raw]}
    elif isinstance(raw, str):
        reference = raw
    else:
        return {}
    matcher = type_matcher("aws_iam_policy")
    found = ctx.resolve(companion, reference, matcher).ids if reference else ()
    if len(found) != 1:
        return {"attached_policy_arns": [Unknown(reference)]}
    policy = ctx.graph.nodes[found[0]]
    arn = policy.properties.get("arn")
    arns: list[Any] = [arn] if isinstance(arn, str) and not is_unknown(arn) else []
    statements = own_policy_statements(policy)
    return {
        "attached_policy_arns": arns,
        "attached_policy_statements": statements if statements is not None else [],
    }


def _inline_role_policy(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    found = own_policy_statements(companion)
    return {"inline_policy_statements": found if found is not None else []}


def _attaches_to_roles(companion: InfraNode) -> bool:
    """A generic attachment lists roles, users or groups; only a role list concerns a role."""
    props = companion.properties
    return "roles" in props or not ("users" in props or "groups" in props)


_ROLE_SPECS = (
    CompanionSpec(
        _ROLE,
        "aws_iam_role_policy_attachment",
        ("role",),
        _attachment,
        absent=_ROLE_ABSENT,
    ),
    CompanionSpec(
        _ROLE,
        "aws_iam_policy_attachment",
        ("roles",),
        _attachment,
        absent=_ROLE_ABSENT,
        applies=_attaches_to_roles,
    ),
    CompanionSpec(
        _ROLE,
        "aws_iam_role_policy",
        ("role",),
        _inline_role_policy,
        absent=_ROLE_ABSENT,
    ),
)

# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

_SG = "aws_security_group"
_SG_ABSENT: Facts = {"ingress": [], "egress": []}


def _rule(
    cidr_blocks: Any,
    ipv6_cidr_blocks: Any,
    from_port: Any,
    to_port: Any,
    protocol: Any,
    source_security_groups: Any,
    self_reference: Any,
) -> dict[str, Any]:
    """The canonical rule shape every security group source is folded into."""
    return {
        "cidr_blocks": cidr_blocks,
        "ipv6_cidr_blocks": ipv6_cidr_blocks,
        "from_port": from_port,
        "to_port": to_port,
        "protocol": protocol,
        "source_security_groups": source_security_groups,
        "self": self_reference,
    }


def _inline_rule(item: Mapping[str, Any]) -> dict[str, Any]:
    """An inline ingress or egress block, in Terraform or CloudFormation spelling."""
    return _rule(
        _list_of(_first(item, "cidr_blocks", "CidrIp")),
        _list_of(_first(item, "ipv6_cidr_blocks", "CidrIpv6")),
        _first(item, "from_port", "FromPort"),
        _first(item, "to_port", "ToPort"),
        _first(item, "protocol", "IpProtocol"),
        _list_of(
            _first(
                item,
                "security_groups",
                "SourceSecurityGroupId",
                "DestinationSecurityGroupId",
            )
        ),
        _flag(item.get("self")),
    )


def _references_node(companion: InfraNode, raw: Any, target: InfraNode, ctx: EnrichContext) -> bool:
    """Whether a reference value names ``target`` (a rule pointing back at its own group)."""
    reference = raw.reference if is_unknown(raw) else raw
    if not isinstance(reference, str) or not reference:
        return False
    found = ctx.resolve(companion, reference, type_matcher(target.resource_type))
    return target.id in found.ids


def _source_groups(companion: InfraNode, raw: Any, ctx: EnrichContext) -> Any:
    """The source groups of a standalone rule that does not point back at its own group.

    A reference to another security group of the scan is a known fact (some group is the
    source) whose value the scan cannot compute, so it stays one list entry holding the
    Unknown instead of turning the whole list Unknown.
    """
    if is_unknown(raw) and raw.reference:
        found = ctx.resolve(companion, raw.reference, type_matcher(_SG))
        if found.ids:
            return [raw]
    return _list_of(raw)


def _standalone_rule() -> Any:
    def derive(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
        props = companion.properties
        direction = props.get("type")
        if is_unknown(direction):
            # One more rule in a direction the scan cannot tell
            return {"ingress": [direction], "egress": [direction]}
        if direction not in ("ingress", "egress"):
            return {}
        source = props.get("source_security_group_id")
        groups: Any = []
        points_back = _flag(props.get("self"))
        if source is not None:
            if _references_node(companion, source, parent, ctx):
                points_back = True
            else:
                groups = _source_groups(companion, source, ctx)
        rule = _rule(
            _list_of(props.get("cidr_blocks")),
            _list_of(props.get("ipv6_cidr_blocks")),
            props.get("from_port"),
            props.get("to_port"),
            props.get("protocol"),
            groups,
            points_back,
        )
        return {direction: [rule]}

    return derive


def _vpc_rule(direction: str) -> Any:
    def derive(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
        props = companion.properties
        referenced = props.get("referenced_security_group_id")
        groups: Any = []
        points_back = False
        if referenced is not None:
            if _references_node(companion, referenced, parent, ctx):
                points_back = True
            else:
                groups = _source_groups(companion, referenced, ctx)
        rule = _rule(
            _list_of(props.get("cidr_ipv4")),
            _list_of(props.get("cidr_ipv6")),
            props.get("from_port"),
            props.get("to_port"),
            props.get("ip_protocol"),
            groups,
            points_back,
        )
        return {direction: [rule]}

    return derive


def _standalone_keys(companion: InfraNode) -> tuple[str, ...]:
    direction = companion.properties.get("type")
    if direction in ("ingress", "egress"):
        return (str(direction),)
    return ("ingress", "egress")


_SG_SPECS = (
    CompanionSpec(
        _SG,
        "aws_security_group_rule",
        ("security_group_id",),
        _standalone_rule(),
        absent=_SG_ABSENT,
        touches=_standalone_keys,
        additive=True,
    ),
    CompanionSpec(
        _SG,
        "aws_vpc_security_group_ingress_rule",
        ("security_group_id",),
        _vpc_rule("ingress"),
        absent=_SG_ABSENT,
        touches=lambda _companion: ("ingress",),
        additive=True,
    ),
    CompanionSpec(
        _SG,
        "aws_vpc_security_group_egress_rule",
        ("security_group_id",),
        _vpc_rule("egress"),
        absent=_SG_ABSENT,
        touches=lambda _companion: ("egress",),
        additive=True,
    ),
)

COMPANIONS: tuple[CompanionSpec, ...] = (
    *_S3_SPECS,
    *_MISC_SPECS,
    *_google_specs(),
    *_ROLE_SPECS,
    *_SG_SPECS,
)

# ---------------------------------------------------------------------------
# Derivers: policy documents and legacy inline settings
# ---------------------------------------------------------------------------

# Resource type -> the attributes that hold its policy document, in order of preference.
# The CloudFormation names are accepted for templates whose properties are not translated.
POLICY_ATTRIBUTES: dict[str, tuple[str, ...]] = {
    "aws_iam_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_iam_managed_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_iam_role_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_iam_user_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_iam_group_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_kms_key": ("policy", "KeyPolicy", "key_policy"),
    "aws_s3_bucket_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_s3_bucket": ("policy",),
    "aws_sqs_queue": ("policy",),
    "aws_sqs_queue_policy": ("policy", "PolicyDocument", "policy_document"),
    "aws_sns_topic": ("policy",),
    "aws_sns_topic_policy": ("policy", "PolicyDocument", "policy_document"),
}


def _policy_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    found = own_policy_statements(node, ctx)
    if found is None:
        return {}
    return {"policy_statements": found}


def _role_policy_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    props = node.properties
    facts: dict[str, Any] = {}
    assume = _first(props, "assume_role_policy", "AssumeRolePolicyDocument")
    if assume is not None:
        facts["assume_role_statements"] = statements_of(assume)
    inline = _first(props, "inline_policy", "Policies")
    if is_unknown(inline):
        facts["inline_policy_statements"] = inline
    elif inline is not None:
        combined: Any = []
        for entry in blocks(inline):
            document = _first(entry, "policy", "PolicyDocument")
            if document is None:
                continue
            found = statements_of(document)
            if is_unknown(found):
                combined = found
                break
            combined.extend(found)
        facts["inline_policy_statements"] = combined
    managed = _first(props, "managed_policy_arns", "ManagedPolicyArns")
    if managed is not None:
        facts["attached_policy_arns"] = _list_of(managed)
    return facts


def _container_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    value = _first(node.properties, "container_definitions", "ContainerDefinitions")
    if value is None:
        return {}
    loaded = read_document(value) if not isinstance(value, list) else value
    if is_unknown(loaded):
        return {"container_definitions": loaded}
    if isinstance(loaded, Mapping):
        loaded = [loaded]
    if not isinstance(loaded, list) or not all(isinstance(item, Mapping) for item in loaded):
        return {"container_definitions": Unknown()}
    return {"container_definitions": [_jsonable(item) for item in loaded]}


def _jsonable(item: Any) -> Any:
    try:
        return json.loads(json.dumps(item, default=str))
    except (TypeError, ValueError):
        return Unknown()


def _redrive_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    value = node.properties.get("redrive_policy")
    if value is None:
        return {}
    loaded = value if isinstance(value, Mapping) else read_document(value)
    if is_unknown(loaded):
        return {"redrive_policy": loaded}
    if not isinstance(loaded, Mapping):
        return {"redrive_policy": Unknown()}
    return {"redrive_policy": _jsonable(loaded)}


def _s3_inline(node: InfraNode, ctx: EnrichContext) -> Facts:
    """Provider v3 inline blocks of a bucket; the v4 companions are merged over them."""
    props = node.properties
    facts: dict[str, Any] = {}
    versioning = _first(props, "versioning", "VersioningConfiguration")
    if versioning is not None and stands_for_the_setting(
        node, ctx, "versioning_enabled", versioning
    ):
        enabled = dig(versioning, "enabled")
        status = dig(versioning, "status")
        if status is None:
            status = dig(versioning, "Status")
        if enabled is None and status is not None:
            facts["versioning_enabled"] = _equals(status, "enabled")
        elif enabled is not None or is_unknown(versioning):
            facts["versioning_enabled"] = versioning if is_unknown(versioning) else _flag(enabled)
    sse = _first(props, "server_side_encryption_configuration", "BucketEncryption")
    if sse is not None and stands_for_the_setting(node, ctx, "sse_algorithm", sse):
        algorithm = dig(sse, "rule", "apply_server_side_encryption_by_default", "sse_algorithm")
        if algorithm is None:
            algorithm = dig(
                sse,
                "ServerSideEncryptionConfiguration",
                "ServerSideEncryptionByDefault",
                "SSEAlgorithm",
            )
        facts["sse_algorithm"] = sse if is_unknown(sse) else text(algorithm)
    logging = _first(props, "logging", "LoggingConfiguration")
    if logging is not None and stands_for_the_setting(node, ctx, "logging_enabled", logging):
        # An unset block is the empty list a plan prints, which is not a bucket that logs
        facts["logging_enabled"] = logging if is_unknown(logging) else any(blocks(logging))
    acl = _first(props, "acl", "AccessControl")
    if acl is not None and stands_for_the_setting(node, ctx, "acl", acl):
        facts["acl"] = text(acl)
    return facts


def _security_group_inline(node: InfraNode, ctx: EnrichContext) -> Facts:
    facts: dict[str, Any] = {}
    for key, names in (
        ("ingress", ("ingress", "SecurityGroupIngress")),
        ("egress", ("egress", "SecurityGroupEgress")),
    ):
        raw = _first(node.properties, *names)
        if raw is None:
            continue
        if is_unknown(raw):
            # Rules the scan cannot read, next to the ones a standalone resource adds
            facts[key] = [raw]
        else:
            facts[key] = [_inline_rule(item) for item in blocks(raw)]
    return facts


def _secret_inline(node: InfraNode, ctx: EnrichContext) -> Facts:
    props = node.properties
    for name in ("rotation_lambda_arn", "rotation_rules"):
        value = props.get(name)
        if is_unknown(value):
            return {"rotation_enabled": value}
        if value:
            return {"rotation_enabled": True}
    return {}


def _mssql_inline(node: InfraNode, ctx: EnrichContext) -> Facts:
    inline = node.properties.get("extended_auditing_policy")
    if is_unknown(inline):
        return {"auditing_enabled": inline}
    if blocks(inline):
        enabled = block(node.properties, "extended_auditing_policy").get("enabled")
        return {"auditing_enabled": _flag(enabled, default=True)}
    return {}


def _bigquery_inline(node: InfraNode, ctx: EnrichContext) -> Facts:
    access = node.properties.get("access")
    if access is None:
        return {}
    if is_unknown(access):
        return {"access_members": access}
    return {"access_members": _access_members(blocks(access))}


DERIVERS: tuple[Deriver, ...] = (
    Deriver(tuple(POLICY_ATTRIBUTES), _policy_facts),
    Deriver(("aws_iam_role",), _role_policy_facts),
    Deriver(("aws_ecs_task_definition",), _container_facts),
    Deriver(("aws_sqs_queue",), _redrive_facts),
    Deriver(("aws_s3_bucket",), _s3_inline),
    Deriver(("aws_security_group",), _security_group_inline),
    Deriver(("aws_secretsmanager_secret",), _secret_inline),
    Deriver(("azurerm_mssql_server",), _mssql_inline),
    Deriver(("google_bigquery_dataset",), _bigquery_inline),
)

# Every derived fact this module can write, by resource type, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py): a rule may read ``derived.<fact>`` of a
# type only if some module declares it, and a module may write only what it declares.
PRODUCED: Produced = merge_produced(
    produced_by_companions(COMPANIONS),
    produced(tuple(POLICY_ATTRIBUTES), "policy_statements"),
    produced(
        ("aws_iam_role",),
        "assume_role_statements",
        "attached_policy_arns",
        "attached_policy_statements",
        "inline_policy_statements",
    ),
    produced(("aws_ecs_task_definition",), "container_definitions"),
    produced(("aws_sqs_queue",), "redrive_policy"),
    produced(
        ("aws_s3_bucket",),
        "acl",
        "logging_enabled",
        "sse_algorithm",
        "versioning_enabled",
    ),
    produced(("aws_security_group",), "egress", "ingress"),
    produced(("aws_secretsmanager_secret",), "rotation_enabled"),
    produced(("azurerm_mssql_server",), "auditing_enabled"),
    produced(("google_bigquery_dataset",), "access_members"),
)
