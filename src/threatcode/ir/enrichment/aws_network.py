"""Facts for the AWS network and compute rules: defaults, WAF protections, policies, markers.

The rule files ``vpc``, ``ec2``, ``elb``, ``cloudfront``, ``waf``, ``wafv2``, ``eks``, ``ecs``,
``lambda``, ``api_gateway``, ``ecr`` and ``sagemaker`` read the ``derived`` keys documented here.
The security group ingress and egress lists, the flow log fact, the ECS container definitions and
the role facts of a function come from the core modules (``companions`` and ``relations``).

Provider defaults
-----------------

Terraform HCL and CloudFormation leave out the values a plan prints, so ``DEFAULTS`` fills three
attributes in place on those inputs (never on plan JSON):

``aws_eks_cluster``
    ``vpc_config.endpoint_public_access`` is ``true`` when the ``vpc_config`` block exists and does
    not say.
``aws_instance``, ``aws_launch_template``, ``aws_launch_configuration``
    ``metadata_options.http_tokens`` is ``"optional"`` when the ``metadata_options`` block exists
    and does not say.
    A resource with no ``metadata_options`` block is read as optional by the IMDS rule itself.
``aws_lb``
    ``internal`` is ``false``, so an unmarked load balancer is internet facing.

The same values are the exposure table of ``threatcode.ir.exposure``, so a rule and the reachability
logic never disagree about what an omitted attribute means.

Derived keys
------------

``aws_wafv2_web_acl`` and ``aws_wafv2_rule_group``
    Read from the ``rule`` blocks (``Rules`` in a CloudFormation rule group), through ``and``,
    ``or`` and ``not`` statements, rate based scope-down statements and, for a web ACL, the rule
    groups it references that the scan holds: ``has_rules`` (at least one rule),
    ``has_rate_based_rule``, ``rate_limit`` (the lowest limit of its rate based rules, None
    without one), ``managed_rule_groups`` (the names), ``has_managed_rules``, ``has_sqli_rule``
    (the AWS SQLi managed group or a SQLi match statement), ``has_xss_rule`` (the AWS common rule
    set, which holds the XSS rules, or an XSS match statement), ``has_ip_reputation`` and
    ``has_geo_match``.
    A fact is Unknown, not False, when the rule list is not readable (``rule_json``, a dynamic
    block that could not be expanded) or the web ACL references a rule group the scan does not hold.
``aws_api_gateway_rest_api``, ``aws_ecr_repository``
    ``policy_statements``, the statements of the resource policy (the rest API's ``policy``
    attribute or its ``aws_api_gateway_rest_api_policy`` companion; the repository's
    ``aws_ecr_repository_policy`` companion or its CloudFormation ``RepositoryPolicyText``).
``aws_security_group``
    ``temporary_marker``: True when the name, description or a tag value names the group as
    temporary (temp, tmp, debug, remove, delete, todo, test), read word by word.
    The key is absent otherwise.
``aws_vpc``
    ``has_flow_log``, as the ``companions`` module sets it, also true when a flow log of the scan
    targets a subnet of the VPC, and unknown when such a log's subnet cannot be tied to a VPC.
``aws_eks_cluster``
    ``has_oidc_provider``: whether an ``aws_iam_openid_connect_provider`` of the scan points at the
    cluster's issuer.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from threatcode.ir.enrich import (
    CompanionSpec,
    Deriver,
    EnrichContext,
    Produced,
    as_list,
    blocks,
    merge_produced,
    produced,
    produced_by_companions,
    type_matcher,
)
from threatcode.ir.enrichment.companions import statements_of
from threatcode.ir.nodes import InfraNode
from threatcode.values import Unknown, is_unknown

Facts = Mapping[str, Any]

# ---------------------------------------------------------------------------
# Provider defaults
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, dict[str, Any]] = {
    "aws_eks_cluster": {"vpc_config.endpoint_public_access": True},
    "aws_instance": {"metadata_options.http_tokens": "optional"},
    "aws_launch_template": {"metadata_options.http_tokens": "optional"},
    "aws_launch_configuration": {"metadata_options.http_tokens": "optional"},
    "aws_lb": {"internal": False},
}

# ---------------------------------------------------------------------------
# WAFv2
# ---------------------------------------------------------------------------

# Managed rule groups of AWS and the protection each one stands for
SQLI_MANAGED_GROUPS = frozenset({"AWSManagedRulesSQLiRuleSet"})
# The common rule set holds the cross-site scripting rules
XSS_MANAGED_GROUPS = frozenset({"AWSManagedRulesCommonRuleSet"})
IP_REPUTATION_MANAGED_GROUPS = frozenset({"AWSManagedRulesAmazonIpReputationList"})

# Keys that hold statements and are walked; every other key of a rule (action, visibility, name)
# says nothing about what the rule matches
_STATEMENT_CONTAINERS = frozenset(
    {
        "rule",
        "statement",
        "statements",
        "scope_down_statement",
        "and_statement",
        "or_statement",
        "not_statement",
    }
)
_MAX_WALK_DEPTH = 12
_WAF_TYPES = ("aws_wafv2_web_acl", "aws_wafv2_rule_group")


def _present(body: Any) -> bool:
    """Whether a statement block is there: a plan lists every statement type, most as ``[]``."""
    return is_unknown(body) or bool(blocks(body))


class _WafScan:
    """What the statements of one rule list contain."""

    def __init__(self) -> None:
        self.rate_limits: list[int] = []
        self.rate_rule = False
        self.unknown_limit: Unknown | None = None
        self.managed: list[str] = []
        self.sqli_statement = False
        self.xss_statement = False
        self.geo = False
        # The first thing the scan could not read: nothing negative may be concluded from the list
        self.unreadable: Unknown | None = None
        self.references: list[Any] = []
        self.has_rules = False

    def note_unknown(self, value: Unknown) -> None:
        if self.unreadable is None:
            self.unreadable = value

    def walk(self, value: Any, depth: int = 0) -> None:
        if is_unknown(value):
            self.note_unknown(value)
            return
        if depth > _MAX_WALK_DEPTH:
            self.note_unknown(Unknown())
            return
        for item in as_list(value):
            if is_unknown(item):
                self.note_unknown(item)
            elif isinstance(item, Mapping):
                self._mapping(item, depth)

    def _mapping(self, mapping: Mapping[str, Any], depth: int) -> None:
        for key, body in mapping.items():
            if key in _STATEMENT_CONTAINERS:
                self.walk(body, depth + 1)
            elif key == "rate_based_statement":
                self._rate(body, depth)
            elif key == "managed_rule_group_statement":
                self._managed(body)
            elif key == "sqli_match_statement":
                self.sqli_statement = self.sqli_statement or _present(body)
            elif key == "xss_match_statement":
                self.xss_statement = self.xss_statement or _present(body)
            elif key == "geo_match_statement":
                self.geo = self.geo or _present(body)
            elif key == "rule_group_reference_statement":
                self._reference(body)

    def _rate(self, body: Any, depth: int) -> None:
        if not _present(body):
            return
        self.rate_rule = True
        if is_unknown(body):
            self.unknown_limit = self.unknown_limit or body
            return
        for statement in blocks(body):
            limit = statement.get("limit")
            if is_unknown(limit):
                self.unknown_limit = self.unknown_limit or limit
            elif isinstance(limit, int) and not isinstance(limit, bool):
                self.rate_limits.append(limit)
            elif isinstance(limit, str) and limit.strip().isdigit():
                self.rate_limits.append(int(limit))
            else:
                self.unknown_limit = self.unknown_limit or Unknown()
            self.walk(statement.get("scope_down_statement"), depth + 1)

    def _managed(self, body: Any) -> None:
        if is_unknown(body):
            self.note_unknown(body)
            return
        for statement in blocks(body):
            name = statement.get("name")
            if is_unknown(name):
                self.note_unknown(name)
            elif isinstance(name, str):
                self.managed.append(name)

    def _reference(self, body: Any) -> None:
        if is_unknown(body):
            self.note_unknown(body)
            return
        for statement in blocks(body):
            self.references.append(statement.get("arn"))

    def absorb(self, other: _WafScan) -> None:
        """Take on the findings of a referenced rule group."""
        self.rate_limits.extend(other.rate_limits)
        self.rate_rule = self.rate_rule or other.rate_rule
        self.unknown_limit = self.unknown_limit or other.unknown_limit
        self.managed.extend(other.managed)
        self.sqli_statement = self.sqli_statement or other.sqli_statement
        self.xss_statement = self.xss_statement or other.xss_statement
        self.geo = self.geo or other.geo
        if other.unreadable is not None:
            self.note_unknown(other.unreadable)


def _scan_rules(node: InfraNode) -> _WafScan:
    scan = _WafScan()
    if node.properties.get("rule_json") is not None:
        scan.note_unknown(Unknown())
    # CloudFormation spells the rule list of a rule group `Rules`, and the translator renames it
    # to `rule` for web ACLs only
    for name in ("rule", "rules"):
        value = node.properties.get(name)
        if value is None:
            continue
        scan.walk(value)
        if not is_unknown(value) and as_list(value):
            scan.has_rules = True
    return scan


def _unknown_or(found: bool, unreadable: Unknown | None) -> bool | Unknown:
    """True when found, Unknown when the list could not be read, otherwise False."""
    if found:
        return True
    return unreadable if unreadable is not None else False


def _waf_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    scan = _scan_rules(node)
    if node.resource_type == "aws_wafv2_web_acl":
        for reference in scan.references:
            groups = _referenced_groups(node, reference, ctx)
            if len(groups) == 1:
                scan.absorb(_scan_rules(groups[0]))
            else:
                scan.note_unknown(reference if is_unknown(reference) else Unknown())
    names = sorted(set(scan.managed))
    unreadable = scan.unreadable
    if scan.rate_rule and scan.unknown_limit is None:
        rate_limit: Any = min(scan.rate_limits) if scan.rate_limits else None
    elif scan.rate_rule:
        rate_limit = scan.unknown_limit
    else:
        rate_limit = unreadable
    return {
        "has_rules": _unknown_or(scan.has_rules, unreadable),
        "has_rate_based_rule": _unknown_or(scan.rate_rule, unreadable),
        "rate_limit": rate_limit,
        "managed_rule_groups": names,
        "has_managed_rules": _unknown_or(bool(names), unreadable),
        "has_sqli_rule": _unknown_or(
            scan.sqli_statement or bool(SQLI_MANAGED_GROUPS & set(names)), unreadable
        ),
        "has_xss_rule": _unknown_or(
            scan.xss_statement or bool(XSS_MANAGED_GROUPS & set(names)), unreadable
        ),
        "has_ip_reputation": _unknown_or(
            bool(IP_REPUTATION_MANAGED_GROUPS & set(names)), unreadable
        ),
        "has_geo_match": _unknown_or(scan.geo, unreadable),
    }


def _referenced_groups(node: InfraNode, reference: Any, ctx: EnrichContext) -> list[InfraNode]:
    """The rule group of the scan that a ``rule_group_reference_statement`` names."""
    raw: Any = reference.reference if is_unknown(reference) else reference
    if not isinstance(raw, str) or not raw:
        return []
    found = ctx.resolve(node, raw, type_matcher("aws_wafv2_rule_group")).ids
    return [ctx.graph.nodes[i] for i in found]


# ---------------------------------------------------------------------------
# Resource policies
# ---------------------------------------------------------------------------


def _policy_of(*attributes: str) -> Any:
    """The statements of the policy a resource declares itself.

    A plan marks an optional attribute the provider computes (a REST API's ``policy``) unknown
    when the configuration does not set it, and gives that Unknown no reference.
    It is not a policy nobody can read, it is no policy, so it contributes nothing; an Unknown
    that carries a reference (``policy = data.x.json``) is a real policy the scan cannot read.
    """

    def derive(node: InfraNode, ctx: EnrichContext) -> Facts:
        for name in attributes:
            value = node.properties.get(name)
            if is_unknown(value) and not value.reference:
                continue
            if value is not None:
                return {"policy_statements": statements_of(value)}
        return {}

    return derive


def _companion_policy(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    value = companion.properties.get("policy")
    return {"policy_statements": statements_of(value) if value is not None else []}


# ---------------------------------------------------------------------------
# Security groups
# ---------------------------------------------------------------------------

TEMPORARY_WORDS = frozenset(
    {"temp", "tmp", "temporary", "debug", "remove", "delete", "todo", "test", "testing"}
)
_WORD = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+")


def words(text: str) -> list[str]:
    """The lower case words of a name: ``TempAllowAll_RemoveMe`` is temp, allow, all, remove, me."""
    return [w.lower() for w in _WORD.findall(text)]


def _label_texts(node: InfraNode) -> Iterable[str]:
    props = node.properties
    for name in ("name", "name_prefix", "description"):
        value = props.get(name)
        if isinstance(value, str) and not is_unknown(value):
            yield value
    tags = props.get("tags")
    for tag in blocks(tags):
        for value in tag.values():
            if isinstance(value, str) and not is_unknown(value):
                yield value


def _temporary_marker(node: InfraNode, ctx: EnrichContext) -> Facts:
    found = any(word in TEMPORARY_WORDS for text in _label_texts(node) for word in words(text))
    return {"temporary_marker": True} if found else {}


# ---------------------------------------------------------------------------
# VPC: flow logs on a subnet
# ---------------------------------------------------------------------------


def _subnet_flow_logs(vpc: InfraNode, ctx: EnrichContext) -> Facts:
    """A flow log that watches a subnet of the VPC counts as flow logging for the VPC.

    ``companions`` folds the flow logs that name the VPC itself.
    A log on a subnet covers part of the VPC, which is enough not to say the VPC has no flow
    logs at all (the finding is about having none), so it makes ``has_flow_log`` true.
    A log whose subnet, or the VPC of that subnet, cannot be resolved might be this VPC's, so the
    fact is unknown.
    Logs on a network interface or a transit gateway attachment are not read: they say nothing
    about the VPC as a whole.
    """
    subnet_type = type_matcher("aws_subnet")
    vpc_type = type_matcher("aws_vpc")
    undecided: Unknown | None = None
    for log in ctx.peers(vpc, type_matcher("aws_flow_log")):
        if "subnet_id" not in log.properties:
            continue
        link = ctx.resolve_link(log, ("subnet_id",), subnet_type)
        if link.unresolved:
            undecided = undecided or Unknown(link.reference)
        for subnet in link.resolved:
            owner = ctx.resolve_link(subnet, ("vpc_id",), vpc_type)
            if vpc in owner.resolved:
                return {"has_flow_log": True}
            if owner.unresolved:
                undecided = undecided or Unknown(owner.reference)
    return {"has_flow_log": undecided} if undecided is not None else {}


# ---------------------------------------------------------------------------
# EKS: an OIDC provider for service account roles
# ---------------------------------------------------------------------------


def _oidc_provider(node: InfraNode, ctx: EnrichContext) -> Facts:
    """Whether a provider of the scan has the issuer of this cluster as its URL.

    The usual setup reads the issuer through a ``tls_certificate`` data source, which links the
    provider to the cluster through a data node the scan cannot follow.
    A provider whose URL is such a reference, or is an EKS issuer written out, might be this
    cluster's, so it makes the fact unknown instead of leaving the cluster looking unconfigured.
    A provider of another identity provider (a literal URL such as GitHub's) says nothing.
    """
    cluster = type_matcher("aws_eks_cluster")
    undecided: Unknown | None = None
    for provider in ctx.peers(node, type_matcher("aws_iam_openid_connect_provider")):
        url = provider.properties.get("url")
        if is_unknown(url):
            raw: Any = url.reference
        elif isinstance(url, str) and url:
            raw = url
        else:
            continue
        if isinstance(raw, str) and raw.startswith(("https://", "http://")):
            if "oidc.eks." in raw:
                undecided = undecided or Unknown(raw)
            continue
        found = ctx.resolve(provider, raw, cluster).ids if isinstance(raw, str) and raw else ()
        if node.id in found:
            return {"has_oidc_provider": True}
        if not found:
            undecided = undecided or Unknown(raw if isinstance(raw, str) else "")
    return {"has_oidc_provider": undecided if undecided is not None else False}


COMPANIONS: tuple[CompanionSpec, ...] = (
    CompanionSpec(
        "aws_api_gateway_rest_api",
        "aws_api_gateway_rest_api_policy",
        ("rest_api_id",),
        _companion_policy,
        absent={"policy_statements": []},
    ),
    CompanionSpec(
        "aws_ecr_repository",
        "aws_ecr_repository_policy",
        ("repository",),
        _companion_policy,
        absent={"policy_statements": []},
    ),
)

DERIVERS: tuple[Deriver, ...] = (
    Deriver(_WAF_TYPES, _waf_facts),
    Deriver(("aws_api_gateway_rest_api",), _policy_of("policy")),
    Deriver(("aws_ecr_repository",), _policy_of("repository_policy_text")),
    Deriver(("aws_security_group",), _temporary_marker),
    Deriver(("aws_eks_cluster",), _oidc_provider),
    Deriver(("aws_vpc",), _subnet_flow_logs),
)

# Every derived fact this module can write, by resource type, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py): a rule may read ``derived.<fact>`` of a
# type only if some module declares it, and a module may write only what it declares.
PRODUCED: Produced = merge_produced(
    produced_by_companions(COMPANIONS),
    produced(
        _WAF_TYPES,
        "has_geo_match",
        "has_ip_reputation",
        "has_managed_rules",
        "has_rate_based_rule",
        "has_rules",
        "has_sqli_rule",
        "has_xss_rule",
        "managed_rule_groups",
        "rate_limit",
    ),
    produced(("aws_api_gateway_rest_api", "aws_ecr_repository"), "policy_statements"),
    produced(("aws_security_group",), "temporary_marker"),
    produced(("aws_eks_cluster",), "has_oidc_provider"),
    produced(("aws_vpc",), "has_flow_log"),
)
