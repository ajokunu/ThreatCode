"""Provider defaults and policy facts for the AWS data, identity and logging rules.

The rules of ``aws/s3.yml``, ``iam.yml``, ``kms.yml``, ``rds.yml``, ``sqs.yml``, ``sns.yml``,
``ssm.yml``, ``redshift.yml``, ``cloudtrail.yml`` and their neighbours read the facts this module
computes, because three checks cannot be written in the rule language:
a wildcard such as ``iam:*`` needs a suffix test, a condition key such as ``aws:PrincipalOrgID`` is
case insensitive in AWS, and a parameter name has to be split into words.

Defaults
--------

``DEFAULTS`` fills attributes that Terraform HCL and CloudFormation omit and that a plan JSON
materialises, so a rule reads the same value in all three formats (see `threatcode.ir.enrich`).
Every value below is the default the provider documents for the attribute.
The rules that read them also accept the attribute being absent, because the graph builder does
not yet record which parser produced a node (``graph.node_formats``), and the table is inert until
it does:

``aws_kms_key.enable_key_rotation``
    ``false``.
``aws_cloudtrail.is_multi_region_trail`` and ``enable_log_file_validation``
    ``false``.
``aws_cloudtrail.enable_logging``
    ``true``.

Derived facts
-------------

All of them are ``True``, ``False`` or an `Unknown` (the document could not be read or depends on
a value the scan does not have), never a missing key, so a rule reads them with ``equals: true``
and an unreadable policy produces neither a finding nor a pass.

``allows_all_actions``
    On a policy-bearing identity (the four standalone policy types, and a role, user or group with
    ``inline_policy`` blocks): some ``Allow`` statement grants every action (``*`` or ``*:*``) on
    every resource (``*``).
    A ``Deny`` statement never counts, and neither does a statement that names ``NotAction``.
``allows_service_wildcard``
    Some ``Allow`` statement grants every action of one service (``iam:*``, ``s3:*``) on every
    resource.
    A bare ``*`` is ``allows_all_actions`` instead, so the two never report the same statement.
``allows_passrole_wildcard``
    Some ``Allow`` statement grants ``iam:PassRole`` (or a pattern that covers it, such as
    ``iam:Pass*``) on every resource and is not narrowed by an ``iam:PassedToService`` condition.
    ``*`` and ``iam:*`` are reported by the two facts above and are left out here.
``admin_policy_attached``
    On an attachment resource (``policy_arn``) or on a role, user or group
    (``managed_policy_arns``): the AWS managed policy ``AdministratorAccess`` is attached.
``allows_any_principal``
    On a resource that carries a resource policy (bucket, KMS key, queue, topic) or a trust policy
    (role): some ``Allow`` statement names every principal (``"*"`` or ``{"AWS": "*"}``) and has no
    condition key that narrows who can call, see `RESTRICTING_CONDITION_KEYS`.
    For a bucket the statements are those of the bucket policy resources and of the inline
    ``policy`` attribute.
``public_access_block``
    CloudFormation only, on a bucket: the four flags of ``PublicAccessBlockConfiguration``, merged
    into the key the companion resources write (a block resource and an inline block agree on the
    same shape).
``secret_name``
    On ``aws_ssm_parameter``: the name has a word that says it holds a secret, as in
    ``/prod/db/password``.
    A name that is itself unknown is Unknown.
``publicly_accessible`` and ``logging_enabled``
    On ``aws_redshift_cluster``.
    ``publicly_accessible`` is the attribute as written; when it is omitted it is ``True`` for
    Terraform, whose provider defaults it to true, and absent for CloudFormation, whose
    documentation names no default.
    ``logging_enabled`` is ``True`` for an inline ``logging`` block that enables logging or an
    ``aws_redshift_logging`` resource that points at the cluster, Unknown when such a resource
    cannot be matched to a cluster, and ``False`` otherwise.

The statements read here come from `threatcode.ir.policy`, which the ``companions`` module also
uses.
This module is imported before ``companions`` runs its derivers, so it reads raw properties through
the helpers ``companions`` exports instead of the keys that module writes in the same phase.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from typing import Any

from threatcode.ir.enrich import (
    Deriver,
    EnrichContext,
    as_list,
    blocks,
    tri_bool,
    type_matcher,
)
from threatcode.ir.enrichment.companions import own_policy_statements, statements_of
from threatcode.ir.nodes import InfraNode
from threatcode.values import Unknown, is_unknown

Facts = Mapping[str, Any]
Tri = bool | None
"""True, False, or None when the answer depends on a value the scan does not have."""

# ---------------------------------------------------------------------------
# Provider defaults
# ---------------------------------------------------------------------------

_PUBLIC_ACCESS_FLAGS = (
    "block_public_acls",
    "block_public_policy",
    "ignore_public_acls",
    "restrict_public_buckets",
)

DEFAULTS: dict[str, dict[str, Any]] = {
    # Provider docs: "enable_key_rotation - (Optional) Specifies whether key rotation is
    # enabled. Defaults to false." CloudFormation EnableKeyRotation defaults to false too.
    "aws_kms_key": {"enable_key_rotation": False},
    # Provider docs: is_multi_region_trail and enable_log_file_validation default to false,
    # enable_logging defaults to true. CloudFormation IsMultiRegionTrail and
    # EnableLogFileValidation default to false.
    "aws_cloudtrail": {
        "is_multi_region_trail": False,
        "enable_log_file_validation": False,
        "enable_logging": True,
    },
}

# ---------------------------------------------------------------------------
# Condition keys that narrow who can use a statement with a wildcard principal
# ---------------------------------------------------------------------------

RESTRICTING_CONDITION_KEYS: frozenset[str] = frozenset(
    {
        "aws:principalorgid",
        "aws:principalorgpaths",
        "aws:principalarn",
        "aws:principalaccount",
        "aws:sourcevpce",
        "aws:sourcevpc",
        "aws:sourcearn",
        "aws:sourceaccount",
        "aws:sourceowner",
        "aws:sourceorgid",
        "aws:sourceorgpaths",
        "kms:calleraccount",
    }
)
"""Condition keys, lower case, that limit a ``Principal: "*"`` statement to a known caller.

AWS compares condition keys without regard to case, so a key is lower cased before the lookup.
``aws:SourceOwner`` is what the default SNS topic policy uses, ``aws:SourceArn`` and
``aws:SourceAccount`` are what services use to reach a queue or a key, and ``aws:PrincipalOrgID``
is the organisation guard.
Keys that do not say who is calling (``aws:SecureTransport``, ``aws:RequestedRegion``,
``aws:SourceIp``) are deliberately absent: a statement that has only those still names every
principal.
"""

_ADMIN_POLICY_ARN = re.compile(r"^arn:[^:]*:iam::aws:policy/AdministratorAccess$", re.IGNORECASE)
_SERVICE_WILDCARD = re.compile(r"^[A-Za-z0-9-]+:\*$")
_ALL_ACTIONS = frozenset({"*", "*:*"})
_PASSROLE = "iam:passrole"
_PASSROLE_NARROWING_KEYS = frozenset({"iam:passedtoservice"})

# ---------------------------------------------------------------------------
# Three-valued helpers (None means the scan cannot tell)
# ---------------------------------------------------------------------------


def _or(values: Iterable[Tri]) -> Tri:
    result: Tri = False
    for value in values:
        if value is True:
            return True
        if value is None:
            result = None
    return result


def _and(values: Iterable[Tri]) -> Tri:
    result: Tri = True
    for value in values:
        if value is False:
            return False
        if value is None:
            result = None
    return result


def _fact(value: Tri) -> bool | Unknown:
    return Unknown() if value is None else value


def _any_text(items: Sequence[Any], predicate: Callable[[str], bool]) -> Tri:
    """True if a known string satisfies ``predicate``; None if none does and one is unknown."""
    unknown = False
    for item in items:
        if is_unknown(item):
            unknown = True
        elif isinstance(item, str) and predicate(item.strip()):
            return True
    return None if unknown else False


# ---------------------------------------------------------------------------
# Statements
# ---------------------------------------------------------------------------

Statements = list[dict[str, Any]]


def _read(statements: Statements | Unknown | None) -> tuple[Statements, bool]:
    """The statements of one document and whether the document could not be read."""
    if statements is None:
        return [], False
    if isinstance(statements, Unknown):
        return [], True
    return statements, False


def _lower_keys(statement: Mapping[str, Any]) -> set[str]:
    return {key.lower() for key in as_list(statement.get("condition_keys")) if isinstance(key, str)}


def _allows(statement: Mapping[str, Any]) -> Tri:
    return statement.get("effect") == "Allow"


def _all_actions(statement: Mapping[str, Any]) -> Tri:
    return _any_text(as_list(statement.get("actions")), lambda action: action in _ALL_ACTIONS)


def _service_wildcard(statement: Mapping[str, Any]) -> Tri:
    return _any_text(
        as_list(statement.get("actions")), lambda action: bool(_SERVICE_WILDCARD.match(action))
    )


def _all_resources(statement: Mapping[str, Any]) -> Tri:
    return _any_text(as_list(statement.get("resources")), lambda resource: resource == "*")


def _covers_passrole(action: str) -> bool:
    lowered = action.lower()
    if lowered in _ALL_ACTIONS or lowered == "iam:*":
        return False
    return fnmatch.fnmatchcase(_PASSROLE, lowered)


def _passrole_wildcard(statement: Mapping[str, Any]) -> Tri:
    if _lower_keys(statement) & _PASSROLE_NARROWING_KEYS:
        return False
    return _and(
        [
            _allows(statement),
            _any_text(as_list(statement.get("actions")), _covers_passrole),
            _all_resources(statement),
        ]
    )


def _any_principal(statement: Mapping[str, Any]) -> Tri:
    if _lower_keys(statement) & RESTRICTING_CONDITION_KEYS:
        return False
    return _and(
        [
            _allows(statement),
            _any_text(as_list(statement.get("principals")), lambda principal: principal == "*"),
        ]
    )


def _all_actions_everywhere(statement: Mapping[str, Any]) -> Tri:
    return _and([_allows(statement), _all_actions(statement), _all_resources(statement)])


def _service_wildcard_everywhere(statement: Mapping[str, Any]) -> Tri:
    return _and([_allows(statement), _service_wildcard(statement), _all_resources(statement)])


def _over(
    documents: Iterable[Statements | Unknown | None],
    predicate: Callable[[Mapping[str, Any]], Tri],
) -> bool | Unknown:
    """The fact for several documents: True on a hit, Unknown when a document is unreadable."""
    unreadable = False
    verdicts: list[Tri] = []
    for document in documents:
        statements, unknown = _read(document)
        unreadable = unreadable or unknown
        verdicts.extend(predicate(statement) for statement in statements)
    outcome = _or(verdicts)
    if outcome is False and unreadable:
        outcome = None
    return _fact(outcome)


# ---------------------------------------------------------------------------
# Identity policies
# ---------------------------------------------------------------------------

_OWN_POLICY_IDENTITIES = (
    "aws_iam_policy",
    "aws_iam_role_policy",
    "aws_iam_user_policy",
    "aws_iam_group_policy",
)
_INLINE_BLOCK_IDENTITIES = ("aws_iam_role", "aws_iam_user", "aws_iam_group")


def _inline_block_documents(node: InfraNode) -> list[Statements | Unknown | None]:
    """The documents of the ``inline_policy`` blocks a role, user or group declares itself.

    A standalone ``aws_iam_role_policy`` is judged on its own resource, not repeated here.
    """
    raw = node.properties.get("inline_policy", node.properties.get("Policies"))
    if raw is None:
        return []
    if is_unknown(raw):
        return [raw]
    documents: list[Statements | Unknown | None] = []
    for entry in blocks(raw):
        policy = entry.get("policy", entry.get("PolicyDocument"))
        if policy is not None:
            documents.append(statements_of(policy))
    return documents


def _identity_documents(node: InfraNode) -> list[Statements | Unknown | None]:
    if node.resource_type in _OWN_POLICY_IDENTITIES:
        return [own_policy_statements(node)]
    return _inline_block_documents(node)


def _identity_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    documents = _identity_documents(node)
    return {
        "allows_all_actions": _over(documents, _all_actions_everywhere),
        "allows_service_wildcard": _over(documents, _service_wildcard_everywhere),
        "allows_passrole_wildcard": _over(documents, _passrole_wildcard),
    }


# ---------------------------------------------------------------------------
# AdministratorAccess
# ---------------------------------------------------------------------------

_ATTACHMENTS = (
    "aws_iam_role_policy_attachment",
    "aws_iam_user_policy_attachment",
    "aws_iam_group_policy_attachment",
    "aws_iam_policy_attachment",
)


def _names_admin_policy(value: Any) -> Tri:
    if is_unknown(value):
        return None
    if isinstance(value, str):
        return bool(_ADMIN_POLICY_ARN.match(value.strip()))
    return False


def _attached_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    arns = as_list(node.properties.get("policy_arn", node.properties.get("PolicyArn")))
    return {"admin_policy_attached": _fact(_or(_names_admin_policy(arn) for arn in arns))}


def _managed_arn_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    raw = node.properties.get("managed_policy_arns", node.properties.get("ManagedPolicyArns"))
    if raw is None:
        return {"admin_policy_attached": False}
    if is_unknown(raw):
        return {"admin_policy_attached": raw}
    return {"admin_policy_attached": _fact(_or(_names_admin_policy(a) for a in as_list(raw)))}


# ---------------------------------------------------------------------------
# Resource and trust policies
# ---------------------------------------------------------------------------


def _resource_policy_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    documents: list[Statements | Unknown | None] = [own_policy_statements(node)]
    if node.resource_type == "aws_s3_bucket":
        # Bucket policy resources are folded in by the companion phase, which has already run
        companion = ctx.derived(node).get("policy_statements")
        if isinstance(companion, list) or is_unknown(companion):
            documents.append(companion)
    return {"allows_any_principal": _over(documents, _any_principal)}


def _trust_policy_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    raw = node.properties.get("assume_role_policy", node.properties.get("AssumeRolePolicyDocument"))
    document = statements_of(raw) if raw is not None else None
    return {"allows_any_principal": _over([document], _any_principal)}


# ---------------------------------------------------------------------------
# S3 public access block written inline (CloudFormation)
# ---------------------------------------------------------------------------


def _first_block(raw: Any) -> dict[str, Any]:
    """The first nested block of a value that is a block or a list of blocks, or an empty one."""
    found = blocks(raw)
    return found[0] if found else {}


def _inline_public_access_block(node: InfraNode, ctx: EnrichContext) -> Facts:
    raw = node.properties.get(
        "public_access_block", node.properties.get("PublicAccessBlockConfiguration")
    )
    if raw is None:
        return {}
    if is_unknown(raw):
        return {"public_access_block": raw}
    found = _first_block(raw)
    flags: dict[str, Any] = {}
    for flag in _PUBLIC_ACCESS_FLAGS:
        value = tri_bool(found.get(flag))
        flags[flag] = False if value is None else value
    return {"public_access_block": flags}


# ---------------------------------------------------------------------------
# SSM parameter names
# ---------------------------------------------------------------------------

_SECRET_WORDS = frozenset(
    {
        "password",
        "passwords",
        "passwd",
        "pwd",
        "passphrase",
        "secret",
        "secrets",
        "token",
        "tokens",
        "apikey",
        "credential",
        "credentials",
    }
)
_SECRET_PAIRS = frozenset(
    {("api", "key"), ("private", "key"), ("auth", "token"), ("access", "key"), ("secret", "key")}
)
# A name that ends in one of these holds a location or a label, not the secret itself
_NOT_THE_SECRET = frozenset(
    {
        "path",
        "file",
        "url",
        "uri",
        "name",
        "id",
        "dir",
        "directory",
        "arn",
        "version",
        "length",
        "ttl",
        "expiry",
        "endpoint",
        "header",
        "policy",
        "enabled",
        "rotation",
    }
)
_WORD_SPLIT = re.compile(r"[^A-Za-z0-9]+")
_CAMEL_WORDS = re.compile(r"[A-Z]+(?![a-z])|[A-Z]?[a-z]+|[0-9]+")


def name_words(name: str) -> list[str]:
    """Lower case words of a name, split on punctuation and camelCase (``DbPassword`` is two)."""
    words: list[str] = []
    for chunk in _WORD_SPLIT.split(name):
        words.extend(match.lower() for match in _CAMEL_WORDS.findall(chunk))
    return words


def looks_like_secret_name(name: str) -> bool:
    """Whether a parameter name says the value is a secret, by whole words only.

    ``/prod/db/password``, ``/app/ApiKey`` and ``/svc/auth_token`` do.
    ``/app/keyboard``, ``/app/password_policy`` and ``/app/token_url`` do not, because ``key`` alone
    proves nothing and a name that ends in a label word names something else.
    """
    words = name_words(name)
    if not words or words[-1] in _NOT_THE_SECRET:
        return False
    if any(word in _SECRET_WORDS or word.endswith(("password", "passwd")) for word in words):
        return True
    return any(pair in _SECRET_PAIRS for pair in zip(words, words[1:], strict=False))


def _ssm_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    name = node.properties.get("name", node.properties.get("Name"))
    if is_unknown(name):
        return {"secret_name": name}
    if not isinstance(name, str):
        return {"secret_name": False}
    return {"secret_name": looks_like_secret_name(name)}


# ---------------------------------------------------------------------------
# Redshift
# ---------------------------------------------------------------------------

_CLUSTER = "aws_redshift_cluster"
_LOGGING_RESOURCE = "aws_redshift_logging"
_CLUSTER_LINK_KEYS = ("cluster_identifier", "id", "name")


def _is_cloudformation(node: InfraNode, ctx: EnrichContext) -> bool:
    """Whether a node came from a CloudFormation template.

    The graph records the parser format of each node when it can (``node_formats``); a
    translated template node also keeps its raw spelling under ``_cfn``.
    """
    formats = getattr(ctx.graph, "node_formats", None)
    if isinstance(formats, Mapping) and formats.get(node.id) == "cloudformation":
        return True
    return "_cfn" in node.properties


def _inline_logging(node: InfraNode) -> Tri:
    """The deprecated inline ``logging`` block: enabled, disabled, or not written."""
    raw = node.properties.get("logging", node.properties.get("LoggingProperties"))
    if raw is None:
        return False
    if is_unknown(raw):
        return None
    found = _first_block(raw)
    enabled = found.get("enable")
    if enabled is None:
        return bool(found)
    flag = tri_bool(enabled)
    return None if flag is None or isinstance(flag, Unknown) else flag


def _companion_logging(node: InfraNode, ctx: EnrichContext) -> Tri:
    """Whether an ``aws_redshift_logging`` resource points at this cluster."""
    verdicts: list[Tri] = []
    for companion in ctx.peers(node, type_matcher(_LOGGING_RESOURCE), any_input=True):
        link = ctx.resolve_link(
            companion,
            ("cluster_identifier",),
            type_matcher(_CLUSTER),
            literal_keys=_CLUSTER_LINK_KEYS,
        )
        if any(target.id == node.id for target in link.resolved):
            verdicts.append(True)
        elif link.unresolved:
            verdicts.append(None)
    return _or(verdicts)


def _redshift_facts(node: InfraNode, ctx: EnrichContext) -> Facts:
    facts: dict[str, Any] = {}
    public = node.properties.get("publicly_accessible", node.properties.get("PubliclyAccessible"))
    if public is None:
        if not _is_cloudformation(node, ctx):
            facts["publicly_accessible"] = True
    elif is_unknown(public):
        facts["publicly_accessible"] = public
    else:
        facts["publicly_accessible"] = tri_bool(public) is True
    facts["logging_enabled"] = _fact(_or([_inline_logging(node), _companion_logging(node, ctx)]))
    return facts


DERIVERS: tuple[Deriver, ...] = (
    Deriver(_OWN_POLICY_IDENTITIES + _INLINE_BLOCK_IDENTITIES, _identity_facts),
    Deriver(_ATTACHMENTS, _attached_facts),
    Deriver(_INLINE_BLOCK_IDENTITIES, _managed_arn_facts),
    Deriver(
        (
            "aws_s3_bucket",
            "aws_kms_key",
            "aws_sqs_queue",
            "aws_sqs_queue_policy",
            "aws_sns_topic",
            "aws_sns_topic_policy",
        ),
        _resource_policy_facts,
    ),
    Deriver(("aws_iam_role",), _trust_policy_facts),
    Deriver(("aws_s3_bucket",), _inline_public_access_block),
    Deriver(("aws_ssm_parameter",), _ssm_facts),
    Deriver((_CLUSTER,), _redshift_facts),
)

__all__ = [
    "DEFAULTS",
    "DERIVERS",
    "RESTRICTING_CONDITION_KEYS",
    "looks_like_secret_name",
    "name_words",
]
