"""No builtin rule reads a property that nothing produces.

A rule that reads a property no parser or enrichment module writes can never fire, and nothing
says so: the finding is just absent.
Seven Docker and Kubernetes rules and sixteen Terraform ones were dead this way.

For every ``(resource type, property)`` a builtin rule reads at the top level of the resource,
exactly one of these has to hold:

1. a module declares it in its ``PRODUCED`` registry (a parser for Dockerfile, Kubernetes and MCP
   resources, an enrichment module for ``derived.<fact>``);
2. a parser delivers it for that type in the corpus: the example snippets of the rule cases, the
   fixtures and the example stacks (this is what documents a Terraform, CloudFormation or Azure
   attribute: the real parser put it there for a real input);
3. it is listed in ``ALLOWED`` below with the reason it is fine.

The registries are kept honest from both sides: a property the corpus shows a module writing has
to be declared, and a property a module declares has to be seen being written.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

import pytest

from tests.helpers.provenance import (
    PARSER_MODULES,
    Read,
    declared_for,
    declared_properties,
    is_produced,
    key_of,
    observed_properties,
    producer_modules,
    reads_of,
    registry_of,
    rule_reads,
    unproduced_reads,
)
from threatcode.engine.rules.loader import Rule, load_builtin_rules
from threatcode.engine.rules.matcher import resource_type_matches
from threatcode.ir.enrich import DERIVED, enrichment_modules

# ---------------------------------------------------------------------------------------
# Reads that are fine without a producer
# ---------------------------------------------------------------------------------------

PROVIDER = "provider"
SHARED = "shared"


@dataclass(frozen=True)
class Allowed:
    """Reads that are fine although nothing in the corpus produces them.

    ``provider``: an attribute of the resource in the provider's schema, which no rule example
    sets.
    ``shared``: a rule lists several resource types and tests each spelling of one setting
    (``member`` on an IAM member, ``members`` on an IAM binding), so each type reads the
    attribute of the others; the extra branch is inert on that type and the rule is not.
    """

    kind: str
    types: str  # a regular expression, matched against the whole resource type
    keys: frozenset[str]
    reason: str

    def covers(self, read: Read) -> bool:
        return bool(re.fullmatch(self.types, read.resource_type)) and read.key in self.keys


def _allow(kind: str, types: str, keys: str, reason: str) -> Allowed:
    return Allowed(kind, types, frozenset(keys.split()), reason)


_IAM_MEMBER = r"google_\w+_iam_member"
_IAM_BINDING = r"google_\w+_iam_binding"
_BUCKET_ACLS = r"google_storage_(?:bucket|default_object)_acl"
_BUCKET_CONTROLS = r"google_storage_(?:bucket|default_object)_access_control"
_ONE_RULE_MANY_SPELLINGS = (
    "the rule lists the IAM member, IAM binding and ACL types together and tests every spelling "
    "of the member on each of them"
)

ALLOWED: tuple[Allowed, ...] = (
    # --- AWS: attributes of the provider schema that no rule example sets
    _allow(PROVIDER, r"aws_apigatewayv2_stage", "access_log_settings", "block of the resource"),
    _allow(
        PROVIDER,
        r"aws_db_instance",
        "replicate_source_db snapshot_identifier",
        "arguments for a replica or a restored instance, which inherit the source's encryption",
    ),
    _allow(
        PROVIDER,
        r"aws_rds_cluster",
        "engine_mode replication_source_identifier snapshot_identifier",
        "arguments for a serverless, replica or restored cluster",
    ),
    _allow(
        PROVIDER, r"aws_rds_cluster_instance", "publicly_accessible", "argument of the resource"
    ),
    _allow(
        PROVIDER,
        r"aws_elasticache_replication_group",
        "auth_token",
        "argument of the resource",
    ),
    _allow(
        PROVIDER, r"aws_elasticsearch_domain", "node_to_node_encryption", "block of the resource"
    ),
    _allow(
        PROVIDER,
        r"aws_launch_(?:configuration|template)",
        "metadata_options",
        "block of the resource; the IMDS rule reads a missing block as optional",
    ),
    _allow(
        PROVIDER,
        r"aws_s3_account_public_access_block",
        "block_public_acls block_public_policy ignore_public_acls restrict_public_buckets",
        "the four arguments of the account level block",
    ),
    _allow(
        SHARED,
        r"aws_rds_cluster",
        "db_cluster_identifier replicate_source_db",
        "RDS_NO_ENCRYPTION lists aws_db_instance and aws_rds_cluster and skips both kinds of "
        "inheriting resource; each type reads the other's arguments",
    ),
    _allow(
        SHARED,
        r"aws_db_instance",
        "engine_mode replication_source_identifier",
        "RDS_NO_ENCRYPTION lists aws_db_instance and aws_rds_cluster and skips both kinds of "
        "inheriting resource; each type reads the other's arguments",
    ),
    # --- Azure
    _allow(
        PROVIDER,
        r"azurerm_kubernetes_cluster",
        "api_server_authorized_ip_ranges",
        "azurerm 3.x spelling; 4.x moves it to api_server_access_profile, which the rule reads too",
    ),
    _allow(
        PROVIDER,
        r"azurerm_(?:linux|windows)_web_app",
        "auth_settings",
        "block of the resource",
    ),
    _allow(PROVIDER, r"azurerm_windows_web_app", "auth_settings_v2", "block of the resource"),
    _allow(
        PROVIDER,
        r"azurerm_virtual_machine",
        "identity os_profile_linux_config",
        "blocks of the legacy virtual machine resource",
    ),
    _allow(
        SHARED,
        r"azurerm_app_service",
        "auth_settings_v2",
        "APPSVC_NO_AUTH lists the app service and both web app types; the v2 block is on the "
        "web apps only",
    ),
    _allow(
        SHARED,
        r"azurerm_linux_virtual_machine",
        "os_profile_linux_config",
        "AZURE_VM_PASSWORD_AUTH lists both machine types; the nested block is on the legacy one",
    ),
    _allow(
        SHARED,
        r"azurerm_virtual_machine",
        "disable_password_authentication",
        "AZURE_VM_PASSWORD_AUTH lists both machine types; the flat argument is on the new one",
    ),
    _allow(
        SHARED,
        r"azurerm_network_security_group",
        "access direction protocol source_address_prefix source_address_prefixes "
        "destination_port_range destination_port_ranges",
        "the NSG rules list the group and the standalone rule; the group holds these in its "
        "security_rule blocks, which the rules also test",
    ),
    _allow(
        SHARED,
        r"azurerm_network_security_rule",
        "security_rule",
        "the NSG rules list the group and the standalone rule; the standalone rule has no "
        "security_rule block",
    ),
    # --- Google Cloud
    _allow(
        PROVIDER,
        r"google_compute_instance_template",
        "service_account",
        "block of the resource",
    ),
    _allow(PROVIDER, r"google_cloudfunctions_function", "event_trigger", "block of the resource"),
    _allow(
        SHARED,
        r"google_cloudfunctions_function",
        "build_config service_config",
        "the Cloud Functions rules list both generations and test both spellings; these blocks "
        "are the second generation's",
    ),
    _allow(
        SHARED,
        r"google_cloudfunctions2_function",
        "https_trigger_security_level ingress_settings max_instances trigger_http vpc_connector",
        "the Cloud Functions rules list both generations and test both spellings; these "
        "arguments are the first generation's",
    ),
    _allow(PROVIDER, _IAM_MEMBER, "member role", "arguments of every IAM member resource"),
    _allow(PROVIDER, _IAM_BINDING, "members role", "arguments of every IAM binding resource"),
    _allow(PROVIDER, _BUCKET_ACLS, "role_entity", "argument of the bucket ACL resources"),
    _allow(PROVIDER, _BUCKET_CONTROLS, "entity", "argument of the access control resources"),
    _allow(SHARED, _IAM_MEMBER, "members entity role_entity", _ONE_RULE_MANY_SPELLINGS),
    _allow(SHARED, _IAM_BINDING, "member entity role_entity", _ONE_RULE_MANY_SPELLINGS),
    _allow(SHARED, _BUCKET_ACLS, "entity member members", _ONE_RULE_MANY_SPELLINGS),
    _allow(SHARED, _BUCKET_CONTROLS, "member members role_entity", _ONE_RULE_MANY_SPELLINGS),
)


def allowed_by(read: Read) -> Allowed | None:
    return next((entry for entry in ALLOWED if entry.covers(read)), None)


# ---------------------------------------------------------------------------------------
# The gate
# ---------------------------------------------------------------------------------------


def test_every_property_a_builtin_rule_reads_is_produced_or_justified() -> None:
    dead = [r for r in unproduced_reads(rule_reads()) if allowed_by(r) is None]
    assert not dead, (
        "these builtin rules read a property that no parser or enrichment module produces, so "
        "they can never fire. Make the parser or enrichment write it (and declare it in that "
        "module's PRODUCED), read the property that exists, or delete the rule:\n  "
        + "\n  ".join(
            f"{r.rule_id}: {r.key} on {r.resource_type}" for r in sorted(dead, key=_order)
        )
    )


def _order(read: Read) -> tuple[str, str, str]:
    return (read.rule_id, read.resource_type, read.key)


def test_the_allowlist_has_no_stale_entries() -> None:
    """An entry that matches nothing was either fixed or never needed: delete it."""
    unproduced = unproduced_reads(rule_reads())
    stale: list[str] = []
    for entry in ALLOWED:
        hit_keys = {r.key for r in unproduced if entry.covers(r)}
        missing = entry.keys - hit_keys
        if missing:
            stale.append(f"{entry.types}: {sorted(missing)} ({entry.kind})")
    assert not stale, "ALLOWED entries that no unproduced read needs:\n  " + "\n  ".join(stale)


def test_every_allowlist_entry_has_a_reason_and_a_known_kind() -> None:
    for entry in ALLOWED:
        assert entry.kind in (PROVIDER, SHARED), entry
        assert entry.reason.strip(), entry
        assert entry.keys, entry
        assert not any(key.startswith(f"{DERIVED}.") for key in entry.keys), (
            f"{entry.types}: a derived fact is declared in a module's PRODUCED, not allowed here"
        )


# ---------------------------------------------------------------------------------------
# The gate fails on a fabricated property
# ---------------------------------------------------------------------------------------


def _rule(resource_type: str, condition: dict[str, object]) -> Rule:
    return Rule(
        id="FABRICATED",
        title="t",
        description="d",
        stride_category="tampering",
        severity="low",
        resource_types=(resource_type,),
        condition=condition,
    )


def test_a_fabricated_synthetic_property_is_caught() -> None:
    rule = _rule("dockerfile_image", {"has_a_property_nothing_sets": {"equals": True}})
    assert [r.key for r in unproduced_reads(reads_of(rule))] == ["has_a_property_nothing_sets"]


def test_a_fabricated_derived_fact_is_caught() -> None:
    rule = _rule("aws_s3_bucket", {"derived.never_written": {"equals": True}})
    assert [r.key for r in unproduced_reads(reads_of(rule))] == ["derived.never_written"]


def test_a_derived_fact_declared_for_another_type_is_caught() -> None:
    """``has_flow_log`` is a VPC fact: a bucket rule cannot read it."""
    rule = _rule("aws_s3_bucket", {"derived.has_flow_log": {"equals": True}})
    assert [r.key for r in unproduced_reads(reads_of(rule))] == ["derived.has_flow_log"]


def test_real_properties_pass() -> None:
    assert not unproduced_reads(
        reads_of(_rule("dockerfile_image", {"has_digest_pin": {"equals": False}}))
    )
    assert not unproduced_reads(
        reads_of(_rule("kubernetes_ingress", {"has_tls": {"equals": False}}))
    )
    assert not unproduced_reads(
        reads_of(_rule("aws_vpc", {"derived.has_flow_log": {"equals": False}}))
    )


def test_a_key_under_a_quantifier_belongs_to_the_element_and_is_not_read_from_the_resource() -> (
    None
):
    rule = _rule(
        "aws_security_group",
        {"derived.ingress": {"any_item": {"nothing_on_the_group": {"equals": 1}}}},
    )
    assert {r.key for r in reads_of(rule)} == {"derived.ingress"}


def test_a_path_is_reduced_to_its_first_segment_or_its_derived_fact() -> None:
    assert key_of("metadata_options.http_tokens") == "metadata_options"
    assert key_of("ingress[0].cidr_blocks") == "ingress"
    assert key_of("derived.public_access_block.block_public_acls") == "derived.public_access_block"


# ---------------------------------------------------------------------------------------
# The registries are honest
# ---------------------------------------------------------------------------------------

_SYNTHETIC_FAMILIES = ("dockerfile_", "kubernetes_", "mcp_")


def test_every_parser_and_enrichment_module_exports_a_registry() -> None:
    for name in producer_modules():
        registry = registry_of(name)
        for pattern, keys in registry.items():
            assert isinstance(keys, frozenset) and keys, (name, pattern)
            assert pattern and all(isinstance(key, str) and key for key in keys), (name, pattern)


def test_the_registered_parsers_are_all_covered() -> None:
    import threatcode.parsers as parsers

    modules = {type(entry.factory()).__module__ for entry in parsers._REGISTRY}
    assert modules <= set(PARSER_MODULES), sorted(modules - set(PARSER_MODULES))


def test_an_enrichment_module_that_writes_facts_declares_them() -> None:
    for module in enrichment_modules():
        writes = any(
            getattr(module, name, None) for name in ("COMPANIONS", "DERIVERS", "RELATIONS")
        )
        if writes:
            assert getattr(module, "PRODUCED", None), (
                f"{module.__name__} writes derived facts and has no PRODUCED registry"
            )


def test_only_enrichment_registries_declare_derived_facts() -> None:
    for name in PARSER_MODULES:
        offenders = {k for keys in registry_of(name).values() for k in keys if "." in k}
        assert not offenders, (name, sorted(offenders))
    for name in producer_modules():
        if name in PARSER_MODULES:
            continue
        offenders = {
            k
            for keys in registry_of(name).values()
            for k in keys
            if not k.startswith(f"{DERIVED}.")
        }
        assert not offenders, (name, sorted(offenders))


def test_a_property_a_parser_emits_is_declared() -> None:
    """The registry cannot lag the parser: every key the corpus shows on a synthetic type."""
    undeclared = [
        f"{resource_type}: {key}"
        for resource_type, keys in sorted(observed_properties().items())
        if resource_type.startswith(_SYNTHETIC_FAMILIES)
        for key in sorted(keys)
        if key not in declared_for(resource_type)
    ]
    assert not undeclared, (
        "properties emitted but missing from the parser's PRODUCED registry:\n  "
        + "\n  ".join(undeclared)
    )


def test_a_derived_fact_enrichment_writes_is_declared() -> None:
    undeclared = [
        f"{resource_type}: {key}"
        for resource_type, keys in sorted(observed_properties().items())
        for key in sorted(keys)
        if key.startswith(f"{DERIVED}.") and key not in declared_for(resource_type)
    ]
    assert not undeclared, (
        "derived facts written but missing from the module's PRODUCED registry:\n  "
        + "\n  ".join(undeclared)
    )


def test_a_declared_property_is_seen_being_written() -> None:
    """A registry entry nobody writes would make a dead rule look alive.

    Checked per property: some resource type the registry declares it for has to show it in the
    corpus (a type-by-type check would need a fixture for every type a module lists).
    """
    types_by_key: dict[str, set[str]] = {}
    for pattern, keys in declared_properties().items():
        for key in keys:
            types_by_key.setdefault(key, set()).add(pattern)
    observed = observed_properties()
    unseen = sorted(
        key
        for key, patterns in types_by_key.items()
        if not any(
            key in found
            for resource_type, found in observed.items()
            if resource_type_matches(patterns, resource_type)
        )
    )
    assert not unseen, (
        "declared but never written for any declared type in the corpus; add a fixture or "
        "rule case that makes the module write it, or remove the entry:\n  " + "\n  ".join(unseen)
    )


def test_the_corpus_reaches_every_builtin_rule_type_family() -> None:
    """The gate is only as good as its corpus: it has to cover each provider and each format."""
    seen = {t.split("_")[0] for t in observed_properties()}
    assert {"aws", "azurerm", "google", "kubernetes", "dockerfile", "mcp"} <= seen


def test_every_rule_resource_type_is_reached_by_at_least_one_read_or_has_no_condition() -> None:
    """Sanity check on the walker: it finds reads for nearly every rule."""
    rules = load_builtin_rules()
    without = [rule.id for rule in rules if not reads_of(rule)]
    assert len(without) <= 2, f"the walker found no read for {without}"


@pytest.mark.parametrize(
    ("resource_type", "key"),
    [
        ("dockerfile_image", "has_digest_pin"),
        ("dockerfile_image", "is_non_minimal"),
        ("dockerfile_add", "is_url_add"),
        ("dockerfile_run", "has_apt_no_clean"),
        ("kubernetes_ingress", "has_tls"),
        ("kubernetes_deployment", "seccomp_profile_type"),
        ("aws_wafv2_web_acl", "derived.has_rate_based_rule"),
        ("google_compute_firewall", "derived.world_source"),
    ],
)
def test_the_properties_the_dead_rules_needed_are_now_produced(
    resource_type: str, key: str
) -> None:
    assert is_produced(Read("X", resource_type, key))
