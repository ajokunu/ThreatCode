"""Azure facts the Azure rules read: provider defaults, storage firewalls and VM public IPs.

``DEFAULTS``
    The effective value of an attribute that Terraform HCL leaves out and a plan materialises, for
    the resource types an Azure rule tests with ``equals``.
    The values are the azurerm provider defaults and match the exposure table of the graph, so a
    rule and the exposure logic never disagree about what an omitted attribute means.
    Nothing here is a general catalogue of defaults: an entry exists only because a rule would
    otherwise be silent about a configuration that is insecure by default.

``derived.network_default_deny`` (``azurerm_storage_account``)
    True when the account's firewall denies by default, either through the inline
    ``network_rules`` block or through an ``azurerm_storage_account_network_rules`` resource
    that points at the account.
    False when neither does.
    Unknown when a network rules resource cannot be matched to an account.

``derived.has_public_ip`` (virtual machines)
    True when a network interface of the machine has an ``ip_configuration`` with a public IP
    address.
    False when every interface it names has none, or when it names no interface.
    Unknown when an interface or its public IP cannot be resolved, so a machine whose interface
    is outside the scan never reads as private.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from threatcode.ir.enrich import (
    CompanionSpec,
    Deriver,
    EnrichContext,
    Produced,
    RelationSpec,
    blocks,
    merge_produced,
    merge_value,
    produced,
    produced_by_companions,
    produced_by_relations,
    text,
    type_matcher,
)
from threatcode.ir.nodes import InfraNode
from threatcode.values import Unknown, is_unknown

Facts = dict[str, Any]

# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULTS: dict[str, dict[str, Any]] = {
    # An App Service and a Function App accept plain HTTP unless https_only is set
    "azurerm_app_service": {"https_only": False},
    "azurerm_linux_web_app": {"https_only": False},
    "azurerm_windows_web_app": {"https_only": False},
    "azurerm_function_app": {"https_only": False},
    "azurerm_linux_function_app": {"https_only": False, "public_network_access_enabled": True},
    "azurerm_windows_function_app": {"https_only": False, "public_network_access_enabled": True},
    "azurerm_kubernetes_cluster": {"private_cluster_enabled": False},
    "azurerm_key_vault": {
        "purge_protection_enabled": False,
        "public_network_access_enabled": True,
    },
    "azurerm_storage_account": {"allow_nested_items_to_be_public": True},
    "azurerm_cosmosdb_account": {"public_network_access_enabled": True},
    "azurerm_mssql_server": {"public_network_access_enabled": True},
    "azurerm_container_registry": {"public_network_access_enabled": True},
    "azurerm_redis_cache": {"public_network_access_enabled": True},
}

# ---------------------------------------------------------------------------
# Storage account firewall
# ---------------------------------------------------------------------------


def _denies(action: Any) -> bool | Unknown:
    """Whether a firewall default_action denies; an Unknown stays Unknown."""
    if is_unknown(action):
        return action
    found = text(action)
    return isinstance(found, str) and found.strip().lower() == "deny"


def _network_rules_resource(companion: InfraNode, parent: InfraNode, ctx: EnrichContext) -> Facts:
    return {"network_default_deny": _denies(companion.properties.get("default_action"))}


def _network_rules_inline(node: InfraNode, ctx: EnrichContext) -> Facts:
    inline = node.properties.get("network_rules")
    if is_unknown(inline):
        return {"network_default_deny": inline}
    found = blocks(inline)
    if not found:
        return {}
    return {"network_default_deny": _denies(found[0].get("default_action"))}


# ---------------------------------------------------------------------------
# Virtual machine public IP
# ---------------------------------------------------------------------------

_PUBLIC_IP = type_matcher("azurerm_public_ip")


def _has_public_ip(nics: Sequence[InfraNode], ctx: EnrichContext) -> Facts:
    """True when any interface carries a public IP, Unknown when one cannot be told."""
    result: Any = False
    for nic in nics:
        configurations = nic.properties.get("ip_configuration")
        if is_unknown(configurations):
            result = merge_value(result, configurations)
            continue
        for configuration in blocks(configurations):
            value = configuration.get("public_ip_address_id")
            if is_unknown(value):
                # Known only after apply: a reference to a public IP in the scan is an address
                # that will exist, anything else (a variable, a conditional) could be null
                if value.reference and ctx.resolve(nic, value.reference, _PUBLIC_IP).ids:
                    return {"has_public_ip": True}
                result = merge_value(result, value)
            elif isinstance(value, str) and value.strip():
                return {"has_public_ip": True}
    return {"has_public_ip": result}


# The machine types that name network interfaces; the legacy type does too
_VM_TYPES = (
    "azurerm_linux_virtual_machine",
    "azurerm_windows_virtual_machine",
    "azurerm_virtual_machine",
)

COMPANIONS: tuple[CompanionSpec, ...] = (
    CompanionSpec(
        "azurerm_storage_account",
        "azurerm_storage_account_network_rules",
        ("storage_account_id",),
        _network_rules_resource,
        absent={"network_default_deny": False},
    ),
)

DERIVERS: tuple[Deriver, ...] = (Deriver(("azurerm_storage_account",), _network_rules_inline),)

RELATIONS: tuple[RelationSpec, ...] = (
    RelationSpec(
        source_types=_VM_TYPES,
        link_attrs=("network_interface_ids", "primary_network_interface_id"),
        target_type="azurerm_network_interface",
        # network_interface_ids is mandatory, so a plan that omits it has it computed
        required=True,
        derive=_has_public_ip,
        absent={"has_public_ip": False},
    ),
)

# Every derived fact this module can write, by resource type, for the provenance gate
# (tests/test_engine/test_rule_property_provenance.py): a rule may read ``derived.<fact>`` of a
# type only if some module declares it, and a module may write only what it declares.
PRODUCED: Produced = merge_produced(
    produced_by_companions(COMPANIONS),
    produced_by_relations(RELATIONS),
    produced(("azurerm_storage_account",), "network_default_deny"),
)
