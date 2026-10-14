"""Azure resource categories and trust zones.

A type without a `ZONES` entry gets the default zone of its category, so every database, storage
account and key vault below is a DATA node without an entry of its own.
"""

from __future__ import annotations

from typing import Any

from threatcode.ir.catalog.types import NodeCategory, TrustZone
from threatcode.values import is_unknown
from threatcode.vocab import is_world_source

CATEGORIES: dict[str, NodeCategory] = {
    # Compute and app hosting
    "azurerm_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_linux_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_windows_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_linux_web_app": NodeCategory.COMPUTE,
    "azurerm_windows_web_app": NodeCategory.COMPUTE,
    "azurerm_app_service": NodeCategory.COMPUTE,
    "azurerm_service_plan": NodeCategory.COMPUTE,
    "azurerm_function_app": NodeCategory.SERVERLESS,
    "azurerm_linux_function_app": NodeCategory.SERVERLESS,
    "azurerm_windows_function_app": NodeCategory.SERVERLESS,
    "azurerm_logic_app": NodeCategory.SERVERLESS,
    # Containers
    "azurerm_kubernetes_cluster": NodeCategory.CONTAINER,
    "azurerm_container_registry": NodeCategory.CONTAINER,
    "azurerm_container_group": NodeCategory.CONTAINER,
    "azurerm_container_app": NodeCategory.CONTAINER,
    # Data stores
    "azurerm_storage": NodeCategory.STORAGE,
    "azurerm_managed_disk": NodeCategory.STORAGE,
    "azurerm_sql": NodeCategory.DATABASE,
    "azurerm_sql_server": NodeCategory.DATABASE,
    "azurerm_sql_database": NodeCategory.DATABASE,
    "azurerm_mssql": NodeCategory.DATABASE,
    "azurerm_postgresql": NodeCategory.DATABASE,
    "azurerm_mysql": NodeCategory.DATABASE,
    "azurerm_mariadb": NodeCategory.DATABASE,
    "azurerm_cosmosdb": NodeCategory.DATABASE,
    "azurerm_redis": NodeCategory.DATABASE,
    # Secret and key material
    "azurerm_key_vault": NodeCategory.SECRET,
    "azurerm_key_vault_access_policy": NodeCategory.IAM,
    # Networks
    "azurerm_virtual_network": NodeCategory.NETWORK,
    "azurerm_subnet": NodeCategory.NETWORK,
    "azurerm_network": NodeCategory.NETWORK,
    "azurerm_network_security_group": NodeCategory.NETWORK,
    "azurerm_network_security_rule": NodeCategory.NETWORK,
    "azurerm_network_interface": NodeCategory.NETWORK,
    "azurerm_public_ip": NodeCategory.NETWORK,
    "azurerm_application_gateway": NodeCategory.NETWORK,
    "azurerm_lb": NodeCategory.NETWORK,
    "azurerm_firewall": NodeCategory.NETWORK,
    "azurerm_route": NodeCategory.NETWORK,
    "azurerm_nat_gateway": NodeCategory.NETWORK,
    "azurerm_private_endpoint": NodeCategory.NETWORK,
    "azurerm_virtual_network_gateway": NodeCategory.NETWORK,
    "azurerm_bastion_host": NodeCategory.NETWORK,
    # Edge, DNS and messaging
    "azurerm_frontdoor": NodeCategory.CDN,
    "azurerm_cdn": NodeCategory.CDN,
    "azurerm_dns": NodeCategory.DNS,
    "azurerm_private_dns": NodeCategory.DNS,
    "azurerm_api_management": NodeCategory.API,
    "azurerm_servicebus": NodeCategory.MESSAGING,
    "azurerm_eventhub": NodeCategory.MESSAGING,
    "azurerm_eventgrid": NodeCategory.MESSAGING,
    # Identity
    "azurerm_role_assignment": NodeCategory.IAM,
    "azurerm_role_definition": NodeCategory.IAM,
    "azurerm_user_assigned_identity": NodeCategory.IAM,
    # Monitoring
    "azurerm_monitor": NodeCategory.MONITORING,
    "azurerm_log_analytics": NodeCategory.MONITORING,
    "azurerm_application_insights": NodeCategory.MONITORING,
    "azurerm_security_center": NodeCategory.MONITORING,
    "azurerm_sentinel": NodeCategory.MONITORING,
}

ZONES: dict[str, TrustZone] = {
    "azurerm_kubernetes_cluster": TrustZone.PRIVATE,
    # A rule is internet facing only when it allows inbound traffic from anywhere; zone_override
    # moves every other rule out of the DMZ
    "azurerm_network_security_rule": TrustZone.DMZ,
    "azurerm_sql_server": TrustZone.DATA,
    "azurerm_sql_database": TrustZone.DATA,
    # Public entry points
    "azurerm_public_ip": TrustZone.DMZ,
    "azurerm_application_gateway": TrustZone.DMZ,
    "azurerm_lb": TrustZone.DMZ,
    "azurerm_linux_web_app": TrustZone.DMZ,
    "azurerm_windows_web_app": TrustZone.DMZ,
    "azurerm_app_service": TrustZone.DMZ,
    "azurerm_api_management": TrustZone.DMZ,
    # The plan hosts apps; it is not itself an endpoint
    "azurerm_service_plan": TrustZone.PRIVATE,
    "azurerm_app_service_plan": TrustZone.PRIVATE,
}

_RULE_TYPE = "azurerm_network_security_rule"


def _text(value: Any) -> str | None:
    """A known, non-empty string, lower-cased; None for anything else (including Unknown)."""
    if is_unknown(value) or not isinstance(value, str) or not value.strip():
        return None
    return value.strip().lower()


def _sources(properties: dict[str, Any]) -> list[Any]:
    found: list[Any] = []
    for key in ("source_address_prefix", "source_address_prefixes"):
        value = properties.get(key)
        if isinstance(value, list):
            found.extend(value)
        elif value is not None:
            found.append(value)
    return found


def allows_inbound_from_world(properties: dict[str, Any]) -> bool | None:
    """Whether a network security rule allows inbound traffic from a world source.

    True for an `Inbound` and `Allow` rule with a world source (`*`, `Internet`, `0.0.0.0/0`).
    False for a rule that is outbound, denies, or names only sources inside the network.
    None when the direction, the access or the source is missing or not known, because a value
    the scan cannot read decides nothing.
    """
    direction = _text(properties.get("direction"))
    access = _text(properties.get("access"))
    if direction is None or access is None:
        return None
    if direction != "inbound" or access != "allow":
        return False
    sources = _sources(properties)
    if any(not is_unknown(source) and is_world_source(source) for source in sources):
        return True
    if not sources or any(is_unknown(source) for source in sources):
        return None
    return False


def zone_override(resource_type: str, properties: dict[str, Any]) -> TrustZone | None:
    """The zone a network security rule's own properties decide, else None.

    A rule that allows inbound traffic from a world source is in the DMZ.
    A rule that is known to be outbound, to deny, or to name a source inside the network is
    private.
    A rule whose direction, access or source is missing or not known keeps its type default,
    because an unresolved value never selects a zone.
    """
    if resource_type != _RULE_TYPE:
        return None
    world = allows_inbound_from_world(properties)
    if world is None:
        return None
    return TrustZone.DMZ if world else TrustZone.PRIVATE
