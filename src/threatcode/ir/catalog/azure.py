"""Azure resource categories and trust zones."""

from __future__ import annotations

from threatcode.ir.catalog.types import NodeCategory, TrustZone

CATEGORIES: dict[str, NodeCategory] = {
    "azurerm_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_linux_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_windows_virtual_machine": NodeCategory.COMPUTE,
    "azurerm_storage": NodeCategory.STORAGE,
    "azurerm_virtual_network": NodeCategory.NETWORK,
    "azurerm_subnet": NodeCategory.NETWORK,
    "azurerm_network_security_group": NodeCategory.NETWORK,
    "azurerm_sql": NodeCategory.DATABASE,
    "azurerm_cosmosdb": NodeCategory.DATABASE,
    "azurerm_function_app": NodeCategory.SERVERLESS,
    "azurerm_kubernetes_cluster": NodeCategory.CONTAINER,
    "azurerm_network_security_rule": NodeCategory.NETWORK,
    "azurerm_sql_server": NodeCategory.DATABASE,
    "azurerm_sql_database": NodeCategory.DATABASE,
}

ZONES: dict[str, TrustZone] = {
    "azurerm_kubernetes_cluster": TrustZone.PRIVATE,
    "azurerm_network_security_rule": TrustZone.DMZ,
    "azurerm_sql_server": TrustZone.DATA,
    "azurerm_sql_database": TrustZone.DATA,
}
