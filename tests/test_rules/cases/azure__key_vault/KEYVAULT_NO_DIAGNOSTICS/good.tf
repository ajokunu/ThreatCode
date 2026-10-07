resource "azurerm_key_vault" "kv" {
  name                = "kv-kv-prod"
  location            = "eastus"
  resource_group_name = "rg-sec"
  tenant_id           = "00000000-0000-0000-0000-000000000000"
  sku_name            = "standard"
  purge_protection_enabled = true
}

resource "azurerm_monitor_diagnostic_setting" "kv" {
  name                       = "kv-audit"
  target_resource_id         = azurerm_key_vault.kv.id
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.OperationalInsights/workspaces/law"

  enabled_log {
    category = "AuditEvent"
  }
}
