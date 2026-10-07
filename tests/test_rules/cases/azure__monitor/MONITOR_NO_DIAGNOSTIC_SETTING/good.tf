resource "azurerm_monitor_diagnostic_setting" "logs" {
  name                       = "logs"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  enabled_log {
    category_group = "allLogs"
  }
}

resource "azurerm_monitor_diagnostic_setting" "legacy_logs" {
  name                       = "legacy_logs"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  log {
    category = "AuditEvent"
    enabled  = true
  }
}
