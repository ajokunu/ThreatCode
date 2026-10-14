resource "azurerm_monitor_diagnostic_setting" "short" {
  name                       = "short"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  log {
    category = "AuditEvent"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 30
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "short_enabled_log" {
  name                       = "short_enabled_log"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  enabled_log {
    category = "AuditEvent"

    retention_policy {
      enabled = true
      days    = 45
    }
  }
}
