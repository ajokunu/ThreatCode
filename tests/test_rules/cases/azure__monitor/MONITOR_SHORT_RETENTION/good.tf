resource "azurerm_monitor_diagnostic_setting" "long" {
  name                       = "long"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  log {
    category = "AuditEvent"
    enabled  = true

    retention_policy {
      enabled = true
      days    = 365
    }
  }
}

resource "azurerm_monitor_diagnostic_setting" "forever" {
  name                       = "forever"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  enabled_log {
    category = "AuditEvent"

    retention_policy {
      enabled = true
      days    = 0
    }
  }
}
