resource "azurerm_monitor_diagnostic_setting" "metrics_only" {
  name                       = "metrics_only"
  target_resource_id         = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-sec/providers/Microsoft.KeyVault/vaults/kv"
  log_analytics_workspace_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-mon/providers/Microsoft.OperationalInsights/workspaces/law"

  metric {
    category = "AllMetrics"
  }
}
