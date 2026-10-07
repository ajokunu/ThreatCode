resource "azurerm_monitor_activity_log_alert" "policy" {
  name                = "policy-changes"
  resource_group_name = "rg-mon"
  location            = "global"
  scopes              = ["/subscriptions/00000000-0000-0000-0000-000000000000"]
  description         = "Policy assignment changes"
  enabled             = false

  criteria {
    category       = "Administrative"
    operation_name = "Microsoft.Authorization/policyAssignments/write"
  }
}
