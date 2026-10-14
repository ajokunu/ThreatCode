variable "func_storage_key" {
  type      = string
  sensitive = true
}

resource "azurerm_linux_function_app" "private" {
  name                = "func-private"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  storage_account_name       = "acmefuncs"
  storage_account_access_key = var.func_storage_key
  https_only = true
  public_network_access_enabled = false

  site_config {
  }
}

resource "azurerm_windows_function_app" "restricted" {
  name                = "func-restricted"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  storage_account_name       = "acmefuncs"
  storage_account_access_key = var.func_storage_key
  https_only = true
  public_network_access_enabled = true

  site_config {
    ip_restriction {
      ip_address = "203.0.113.0/24"
      action     = "Allow"
      priority   = 100
    }
  }
}
