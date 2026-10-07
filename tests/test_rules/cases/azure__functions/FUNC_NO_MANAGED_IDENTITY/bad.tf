variable "func_storage_key" {
  type      = string
  sensitive = true
}

resource "azurerm_function_app" "bad" {
  name                = "func-bad"
  location            = "eastus"
  resource_group_name = "rg-app"
  app_service_plan_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  storage_account_name       = "acmefuncs"
  storage_account_access_key = var.func_storage_key
  https_only = true
}

resource "azurerm_linux_function_app" "bad" {
  name                = "func-bad"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  storage_account_name       = "acmefuncs"
  storage_account_access_key = var.func_storage_key
  https_only = true

  site_config {
  }
}

resource "azurerm_windows_function_app" "bad" {
  name                = "func-bad"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  storage_account_name       = "acmefuncs"
  storage_account_access_key = var.func_storage_key
  https_only = true

  site_config {
  }
}
