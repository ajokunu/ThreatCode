resource "azurerm_app_service" "legacy" {
  name                = "app-legacy"
  location            = "eastus"
  resource_group_name = "rg-app"
  app_service_plan_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  auth_settings {
    enabled          = true
    default_provider = "AzureActiveDirectory"
  }
}

resource "azurerm_linux_web_app" "v2" {
  name                = "app-v2"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  auth_settings_v2 {
    auth_enabled = true
    login {}
  }

  site_config {
  }
}
