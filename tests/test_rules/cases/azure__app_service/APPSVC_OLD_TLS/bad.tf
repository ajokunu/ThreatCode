resource "azurerm_app_service" "old" {
  name                = "app-old"
  location            = "eastus"
  resource_group_name = "rg-app"
  app_service_plan_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
    min_tls_version = "1.0"
  }
}

resource "azurerm_linux_web_app" "old" {
  name                = "app-old"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
    minimum_tls_version = "1.1"
  }
}
