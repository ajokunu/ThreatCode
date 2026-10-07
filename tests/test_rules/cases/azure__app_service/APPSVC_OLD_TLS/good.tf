resource "azurerm_app_service" "modern" {
  name                = "app-modern"
  location            = "eastus"
  resource_group_name = "rg-app"
  app_service_plan_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
    min_tls_version = "1.2"
  }
}

resource "azurerm_linux_web_app" "modern" {
  name                = "app-modern"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
    minimum_tls_version = "1.2"
  }
}

resource "azurerm_windows_web_app" "default" {
  name                = "app-default"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
  }
}
