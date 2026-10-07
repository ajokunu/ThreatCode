resource "azurerm_app_service" "ftp" {
  name                = "app-ftp"
  location            = "eastus"
  resource_group_name = "rg-app"
  app_service_plan_id = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
    ftps_state = "AllAllowed"
  }
}

resource "azurerm_windows_web_app" "ftp" {
  name                = "app-ftp"
  location            = "eastus"
  resource_group_name = "rg-app"
  service_plan_id     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-app/providers/Microsoft.Web/serverfarms/plan"
  https_only = true

  site_config {
    ftps_state = "AllAllowed"
  }
}
