resource "azurerm_container_registry" "platform" {
  name                = "crplatformprod"
  resource_group_name = "rg-platform"
  location            = "eastus"
  sku                 = "Premium"
  admin_enabled = true
}
