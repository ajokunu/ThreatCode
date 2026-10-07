resource "azurerm_container_registry" "platform" {
  name                = "crplatformprod"
  resource_group_name = "rg-platform"
  location            = "eastus"
  sku                 = "Premium"
  anonymous_pull_enabled = true
}
