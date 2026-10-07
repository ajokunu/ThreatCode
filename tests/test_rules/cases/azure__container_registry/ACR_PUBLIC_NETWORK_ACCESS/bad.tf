resource "azurerm_container_registry" "open" {
  name                = "cropenprod"
  resource_group_name = "rg-platform"
  location            = "eastus"
  sku                 = "Premium"
  public_network_access_enabled = true
}
