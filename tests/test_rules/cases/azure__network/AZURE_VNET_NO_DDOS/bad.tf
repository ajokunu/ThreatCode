resource "azurerm_virtual_network" "platform" {
  name                = "vnet-platform"
  address_space       = ["10.50.0.0/16"]
  location            = "eastus"
  resource_group_name = "rg-platform"
}
