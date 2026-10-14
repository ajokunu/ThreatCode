resource "azurerm_network_ddos_protection_plan" "platform" {
  name                = "ddos-platform"
  location            = "eastus"
  resource_group_name = "rg-platform"
}

resource "azurerm_virtual_network" "platform" {
  name                = "vnet-platform"
  address_space       = ["10.50.0.0/16"]
  location            = "eastus"
  resource_group_name = "rg-platform"

  ddos_protection_plan {
    id     = azurerm_network_ddos_protection_plan.platform.id
    enable = true
  }
}
