resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = "eastus"
  resource_group_name = "rg-app"

  security_rule {
    name                       = "sql"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "1433"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "redis_and_mongo" {
  name                        = "redis_and_mongo"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["6379", "27017"]
  source_address_prefix       = "Internet"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}
