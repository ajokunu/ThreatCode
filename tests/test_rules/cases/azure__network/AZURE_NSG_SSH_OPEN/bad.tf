resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = "eastus"
  resource_group_name = "rg-app"

  security_rule {
    name                       = "ssh_range"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_ranges    = ["20-25"]
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "ssh_and_rdp" {
  name                        = "ssh_and_rdp"
  priority                    = 110
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_ranges     = ["3389", "22"]
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}
