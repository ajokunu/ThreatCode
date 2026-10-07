resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = "eastus"
  resource_group_name = "rg-app"

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "Internet"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "AllowSSHFromMgmt"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.50.10.0/24"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "DenyAllInbound"
    priority                   = 4096
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "*"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "internal_all" {
  name                        = "internal_all"
  priority                    = 210
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "10.0.0.0/8"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}

resource "azurerm_network_security_rule" "outbound_all" {
  name                        = "outbound_all"
  priority                    = 220
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "*"
  source_port_range           = "*"
  destination_port_range      = "*"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}
