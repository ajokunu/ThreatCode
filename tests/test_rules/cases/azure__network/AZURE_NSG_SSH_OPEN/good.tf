resource "azurerm_network_security_group" "app" {
  name                = "nsg-app"
  location            = "eastus"
  resource_group_name = "rg-app"

  security_rule {
    name                       = "ssh_from_bastion"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "10.50.10.0/24"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "ssh_udp"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Udp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "ssh_denied"
    priority                   = 120
    direction                  = "Inbound"
    access                     = "Deny"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "22"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "ssh_from_corp" {
  name                        = "ssh_from_corp"
  priority                    = 130
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefixes     = ["10.0.0.0/24", "192.168.4.0/24"]
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}

resource "azurerm_network_security_rule" "ssh_outbound" {
  name                        = "ssh_outbound"
  priority                    = 140
  direction                   = "Outbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "22"
  source_address_prefix       = "*"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}
