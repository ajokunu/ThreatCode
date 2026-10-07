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
    source_address_prefix      = "AzureFrontDoor.Backend"
    destination_address_prefix = "*"
  }
  security_rule {
    name                       = "AllowHTTP_internal"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "10.50.0.0/16"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_security_rule" "https_from_gateway" {
  name                        = "https_from_gateway"
  priority                    = 120
  direction                   = "Inbound"
  access                      = "Allow"
  protocol                    = "Tcp"
  source_port_range           = "*"
  destination_port_range      = "443"
  source_address_prefix       = "AzureLoadBalancer"
  destination_address_prefix  = "*"
  resource_group_name         = "rg-app"
  network_security_group_name = "nsg-app"
}
