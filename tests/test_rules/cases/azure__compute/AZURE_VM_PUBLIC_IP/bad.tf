resource "azurerm_public_ip" "vm" {
  name                = "pip-vm"
  location            = "eastus"
  resource_group_name = "rg-app"
  allocation_method   = "Static"
}

resource "azurerm_network_interface" "nic" {
  name                = "nic"
  location            = "eastus"
  resource_group_name = "rg-app"

  ip_configuration {
    name                          = "internal"
    subnet_id                     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app"
    private_ip_address_allocation = "Dynamic"
    public_ip_address_id          = azurerm_public_ip.vm.id
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm-vm"
  resource_group_name   = "rg-app"
  location              = "eastus"
  size                  = "Standard_B2s"
  admin_username        = "azureadmin"
  network_interface_ids = [azurerm_network_interface.nic.id]

  admin_ssh_key {
    username   = "azureadmin"
    public_key = file("~/.ssh/id_rsa.pub")
  }

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "Canonical"
    offer     = "0001-com-ubuntu-server-jammy"
    sku       = "22_04-lts-gen2"
    version   = "latest"
  }
}
