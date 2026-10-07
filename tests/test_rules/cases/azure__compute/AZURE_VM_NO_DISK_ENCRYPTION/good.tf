variable "admin_password" {
  type      = string
  sensitive = true
}

resource "azurerm_network_interface" "nic" {
  name                = "nic"
  location            = "eastus"
  resource_group_name = "rg-app"

  ip_configuration {
    name                          = "internal"
    subnet_id                     = "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/rg-net/providers/Microsoft.Network/virtualNetworks/vnet/subnets/app"
    private_ip_address_allocation = "Dynamic"
  }
}

resource "azurerm_linux_virtual_machine" "vm" {
  name                  = "vm-vm"
  resource_group_name   = "rg-app"
  location              = "eastus"
  size                  = "Standard_B2s"
  admin_username        = "azureadmin"
  network_interface_ids = [azurerm_network_interface.nic.id]
  encryption_at_host_enabled = true

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

resource "azurerm_windows_virtual_machine" "winvm" {
  name                  = "win-winvm"
  resource_group_name   = "rg-app"
  location              = "eastus"
  size                  = "Standard_D2s_v5"
  admin_username        = "azureadmin"
  admin_password        = var.admin_password
  network_interface_ids = [azurerm_network_interface.nic.id]
  encryption_at_host_enabled = true

  os_disk {
    caching              = "ReadWrite"
    storage_account_type = "Premium_LRS"
  }

  source_image_reference {
    publisher = "MicrosoftWindowsServer"
    offer     = "WindowsServer"
    sku       = "2022-datacenter-azure-edition"
    version   = "latest"
  }
}
