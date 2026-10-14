resource "azurerm_kubernetes_cluster" "platform" {
  name                = "aks-platform"
  location            = "eastus"
  resource_group_name = "rg-platform"
  dns_prefix          = "platform"

  default_node_pool {
    name       = "system"
    node_count = 3
    vm_size    = "Standard_D4s_v3"
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin = "azure"
    network_policy = "calico"
  }
}
