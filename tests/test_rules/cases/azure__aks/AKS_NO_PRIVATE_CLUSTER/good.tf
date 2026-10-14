resource "azurerm_kubernetes_cluster" "private" {
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

  private_cluster_enabled = true
}

resource "azurerm_kubernetes_cluster" "restricted" {
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

  private_cluster_enabled = false

  api_server_access_profile {
    authorized_ip_ranges = ["203.0.113.0/24"]
  }
}
