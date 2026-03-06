# Azure AKS-based microservices platform
# Team: Platform Engineering
# Last reviewed: 2026-01-15
# Jira: PLAT-892

terraform {
  required_version = ">= 1.5"
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.80"
    }
  }
  backend "azurerm" {
    resource_group_name  = "rg-terraform-state"
    storage_account_name = "stterraformstateprod"
    container_name       = "tfstate"
    key                  = "aks-platform.tfstate"
  }
}

provider "azurerm" {
  features {}
  subscription_id = "12345678-1234-1234-1234-123456789abc"
}

resource "azurerm_resource_group" "platform" {
  name     = "rg-platform-prod-eastus"
  location = "East US"
  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
    CostCenter  = "CC-7891"
  }
}

resource "azurerm_virtual_network" "platform" {
  name                = "vnet-platform-prod"
  address_space       = ["10.50.0.0/16"]
  location            = azurerm_resource_group.platform.location
  resource_group_name = azurerm_resource_group.platform.name
}

resource "azurerm_subnet" "aks_nodes" {
  name                 = "snet-aks-nodes"
  resource_group_name  = azurerm_resource_group.platform.name
  virtual_network_name = azurerm_virtual_network.platform.name
  address_prefixes     = ["10.50.1.0/24"]
}

resource "azurerm_subnet" "aks_pods" {
  name                 = "snet-aks-pods"
  resource_group_name  = azurerm_resource_group.platform.name
  virtual_network_name = azurerm_virtual_network.platform.name
  address_prefixes     = ["10.50.2.0/22"]
}

resource "azurerm_subnet" "db" {
  name                 = "snet-database"
  resource_group_name  = azurerm_resource_group.platform.name
  virtual_network_name = azurerm_virtual_network.platform.name
  address_prefixes     = ["10.50.10.0/24"]
  service_endpoints    = ["Microsoft.Sql"]
}

resource "azurerm_network_security_group" "aks" {
  name                = "nsg-aks-platform"
  location            = azurerm_resource_group.platform.location
  resource_group_name = azurerm_resource_group.platform.name

  security_rule {
    name                       = "AllowHTTPS"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "443"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }

  security_rule {
    name                       = "AllowHTTP"
    priority                   = 110
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "80"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_kubernetes_cluster" "platform" {
  name                = "aks-platform-prod"
  location            = azurerm_resource_group.platform.location
  resource_group_name = azurerm_resource_group.platform.name
  dns_prefix          = "platform-prod"
  kubernetes_version  = "1.28.5"

  default_node_pool {
    name                = "system"
    node_count          = 3
    vm_size             = "Standard_D4s_v3"
    vnet_subnet_id      = azurerm_subnet.aks_nodes.id
    enable_auto_scaling = true
    min_count           = 3
    max_count           = 10
    os_disk_size_gb     = 128
  }

  identity {
    type = "SystemAssigned"
  }

  network_profile {
    network_plugin    = "azure"
    network_policy    = "calico"
    load_balancer_sku = "standard"
    service_cidr      = "10.60.0.0/16"
    dns_service_ip    = "10.60.0.10"
  }

  # RBAC is not enabled — flagged in last security review
  # TODO: PLAT-901 enable Azure AD RBAC
}

resource "azurerm_kubernetes_cluster_node_pool" "workloads" {
  name                  = "workloads"
  kubernetes_cluster_id = azurerm_kubernetes_cluster.platform.id
  vm_size               = "Standard_D8s_v3"
  enable_auto_scaling   = true
  min_count             = 2
  max_count             = 20
  vnet_subnet_id        = azurerm_subnet.aks_pods.id
  os_disk_size_gb       = 256

  node_labels = {
    "workload-type" = "application"
  }
}

resource "azurerm_container_registry" "platform" {
  name                = "crplatformprod"
  resource_group_name = azurerm_resource_group.platform.name
  location            = azurerm_resource_group.platform.location
  sku                 = "Premium"
  admin_enabled       = true  # Should be false, using managed identity instead
}

resource "azurerm_mssql_server" "platform" {
  name                         = "sql-platform-prod"
  resource_group_name          = azurerm_resource_group.platform.name
  location                     = azurerm_resource_group.platform.location
  version                      = "12.0"
  administrator_login          = "sqladmin"
  administrator_login_password = "<REPLACE_WITH_KEYVAULT_REF>"
  minimum_tls_version          = "1.2"
}

resource "azurerm_mssql_database" "orders" {
  name         = "sqldb-orders"
  server_id    = azurerm_mssql_server.platform.id
  collation    = "SQL_Latin1_General_CP1_CI_AS"
  max_size_gb  = 250
  sku_name     = "S3"
  zone_redundant = false
}

resource "azurerm_mssql_database" "inventory" {
  name         = "sqldb-inventory"
  server_id    = azurerm_mssql_server.platform.id
  collation    = "SQL_Latin1_General_CP1_CI_AS"
  max_size_gb  = 100
  sku_name     = "S2"
}

resource "azurerm_key_vault" "platform" {
  name                       = "kv-platform-prod"
  location                   = azurerm_resource_group.platform.location
  resource_group_name        = azurerm_resource_group.platform.name
  tenant_id                  = "87654321-4321-4321-4321-cba987654321"
  sku_name                   = "standard"
  soft_delete_retention_days = 90
  purge_protection_enabled   = true

  access_policy {
    tenant_id = "87654321-4321-4321-4321-cba987654321"
    object_id = "11111111-2222-3333-4444-555555555555"
    secret_permissions = ["Get", "List", "Set", "Delete"]
    key_permissions    = ["Get", "List", "Create", "Delete", "Encrypt", "Decrypt"]
  }
}

resource "azurerm_storage_account" "data_lake" {
  name                     = "stplatformdatalake"
  resource_group_name      = azurerm_resource_group.platform.name
  location                 = azurerm_resource_group.platform.location
  account_tier             = "Standard"
  account_replication_type = "GRS"
  is_hns_enabled           = true
  min_tls_version          = "TLS1_2"

  blob_properties {
    versioning_enabled = true
  }
}

resource "azurerm_linux_virtual_machine" "jumpbox" {
  name                = "vm-jumpbox-prod"
  resource_group_name = azurerm_resource_group.platform.name
  location            = azurerm_resource_group.platform.location
  size                = "Standard_B2s"
  admin_username      = "azureadmin"
  network_interface_ids = []

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
