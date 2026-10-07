resource "azurerm_storage_account" "legacy" {
  name                     = "acmelegacy"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  enable_https_traffic_only = true
}

resource "azurerm_storage_account" "current" {
  name                     = "acmecurrent"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
  https_traffic_only_enabled = true
}

resource "azurerm_storage_account" "default" {
  name                     = "acmedefault"
  resource_group_name      = "rg-data"
  location                 = "eastus"
  account_tier             = "Standard"
  account_replication_type = "GRS"
}
